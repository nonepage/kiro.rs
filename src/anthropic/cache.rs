//! Prompt Caching 模块 - 使用 Redis 实现前缀 hash 匹配

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::anthropic::types::{CacheControl, Message, SystemMessage, Tool};
use crate::token;

/// 全局 Redis 连接管理器
static REDIS_CONN: OnceLock<ConnectionManager> = OnceLock::new();

/// 默认 TTL: 5 分钟
const DEFAULT_TTL_SECS: u64 = 5 * 60;
/// 1 小时 TTL
const EXTENDED_TTL_SECS: u64 = 60 * 60;

/// 缓存断点信息
#[derive(Debug, Clone)]
pub struct CacheBreakpoint {
    pub hash: String,
    pub tokens: i32,
    pub ttl: u64,
}

/// 缓存查询结果
#[derive(Debug, Clone, Default)]
pub struct CacheResult {
    pub cache_read_input_tokens: i32,
    pub cache_creation_input_tokens: i32,
    pub uncached_input_tokens: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CacheMutation {
    Refresh { index: usize },
    Create { index: usize },
}

/// 初始化 Redis 连接
pub async fn init_redis(redis_url: &str) -> anyhow::Result<()> {
    let client = redis::Client::open(redis_url)?;
    let conn = ConnectionManager::new(client).await?;
    REDIS_CONN
        .set(conn)
        .map_err(|_| anyhow::anyhow!("Redis already initialized"))?;
    tracing::info!("Redis cache initialized: {}", redis_url);
    Ok(())
}

/// 检查 Redis 是否已初始化
pub fn is_redis_available() -> bool {
    REDIS_CONN.get().is_some()
}

/// 计算请求的缓存断点
pub fn compute_cache_breakpoints(
    tools: &Option<Vec<Tool>>,
    system: &Option<Vec<SystemMessage>>,
    messages: &[Message],
) -> Vec<CacheBreakpoint> {
    let tools_with_cache_control = tools
        .as_ref()
        .map(|t| t.iter().filter(|tool| tool.cache_control.is_some()).count())
        .unwrap_or(0);

    let system_with_cache_control = system
        .as_ref()
        .map(|s| s.iter().filter(|msg| msg.cache_control.is_some()).count())
        .unwrap_or(0);

    let messages_with_cache_control = messages
        .iter()
        .filter(|msg| {
            msg.content
                .as_array()
                .map(|blocks| blocks.iter().any(|b| b.get("cache_control").is_some()))
                .unwrap_or(false)
        })
        .count();

    tracing::debug!(
        "Cache control in request: tools={}/{}, system={}/{}, messages={}/{}",
        tools_with_cache_control,
        tools.as_ref().map(|t| t.len()).unwrap_or(0),
        system_with_cache_control,
        system.as_ref().map(|s| s.len()).unwrap_or(0),
        messages_with_cache_control,
        messages.len()
    );

    let mut hasher = Sha256::new();
    let mut breakpoints = Vec::new();
    let mut cumulative_tokens: i32 = 0;

    // 处理 tools（按 name 排序，确保顺序稳定）
    if let Some(tools) = tools {
        let mut sorted_tools: Vec<_> = tools.iter().collect();
        sorted_tools.sort_by(|a, b| a.name.cmp(&b.name));

        for tool in sorted_tools {
            let normalized = normalize_tool(tool);
            hasher.update(normalized.as_bytes());
            cumulative_tokens += count_tool_tokens(tool);

            if let Some(cc) = &tool.cache_control {
                let ttl = parse_ttl(cc);
                breakpoints.push(CacheBreakpoint {
                    hash: format!("{:x}", hasher.clone().finalize()),
                    tokens: cumulative_tokens,
                    ttl,
                });
            }
        }
    }

    // 处理 system
    if let Some(system) = system {
        for msg in system {
            hasher.update(msg.text.as_bytes());
            cumulative_tokens += token::count_tokens(&msg.text) as i32;

            if let Some(cc) = &msg.cache_control {
                let ttl = parse_ttl(cc);
                breakpoints.push(CacheBreakpoint {
                    hash: format!("{:x}", hasher.clone().finalize()),
                    tokens: cumulative_tokens,
                    ttl,
                });
            }
        }
    }

    // 处理 messages（遍历所有消息内容块）
    for msg in messages {
        if let Some(blocks) = msg.content.as_array() {
            for block in blocks {
                let block_json = normalize_message_block(block);
                hasher.update(block_json.as_bytes());

                if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                    cumulative_tokens += token::count_tokens(text) as i32;
                }

                if let Some(cc) = block.get("cache_control") {
                    if let Ok(cache_control) = serde_json::from_value::<CacheControl>(cc.clone()) {
                        let ttl = parse_ttl(&cache_control);
                        breakpoints.push(CacheBreakpoint {
                            hash: format!("{:x}", hasher.clone().finalize()),
                            tokens: cumulative_tokens,
                            ttl,
                        });
                    }
                }
            }
        } else if let Some(text) = msg.content.as_str() {
            hasher.update(text.as_bytes());
            cumulative_tokens += token::count_tokens(text) as i32;
        }
    }

    tracing::debug!(
        "Cache breakpoints computed: count={}, tools={}, system={}, messages={}",
        breakpoints.len(),
        tools.as_ref().map(|t| t.len()).unwrap_or(0),
        system.as_ref().map(|s| s.len()).unwrap_or(0),
        messages.len()
    );

    breakpoints
}

fn parse_ttl(cc: &CacheControl) -> u64 {
    match cc.ttl.as_deref() {
        Some("1h") => EXTENDED_TTL_SECS,
        _ => DEFAULT_TTL_SECS,
    }
}

fn sort_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), sort_json_value(v));
            }
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(sort_json_value).collect())
        }
        _ => value.clone(),
    }
}

fn sort_json_keys(value: &serde_json::Value) -> Result<String, serde_json::Error> {
    let sorted = sort_json_value(value);
    serde_json::to_string(&sorted)
}

fn normalize_tool(tool: &Tool) -> String {
    let mut parts = Vec::new();
    parts.push(format!("name:{}", tool.name));
    if !tool.description.is_empty() {
        parts.push(format!("desc:{}", tool.description));
    }
    if !tool.input_schema.is_empty() {
        let schema_value = serde_json::to_value(&tool.input_schema).unwrap_or_default();
        if let Ok(sorted) = sort_json_keys(&schema_value) {
            parts.push(format!("schema:{}", sorted));
        }
    }
    parts.join("|")
}

fn count_tool_tokens(tool: &Tool) -> i32 {
    let mut total = 0;

    if !tool.name.is_empty() {
        total += token::count_tokens(&tool.name) as i32;
    }
    if !tool.description.is_empty() {
        total += token::count_tokens(&tool.description) as i32;
    }
    if !tool.input_schema.is_empty() {
        let schema_value = serde_json::to_value(&tool.input_schema).unwrap_or_default();
        let schema = sort_json_keys(&schema_value).unwrap_or_default();
        total += token::count_tokens(&schema) as i32;
    }

    total
}

fn normalize_message_block(block: &serde_json::Value) -> String {
    let normalized = strip_cache_control(block);
    sort_json_keys(&normalized).unwrap_or_else(|_| normalized.to_string())
}

fn strip_cache_control(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut normalized = serde_json::Map::new();
            for (key, child) in map {
                if key != "cache_control" {
                    normalized.insert(key.clone(), strip_cache_control(child));
                }
            }
            serde_json::Value::Object(normalized)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.iter().map(strip_cache_control).collect())
        }
        _ => value.clone(),
    }
}

fn plan_cache_mutations(
    breakpoints: &[CacheBreakpoint],
    cached_tokens: &[Option<i32>],
    total_input_tokens: i32,
) -> (CacheResult, Vec<CacheMutation>) {
    debug_assert_eq!(breakpoints.len(), cached_tokens.len());

    if breakpoints.is_empty() {
        return (
            CacheResult {
                uncached_input_tokens: total_input_tokens,
                ..Default::default()
            },
            Vec::new(),
        );
    }

    let mut result = CacheResult::default();
    let mut mutations = Vec::new();

    if let Some((hit_index, stored_tokens)) = cached_tokens
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, tokens)| tokens.map(|tokens| (index, tokens)))
    {
        let hit_tokens = stored_tokens.clamp(0, breakpoints[hit_index].tokens);
        result.cache_read_input_tokens = hit_tokens;
        mutations.push(CacheMutation::Refresh { index: hit_index });

        let mut covered_tokens = hit_tokens;
        for index in (hit_index + 1)..breakpoints.len() {
            let bp_tokens = breakpoints[index].tokens;

            match cached_tokens[index] {
                Some(existing_tokens) => {
                    mutations.push(CacheMutation::Refresh { index });
                    covered_tokens = covered_tokens.max(existing_tokens.clamp(0, bp_tokens));
                }
                None => {
                    let additional_tokens = (bp_tokens - covered_tokens).max(0);
                    result.cache_creation_input_tokens += additional_tokens;
                    covered_tokens = bp_tokens;
                    mutations.push(CacheMutation::Create { index });
                }
            }
        }
    } else {
        let mut covered_tokens = 0;
        for (index, bp) in breakpoints.iter().enumerate() {
            let additional_tokens = (bp.tokens - covered_tokens).max(0);
            result.cache_creation_input_tokens += additional_tokens;
            covered_tokens = bp.tokens;
            mutations.push(CacheMutation::Create { index });
        }
    }

    let cached_total = result.cache_read_input_tokens + result.cache_creation_input_tokens;
    result.uncached_input_tokens = (total_input_tokens - cached_total).max(0);

    (result, mutations)
}

/// 查询或创建缓存
pub async fn lookup_or_create(
    api_key: &str,
    breakpoints: &[CacheBreakpoint],
    total_input_tokens: i32,
) -> CacheResult {
    let Some(conn) = REDIS_CONN.get() else {
        tracing::debug!("Cache lookup skipped: Redis not available");
        return CacheResult {
            uncached_input_tokens: total_input_tokens,
            ..Default::default()
        };
    };

    if breakpoints.is_empty() {
        tracing::debug!("Cache lookup skipped: no breakpoints");
        return CacheResult {
            uncached_input_tokens: total_input_tokens,
            ..Default::default()
        };
    }

    let mut conn = conn.clone();
    let keys: Vec<String> = breakpoints
        .iter()
        .map(|bp| format!("cache:{}:{}", api_key, bp.hash))
        .collect();

    let mut cached_tokens = Vec::with_capacity(keys.len());
    for key in &keys {
        let cached: Option<i32> = match conn.get(key).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("Failed to query cache key {}: {}", key, error);
                None
            }
        };

        if let Some(tokens) = cached {
            tracing::debug!("Cache hit: key={}, cached_tokens={}", key, tokens);
        } else {
            tracing::debug!("Cache miss: key={}", key);
        }

        cached_tokens.push(cached);
    }

    let (result, mutations) = plan_cache_mutations(breakpoints, &cached_tokens, total_input_tokens);

    for mutation in mutations {
        match mutation {
            CacheMutation::Refresh { index } => {
                if let Err(error) = conn
                    .expire::<_, ()>(&keys[index], breakpoints[index].ttl as i64)
                    .await
                {
                    tracing::warn!(
                        "Failed to refresh cache TTL for key {}: {}",
                        keys[index],
                        error
                    );
                }
            }
            CacheMutation::Create { index } => {
                if let Err(error) = conn
                    .set_ex::<_, _, ()>(
                        &keys[index],
                        breakpoints[index].tokens,
                        breakpoints[index].ttl,
                    )
                    .await
                {
                    tracing::warn!("Failed to create cache for key {}: {}", keys[index], error);
                }
            }
        }
    }

    tracing::debug!(
        "Cache result: read={}, creation={}, uncached={}",
        result.cache_read_input_tokens,
        result.cache_creation_input_tokens,
        result.uncached_input_tokens
    );

    result
}
