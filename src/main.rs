mod admin;
mod admin_ui;
mod anthropic;
mod common;
mod http_client;
pub mod image;
mod kiro;
mod model;
pub mod token;

use std::sync::Arc;

use clap::Parser;
use kiro::model::credentials::{CredentialsConfig, KiroCredentials};
use kiro::provider::KiroProvider;
use kiro::token_manager::MultiTokenManager;
use model::arg::Args;
use model::config::Config;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = args
        .config
        .unwrap_or_else(|| Config::default_config_path().to_string());
    let config = Config::load(&config_path).unwrap_or_else(|e| {
        tracing::error!("加载配置失败: {}", e);
        std::process::exit(1);
    });

    let credentials_path = args
        .credentials
        .unwrap_or_else(|| KiroCredentials::default_credentials_path().to_string());
    let credentials_config = CredentialsConfig::load(&credentials_path).unwrap_or_else(|e| {
        tracing::error!("加载凭据失败: {}", e);
        std::process::exit(1);
    });

    let is_multiple_format = credentials_config.is_multiple();
    let credentials_list = credentials_config.into_sorted_credentials();
    tracing::info!("已加载 {} 个凭据配置", credentials_list.len());

    let first_credentials = credentials_list.first().cloned().unwrap_or_default();
    #[cfg(feature = "sensitive-logs")]
    tracing::debug!("主凭据: {:?}", first_credentials);
    #[cfg(not(feature = "sensitive-logs"))]
    tracing::debug!(
        id = ?first_credentials.id,
        priority = first_credentials.priority,
        has_profile_arn = first_credentials.profile_arn.is_some(),
        has_expires_at = first_credentials.expires_at.is_some(),
        auth_method = ?first_credentials.auth_method.as_deref(),
        "主凭据摘要"
    );

    let api_key = config.api_key.clone().unwrap_or_else(|| {
        tracing::error!("配置文件中未设置 apiKey");
        std::process::exit(1);
    });

    let proxy_config = config.proxy_url.as_ref().map(|url| {
        let mut proxy = http_client::ProxyConfig::new(url);
        if let (Some(username), Some(password)) = (&config.proxy_username, &config.proxy_password) {
            proxy = proxy.with_auth(username, password);
        }
        proxy
    });

    if let Some(proxy_url) = &config.proxy_url {
        tracing::info!("已配置 HTTP 代理: {}", proxy_url);
    }

    let token_manager = MultiTokenManager::new(
        config.clone(),
        credentials_list,
        proxy_config.clone(),
        Some(credentials_path.into()),
        is_multiple_format,
    )
    .unwrap_or_else(|e| {
        tracing::error!("创建 Token 管理器失败: {}", e);
        std::process::exit(1);
    });
    let token_manager = Arc::new(token_manager);

    let init_count = token_manager.initialize_balances().await;
    if init_count == 0 && token_manager.total_count() > 0 {
        tracing::warn!("所有凭据余额初始化失败，将按优先级选择凭据");
    }

    let kiro_provider = KiroProvider::with_proxy(token_manager.clone(), proxy_config.clone());

    token::init_config(token::CountTokensConfig {
        api_url: config.count_tokens_api_url.clone(),
        api_key: config.count_tokens_api_key.clone(),
        auth_type: config.count_tokens_auth_type.clone(),
        proxy: proxy_config,
        tls_backend: config.tls_backend,
    });

    anthropic::cache::set_debug_logging(config.cache_debug_logging);
    if let Some(redis_url) = &config.redis_url {
        if let Err(e) = anthropic::cache::init_redis(redis_url).await {
            tracing::warn!("Failed to initialize Redis cache: {}", e);
        }
    }

    let anthropic_app = anthropic::create_router_with_provider(
        &api_key,
        Some(kiro_provider),
        first_credentials.profile_arn.clone(),
        config.compression.clone(),
    );

    let admin_key_valid = config
        .admin_api_key
        .as_ref()
        .map(|k| !k.trim().is_empty())
        .unwrap_or(false);

    let app = if let Some(admin_key) = &config.admin_api_key {
        if admin_key.trim().is_empty() {
            tracing::warn!("admin_api_key 配置为空，Admin API 未启用");
            anthropic_app
        } else {
            let admin_service = admin::AdminService::new(token_manager.clone());
            let admin_state = admin::AdminState::new(admin_key, admin_service);
            let admin_app = admin::create_admin_router(admin_state);
            let admin_ui_app = admin_ui::create_admin_ui_router();

            tracing::info!("Admin API 已启用");
            tracing::info!("Admin UI 已启用: /admin");
            anthropic_app
                .nest("/api/admin", admin_app)
                .nest("/admin", admin_ui_app)
        }
    } else {
        anthropic_app
    };

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("启动 Anthropic API 端点: {}", addr);
    #[cfg(feature = "sensitive-logs")]
    tracing::debug!("API Key: {}***", &api_key[..(api_key.len() / 2)]);
    #[cfg(not(feature = "sensitive-logs"))]
    tracing::info!(
        "API Key: ***{} (长度: {})",
        &api_key[api_key.len().saturating_sub(4)..],
        api_key.len()
    );
    tracing::info!("可用 API:");
    tracing::info!("  GET  /v1/models");
    tracing::info!("  POST /v1/messages");
    tracing::info!("  POST /v1/messages/count_tokens");
    if admin_key_valid {
        tracing::info!("Admin API:");
        tracing::info!("  GET  /api/admin/credentials");
        tracing::info!("  POST /api/admin/credentials/:index/disabled");
        tracing::info!("  POST /api/admin/credentials/:index/priority");
        tracing::info!("  POST /api/admin/credentials/:index/reset");
        tracing::info!("  GET  /api/admin/credentials/:index/balance");
        tracing::info!("Admin UI:");
        tracing::info!("  GET  /admin");
    }

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("绑定监听地址失败 ({}): {}", addr, e);
            std::process::exit(1);
        });
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("HTTP 服务异常退出: {}", e);
        std::process::exit(1);
    }
}
