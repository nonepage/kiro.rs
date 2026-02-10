//! 图片处理模块
//!
//! 提供图片 token 计算和缩放功能。
//!
//! # Token 计算公式（Anthropic 官方）
//! ```text
//! tokens = (width × height) / 750
//! ```
//!
//! # 缩放规则
//! 1. 长边超过 max_long_edge 时，等比缩放
//! 2. 总像素超过 max_pixels 时，等比缩放
//! 3. 多图模式（图片数 >= threshold）使用独立的像素限制配置

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use image::{DynamicImage, ImageFormat, ImageReader};
use std::io::Cursor;

use crate::model::config::CompressionConfig;

/// 图片处理结果
#[derive(Debug)]
pub struct ImageProcessResult {
    /// 处理后的 base64 数据
    pub data: String,
    /// 原始尺寸 (width, height)
    pub original_size: (u32, u32),
    /// 处理后尺寸 (width, height)
    pub final_size: (u32, u32),
    /// 估算的 token 数
    pub tokens: u64,
    /// 是否进行了缩放
    pub was_resized: bool,
}

/// 从 base64 数据计算图片 token（不缩放）
///
/// 返回 (tokens, width, height)，解析失败返回 None
pub fn estimate_image_tokens(base64_data: &str) -> Option<(u64, u32, u32)> {
    let bytes = BASE64.decode(base64_data).ok()?;
    let reader = ImageReader::new(Cursor::new(&bytes))
        .with_guessed_format()
        .ok()?;
    let (width, height) = reader.into_dimensions().ok()?;

    // 应用 Anthropic 缩放规则计算 token
    let (scaled_w, scaled_h) = apply_scaling_rules(width, height, 1568, 1_150_000);
    let tokens = calculate_tokens(scaled_w, scaled_h);

    Some((tokens, width, height))
}

/// 处理图片：根据配置缩放并返回处理结果
///
/// # 参数
/// - `base64_data`: 原始 base64 编码的图片数据
/// - `format`: 图片格式（"jpeg", "png", "gif", "webp"）
/// - `config`: 压缩配置
/// - `image_count`: 当前请求中的图片总数（用于判断是否启用多图模式）
pub fn process_image(
    base64_data: &str,
    format: &str,
    config: &CompressionConfig,
    image_count: usize,
) -> Result<ImageProcessResult, String> {
    // 解码 base64
    let bytes = BASE64
        .decode(base64_data)
        .map_err(|e| format!("base64 解码失败: {}", e))?;

    // 先只读取图片头获取尺寸（避免不必要的全量解码）
    let reader = ImageReader::new(Cursor::new(&bytes))
        .with_guessed_format()
        .map_err(|e| format!("图片格式识别失败: {}", e))?;
    let original_size = reader
        .into_dimensions()
        .map_err(|e| format!("读取图片尺寸失败: {}", e))?;

    // 根据图片数量选择像素限制
    let max_pixels = if image_count >= config.image_multi_threshold {
        config.image_max_pixels_multi
    } else {
        config.image_max_pixels_single
    };

    // 计算目标尺寸
    let (target_w, target_h) = apply_scaling_rules(
        original_size.0,
        original_size.1,
        config.image_max_long_edge,
        max_pixels,
    );

    let needs_resize = target_w != original_size.0 || target_h != original_size.1;

    // 仅在需要缩放时才全量解码图片
    let (output_data, final_size) = if needs_resize {
        let img =
            image::load_from_memory(&bytes).map_err(|e| format!("图片加载失败: {}", e))?;
        let resized = img.resize(target_w, target_h, image::imageops::FilterType::Lanczos3);
        let size = (resized.width(), resized.height());
        (encode_image(&resized, format)?, size)
    } else {
        (base64_data.to_string(), original_size)
    };

    let tokens = calculate_tokens(final_size.0, final_size.1);

    Ok(ImageProcessResult {
        data: output_data,
        original_size,
        final_size,
        tokens,
        was_resized: needs_resize,
    })
}

/// 应用 Anthropic 缩放规则
///
/// 1. 长边不超过 max_long_edge
/// 2. 总像素不超过 max_pixels
fn apply_scaling_rules(width: u32, height: u32, max_long_edge: u32, max_pixels: u32) -> (u32, u32) {
    let mut w = width as f64;
    let mut h = height as f64;

    // 规则 1: 长边限制
    let long_edge = w.max(h);
    if long_edge > max_long_edge as f64 {
        let scale = max_long_edge as f64 / long_edge;
        w *= scale;
        h *= scale;
    }

    // 规则 2: 总像素限制
    let pixels = w * h;
    if pixels > max_pixels as f64 {
        let scale = (max_pixels as f64 / pixels).sqrt();
        w *= scale;
        h *= scale;
    }

    (w.floor().max(1.0) as u32, h.floor().max(1.0) as u32)
}

/// 计算 token 数
#[inline]
fn calculate_tokens(width: u32, height: u32) -> u64 {
    ((width as u64 * height as u64) + 375) / 750 // 四舍五入
}

/// 将图片编码为 base64
fn encode_image(img: &DynamicImage, format: &str) -> Result<String, String> {
    let mut buffer = Cursor::new(Vec::new());

    let image_format = match format {
        "jpeg" | "jpg" => ImageFormat::Jpeg,
        "png" => ImageFormat::Png,
        "gif" => ImageFormat::Gif,
        "webp" => ImageFormat::WebP,
        _ => return Err(format!("不支持的图片格式: {}", format)),
    };

    img.write_to(&mut buffer, image_format)
        .map_err(|e| format!("图片编码失败: {}", e))?;

    Ok(BASE64.encode(buffer.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scaling_rules() {
        // 测试长边限制
        assert_eq!(
            apply_scaling_rules(2000, 1000, 1568, 10_000_000),
            (1568, 784)
        );

        // 测试像素限制
        assert_eq!(
            apply_scaling_rules(1200, 1200, 1568, 1_000_000),
            (1000, 1000)
        );

        // 测试无需缩放
        assert_eq!(apply_scaling_rules(800, 600, 1568, 1_150_000), (800, 600));
    }

    #[test]
    fn test_calculate_tokens() {
        assert_eq!(calculate_tokens(1092, 1092), 1590); // 1:1 标准
        assert_eq!(calculate_tokens(200, 200), 53); // 小图
    }
}
