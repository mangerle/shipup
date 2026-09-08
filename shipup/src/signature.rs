// shipup 跨平台自更新系统 - SHA-256 完整性与 Ed25519 签名校验器

use crate::error::{Result, UpdateError};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// 校验内存中文件字节内容的 SHA-256 完整性哈希值
///
/// # 设计原理
/// - **实现初衷**：在第一道防线排查弱网传输导致的字节损坏或传输未完成，区分“传输中断损坏”与“身份恶意篡改”。
/// - **核心优势**：直接针对字节切片借用计算，无需重复堆分配；支持带 `sha256:` 前缀或裸 Hex 的灵活比对。
/// - **代价与局限**：对大文件若已全量读入内存会产生瞬时内存占用（流式校验适合下载时边写边算）。
///
/// # Errors
/// 当计算哈希值与期望哈希不一致时，返回 [`UpdateError::ChecksumMismatch`]。
pub fn verify_sha256(data: &[u8], expected_checksum: &str) -> Result<()> {
    // 兼容 "sha256:<hex>" 或直接 "<hex>" 格式
    let expected_hex = expected_checksum
        .strip_prefix("sha256:")
        .unwrap_or(expected_checksum)
        .trim();

    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_hex = format!("{:x}", hasher.finalize());

    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }

    Ok(())
}

/// 使用 Ed25519 非对称公钥验证下载内容的数字签名
///
/// # 设计原理
/// - **实现初衷**：通过工业级高强度椭圆曲线签名（Ed25519）建立身份防伪防篡改第二道防线，杜绝中间人劫持与恶意源投毒。
/// - **核心优势**：纯 Rust 实现，签名短（64字节）、验签性能极高且无外部 C 依赖。
/// - **代价与局限**：调用方必须预先在客户端硬编码或安全预置发布者公钥。
///
/// # 参数
/// * `data`: 待验证的目标二进制或归档文件原始字节
/// * `base64_signature`: Base64 编码的 64 字节 Ed25519 数字签名
/// * `base64_public_key`: Base64 编码的 32 字节 Ed25519 验证公钥
///
/// # Errors
/// - 当 Base64 文本解码失败时返回 [`UpdateError::Base64`]。
/// - 当公钥/签名长度不合法或数字签名验证未通过时返回 [`UpdateError::InvalidSignature`]。
pub fn verify_ed25519(data: &[u8], base64_signature: &str, base64_public_key: &str) -> Result<()> {
    // 1. 解码并解析 32 字节公钥
    let pub_key_bytes = BASE64
        .decode(base64_public_key.trim())
        .map_err(UpdateError::Base64)?;

    let pub_key_array: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_array).map_err(|_| UpdateError::InvalidSignature)?;

    // 2. 解码并解析 64 字节签名
    let sig_bytes = BASE64
        .decode(base64_signature.trim())
        .map_err(UpdateError::Base64)?;

    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::InvalidSignature)?;

    let signature = Signature::from_bytes(&sig_array);

    // 3. 执行签名校验
    verifying_key
        .verify(data, &signature)
        .map_err(|_| UpdateError::InvalidSignature)?;

    Ok(())
}
