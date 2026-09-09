// shipup 跨平台自更新系统 - SHA-256 完整性与 Ed25519 签名校验器

use crate::error::{Result, UpdateError};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const HASH_BUFFER_SIZE: usize = 64 * 1024; // 64KB 流式缓冲区

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
    let hash = hasher.finalize();
    let mut actual_hex = String::with_capacity(hash.len() * 2);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(actual_hex, "{b:02x}");
    }

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
    let pub_key_bytes = BASE64.decode(base64_public_key.trim())?;

    let pub_key_array: [u8; 32] = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| UpdateError::InvalidSignature)?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_array).map_err(|_| UpdateError::InvalidSignature)?;

    // 2. 解码并解析 64 字节签名
    let sig_bytes = BASE64.decode(base64_signature.trim())?;

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

/// 基于流式分块读取文件并计算其 SHA-256 的 32 字节二进制摘要
///
/// # 设计原理
/// - **实现初衷**：为任意体积文件的数字签名校验提供标准化输入，彻底消除大包全量读入内存的开销。
/// - **核心优势**：固定 64KB 缓冲区循环迭代，内存占用恒定且无论文件多大都不会触发 OOM。
///
/// # Errors
/// 当底层文件打开或读取失败时返回 [`UpdateError::Io`]。
pub fn compute_file_sha256_digest(file_path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(file_path)?;
    let mut buffer = [0u8; HASH_BUFFER_SIZE];
    let mut hasher = Sha256::new();

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hasher.finalize().into())
}

/// 基于流式分块读取文件并校验 SHA-256 完整性哈希值
///
/// # 设计原理
/// - **实现初衷**：彻底杜绝大文件（几百兆至数吉字节安装包）一次性读入内存造成的瞬时内存暴涨与 OOM。
/// - **核心优势**：固定 64KB 缓冲区循环迭代哈希计算，无论目标文件多大，内存消耗始终恒定。
///
/// # Errors
/// 当底层文件读取失败或计算哈希值与期望哈希不一致时，分别返回 [`UpdateError::Io`] 或 [`UpdateError::ChecksumMismatch`]。
pub fn verify_sha256_file(file_path: &Path, expected_checksum: &str) -> Result<()> {
    let digest = compute_file_sha256_digest(file_path)?;

    let expected_hex = expected_checksum
        .strip_prefix("sha256:")
        .unwrap_or(expected_checksum)
        .trim();

    let mut actual_hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(actual_hex, "{b:02x}");
    }

    if !actual_hex.eq_ignore_ascii_case(expected_hex) {
        return Err(UpdateError::ChecksumMismatch {
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }

    Ok(())
}

/// 针对单个本地文件执行单公钥 Ed25519 数字签名验证
///
/// # 设计原理
/// - **实现初衷**：为传统单私钥签名场景提供直接便利的方法入口。
///
/// # Errors
/// 当文件读取失败、签名格式不合法或密码学签名不匹配时返回错误。
pub fn verify_ed25519_file(
    file_path: &Path,
    base64_signature: &str,
    base64_public_key: &str,
) -> Result<()> {
    verify_ed25519_file_any_key(file_path, base64_signature, &[base64_public_key])
}

/// 使用候选公钥列表验证数字签名（任一公钥验签通过即判定合法）
///
/// # 设计原理
/// - **实现初衷**：支持公钥平滑轮换（Key Rotation）与多信任源，避免因更换私钥导致老版本更新锁死。
/// - **核心优势**：一旦匹配即刻短路返回，且不产生堆内存重新分配。
///
/// # Errors
/// 当公钥列表为空时返回 [`UpdateError::MissingPublicKey`]；当所有公钥均验证失败时返回 [`UpdateError::InvalidSignature`]。
pub fn verify_ed25519_any_key(
    data: &[u8],
    base64_signature: &str,
    base64_public_keys: &[impl AsRef<str>],
) -> Result<()> {
    if base64_public_keys.is_empty() {
        return Err(UpdateError::MissingPublicKey);
    }

    for pub_key in base64_public_keys {
        if verify_ed25519(data, base64_signature, pub_key.as_ref()).is_ok() {
            return Ok(());
        }
    }

    Err(UpdateError::InvalidSignature)
}

/// 允许一次性读入内存执行 Ed25519 签名验证的最大文件体积上限（512MB）
pub const MAX_SIGNATURE_PAYLOAD_SIZE: u64 = 512 * 1024 * 1024;

/// 针对本地文件路径使用候选公钥列表执行 Ed25519 数字签名验证
///
/// # 设计原理
/// - **实现初衷**：将下载完成的临时物理文件与配置的公钥环进行整体真实性校验，只要通过任一公钥验证即放行。
/// - **核心优势**：
///   - 优先采用基于 32 字节 SHA-256 摘要流式验签，内存占用恒定为 64KB，彻底解除 512MB 体积上限并防范 OOM。
///   - 对历史未采用摘要签名的小文件（<= 512MB）提供向后兼容全文验签支持。
/// - **代价与局限**：向前兼容路径对未采用摘要签名的文件仍受 512MB 内存上限保护。
///
/// # Errors
/// 当底层文件读取失败或所有候选公钥均验证失败时返回对应错误。
pub fn verify_ed25519_file_any_key(
    file_path: &Path,
    base64_signature: &str,
    base64_public_keys: &[impl AsRef<str>],
) -> Result<()> {
    // 1. 优先尝试 TUF/Sigstore 规范的标准摘要验签（流式计算 32 字节哈希）
    let digest = compute_file_sha256_digest(file_path)?;
    if verify_ed25519_any_key(&digest, base64_signature, base64_public_keys).is_ok() {
        return Ok(());
    }

    // 2. 向前兼容回退：若摘要验签未通过，尝试对全文字节进行兼容验证（限制 <= 512MB 安全上限）
    let metadata = std::fs::metadata(file_path)?;
    if metadata.len() <= MAX_SIGNATURE_PAYLOAD_SIZE {
        let file_len = metadata.len() as usize;
        let mut file = File::open(file_path)?;
        let mut data = Vec::with_capacity(file_len);
        file.read_to_end(&mut data)?;

        if verify_ed25519_any_key(&data, base64_signature, base64_public_keys).is_ok() {
            return Ok(());
        }
    }

    Err(UpdateError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use std::io::Write;

    #[test]
    fn test_sha256_slice_and_file_verification() {
        let content = b"shipup payload streaming verification content";
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hasher.finalize();
        let mut hex = String::with_capacity(hash.len() * 2);
        for b in hash {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        let expected = format!("sha256:{hex}");

        // 验证切片哈希
        let slice_res = verify_sha256(content, &expected);
        assert!(slice_res.is_ok());

        // 验证文件流式哈希
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("shipup_sha256_test_{}.bin", std::process::id()));
        let mut f = File::create(&temp_file).unwrap();
        f.write_all(content).unwrap();
        drop(f);

        let file_res = verify_sha256_file(&temp_file, &expected);
        let _ = std::fs::remove_file(&temp_file);
        assert!(file_res.is_ok());

        // 校验错误哈希分支
        let mismatch_res = verify_sha256(content, "sha256:00000000000000000000000000000000");
        assert!(matches!(
            mismatch_res,
            Err(UpdateError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn test_ed25519_verification_branches() {
        let payload = b"critical-binary-content";
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let sig = signing_key.sign(payload);
        let sig_b64 = BASE64.encode(sig.to_bytes());
        let pub_b64 = BASE64.encode(verifying_key.to_bytes());

        // 正常验签
        assert!(verify_ed25519(payload, &sig_b64, &pub_b64).is_ok());

        // 内容篡改验签失败
        assert!(matches!(
            verify_ed25519(b"tampered", &sig_b64, &pub_b64),
            Err(UpdateError::InvalidSignature)
        ));

        // Base64 解码错误分支
        assert!(matches!(
            verify_ed25519(payload, "invalid-base64!@", &pub_b64),
            Err(UpdateError::Base64(_))
        ));
    }

    #[test]
    fn test_ed25519_multi_key_rotation() {
        let payload = b"software-update-v2-binary";

        // 生成旧密钥对
        let old_seed = [1u8; 32];
        let old_signing = SigningKey::from_bytes(&old_seed);
        let old_pub_b64 = BASE64.encode(old_signing.verifying_key().to_bytes());

        // 生成新密钥对
        let new_seed = [2u8; 32];
        let new_signing = SigningKey::from_bytes(&new_seed);
        let new_pub_b64 = BASE64.encode(new_signing.verifying_key().to_bytes());

        // 客户端同时信任旧公钥与新公钥
        let trusted_keys = vec![old_pub_b64.clone(), new_pub_b64.clone()];

        // 1. 新密钥签名的更新包，在客户端多公钥列表下成功验签通过
        let new_sig = BASE64.encode(new_signing.sign(payload).to_bytes());
        assert!(verify_ed25519_any_key(payload, &new_sig, &trusted_keys).is_ok());

        // 2. 旧密钥签名的历史包，在客户端多公钥列表下同样成功验签通过
        let old_sig = BASE64.encode(old_signing.sign(payload).to_bytes());
        assert!(verify_ed25519_any_key(payload, &old_sig, &trusted_keys).is_ok());

        // 3. 未被信任的第三方密钥签名的恶意包，验签失败
        let rogue_seed = [3u8; 32];
        let rogue_signing = SigningKey::from_bytes(&rogue_seed);
        let rogue_sig = BASE64.encode(rogue_signing.sign(payload).to_bytes());
        assert!(matches!(
            verify_ed25519_any_key(payload, &rogue_sig, &trusted_keys),
            Err(UpdateError::InvalidSignature)
        ));

        // 4. 空公钥列表返回 MissingPublicKey
        let empty_keys: Vec<String> = Vec::new();
        assert!(matches!(
            verify_ed25519_any_key(payload, &new_sig, &empty_keys),
            Err(UpdateError::MissingPublicKey)
        ));
    }

    #[test]
    fn test_ed25519_file_digest_and_full_payload_verification() {
        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join(format!("shipup_digest_test_{}.bin", std::process::id()));
        let content = b"large payload simulation block for digest signature verification";
        let mut f = File::create(&temp_file).unwrap();
        f.write_all(content).unwrap();
        drop(f);

        let seed = [7u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let pubkey = BASE64.encode(signing.verifying_key().to_bytes());

        // 1. 基于 SHA-256 摘要签名并测试验签成功
        let digest = compute_file_sha256_digest(&temp_file).unwrap();
        let digest_sig = BASE64.encode(signing.sign(&digest).to_bytes());
        assert!(verify_ed25519_file(&temp_file, &digest_sig, &pubkey).is_ok());

        // 2. 基于文件全文签名并测试向后兼容验签成功
        let full_sig = BASE64.encode(signing.sign(content).to_bytes());
        assert!(verify_ed25519_file(&temp_file, &full_sig, &pubkey).is_ok());

        // 3. 篡改文件后两种签名验签均失败
        let mut f_tampered = File::create(&temp_file).unwrap();
        f_tampered.write_all(b"tampered content bytes").unwrap();
        drop(f_tampered);

        assert!(verify_ed25519_file(&temp_file, &digest_sig, &pubkey).is_err());
        assert!(verify_ed25519_file(&temp_file, &full_sig, &pubkey).is_err());

        let _ = std::fs::remove_file(&temp_file);
    }
}
