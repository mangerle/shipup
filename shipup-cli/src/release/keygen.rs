//! 密钥生成子模块：`keygen` 命令的完整实现。
//!
//! # 模块职责
//! 基于系统安全随机数生成 Ed25519 密钥对，并以 Base64 编码分别写入
//! `ed25519.key`（私钥）与 `ed25519.pub`（公钥）两个文件。
//!
//! # 设计原理
//! - **实现初衷**：发布签名体系的根基是密钥对。把生成逻辑独立成模块，
//!   使「密钥生命周期」与「清单合并」两条关注点彻底分离。
//! - **核心优势**：私钥仅在生成瞬间存在于内存，写盘后立即释放，
//!   且不向任何日志输出私钥内容。
//! - **代价与局限**：本模块不提供密钥轮换或加密存储能力，
//!   私钥文件的访问控制完全依赖操作系统文件权限。
//!
//! # 安全契约
//! `ed25519.key` 为极高敏感私钥，严禁检入版本控制系统；
//! `ed25519.pub` 为公钥，供嵌入客户端 `UpdaterBuilder`。
//!
//! # 兄弟导航
//! - [`super::single`] / [`super::batch`]：使用本模块生成的密钥签署包体；
//! - [`super::sign`]：对既有包体补充签名时同样依赖 Ed25519 私钥。

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::Path;

/// 执行 Ed25519 密钥对生成并将私钥与公钥输出至指定目录。
///
/// # 设计原理
/// - **实现初衷**：基于系统安全随机数（`getrandom`）生成 32 字节高熵种子，
///   派生出标准 Ed25519 密钥对并以 Base64 编码保存。
/// - **安全警示**：`ed25519.key` 为极高敏感私钥，严禁检入版本控制系统；
///   `ed25519.pub` 为公钥，供嵌入客户端 `UpdaterBuilder`。
///
/// # Errors
/// 输出目录创建失败、随机数获取失败或密钥文件写入失败时返回带路径上下文的中文错误。
pub(crate) fn handle_keygen(out_dir: &Path) -> Result<()> {
    log::info!("开始生成 Ed25519 密钥对，输出目录: {}", out_dir.display());
    fs::create_dir_all(out_dir)
        .with_context(|| format!("创建密钥输出目录失败: {}", out_dir.display()))?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("获取安全随机数种子失败")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let private_key_b64 = BASE64.encode(signing_key.to_bytes());
    let public_key_b64 = BASE64.encode(verifying_key.to_bytes());

    let key_path = out_dir.join("ed25519.key");
    let pub_path = out_dir.join("ed25519.pub");

    fs::write(&key_path, &private_key_b64)
        .with_context(|| format!("写入私钥文件失败: {}", key_path.display()))?;
    fs::write(&pub_path, &public_key_b64)
        .with_context(|| format!("写入公钥文件失败: {}", pub_path.display()))?;

    log::info!("Ed25519 密钥对已成功生成");
    log::info!("  私钥文件（请妥善保密）: {}", key_path.display());
    log::info!("  公钥文件（配置于客户端）: {}", pub_path.display());
    log::info!("  公钥 Base64 内容: {}", public_key_b64);

    Ok(())
}
