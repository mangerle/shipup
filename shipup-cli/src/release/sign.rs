//! 独立签名子模块：`sign` 命令的完整实现。
//!
//! # 模块职责
//! 对指定物理文件直接计算 SHA-256 摘要并生成 Ed25519 数字签名，
//! 支持输出到控制台或写入 `.sig` 文件，无需完整生成 Manifest 即可完成鉴权验签集成。
//!
//! # 设计原理
//! - **实现初衷**：满足将 shipup 签名能力无缝嵌入第三方流水线
//!   （如 GitHub Actions、GitLab CI）的场景。
//! - **核心优势**：直接输出 Base64 签名字符串并支持写入 `.sig` 文件，
//!   流水线无需理解 Manifest 协议即可完成签名集成。
//! - **代价与局限**：需要调用方显式指定 Ed25519 私钥路径，
//!   本模块不提供密钥查找或自动发现能力。
//!
//! # 兄弟导航
//! - [`super::keygen`]：生成本模块所需的 Ed25519 私钥；
//! - [`super::single`] / [`super::batch`]：在发布流程中对包体做同样的签名计算。

use crate::cli::SignArgs;
use crate::util::compute_payload_integrity;
use anyhow::{Context, Result, anyhow};
use std::fs;

/// 执行单独文件的 SHA-256 计算与 Ed25519 签名生成。
///
/// # 设计原理
/// - **实现初衷**：满足将 shipup 签名能力无缝嵌入第三方流水线的场景。
/// - **核心优势**：直接输出 Base64 签名字符串并支持写入 `.sig` 文件，
///   无需完整生成 Manifest 即可完成鉴权验签集成。
/// - **代价与局限**：需要调用方显式指定 Ed25519 私钥路径。
///
/// # Errors
/// 待签名文件不存在、密钥文件无效、签名生成失败或输出文件写入失败时返回中文错误。
pub(crate) fn handle_sign(args: &SignArgs) -> Result<()> {
    if !args.file.exists() {
        return Err(anyhow!("待签名物理文件不存在: {}", args.file.display()));
    }
    let (checksum, opt_sig) = compute_payload_integrity(&args.file, Some(&args.key))?;
    let sig_b64 = opt_sig.ok_or_else(|| anyhow!("数字签名生成失败"))?;
    let file_size = fs::metadata(&args.file)
        .with_context(|| format!("获取文件元数据失败: {}", args.file.display()))?
        .len();

    println!("=================== shipup 独立签名结果 ===================");
    println!("文件路径:       {}", args.file.display());
    println!("文件大小:       {} 字节", file_size);
    println!("SHA-256:        {}", checksum);
    println!("Ed25519 签名:   {}", sig_b64);
    println!("===========================================================");

    if let Some(ref out_path) = args.output {
        write_signature_file(out_path, &sig_b64)?;
        println!("数字签名已保存至: {}", out_path.display());
    }

    Ok(())
}

/// 将 Base64 编码的签名写入指定输出文件。
///
/// # Errors
/// 父目录创建失败或文件写入失败时返回带路径上下文的中文错误。
fn write_signature_file(out_path: &std::path::Path, sig_b64: &str) -> Result<()> {
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建签名输出父目录失败: {}", parent.display()))?;
    }
    fs::write(out_path, sig_b64)
        .with_context(|| format!("写入签名输出文件失败: {}", out_path.display()))?;
    Ok(())
}
