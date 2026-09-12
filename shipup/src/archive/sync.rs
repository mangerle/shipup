//! 解压后载荷哈希校验与资源同步到宿主目录。
//!
//! # 模块职责
//! - [`verify_extracted_payload_checksums`][]: 对 Manifest 声明的关键文件做 SHA-256 二次完整性校验。
//! - [`sync_extracted_payload`][]: 将解压目录中除主执行程序外的伴随资源同步部署到宿主应用目录。

use crate::error::{Result, UpdateError};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// 将解压目录中除主执行程序之外的全部依赖文件与资产子目录同步部署到目标应用目录
///
/// # 设计原理
/// - **实现初衷**：桌面软件通常包含伴随动态链接库（.dll / .so / .dylib）与静态资源目录。
///   若解压仅替换主程序，会导致应用因缺失资源文件或运行库而崩溃。
/// - **核心优势**：基于迭代式文件树遍历，排除了深层递归爆栈风险；前置排除主执行文件以交由原子替换机制处理。
///
/// # Errors
/// 当读写文件或创建目录失败时返回 [`UpdateError::Io`]。
pub fn sync_extracted_payload(
    payload_dir: &Path,
    target_dir: &Path,
    excluded_binary: &Path,
) -> Result<()> {
    log::info!(
        "正在同步解压资产文件，源目录: {}，目标目录: {}",
        payload_dir.display(),
        target_dir.display()
    );

    // 采用显式栈迭代遍历，防爆栈
    let mut stack = vec![payload_dir.to_path_buf()];

    while let Some(current_dir) = stack.pop() {
        for entry in fs::read_dir(&current_dir)? {
            let entry = entry?;
            let path = entry.path();

            // 如果是主程序文件，跳过（留待原子替换流程单独处理）
            if path == excluded_binary {
                continue;
            }

            let rel_path = match path.strip_prefix(payload_dir) {
                Ok(rel) => rel,
                Err(_) => continue,
            };
            let dest_path = target_dir.join(rel_path);

            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
                stack.push(path);
            } else if file_type.is_file() {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&path, &dest_path)?;
                #[cfg(unix)]
                {
                    if let Ok(meta) = path.metadata() {
                        let _ = fs::set_permissions(&dest_path, meta.permissions());
                    }
                }
            }
        }
    }

    Ok(())
}

/// 校验归档解压目录内声明的关键文件 SHA-256 完整性
///
/// # 设计原理
/// - **实现初衷**：归档级数字签名仅覆盖压缩包原始字节；若解压器存在边界缺陷，落盘内容可能偏离原始意图。
///   通过 Manifest 声明关键文件哈希，在部署前形成二次防伪。
/// - **核心优势**：仅校验调用方声明的关键文件，避免全量扫盘的性能开销；路径强制限制在沙箱根内，防路径逃逸。
/// - **代价与局限**：发布端必须维护并更新 `payload_checksums`；未声明的文件不会被额外校验。
///
/// # Errors
/// - 当相对路径越界逃逸沙箱时返回 [`UpdateError::ZipSlipViolation`]。
/// - 当关键文件缺失时返回 [`UpdateError::ArchiveExtract`]。
/// - 当哈希不匹配时返回 [`UpdateError::ChecksumMismatch`]。
pub fn verify_extracted_payload_checksums(
    extract_root: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }

    let canonical_root = extract_root
        .canonicalize()
        .map_err(|e| UpdateError::ArchiveExtract(format!("解压根目录规范化失败: {e}")))?;

    for (rel, checksum) in expected {
        let target = canonical_root.join(rel);
        let canonical_target = target
            .canonicalize()
            .map_err(|_| UpdateError::ArchiveExtract(format!("解压后关键文件缺失: {}", rel)))?;
        if !canonical_target.starts_with(&canonical_root) {
            return Err(UpdateError::ZipSlipViolation(rel.clone()));
        }
        if !canonical_target.is_file() {
            return Err(UpdateError::ArchiveExtract(format!(
                "解压后关键路径不是普通文件: {}",
                rel
            )));
        }
        crate::signature::verify_sha256_file(&canonical_target, checksum)?;
    }

    Ok(())
}
