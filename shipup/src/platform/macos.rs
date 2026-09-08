// shipup 跨平台自更新系统 - macOS 专属平台适配

use crate::error::{Result, UpdateError};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TEMP_SUFFIX: &str = ".shipup.tmp";

/// 清理 macOS Gatekeeper 隔离属性（com.apple.quarantine）
///
/// # 设计原理
/// - **实现初衷**：在从公网下载并解压替换 `.app` Bundle 后，macOS 会自动附加隔离属性导致启动时弹窗报错。
/// - **核心优势**：自动调用 `xattr -cr` 递归清除隔离属性，保障更新后无需用户手动信任即可直接打开。
/// - **代价与局限**：调用系统 `xattr` 命令，若系统沙盒权限极端严格可能受限。
///
/// # Errors
/// 当派生 `xattr` 命令失败时返回 [`UpdateError::SelfReplace`]。
pub fn clear_quarantine_attribute(bundle_path: &Path) -> Result<()> {
    let status = Command::new("xattr")
        .arg("-cr")
        .arg(bundle_path)
        .status()
        .map_err(|e| UpdateError::SelfReplace(format!("执行 xattr 清理隔离属性失败: {}", e)))?;

    if !status.success() {
        log::warn!(
            "清理 macOS 隔离属性返回非零状态，路径: {}",
            bundle_path.display()
        );
    }
    Ok(())
}

/// macOS 原地替换可执行文件
pub fn replace_current_binary(new_binary_path: &Path) -> Result<()> {
    self_replace::self_replace(new_binary_path)
        .map_err(|e| UpdateError::SelfReplace(format!("macOS 原地替换可执行程序失败: {}", e)))?;
    Ok(())
}

/// 拉起 macOS 外部安装程序（如 .pkg 或 .dmg）
pub fn spawn_installer(installer_path: &Path, user_args: &[String]) -> Result<()> {
    let mut cmd = Command::new("open");
    if !user_args.is_empty() {
        cmd.args(user_args);
    }
    cmd.arg(installer_path);

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 macOS 安装器失败: {}", e)))?;

    Ok(())
}

/// 获取同卷临时文件路径
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app");
    let temp_name = format!("{}{}", exe_name, TEMP_SUFFIX);

    let parent = current_exe
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取当前执行文件父目录失败".to_string()))?;

    Ok(parent.join(temp_name))
}
