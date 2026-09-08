// shipup 跨平台自更新系统 - Linux 专属平台适配

use crate::error::{Result, UpdateError};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const TEMP_SUFFIX: &str = ".shipup.tmp";

/// 为 Linux 新程序赋予 0o755 执行权限
///
/// # 设计原理
/// - **实现初衷**：从 HTTP 下载的二进制切片默认不带 Unix 可执行权限位，直接替换会导致 `Permission denied` 无法启动。
/// - **核心优势**：自动赋予标准 `rwxr-xr-x`（0o755）权限位，避免用户手动执行 `chmod +x`。
///
/// # Errors
/// 当修改文件元数据失败时返回 [`UpdateError::Io`]。
pub fn ensure_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

/// Linux 原地替换可执行文件
///
/// # 设计原理
/// - **实现初衷**：在 POSIX 系统中，正在执行的文件可以通过 `unlink` 移除目录项并由新文件原子替换。
///
/// # Errors
/// 当权限修正或二进制替换失败时返回 [`UpdateError::SelfReplace`]。
pub fn replace_current_binary(new_binary_path: &Path) -> Result<()> {
    ensure_executable(new_binary_path)?;
    self_replace::self_replace(new_binary_path)
        .map_err(|e| UpdateError::SelfReplace(format!("Linux 原地替换可执行程序失败: {}", e)))?;
    Ok(())
}

/// 拉起 Linux 外部安装器（如 AppImage 或脚本）
pub fn spawn_installer(installer_path: &Path, user_args: &[String]) -> Result<()> {
    ensure_executable(installer_path)?;

    let mut cmd = Command::new(installer_path);
    if !user_args.is_empty() {
        cmd.args(user_args);
    }

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 Linux 安装器失败: {}", e)))?;

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
