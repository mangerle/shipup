// shipup 跨平台自更新系统 - Windows 专属平台适配

use crate::error::{Result, UpdateError};
use std::env;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 临时替换文件后缀
pub const TEMP_SUFFIX: &str = ".shipup.tmp";
/// 旧版本备份文件后缀（Windows 文件锁绕过）
pub const OLD_BACKUP_SUFFIX: &str = ".shipup.old";

/// 在 Windows 上派生安装器进程时的标志：DETACHED_PROCESS 与 CREATE_NEW_PROCESS_GROUP
const DETACHED_PROCESS: u32 = 0x00000008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

/// 清理当前主程序同目录下遗留的 *.shipup.old 旧版本文件
///
/// # 设计原理
/// - **实现初衷**：在 Windows 平台上，由于操作系统强制加锁运行中的可执行文件，替换时旧文件被重命名为 `.shipup.old`。
///   旧进程退出后该文件锁已解除，因此由新启动的进程在初始化阶段静默删除旧副本。
/// - **核心优势**：自动无感闭环，不需要额外的清理批处理脚本或临时服务。
/// - **代价与局限**：若由于权限受限未能删除，将在下一次启动时继续重试。
pub fn cleanup_old_backup_files() {
    if let Ok(current_exe) = env::current_exe()
        && let Some(parent) = current_exe.parent()
        && let Ok(entries) = fs::read_dir(parent)
    {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str())
                && file_name.ends_with(OLD_BACKUP_SUFFIX)
            {
                if let Err(e) = fs::remove_file(&path) {
                    log::debug!("清理遗留旧副本文件失败 ({}): {}", path.display(), e);
                } else {
                    log::debug!("成功清理遗留旧副本文件: {}", path.display());
                }
            }
        }
    }
}

/// Windows 原地原子替换执行
///
/// # 设计原理
/// - **实现初衷**：基于底层 MoveFileEx 与安全重命名原语将正在运行的二进制重命名后替换为新二进制。
/// - **核心优势**：避免宿主应用在退出前残留半更新状态。
///
/// # Errors
/// 当文件重命名或写入失败时返回 [`UpdateError::SelfReplace`]。
pub fn replace_current_binary(new_binary_path: &Path) -> Result<()> {
    log::info!("正在执行 Windows 二进制原地原子替换...");
    self_replace::self_replace(new_binary_path)
        .map_err(|e| UpdateError::SelfReplace(format!("Windows 原地替换可执行程序失败: {}", e)))?;
    Ok(())
}

/// 派生拉起外部安装器，并使子进程脱离当前进程树
///
/// # 设计原理
/// - **实现初衷**：注入 DETACHED_PROCESS 与 CREATE_NEW_PROCESS_GROUP 标志，切断父子进程控制台句柄继承。
/// - **核心优势**：主程序在后续 `process::exit(0)` 退出后，安装器子进程能够顺畅运行并拥有完整文件重写能力。
///
/// # Errors
/// 当进程派生失败时返回 [`UpdateError::InstallerSpawn`]。
pub fn spawn_installer(installer_path: &Path, user_args: &[String]) -> Result<()> {
    log::info!(
        "正在派生拉起 Windows 外部安装器: {}",
        installer_path.display()
    );
    let mut cmd = Command::new(installer_path);

    if user_args.is_empty() {
        let ext = installer_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if ext == "msi" {
            cmd = Command::new("msiexec");
            cmd.arg("/i")
                .arg(installer_path)
                .arg("/passive")
                .arg("/norestart");
        } else {
            cmd.arg("/S");
        }
    } else {
        cmd.args(user_args);
    }

    cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);

    cmd.spawn()
        .map_err(|e| UpdateError::InstallerSpawn(format!("拉起 Windows 安装器失败: {}", e)))?;

    Ok(())
}

/// 获取当前程序同卷下的临时文件路径
///
/// # 设计原理
/// - **实现初衷**：同卷保证 `rename` 绝对为原子操作且不会报跨设备 `EXDEV` 错误。
///
/// # Errors
/// 当获取可执行程序路径失败时返回 [`UpdateError::SelfReplace`]。
pub fn get_same_volume_temp_path() -> Result<PathBuf> {
    let current_exe = env::current_exe()?;
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("app.exe");
    let temp_name = format!("{}{}", exe_name, TEMP_SUFFIX);

    let parent = current_exe
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取当前执行文件父目录失败".to_string()))?;

    Ok(parent.join(temp_name))
}
