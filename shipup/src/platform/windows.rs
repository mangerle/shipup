// shipup 跨平台自更新系统 - Windows 专属平台适配

use crate::error::{Result, UpdateError};
use crate::manifest::InstallMode;
use crate::platform::InstallerOptions;
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

/// 孤儿临时下载切片的最长保留过期时长（24 小时）
const ORPHAN_TEMP_EXPIRATION_SECS: u64 = 24 * 3600;

/// 清理当前主程序自身遗留的历史 *.shipup.old 备份文件与过期孤儿临时切片
///
/// # 设计原理
/// - **实现初衷**：替换完成且新版本稳定后，定向销毁自身旧二进制；对历史残留临时切片引入 24 小时修改时间保护。
/// - **核心优势**：定向清理自身备份，绝不误删同目录其他进程正在下载中的临时文件或并发实例。
/// - **代价与局限**：24 小时内的未完成下载切片将被保留供断点续传，直到超时后自动回收。
pub fn cleanup_old_backup_files() {
    if let Ok(current_exe) = env::current_exe()
        && let Some(parent) = current_exe.parent()
    {
        let exe_name = current_exe
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("app");

        // 1. 定向清理主程序自身对应的历史备份文件
        let my_backup = parent.join(format!("{}{}", exe_name, OLD_BACKUP_SUFFIX));
        if my_backup.exists() {
            if let Err(e) = fs::remove_file(&my_backup) {
                log::debug!("清理当前程序历史备份失败 ({}): {}", my_backup.display(), e);
            } else {
                log::debug!("成功清理当前程序历史备份: {}", my_backup.display());
            }
        }

        // 2. 仅清理修改时间超过 24 小时的孤儿临时切片，避免误删正在下载的文件
        if let Ok(entries) = fs::read_dir(parent) {
            let now = std::time::SystemTime::now();
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str())
                    && file_name.ends_with(TEMP_SUFFIX)
                    && let Ok(metadata) = entry.metadata()
                    && let Ok(modified) = metadata.modified()
                    && let Ok(age) = now.duration_since(modified)
                    && age.as_secs() > ORPHAN_TEMP_EXPIRATION_SECS
                {
                    if let Err(e) = fs::remove_file(&path) {
                        log::debug!("清理过期孤儿临时切片失败 ({}): {}", path.display(), e);
                    } else {
                        log::debug!("成功清理过期孤儿临时切片: {}", path.display());
                    }
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

/// 根据 Windows 安装器类型（MSI / EXE）与交互模式组装启动命令与静默参数
///
/// # 设计原理
/// - **实现初衷**：统一抽象 Windows 下主流安装包的静默与被动参数规范。
///   MSI 安装包通过 `msiexec.exe /i <path>` 拉起，结合 `/passive`、`/qn` 与 `/norestart`；
///   EXE 安装程序（如 NSIS 或 Inno Setup）则注入 `/S` 或 `/passive`。
/// - **核心优势**：用户自定义参数追加在标准标志之后，兼具标准化与高度灵活性。
pub(crate) fn build_windows_installer_args(
    installer_path: &Path,
    options: &InstallerOptions<'_>,
) -> (String, Vec<String>) {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut args = Vec::with_capacity(options.user_args.len() + 4);
    let program: String;

    if ext == "msi" {
        program = "msiexec".to_string();
        args.push("/i".to_string());
        args.push(installer_path.to_string_lossy().to_string());

        match options.install_mode {
            Some(InstallMode::Passive) => {
                args.push("/passive".to_string());
                args.push("/norestart".to_string());
            }
            Some(InstallMode::Quiet) => {
                args.push("/qn".to_string());
                args.push("/norestart".to_string());
            }
            Some(InstallMode::BasicUi) => {
                args.push("/qb".to_string());
                args.push("/norestart".to_string());
            }
            None => {
                if options.user_args.is_empty() {
                    args.push("/passive".to_string());
                    args.push("/norestart".to_string());
                }
            }
        }
        // 用户自定义参数追加在标准模式参数之后，避免粗暴全覆盖
        args.extend(options.user_args.iter().cloned());
    } else {
        program = installer_path.to_string_lossy().to_string();

        match options.install_mode {
            Some(InstallMode::Passive) => {
                args.push("/passive".to_string());
            }
            Some(InstallMode::Quiet) => {
                args.push("/S".to_string());
            }
            Some(InstallMode::BasicUi) => {
                // 基础 UI 模式不注入静默标志
            }
            None => {
                if options.user_args.is_empty() {
                    args.push("/S".to_string());
                }
            }
        }
        // 用户自定义参数追加在标准模式参数之后
        args.extend(options.user_args.iter().cloned());
    }

    (program, args)
}

/// 派生拉起外部安装器，并使子进程脱离当前进程树
///
/// # 设计原理
/// - **实现初衷**：注入 DETACHED_PROCESS 与 CREATE_NEW_PROCESS_GROUP 标志，切断父子进程控制台句柄继承。
/// - **核心优势**：主程序在后续 `process::exit(0)` 退出后，安装器子进程能够顺畅运行并拥有完整文件重写能力。
///   当 `options.require_elevation` 为 true 时，通过 PowerShell 触发 UAC 凭据对话框以 Administrator 提权执行。
/// - **代价与局限**：Windows 安装器一旦派生，主程序无法持续监控其退出码，依赖安装器自闭环。
///
/// # Errors
/// 当进程派生失败时返回 [`UpdateError::InstallerSpawn`]。
pub fn spawn_installer(installer_path: &Path, options: &InstallerOptions<'_>) -> Result<()> {
    log::info!(
        "正在派生拉起 Windows 外部安装器: {} (模式: {:?}, UAC 提权: {})",
        installer_path.display(),
        options.install_mode,
        options.require_elevation
    );

    let (program, args) = build_windows_installer_args(installer_path, options);

    if options.require_elevation {
        log::info!("正在通过 PowerShell 以 UAC 管理员提权拉起安装器");
        let arg_list = args.join(" ");
        let mut ps_cmd = Command::new("powershell");
        ps_cmd
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(format!(
                "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs",
                program, arg_list
            ));
        ps_cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        ps_cmd.spawn().map_err(|e| {
            UpdateError::InstallerSpawn(format!("以管理员提权拉起安装器失败: {}", e))
        })?;
        return Ok(());
    }

    let mut cmd = Command::new(&program);
    cmd.args(&args);
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
    let temp_name = format!("{}.{}.shipup.tmp", exe_name, std::process::id());

    let parent = current_exe
        .parent()
        .ok_or_else(|| UpdateError::SelfReplace("获取当前执行文件父目录失败".to_string()))?;

    Ok(parent.join(temp_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_windows_installer_args_msi() {
        let path = Path::new("C:\\temp\\setup.msi");

        // 默认无参数且无 mode
        let empty_args: [String; 0] = [];
        let opt_default = InstallerOptions {
            user_args: &empty_args,
            install_mode: None,
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_default);
        assert_eq!(prog, "msiexec");
        assert_eq!(
            args,
            vec!["/i", "C:\\temp\\setup.msi", "/passive", "/norestart"]
        );

        // Quiet 模式且附加自定义属性参数
        let custom_args = vec!["ALLUSERS=1".to_string()];
        let opt_quiet = InstallerOptions {
            user_args: &custom_args,
            install_mode: Some(InstallMode::Quiet),
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_quiet);
        assert_eq!(prog, "msiexec");
        assert_eq!(
            args,
            vec![
                "/i",
                "C:\\temp\\setup.msi",
                "/qn",
                "/norestart",
                "ALLUSERS=1"
            ]
        );

        // BasicUi 模式
        let opt_basic = InstallerOptions {
            user_args: &empty_args,
            install_mode: Some(InstallMode::BasicUi),
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_basic);
        assert_eq!(prog, "msiexec");
        assert_eq!(args, vec!["/i", "C:\\temp\\setup.msi", "/qb", "/norestart"]);
    }

    #[test]
    fn test_build_windows_installer_args_exe() {
        let path = Path::new("C:\\temp\\setup.exe");
        let empty_args: [String; 0] = [];

        // 默认无模式：自动映射 /S
        let opt_default = InstallerOptions {
            user_args: &empty_args,
            install_mode: None,
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_default);
        assert_eq!(prog, "C:\\temp\\setup.exe");
        assert_eq!(args, vec!["/S"]);

        // Passive 模式并附加目标路径
        let custom_args = vec!["/D=C:\\MyApp".to_string()];
        let opt_passive = InstallerOptions {
            user_args: &custom_args,
            install_mode: Some(InstallMode::Passive),
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_passive);
        assert_eq!(prog, "C:\\temp\\setup.exe");
        assert_eq!(args, vec!["/passive", "/D=C:\\MyApp"]);
    }
}
