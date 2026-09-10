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

#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    pub const SW_SHOWNORMAL: i32 = 1;
    pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    pub const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;

    #[link(name = "shell32")]
    unsafe extern "system" {
        pub fn ShellExecuteW(
            hwnd: *mut c_void,
            lpOperation: *const u16,
            lpFile: *const u16,
            lpParameters: *const u16,
            lpDirectory: *const u16,
            nShowCmd: i32,
        ) -> *mut c_void;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }
}

/// 向 Windows 内核注册系统重启延迟替换任务 (MoveFileExW PendingFileRenameOperations)
///
/// # 设计原理
/// - **实现初衷**：针对 Windows 下常驻服务、排他句柄锁定或安全杀软拦截导致原地替换失败的场景，
///   交由 Windows 内核在下次引导启动阶段自动完成原子文件替换。
/// - **核心优势**：直接写入系统级待处理重命名队列，绕过运行期文件锁限制，保障核心服务的更新闭环。
/// - **代价与局限**：替换仅在机器或服务重启后生效；待替换的临时文件需保持存放在重启前可访问的磁盘分区上。
///
/// # Errors
/// 当底层 Windows 系统调用 `MoveFileExW` 失败时返回 [`UpdateError::SelfReplace`]。
pub fn schedule_reboot_replace(source_file: &Path, target_file: &Path) -> Result<()> {
    let src_wide = to_wide_null(&source_file.to_string_lossy());
    let dst_wide = to_wide_null(&target_file.to_string_lossy());
    let flags = ffi::MOVEFILE_DELAY_UNTIL_REBOOT | ffi::MOVEFILE_REPLACE_EXISTING;

    let res = unsafe { ffi::MoveFileExW(src_wide.as_ptr(), dst_wide.as_ptr(), flags) };
    if res == 0 {
        let err = std::io::Error::last_os_error();
        return Err(UpdateError::SelfReplace(format!(
            "向 Windows 注册系统重启替换任务失败，源文件: {}，目标文件: {}，系统错误: {err}",
            source_file.display(),
            target_file.display()
        )));
    }

    log::info!(
        "已成功向 Windows 系统登记重启延迟替换任务: {} -> {}",
        source_file.display(),
        target_file.display()
    );
    Ok(())
}

/// 向 Windows 内核注册系统重启延迟删除任务 (MoveFileExW NULL)
///
/// # 设计原理
/// - **实现初衷**：在 Windows 下当无法立即销毁旧版本残留文件时，注册为重启后自动清理。
/// - **核心优势**：系统底层保障安全销毁，杜绝孤儿旧版本堆积。
///
/// # Errors
/// 当底层 Windows 系统调用 `MoveFileExW` 失败时返回 [`UpdateError::SelfReplace`]。
pub fn schedule_reboot_delete(file_to_delete: &Path) -> Result<()> {
    let path_wide = to_wide_null(&file_to_delete.to_string_lossy());
    let flags = ffi::MOVEFILE_DELAY_UNTIL_REBOOT;

    let res = unsafe { ffi::MoveFileExW(path_wide.as_ptr(), std::ptr::null(), flags) };
    if res == 0 {
        let err = std::io::Error::last_os_error();
        return Err(UpdateError::SelfReplace(format!(
            "向 Windows 注册系统重启删除任务失败，目标文件: {}，系统错误: {err}",
            file_to_delete.display()
        )));
    }

    log::info!(
        "已成功向 Windows 系统登记重启延迟删除任务: {}",
        file_to_delete.display()
    );
    Ok(())
}

/// 将字符串安全转换为以空字符（0u16）结尾的 UTF-16 宽字符序列
fn to_wide_null(s: &str) -> Vec<u16> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// 格式化 Windows 命令行参数列表，针对包含空格或引号的参数执行标准转义包裹
pub(crate) fn escape_windows_args(args: &[String]) -> String {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        if arg.is_empty() {
            out.push_str("\"\"");
        } else if arg.contains(' ') || arg.contains('\t') || arg.contains('"') {
            out.push('"');
            for c in arg.chars() {
                if c == '"' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    out
}

/// 通过 Windows 原生 ShellExecuteW 以 UAC 管理员提权拉起外部安装器
fn spawn_elevated_installer(program: &str, args: &[String], installer_path: &Path) -> Result<()> {
    log::info!("正在通过 Windows 原生 ShellExecuteW 以 UAC runas 提权拉起外部安装器");
    let op_wide = to_wide_null("runas");
    let program_wide = to_wide_null(program);

    let params_str = escape_windows_args(args);
    let params_wide = if params_str.is_empty() {
        None
    } else {
        Some(to_wide_null(&params_str))
    };

    let dir_str = installer_path
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let dir_wide = if dir_str.is_empty() {
        None
    } else {
        Some(to_wide_null(dir_str))
    };

    let h_instance = unsafe {
        ffi::ShellExecuteW(
            std::ptr::null_mut(),
            op_wide.as_ptr(),
            program_wide.as_ptr(),
            params_wide
                .as_ref()
                .map_or(std::ptr::null(), |p| p.as_ptr()),
            dir_wide.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            ffi::SW_SHOWNORMAL,
        )
    };

    let ret_code = h_instance as usize;
    if ret_code <= 32 {
        let last_err = std::io::Error::last_os_error();
        return Err(UpdateError::InstallerSpawn(format!(
            "以管理员提权拉起安装器失败，ShellExecuteW 错误码: {}，系统原因: {}",
            ret_code, last_err
        )));
    }

    Ok(())
}

/// 派生拉起外部安装器，并使子进程脱离当前进程树
///
/// # 设计原理
/// - **实现初衷**：注入 DETACHED_PROCESS 与 CREATE_NEW_PROCESS_GROUP 标志，切断父子进程控制台句柄继承。
/// - **核心优势**：主程序退出后安装器可顺畅完成文件重写；当需要提权时，改用 Windows 原生 `ShellExecuteW("runas")`，
///   消除 PowerShell 进程与 CLR 运行时的冷启动开销，摆脱执行策略限制，并支持精准捕获系统级 UAC 错误码。
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
        return spawn_elevated_installer(&program, &args, installer_path);
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
    let temp_name = format!("{}{}", exe_name, TEMP_SUFFIX);

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

    #[test]
    fn test_escape_windows_args_handles_spaces_and_quotes() {
        let args = vec![
            "/S".to_string(),
            "/D=C:\\Program Files\\My App".to_string(),
            "plain".to_string(),
            "".to_string(),
            "key=\"val\"".to_string(),
        ];
        let escaped = escape_windows_args(&args);
        assert_eq!(
            escaped,
            r#"/S "/D=C:\Program Files\My App" plain "" "key=\"val\"""#
        );
    }

    #[test]
    fn test_to_wide_null_encoding() {
        let wide = to_wide_null("runas");
        assert_eq!(wide.len(), 6);
        assert_eq!(wide[5], 0u16);
        assert_eq!(wide[0], 'r' as u16);
    }

    #[test]
    fn test_get_same_volume_temp_path() {
        let temp_path = get_same_volume_temp_path().unwrap();
        let file_name = temp_path.file_name().unwrap().to_str().unwrap();
        assert!(
            file_name.ends_with(TEMP_SUFFIX),
            "同卷临时文件必须以后缀 {} 结尾",
            TEMP_SUFFIX
        );
        let parent = temp_path.parent().unwrap();
        assert!(parent.exists(), "同卷临时文件父目录必须真实存在");
    }

    #[test]
    fn test_build_windows_installer_args_msi_modes() {
        let path = Path::new("C:\\temp\\installer.msi");
        let empty_args: [String; 0] = [];

        // 默认模式（无模式指定时缺省为 /passive）
        let opt_default = InstallerOptions {
            user_args: &empty_args,
            install_mode: None,
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_default);
        assert_eq!(prog, "msiexec");
        assert_eq!(
            args,
            vec!["/i", "C:\\temp\\installer.msi", "/passive", "/norestart"]
        );

        // Quiet 模式
        let opt_quiet = InstallerOptions {
            user_args: &empty_args,
            install_mode: Some(InstallMode::Quiet),
            require_elevation: false,
        };
        let (prog, args) = build_windows_installer_args(path, &opt_quiet);
        assert_eq!(prog, "msiexec");
        assert_eq!(
            args,
            vec!["/i", "C:\\temp\\installer.msi", "/qn", "/norestart"]
        );
    }

    #[test]
    fn test_schedule_reboot_replace_and_delete_api() {
        let temp_dir = std::env::temp_dir();
        let src = temp_dir.join(format!("test_src_{}.exe", std::process::id()));
        let dst = temp_dir.join(format!("test_dst_{}.exe", std::process::id()));
        let _ = fs::write(&src, b"src content");
        let _ = fs::write(&dst, b"dst content");

        let res = schedule_reboot_replace(&src, &dst);
        if let Err(e) = res {
            let msg = e.to_string();
            assert!(msg.contains("向 Windows 注册系统重启替换任务失败"));
        }

        let res_del = schedule_reboot_delete(&src);
        if let Err(e) = res_del {
            let msg = e.to_string();
            assert!(msg.contains("向 Windows 注册系统重启删除任务失败"));
        }

        let _ = fs::remove_file(&src);
        let _ = fs::remove_file(&dst);
    }
}
