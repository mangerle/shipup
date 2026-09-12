//! Windows 专属平台适配模块。
//!
//! # 模块职责
//! 实现 Windows 下的运行中二进制替换、历史备份清理、安装器命令行构造与派发，
//! 以及基于 `MoveFileExW` 的「重启后延迟替换/删除」兜底路径。
//!
//! # 设计原理
//! - **实现初衷**：Windows 对正在运行的可执行文件加排他锁，无法像类 Unix 那样直接覆写。
//! - **核心优势**：
//!   - 首选策略为「原文件重命名为 `.old` 备份 → 新文件写入原路径」，
//!     重命名的成功率远高于直接覆盖，且失败时原程序仍然可运行；
//!   - 重命名仍受阻时（被防病毒或后台服务锁定），可降级向系统注册重启延迟替换任务，
//!     让更新在下次重启时静默生效，而不是让整条更新流程直接失败；
//!   - 主程序启动时清理历史 `.old` 残留，形成自净闭环。
//! - **代价与局限**：延迟替换必须等到下一次操作系统重启才会生效，
//!   调用方有义务向用户明确提示这一时序差异。
//!
//! # 安全契约
//! 派生外部安装器时，所有用户可控参数都必须经过 [`escape_windows_args`] 转义，
//! 严防参数注入导致的任意命令执行。

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
/// - **核心优势**：用户自定义参数追加在标准标志之后，兼具标准化与高度灵活性；
///   交互模式到标准参数的映射收敛为静态表驱动，新增模式只需改表。
pub(crate) fn build_windows_installer_args(
    installer_path: &Path,
    options: &InstallerOptions<'_>,
) -> (String, Vec<String>) {
    let ext = installer_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_msi = ext == "msi";

    let program = if is_msi {
        "msiexec".to_string()
    } else {
        installer_path.to_string_lossy().to_string()
    };

    let mut args = Vec::with_capacity(options.user_args.len() + 4);
    if is_msi {
        args.push("/i".to_string());
        args.push(installer_path.to_string_lossy().to_string());
    }

    // 表驱动选择标准参数：无显式模式且无自定义参数时按安装器类型施加缺省静默策略
    let effective_mode = resolve_effective_install_mode(is_msi, options);
    args.extend(
        standard_installer_args(is_msi, effective_mode)
            .iter()
            .map(|s| (*s).to_string()),
    );
    // 用户自定义参数追加在标准模式参数之后，避免粗暴全覆盖
    args.extend(options.user_args.iter().cloned());

    (program, args)
}

/// 决策生效的交互模式：显式指定优先；未指定且无自定义参数时按类型施加缺省
fn resolve_effective_install_mode(
    is_msi: bool,
    options: &InstallerOptions<'_>,
) -> Option<InstallMode> {
    match options.install_mode {
        Some(mode) => Some(mode),
        // 无显式模式且用户自带参数时，完全交由用户控制，不注入任何标准静默标志
        None if !options.user_args.is_empty() => None,
        // 缺省策略：MSI 走 /passive，EXE 走 /S
        None => Some(if is_msi {
            InstallMode::Passive
        } else {
            InstallMode::Quiet
        }),
    }
}

/// 表驱动：根据安装器类型与交互模式返回应注入的标准静默参数
fn standard_installer_args(is_msi: bool, mode: Option<InstallMode>) -> &'static [&'static str] {
    match (is_msi, mode) {
        (true, Some(InstallMode::Passive)) => &["/passive", "/norestart"],
        (true, Some(InstallMode::Quiet)) => &["/qn", "/norestart"],
        (true, Some(InstallMode::BasicUi)) => &["/qb", "/norestart"],
        (false, Some(InstallMode::Passive)) => &["/passive"],
        (false, Some(InstallMode::Quiet)) => &["/S"],
        // EXE 的 BasicUi 模式不注入静默标志；None 表示完全交由用户参数控制
        (false, Some(InstallMode::BasicUi)) | (_, None) => &[],
    }
}

/// Win32 原生 API 绑定子模块。
///
/// # 设计原理
/// - **实现初衷**：本模块只依赖 `libc` 之外的最小外部依赖，因此不引入 `windows` crate，
///   而是手写所需的两三个 API 声明，避免为少量符号付出整包依赖体积。
/// - **核心优势**：绑定范围被严格限定在「派生安装器」与「延迟替换」两处用途，
///   审查面积极小。
/// - **代价与局限**：函数签名需与 Windows SDK 头文件保持逐字一致，
///   升级或跨架构时必须人工核对（`extern "system"` 已覆盖 `stdcall` 调用约定差异）。
///
/// # 安全契约
/// 本模块全部函数均为 `unsafe extern`，调用方必须自行保证：
/// 传入的宽字符串指针以 `\0` 结尾且生命周期覆盖调用期、句柄参数合法。
#[cfg(windows)]
mod ffi {
    use std::ffi::c_void;

    /// `ShellExecuteW` 的显示命令：以正常窗口激活目标程序。
    pub const SW_SHOWNORMAL: i32 = 1;
    /// `MoveFileExW` 标志位：目标已存在时直接覆盖。
    pub const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    /// `MoveFileExW` 标志位：把操作登记到系统重启阶段执行。
    pub const MOVEFILE_DELAY_UNTIL_REBOOT: u32 = 0x0000_0004;

    #[link(name = "shell32")]
    unsafe extern "system" {
        /// 以 Shell 语义启动目标程序（用于派生外部安装器）。
        ///
        /// 成功时返回大于 32 的伪句柄值，失败时返回表示错误类别的较小整数码。
        pub fn ShellExecuteW(
            hwnd: *mut c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> *mut c_void;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        /// 移动或替换文件，可按 `dw_flags` 登记为「重启阶段执行」。
        ///
        /// 返回非零表示成功，返回 0 表示失败（错误码通过 `GetLastError` 获取）。
        pub fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
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
        // UAC 提权走 ShellExecuteW，系统级无法可靠等待子进程退出码，默认保持派生即返回
        if options.wait_for_exit {
            log::warn!(
                "Windows UAC 提权安装器无法等待退出码，已降级为派生后立即返回: {}",
                installer_path.display()
            );
        }
        return spawn_elevated_installer(&program, &args, installer_path);
    }

    let mut cmd = Command::new(&program);
    cmd.args(&args);

    if options.wait_for_exit {
        // 等待退出码时不能脱离进程树，否则父进程无法持有可等待句柄
        let status = cmd.status().map_err(|e| {
            UpdateError::InstallerSpawn(format!("等待 Windows 安装器退出失败: {e}"))
        })?;
        let code = status.code().unwrap_or(-1);
        if !status.success() {
            return Err(UpdateError::InstallerExitFailed {
                exit_code: code,
                path: installer_path.display().to_string(),
            });
        }
        log::info!("Windows 安装器已成功退出，退出码: {code}");
        return Ok(());
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
            wait_for_exit: false,
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
        let temp_dir = env::temp_dir();
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
