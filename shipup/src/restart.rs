//! 跨平台程序自重启与优雅交接生命周期模块。
//!
//! # 模块职责
//! 提供 [`RestartOptions`]、[`restart_with_options`]、[`schedule_restart`] 与 [`RestartContext`]：
//! - 解决即刻退出导致 Web/RPC 响应被异常切断的问题；
//! - 解决微秒级重启导致的端口占用冲突与单实例互斥锁踩踏；
//! - 解决原样继承启动参数（如 `-u` / `--upgrade`）引发的更新死循环与异常秒退。
//!
//! # 设计原理
//! - **实现初衷**：在实际生产（特别是带有 Web UI 或后台常驻的守护程序）中，更新完毕直接强杀旧进程
//!   会导致客户端收不到完成响应；新旧进程几乎同时运行更会引发网络端口与文件锁冲突。
//! - **核心优势**：
//!   - `startup_delay`：延迟拉起新进程（如 1000ms），给旧进程留出充分释放端口与锁的时间；
//!   - `exit_delay`：旧进程延时退出（如 300ms），保障 Web/RPC 响应完整刷入 TCP Socket；
//!   - `filter_args`：自动或按需剔除单次触发的命令行参数，杜绝死循环；
//!   - 跨平台安全延迟执行引擎：Windows 采用轻量且无执行策略限制的 `cmd.exe /C "ping 127.0.0.1 -n N >nul & start ..."`，
//!     Unix/macOS 采用 `sh -c "sleep N && exec ..."`，避免依赖重量级 PowerShell 或临时脚本。
//! - **代价与局限**：Windows 下 `cmd.exe` 延迟精度受 `ping` 秒级步进影响，适合 1~3 秒量级的平滑缓冲。

use crate::error::{Result, UpdateError};
use std::convert::Infallible;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Duration;

/// 自重启时的上下文标记参数
pub const SHIPUP_RESTARTED_ARG: &str = "--shipup-restarted";

/// 重启前的上下文与生命周期管理
///
/// # 设计原理
/// - **实现初衷**：桌面程序通常具有“单实例互斥体”（如 Named Mutex 或本地 Socket 锁），若旧进程尚未退出新进程就被拉起，
///   新进程会被误判为重复启动而自杀。
/// - **核心优势**：提供显式生命周期闭包 `before_exit`，允许宿主应用在退出前释放 Mutex 句柄、断开网络连接或落盘数据。
/// - **代价与局限**：回调函数执行耗时不宜过长，否则影响重启的用户即时响应感。
pub struct RestartContext {
    cleaned_up: bool,
}

impl RestartContext {
    /// 创建空的重启上下文，初始状态下清理回调尚未执行。
    pub(crate) fn new() -> Self {
        Self { cleaned_up: false }
    }

    /// 在进程退出前执行清理回调（如释放单实例互斥体锁、保存未落盘数据、断开网络会话等）
    pub fn before_exit<F>(&mut self, cleanup_fn: F)
    where
        F: FnOnce(),
    {
        cleanup_fn();
        self.cleaned_up = true;
    }

    /// 检查是否已显式完成清理
    pub fn is_cleaned_up(&self) -> bool {
        self.cleaned_up
    }
}

/// 重启配置选项
///
/// # 设计原理
/// - **实现初衷**：收敛重启过程中的延时策略、参数过滤与执行目标，杜绝平铺传参。
/// - **核心优势**：提供链式 Builder API，具备安全合理的开箱即用默认值。
#[derive(Debug, Clone)]
pub struct RestartOptions {
    /// 目标可执行文件路径（默认当前进程 exe）
    pub(crate) executable: Option<PathBuf>,
    /// 启动新进程的延时（给旧进程释放端口、Socket、文件句柄与单实例锁留出时间）
    pub(crate) startup_delay: Duration,
    /// 旧进程退出的延时（保障 Web/RPC 响应完整刷入 TCP Socket）
    pub(crate) exit_delay: Duration,
    /// 需要从当前参数中排除的黑名单参数（如 "-u"、"--upgrade"）
    pub(crate) excluded_args: Vec<String>,
    /// 自定义覆盖的完整参数列表（若设置，则优先使用该列表）
    pub(crate) custom_args: Option<Vec<String>>,
    /// 额外追加的命令行参数
    pub(crate) extra_args: Vec<String>,
    /// 是否在新进程参数中附加 `--shipup-restarted` 标记
    pub(crate) append_restarted_flag: bool,
}

impl Default for RestartOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl RestartOptions {
    /// 创建默认重启配置
    ///
    /// 默认 startup_delay 为 1000ms（给旧进程释放端口留足缓冲）；
    /// 默认 exit_delay 为 300ms（给网络响应留足缓冲）；
    /// 默认排除单次触发参数 `["-u", "--upgrade"]`；
    /// 默认追加 `--shipup-restarted` 标记。
    pub fn new() -> Self {
        Self {
            executable: None,
            startup_delay: Duration::from_millis(1000),
            exit_delay: Duration::from_millis(300),
            excluded_args: vec!["-u".to_string(), "--upgrade".to_string()],
            custom_args: None,
            extra_args: Vec::new(),
            append_restarted_flag: true,
        }
    }

    /// 设置延迟拉起新进程的时间（给旧进程释放端口与互斥锁留出时间）
    pub fn startup_delay(mut self, delay: Duration) -> Self {
        self.startup_delay = delay;
        self
    }

    /// 设置旧进程退出的延迟等待时间（保障 Web/RPC 响应完整刷入 TCP Socket）
    pub fn exit_delay(mut self, delay: Duration) -> Self {
        self.exit_delay = delay;
        self
    }

    /// 指定要从当前命令行参数中排除/过滤掉的单次触发参数（如 "-u"、"--upgrade"）
    pub fn exclude_arg(mut self, arg: impl Into<String>) -> Self {
        self.excluded_args.push(arg.into());
        self
    }

    /// 批量指定要过滤掉的参数
    pub fn exclude_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for a in args {
            self.excluded_args.push(a.into());
        }
        self
    }

    /// 使用自定义谓词闭包从当前命令行参数中过滤保留的参数
    pub fn filter_args<F>(mut self, mut predicate: F) -> Self
    where
        F: FnMut(&str) -> bool,
    {
        let filtered: Vec<String> = env::args().skip(1).filter(|arg| predicate(arg)).collect();
        self.custom_args = Some(filtered);
        self
    }

    /// 覆盖全部参数为指定的参数列表
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_args = Some(args.into_iter().map(Into::into).collect());
        self
    }

    /// 追加额外参数
    pub fn append_arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    /// 设置自定义目标可执行文件路径
    pub fn executable(mut self, path: impl Into<PathBuf>) -> Self {
        self.executable = Some(path.into());
        self
    }

    /// 设置是否追加 `--shipup-restarted` 标记（默认为 true）
    pub fn append_restarted_flag(mut self, enable: bool) -> Self {
        self.append_restarted_flag = enable;
        self
    }
}

/// 检查当前进程的启动参数中是否包含 --shipup-restarted 标记
///
/// # 设计原理
/// - **实现初衷**：告知新启动的进程“当前启动是来自更新系统的自重启”，宿主程序据此可给予单实例锁适当的重试容限或弹出升级成功提示。
pub fn is_restarted_by_shipup() -> bool {
    env::args().any(|arg| arg == SHIPUP_RESTARTED_ARG)
}

/// 计算自重启实际生效的参数列表
pub(crate) fn resolve_effective_args(options: &RestartOptions) -> Vec<String> {
    let mut final_args = match &options.custom_args {
        Some(args) => args.clone(),
        None => env::args()
            .skip(1)
            .filter(|arg| !options.excluded_args.iter().any(|ex| ex == arg))
            .collect(),
    };

    if options.append_restarted_flag && !final_args.iter().any(|a| a == SHIPUP_RESTARTED_ARG) {
        final_args.push(SHIPUP_RESTARTED_ARG.to_string());
    }

    for extra in &options.extra_args {
        final_args.push(extra.clone());
    }

    final_args
}

/// 跨平台构建外部延迟执行拉起命令
pub(crate) fn build_delayed_command(
    options: &RestartOptions,
    target_exe: &Path,
    args: &[String],
) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

        let mut cmd = if options.startup_delay > Duration::from_millis(50) {
            // 使用 cmd.exe + ping 延迟拉起，轻量微秒级冷启动且无安全策略拦截
            let delay_secs = (options.startup_delay.as_secs_f64().ceil() as u64).max(1);
            let ping_count = delay_secs.saturating_add(1);

            let mut cmd_line = format!(
                "ping 127.0.0.1 -n {} >nul & start \"\" \"{}\"",
                ping_count,
                target_exe.display()
            );
            for arg in args {
                cmd_line.push(' ');
                let escaped = arg.replace('"', "\\\"");
                if escaped.contains(' ') || escaped.is_empty() {
                    cmd_line.push('"');
                    cmd_line.push_str(&escaped);
                    cmd_line.push('"');
                } else {
                    cmd_line.push_str(&escaped);
                }
            }
            let mut c = Command::new("cmd.exe");
            // 使用 raw_arg 绕过 Rust 对引号的 \" 转义，防止 cmd.exe 误将 \" 识别为 \\ 文件名
            c.raw_arg("/C");
            c.raw_arg(format!("\"{}\"", cmd_line));
            c
        } else {
            let mut c = Command::new(target_exe);
            c.args(args);
            c
        };

        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        cmd
    }

    #[cfg(not(windows))]
    {
        if options.startup_delay > Duration::from_millis(50) {
            let delay_secs = options.startup_delay.as_secs_f64();
            let mut cmd = Command::new("sh");
            let script = format!("sleep {} && exec \"$0\" \"$@\"", delay_secs);
            cmd.arg("-c").arg(&script).arg(target_exe);
            cmd.args(args);
            cmd
        } else {
            let mut cmd = Command::new(target_exe);
            cmd.args(args);
            cmd
        }
    }
}

/// 派生外部延迟重启子任务
fn spawn_delayed_process(options: &RestartOptions) -> Result<()> {
    let target_exe = match &options.executable {
        Some(p) => p.clone(),
        None => env::current_exe()?,
    };
    let effective_args = resolve_effective_args(options);
    let mut command = build_delayed_command(options, &target_exe, &effective_args);

    command
        .spawn()
        .map_err(|e| UpdateError::SelfReplace(format!("拉起自重启新进程失败: {}", e)))?;
    Ok(())
}

/// 执行优雅自重启（带参数对象配置）：拉起新程序并安全退出当前进程
///
/// # 设计原理
/// - **实现初衷**：在确保外部延迟拉起指令成功派生后，先执行清理，再等待 `exit_delay`，最后终止旧进程。
/// - **核心优势**：为端口释放与文件锁解禁留足时空窗口，彻底杜绝端口冲突秒退。
///
/// # Errors
/// 当子进程派生失败时返回 [`UpdateError::SelfReplace`]。若新进程拉起成功，正常情况下不会返回。
pub fn restart_with_options<F>(options: &RestartOptions, cleanup_wrapper: F) -> Result<Infallible>
where
    F: FnOnce(&mut RestartContext),
{
    log::info!(
        "准备执行程序自重启移交 (启动延时: {:?}, 退出延时: {:?})...",
        options.startup_delay,
        options.exit_delay
    );
    spawn_delayed_process(options)?;

    // 执行用户指定的退出前清理逻辑
    let mut ctx = RestartContext::new();
    cleanup_wrapper(&mut ctx);

    // 等待退出延时（若有），保障网络连接数据充分刷入 Socket
    if options.exit_delay > Duration::ZERO {
        std::thread::sleep(options.exit_delay);
    }

    process::exit(0);
}

/// 默认配置的优雅自重启（完全向后兼容旧版 API）
///
/// 内部自动应用默认配置（1000ms 启动延时，300ms 退出缓冲，自动剔除 `-u` 与 `--upgrade` 参数）。
///
/// # Errors
/// 当子进程派生失败时返回 [`UpdateError::SelfReplace`]。
pub fn restart_with<F>(cleanup_wrapper: F) -> Result<Infallible>
where
    F: FnOnce(&mut RestartContext),
{
    let options = RestartOptions::new();
    restart_with_options(&options, cleanup_wrapper)
}

/// 非阻塞调度优雅自重启（专为 Axum / Actix 等 Web / 异步宿主设计）
///
/// # 设计原理
/// - **实现初衷**：Web 接口收到前端重启请求后，必须先将 HTTP 200 JSON 响应发回前端，不能就地阻塞强杀。
/// - **核心优势**：先在后台派生延迟启动引擎，紧接着派生独立退出调度线程，主线程**立即返回 `Ok(())`**。
///   调用端 Handler 可顺畅向前端响应，`exit_delay` 到期后后台线程才终结旧进程。
///
/// # Errors
/// 当外部延迟拉起命令无法派生时返回 [`UpdateError::SelfReplace`]。
pub fn schedule_restart(options: &RestartOptions) -> Result<()> {
    schedule_restart_with(options, |_| {})
}

/// 非阻塞调度优雅自重启（带清理闭包）
///
/// # Errors
/// 当外部延迟拉起命令无法派生时返回 [`UpdateError::SelfReplace`]。
pub fn schedule_restart_with<F>(options: &RestartOptions, cleanup_wrapper: F) -> Result<()>
where
    F: FnOnce(&mut RestartContext) + Send + 'static,
{
    log::info!(
        "非阻塞调度程序优雅自重启 (启动延时: {:?}, 退出延时: {:?})...",
        options.startup_delay,
        options.exit_delay
    );
    spawn_delayed_process(options)?;

    let exit_delay = options.exit_delay;
    let cleanup_holder = std::sync::Arc::new(std::sync::Mutex::new(Some(cleanup_wrapper)));
    let cleanup_for_thread = cleanup_holder.clone();

    let spawn_res = std::thread::Builder::new()
        .name("shipup-graceful-exit".to_string())
        .spawn(move || {
            if exit_delay > Duration::ZERO {
                std::thread::sleep(exit_delay);
            }
            let mut ctx = RestartContext::new();
            if let Ok(mut guard) = cleanup_for_thread.lock()
                && let Some(cleanup) = guard.take()
            {
                cleanup(&mut ctx);
            }
            process::exit(0);
        });

    if let Err(e) = spawn_res {
        log::error!("派生后台优雅退出调度线程失败: {}，降级为立即退出", e);
        let mut ctx = RestartContext::new();
        if let Ok(mut guard) = cleanup_holder.lock()
            && let Some(cleanup) = guard.take()
        {
            cleanup(&mut ctx);
        }
        process::exit(0);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_restart_options_defaults_and_builder() {
        let opts = RestartOptions::new();
        assert_eq!(opts.startup_delay, Duration::from_millis(1000));
        assert_eq!(opts.exit_delay, Duration::from_millis(300));
        assert!(opts.append_restarted_flag);
        assert!(opts.excluded_args.contains(&"-u".to_string()));
        assert!(opts.excluded_args.contains(&"--upgrade".to_string()));

        let custom = RestartOptions::new()
            .startup_delay(Duration::from_millis(2000))
            .exit_delay(Duration::from_millis(500))
            .exclude_arg("--check-only")
            .append_arg("--debug")
            .append_restarted_flag(false);

        assert_eq!(custom.startup_delay, Duration::from_millis(2000));
        assert_eq!(custom.exit_delay, Duration::from_millis(500));
        assert!(!custom.append_restarted_flag);
        assert!(custom.excluded_args.contains(&"--check-only".to_string()));
        assert_eq!(custom.extra_args, vec!["--debug".to_string()]);
    }

    #[test]
    fn test_resolve_effective_args_with_custom_and_filters() {
        let opts = RestartOptions::new()
            .with_args(vec!["--config", "app.toml", "-u"])
            .exclude_arg("-u")
            .append_arg("--verbose");

        // 当使用 with_args 时，优先使用指定列表并附加 extra 与 restarted
        let effective = resolve_effective_args(&opts);
        assert!(effective.contains(&"--config".to_string()));
        assert!(effective.contains(&"app.toml".to_string()));
        assert!(effective.contains(&"--verbose".to_string()));
        assert!(effective.contains(&SHIPUP_RESTARTED_ARG.to_string()));
    }

    #[test]
    fn test_build_delayed_command_construction() {
        let opts = RestartOptions::new().startup_delay(Duration::from_millis(1500));
        let dummy_exe = Path::new("test_app.exe");
        let dummy_args = vec!["--port".to_string(), "8080".to_string()];
        let cmd = build_delayed_command(&opts, dummy_exe, &dummy_args);

        #[cfg(windows)]
        {
            let program = cmd.get_program().to_string_lossy();
            assert_eq!(program, "cmd.exe");
            let args: Vec<String> = cmd
                .get_args()
                .map(|a| a.to_string_lossy().to_string())
                .collect();
            assert_eq!(args[0], "/C");
            assert!(args[1].contains("ping 127.0.0.1 -n"));
            assert!(args[1].contains("start \"\" \"test_app.exe\""));
            assert!(args[1].contains("--port 8080"));
        }

        #[cfg(not(windows))]
        {
            let program = cmd.get_program().to_string_lossy();
            assert_eq!(program, "sh");
        }
    }

    #[test]
    #[cfg(windows)]
    fn test_delayed_command_spawn_real() {
        let opts = RestartOptions::new().startup_delay(Duration::from_millis(500));
        let dummy_exe = Path::new("cmd.exe");
        let dummy_args = vec!["/C".to_string(), "exit".to_string(), "0".to_string()];
        let mut cmd = build_delayed_command(&opts, dummy_exe, &dummy_args);
        let mut child = cmd.spawn().expect("应该成功派生子进程");
        let status = child.wait().expect("等待子进程退出");
        assert!(status.success());
    }
}
