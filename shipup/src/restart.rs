// shipup 跨平台自更新系统 - 跨平台程序自重启与清理钩子移交

use crate::error::{Result, UpdateError};
use std::convert::Infallible;
use std::env;
use std::process::{self, Command};

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
}

/// 检查当前进程的启动参数中是否包含 --shipup-restarted 标记
///
/// # 设计原理
/// - **实现初衷**：告知新启动的进程“当前启动是来自更新系统的自重启”，宿主程序据此可给予单实例锁适当的重试容限或弹出升级成功提示。
pub fn is_restarted_by_shipup() -> bool {
    env::args().any(|arg| arg == SHIPUP_RESTARTED_ARG)
}

/// 执行优雅自重启：拉起新程序并传递清理上下文
///
/// # 设计原理
/// - **实现初衷**：派生独立子进程后，执行用户清理闭包，紧接着调用 `process::exit(0)` 主动终止旧进程。
/// - **核心优势**：自动附加 `--shipup-restarted` 标记，Windows 下脱离进程控制台。
/// - **代价与局限**：此方法成功执行后会导致当前旧进程直接退出，不可在其后安排依赖旧进程的后续逻辑。
///
/// # Errors
/// 当子进程派生失败时返回 [`UpdateError::SelfReplace`]。若新进程拉起成功，将在执行清理闭包后退出当前进程，正常情况下不会返回。
pub fn restart_with<F>(cleanup_wrapper: F) -> Result<Infallible>
where
    F: FnOnce(&mut RestartContext),
{
    log::info!("准备执行程序自重启移交...");
    let current_exe = env::current_exe()?;
    let mut args: Vec<String> = env::args().skip(1).collect();

    // 附加上下文标记
    if !args.iter().any(|a| a == SHIPUP_RESTARTED_ARG) {
        args.push(SHIPUP_RESTARTED_ARG.to_string());
    }

    let mut command = Command::new(&current_exe);
    command.args(&args);

    // Windows 平台下脱离进程组
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    // 拉起新进程
    command
        .spawn()
        .map_err(|e| UpdateError::SelfReplace(format!("拉起自重启新进程失败: {}", e)))?;

    // 执行用户指定的退出前清理逻辑
    let mut ctx = RestartContext::new();
    cleanup_wrapper(&mut ctx);

    // 正常退出当前旧进程，彻底释放文件锁与单实例锁
    process::exit(0);
}
