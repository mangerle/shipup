//! 网络重试策略模块。
//!
//! # 模块职责
//! 提供指数退避时长计算与「是否值得重试」的错误分类，供同步/异步下载循环共用，
//! 避免两条链路出现「一边可重试、一边直接失败」的行为漂移。
//!
//! # 设计原理
//! - **实现初衷**：并非所有失败都值得重试；确定性安全/校验错误反复重试只会放大错误窗口。
//! - **核心优势**：规则集中、可单测；退避带 60 秒封顶与饱和幂运算。
//! - **代价与局限**：未引入随机抖动；新错误变体默认不可重试。

use crate::error::UpdateError;
use std::time::Duration;

/// 依据重试次数计算指数退避等待时长，并强制封顶在 60 秒。
///
/// # 设计原理
/// - **实现初衷**：网络抖动类故障通常在毫秒级恢复，而服务端限流或机房级故障则需要更长的冷却时间；
///   固定重试间隔无法同时适配两者。
/// - **核心优势**：
///   - 采用 `2^(attempt-1)` 指数增长，第 1 次重试即可快速重试，避免小抖动被过度放大；
///   - 通过 `saturating_pow` 与 60 秒封顶双重保护，杜绝高重试次数下的指数爆炸与数值溢出。
/// - **代价与局限**：未引入随机抖动（Jitter），多个客户端同时失败时可能出现「重试风暴」同步化。
///
/// # 契约
/// `attempt` 为 0 时按第 1 次重试计算（即返回 `retry_delay` 本身），不返回错误也不 panic。
pub(crate) fn calculate_backoff(retry_delay: Duration, attempt: u32) -> Duration {
    let factor = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let backoff_secs = retry_delay.as_secs_f64() * (factor as f64);
    Duration::from_secs_f64(backoff_secs.min(60.0))
}

/// 判定某个错误是否值得重试，决定下载循环是继续退避还是立即上抛。
///
/// # 设计原理
/// - **实现初衷**：并非所有失败都值得重试。对「校验失败」「签名无效」这类确定性错误反复重试，
///   只会毫无意义地放大错误窗口，甚至掩盖真实的安全告警。
/// - **核心优势**：以「错误是否可能因瞬时状态而自愈」为唯一判据，规则集中且可单元测试：
///   - 用户主动取消不可重试（尊重用户意图）；
///   - `408` / `429` / `5xx` 可重试（服务端瞬时过载或网关抖动）；
///   - 连接与读取类 I/O 错误可重试；
///   - 磁盘空间不足、权限拒绝等确定性 I/O 错误不可重试。
/// - **代价与局限**：白名单式判定意味着新增错误变体时默认「不可重试」，
///   若某新错误实际具备瞬时性，需要在此显式补充分支。
///
/// # 契约
/// 返回值仅决定「是否重试」，不改变错误本身的传播方式；达到最大重试次数后原始错误仍会原样上抛。
pub(crate) fn is_retryable_error(err: &UpdateError) -> bool {
    match err {
        UpdateError::Cancelled => false,
        UpdateError::HttpStatus { status_code, .. } => {
            *status_code == 408
                || *status_code == 429
                || (*status_code >= 500 && *status_code <= 599)
        }
        UpdateError::Network(_) => true,
        UpdateError::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
        ),
        _ => false,
    }
}
