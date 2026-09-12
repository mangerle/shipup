//! 下载带宽限速器模块。
//!
//! # 模块职责
//! 提供 [`RateLimiter`]：在后台静默下载时按字节配额自适应休眠，防止占满用户全速带宽。
//!
//! # 设计原理
//! - **实现初衷**：后台轮询预载不应挤占宿主前台业务所需带宽。
//! - **核心优势**：以「累计字节应耗时」与「实际已耗时」的比较结果决定休眠时长，
//!   长期平均速率精准，且避免高频唤醒。
//! - **代价与局限**：单次写入远大于窗口额度时会一次性休眠较长时间，取消信号只能在休眠结束后被感知。

use std::time::{Duration, Instant};

/// 下载流量带宽限速器
///
/// # 设计原理
/// - **实现初衷**：在后台轮询静默下载时防止占满用户全速带宽影响前台交互业务。
/// - **核心优势**：基于毫秒自适应等待与秒级滑动窗口重置，避免频繁陷入系统休眠与时钟溢出。
#[derive(Debug, Clone)]
pub(crate) struct RateLimiter {
    max_bytes_per_sec: u64,
    last_check: Instant,
    bytes_in_window: u64,
}

impl RateLimiter {
    /// 创建限速器，`max_bytes_per_sec` 为 0 表示不限速。
    pub(crate) fn new(max_bytes_per_sec: u64) -> Self {
        Self {
            max_bytes_per_sec,
            last_check: Instant::now(),
            bytes_in_window: 0,
        }
    }

    #[cfg(feature = "blocking")]
    /// 记录本次读写的字节数，并在超出目标速率时同步休眠以实施限速。
    ///
    /// # 设计原理
    /// - **实现初衷**：后台静默预载不应挤占宿主前台业务所需的带宽。
    /// - **核心优势**：以「累计字节应耗时」与「实际已耗时」的比较结果决定休眠时长，
    ///   而非固定切片轮询，既保证长期平均速率精准，又避免高频唤醒。
    /// - **代价与局限**：当单次写入远大于窗口额度时，会一次性休眠较长时间，
    ///   取消信号只能在本次休眠结束后才被感知。
    /// - **休眠阈值**：不足 5ms 的差额直接忽略，避免为微小偏差付出系统调用代价。
    pub(crate) fn record_and_throttle_blocking(&mut self, bytes: usize) {
        if self.max_bytes_per_sec == 0 || bytes == 0 {
            return;
        }
        self.bytes_in_window = self.bytes_in_window.saturating_add(bytes as u64);
        let elapsed = self.last_check.elapsed();
        let expected_duration =
            Duration::from_secs_f64(self.bytes_in_window as f64 / self.max_bytes_per_sec as f64);
        if expected_duration > elapsed {
            let sleep_time = expected_duration - elapsed;
            if sleep_time > Duration::from_millis(5) {
                std::thread::sleep(sleep_time);
            }
        }
        if self.last_check.elapsed() >= Duration::from_secs(1) {
            self.last_check = Instant::now();
            self.bytes_in_window = 0;
        }
    }

    #[cfg(feature = "async")]
    /// 异步版本的限速实现，语义与 [`Self::record_and_throttle_blocking`] 完全对齐。
    ///
    /// 差异仅在于使用 `tokio::time::sleep` 让出执行权，而不是阻塞当前操作系统线程，
    /// 因此可在高并发下载任务中安全使用。
    pub(crate) async fn record_and_throttle_async(&mut self, bytes: usize) {
        if self.max_bytes_per_sec == 0 || bytes == 0 {
            return;
        }
        self.bytes_in_window = self.bytes_in_window.saturating_add(bytes as u64);
        let elapsed = self.last_check.elapsed();
        let expected_duration =
            Duration::from_secs_f64(self.bytes_in_window as f64 / self.max_bytes_per_sec as f64);
        if expected_duration > elapsed {
            let sleep_time = expected_duration - elapsed;
            if sleep_time > Duration::from_millis(5) {
                tokio::time::sleep(sleep_time).await;
            }
        }
        if self.last_check.elapsed() >= Duration::from_secs(1) {
            self.last_check = Instant::now();
            self.bytes_in_window = 0;
        }
    }
}
