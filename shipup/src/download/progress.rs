//! 下载进度与速率平滑采样模块。
//!
//! # 模块职责
//! 提供 [`DownloadProgressTracker`]：在流式下载过程中按固定时间窗口采样，
//! 输出「百分比 / 瞬时速率 / 预计剩余时间」三元组，供事件回调直接驱动 UI。
//!
//! # 设计原理
//! - **实现初衷**：微小数据块读取间隔可能仅数十微秒，若每次重算速率会产生剧烈抖动并抬高系统时间查询成本。
//! - **核心优势**：500ms 时间窗口平滑采样，配合饱和算术防溢出与除零。
//! - **代价与局限**：首个窗口内瞬时速率基于总耗时做粗略均值预估。

use std::time::{Duration, Instant};

/// 进度度量采样器
///
/// # 设计原理
/// - **实现初衷**：在流式下载过程中，单次循环可能仅有数十微秒或几毫秒间隔。若每次微小块读取都重新计算速率，
///   数值会产生剧烈抖动且增加无谓的系统时间查询。
/// - **核心优势**：通过固定时间窗口（例如 500ms）进行速率平滑计算，结合饱和算术避免除零与溢出。
/// - **代价与局限**：首个 500ms 窗口内的瞬时速率基于已下载总耗时做粗略均值预估。
#[derive(Debug)]
pub(crate) struct DownloadProgressTracker {
    start_time: Instant,
    last_sample_time: Instant,
    last_sample_bytes: u64,
    /// 当前平滑后的瞬时速率；测试与进度汇总可直接读取
    pub(crate) current_speed: Option<u64>,
    total_bytes: Option<u64>,
}

impl DownloadProgressTracker {
    /// 创建进度跟踪器。
    ///
    /// `total_bytes` 为 `None` 表示服务端未声明 `Content-Length`，
    /// 此百分比与预计剩余时间将恒为 `None`，仅提供瞬时速率。
    pub(crate) fn new(total_bytes: Option<u64>) -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            last_sample_time: now,
            last_sample_bytes: 0,
            current_speed: None,
            total_bytes,
        }
    }

    /// 以当前累计下载字节数刷新统计数据，返回 `(百分比, 瞬时速率, 预计剩余时间)`。
    ///
    /// # 设计原理
    /// - **时间窗口平滑**：仅在距上次采样满 500ms 时才重算速率，避免每个数据块都触发系统时间查询，
    ///   并防止界面上的速率数值剧烈跳动。
    /// - **首窗口兜底**：在首个 500ms 窗口内以「已下载总量 / 总耗时」给出粗略均值，
    ///   使界面不至于长时间显示为空。
    /// - **饱和算术**：所有差值计算均使用饱和运算，杜绝极端字节计数下的溢出回绕。
    pub(crate) fn update(
        &mut self,
        downloaded_bytes: u64,
    ) -> (Option<f32>, Option<u64>, Option<Duration>) {
        let now = Instant::now();
        let elapsed_since_sample = now.duration_since(self.last_sample_time);

        // 每 500ms 刷新一次瞬时采样速率
        if elapsed_since_sample.as_millis() >= 500 {
            let bytes_in_window = downloaded_bytes.saturating_sub(self.last_sample_bytes);
            let secs = elapsed_since_sample.as_secs_f64();
            if secs > 0.0 {
                let speed = (bytes_in_window as f64 / secs).round() as u64;
                self.current_speed = Some(speed);
            }
            self.last_sample_time = now;
            self.last_sample_bytes = downloaded_bytes;
        } else if self.current_speed.is_none() {
            let total_elapsed = now.duration_since(self.start_time).as_secs_f64();
            if total_elapsed >= 0.1 {
                let speed = (downloaded_bytes as f64 / total_elapsed).round() as u64;
                self.current_speed = Some(speed);
            }
        }

        let percent = self.total_bytes.map(|total| {
            if total > 0 {
                ((downloaded_bytes as f64 / total as f64) * 100.0) as f32
            } else {
                0.0
            }
        });

        let eta = match (self.total_bytes, self.current_speed) {
            (Some(total), Some(speed)) if speed > 0 && total > downloaded_bytes => {
                let remaining_bytes = total - downloaded_bytes;
                let remaining_secs = remaining_bytes / speed;
                Some(Duration::from_secs(remaining_secs))
            }
            _ => None,
        };

        (percent, self.current_speed, eta)
    }
}
