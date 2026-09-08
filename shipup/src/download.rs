#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - 流式下载引擎（支持进度派发与主动取消）

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use std::fs::{self, File};
#[cfg(feature = "blocking")]
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(feature = "blocking")]
const BUFFER_SIZE: usize = 64 * 1024; // 64KB 缓冲区

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
    current_speed: Option<u64>,
    total_bytes: Option<u64>,
}

impl DownloadProgressTracker {
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

/// 更新包流式下载配置选项
///
/// # 设计原理
/// - **实现初衷**：采用参数对象模式（Parameter Object Pattern）收敛下载目标 URL、落盘文件路径及取消令牌，
///   避免方法入参过度平铺膨胀。
/// - **核心优势**：借用切片生命周期，避免 URL 与 Path 的克隆分配开销。
/// - **代价与局限**：生命周期 `'a` 与调用上下文借用绑定。
#[derive(Debug, Clone)]
pub struct DownloadOptions<'a> {
    /// 目标资源公网下载直链
    pub url: &'a str,
    /// 下载落盘保存的目标临时路径
    pub target_path: &'a Path,
    /// 跨线程/异步任务的主动取消信号标记
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

#[cfg(feature = "blocking")]
/// 同步阻塞流式下载更新包到目标文件
///
/// # 设计原理
/// - **实现初衷**：基于固定大小缓冲区（64KB）循环拉取 HTTP 响应流，并实时派发进度通知事件。
/// - **核心优势**：单次内存占用恒定，即便下载数百兆的安装包也不会造成内存暴涨；支持毫秒级轮询响应主动取消。
/// - **代价与局限**：在调用线程中形成阻塞，若需在 GUI 中使用需调度至后台工作线程。
///
/// # Errors
/// - 当网络请求发起失败或 HTTP 响应非 2xx 时返回 [`UpdateError::Network`] 或 [`UpdateError::HttpStatus`]。
/// - 当用户触发取消信号时物理销毁临时文件并返回 [`UpdateError::Cancelled`]。
/// - 当磁盘写入失败时返回 [`UpdateError::Io`]。
pub fn download_file_blocking<F>(
    client: &reqwest::blocking::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    log::info!("正在发起同步下载请求，目标地址: {}", options.url);
    let mut response = client
        .get(options.url)
        .send()
        .map_err(|e| UpdateError::Network(format!("发起下载请求失败: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    let total_bytes = response.content_length();
    event_callback(UpdateEvent::DownloadStarted { total_bytes });

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(options.target_path)?;
    pipe_blocking_stream(
        &mut response,
        file,
        total_bytes,
        options,
        &mut event_callback,
    )?;

    log::info!(
        "更新包同步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "blocking")]
fn pipe_blocking_stream<F>(
    response: &mut reqwest::blocking::Response,
    mut file: File,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let mut downloaded_bytes: u64 = 0;
    let mut tracker = DownloadProgressTracker::new(total_bytes);
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消下载信号，正在清理临时文件");
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Cancelled);
        }

        let read_bytes = match response.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(options.target_path);
                return Err(UpdateError::Io(e));
            }
        };

        if let Err(e) = file.write_all(&buffer[..read_bytes]) {
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes += read_bytes as u64;
        let (percent, speed_bytes_per_sec, eta) = tracker.update(downloaded_bytes);

        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes,
            percent,
            speed_bytes_per_sec,
            eta,
        });
    }

    file.flush()?;
    Ok(())
}

#[cfg(feature = "async")]
/// 异步流式下载更新包到目标文件
///
/// # 设计原理
/// - **实现初衷**：利用异步数据流（`bytes_stream`）逐块拉取更新包，契合 Tokio 异步事件驱动架构。
/// - **核心优势**：在单线程或多任务并发上下文中不阻塞 OS 线程，资源开销小。
/// - **代价与局限**：回调函数需满足 `Send` 约束。
///
/// # Errors
/// - 当异步网络请求失败或响应非 2xx 时返回 [`UpdateError::Network`] 或 [`UpdateError::HttpStatus`]。
/// - 当用户触发取消信号时物理销毁临时文件并返回 [`UpdateError::Cancelled`]。
/// - 当文件落盘失败时返回 [`UpdateError::Io`]。
pub async fn download_file_async<F>(
    client: &reqwest::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    log::info!("正在发起异步下载请求，目标地址: {}", options.url);
    let response = client
        .get(options.url)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("发起异步下载请求失败: {}", e)))?;

    let status = response.status();
    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    let total_bytes = response.content_length();
    event_callback(UpdateEvent::DownloadStarted { total_bytes });

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = File::create(options.target_path)?;
    pipe_async_stream(response, file, total_bytes, options, &mut event_callback).await?;

    log::info!(
        "更新包异步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "async")]
async fn pipe_async_stream<F>(
    response: reqwest::Response,
    mut file: File,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    use futures_util::StreamExt;
    let mut downloaded_bytes: u64 = 0;
    let mut tracker = DownloadProgressTracker::new(total_bytes);
    let mut stream = response.bytes_stream();

    while let Some(chunk_res) = stream.next().await {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消异步下载信号，正在清理临时文件");
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Cancelled);
        }

        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(options.target_path);
                return Err(UpdateError::Network(format!("下载数据流中断: {}", e)));
            }
        };

        if let Err(e) = file.write_all(&chunk) {
            drop(file);
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes += chunk.len() as u64;
        let (percent, speed_bytes_per_sec, eta) = tracker.update(downloaded_bytes);

        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes,
            percent,
            speed_bytes_per_sec,
            eta,
        });
    }

    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_download_progress_tracker_zero_and_percent() {
        let mut tracker = DownloadProgressTracker::new(Some(1000));
        let (percent, _speed, _eta) = tracker.update(0);
        assert_eq!(percent, Some(0.0));

        let (percent, _speed, _eta) = tracker.update(500);
        assert_eq!(percent, Some(50.0));

        let (percent, _speed, _eta) = tracker.update(1000);
        assert_eq!(percent, Some(100.0));
    }

    #[test]
    fn test_download_progress_tracker_unknown_total() {
        let mut tracker = DownloadProgressTracker::new(None);
        let (percent, _speed, eta) = tracker.update(2048);
        assert_eq!(percent, None);
        assert_eq!(eta, None);
    }

    #[test]
    fn test_download_progress_tracker_eta_calculation() {
        let mut tracker = DownloadProgressTracker::new(Some(2_000_000));
        // 手动模拟速率计算
        tracker.current_speed = Some(1_000_000); // 1MB/s
        let (percent, speed, eta) = tracker.update(1_000_000); // 剩余 1MB
        assert_eq!(percent, Some(50.0));
        assert_eq!(speed, Some(1_000_000));
        assert_eq!(eta, Some(Duration::from_secs(1)));
    }
}
