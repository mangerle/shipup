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

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::StatusCode;
#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::RANGE;

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
    /// 网络自动重试最大次数
    pub max_retries: u32,
    /// 网络重试初始退避延迟
    pub retry_delay: Duration,
}

pub(crate) fn calculate_backoff(retry_delay: Duration, attempt: u32) -> Duration {
    let factor = 2_u64.saturating_pow(attempt.saturating_sub(1));
    let backoff_secs = retry_delay.as_secs_f64() * (factor as f64);
    Duration::from_secs_f64(backoff_secs.min(60.0))
}

pub(crate) fn is_retryable_error(err: &UpdateError) -> bool {
    match err {
        UpdateError::Cancelled => false,
        UpdateError::HttpStatus { status_code, .. } => {
            *status_code == 408 || *status_code == 429 || *status_code >= 500
        }
        _ => true,
    }
}

#[cfg(feature = "blocking")]
/// 同步阻塞流式下载更新包（支持 HTTP Range 断点续传与指数退避网络重试）
///
/// # 设计原理
/// - **实现初衷**：在弱网或网络中断环境下自动进行指数退避重试，并利用 HTTP Range 头续传已下载部分，
///   避免数十兆或数百兆文件反复从头下载。
/// - **核心优势**：在单次会话或跨次会话中均支持断点续传；用户主动取消时保留断点切片；错误重试机制内聚。
/// - **代价与局限**：若远端服务器不支持 206 Partial Content，将自动降级为全量下载。
///
/// # Errors
/// - 超过最大重试次数时返回最后一次的网络或 I/O 错误。
/// - 当用户主动取消时返回 [`UpdateError::Cancelled`]。
pub fn download_file_blocking<F>(
    client: &reqwest::blocking::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let mut attempts = 0;
    loop {
        attempts += 1;
        match download_file_blocking_attempt(client, options, &mut event_callback) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !is_retryable_error(&e) || attempts > options.max_retries {
                    return Err(e);
                }
                let backoff = calculate_backoff(options.retry_delay, attempts);
                log::warn!(
                    "同步下载遇到暂时性故障: {}，正在等待 {:?} 进行第 {}/{} 次重试",
                    e,
                    backoff,
                    attempts,
                    options.max_retries
                );
                std::thread::sleep(backoff);
            }
        }
    }
}

#[cfg(feature = "blocking")]
fn download_file_blocking_attempt<F>(
    client: &reqwest::blocking::Client,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let existing_len = fs::metadata(options.target_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut request = client.get(options.url);
    if existing_len > 0 {
        log::info!(
            "检测到已存在部分下载文件 ({} 字节)，尝试发起 Range 断点续传",
            existing_len
        );
        request = request.header(RANGE, format!("bytes={}-", existing_len));
    } else {
        log::info!("发起全新同步下载请求，目标地址: {}", options.url);
    }

    let mut response = request
        .send()
        .map_err(|e| UpdateError::Network(format!("发起下载请求失败: {}", e)))?;

    let status = response.status();
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        log::warn!("Range 范围无效（416），清除损坏或超长临时文件后重新全量下载");
        let _ = fs::remove_file(options.target_path);
        return Err(UpdateError::HttpStatus {
            status_code: 416,
            message: "HTTP 416 Range Not Satisfiable".to_string(),
        });
    }

    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (file, initial_downloaded, total_bytes) = if status == StatusCode::PARTIAL_CONTENT {
        let remaining = response.content_length();
        let total = remaining.map(|r| existing_len.saturating_add(r));
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(options.target_path)?;
        (f, existing_len, total)
    } else {
        let total = response.content_length();
        let f = File::create(options.target_path)?;
        (f, 0, total)
    };

    event_callback(UpdateEvent::DownloadStarted { total_bytes });
    pipe_blocking_stream(
        &mut response,
        file,
        initial_downloaded,
        total_bytes,
        options,
        event_callback,
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
    initial_downloaded: u64,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let mut downloaded_bytes: u64 = initial_downloaded;
    let mut tracker = DownloadProgressTracker::new(total_bytes);
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消下载信号，保留已下载文件以供断点续传");
            return Err(UpdateError::Cancelled);
        }

        let read_bytes = match response.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(UpdateError::Io(e)),
        };

        if let Err(e) = file.write_all(&buffer[..read_bytes]) {
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes = downloaded_bytes.saturating_add(read_bytes as u64);
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
/// 异步流式下载更新包（支持 HTTP Range 断点续传与指数退避网络重试）
///
/// # 设计原理
/// - **实现初衷**：利用异步事件驱动模型实现弱网退避重试与 Range 断点续传，不阻塞 OS 线程。
/// - **核心优势**：在单线程或多任务并发上下文中资源开销小，主动取消保留断点切片以供续传。
/// - **代价与局限**：回调函数需满足 `Send` 约束。
///
/// # Errors
/// - 超过最大重试次数时返回最后一次的网络或 I/O 错误。
/// - 当用户主动取消时返回 [`UpdateError::Cancelled`]。
pub async fn download_file_async<F>(
    client: &reqwest::Client,
    options: &DownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    let mut attempts = 0;
    loop {
        attempts += 1;
        match download_file_async_attempt(client, options, &mut event_callback).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                if !is_retryable_error(&e) || attempts > options.max_retries {
                    return Err(e);
                }
                let backoff = calculate_backoff(options.retry_delay, attempts);
                log::warn!(
                    "异步下载遇到暂时性故障: {}，正在等待 {:?} 进行第 {}/{} 次重试",
                    e,
                    backoff,
                    attempts,
                    options.max_retries
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[cfg(feature = "async")]
async fn download_file_async_attempt<F>(
    client: &reqwest::Client,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    let existing_len = fs::metadata(options.target_path)
        .map(|m| m.len())
        .unwrap_or(0);

    let mut request = client.get(options.url);
    if existing_len > 0 {
        log::info!(
            "检测到已存在部分下载文件 ({} 字节)，尝试发起异步 Range 断点续传",
            existing_len
        );
        request = request.header(RANGE, format!("bytes={}-", existing_len));
    } else {
        log::info!("发起全新异步下载请求，目标地址: {}", options.url);
    }

    let response = request
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("发起异步下载请求失败: {}", e)))?;

    let status = response.status();
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        log::warn!("Range 范围无效（416），清除损坏或超长临时文件后重新全量下载");
        let _ = fs::remove_file(options.target_path);
        return Err(UpdateError::HttpStatus {
            status_code: 416,
            message: "HTTP 416 Range Not Satisfiable".to_string(),
        });
    }

    if !status.is_success() {
        return Err(UpdateError::HttpStatus {
            status_code: status.as_u16(),
            message: format!("下载响应异常: {}", status),
        });
    }

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let (file, initial_downloaded, total_bytes) = if status == StatusCode::PARTIAL_CONTENT {
        let remaining = response.content_length();
        let total = remaining.map(|r| existing_len.saturating_add(r));
        let f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(options.target_path)?;
        (f, existing_len, total)
    } else {
        let total = response.content_length();
        let f = File::create(options.target_path)?;
        (f, 0, total)
    };

    event_callback(UpdateEvent::DownloadStarted { total_bytes });
    pipe_async_stream(
        response,
        file,
        initial_downloaded,
        total_bytes,
        options,
        event_callback,
    )
    .await?;

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
    initial_downloaded: u64,
    total_bytes: Option<u64>,
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    use futures_util::StreamExt;
    let mut downloaded_bytes: u64 = initial_downloaded;
    let mut tracker = DownloadProgressTracker::new(total_bytes);
    let mut stream = response.bytes_stream();

    while let Some(chunk_res) = stream.next().await {
        if let Some(ref flag) = options.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消异步下载信号，保留已下载文件以供断点续传");
            return Err(UpdateError::Cancelled);
        }

        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => return Err(UpdateError::Network(format!("下载数据流中断: {}", e))),
        };

        if let Err(e) = file.write_all(&chunk) {
            return Err(UpdateError::Io(e));
        }

        downloaded_bytes = downloaded_bytes.saturating_add(chunk.len() as u64);
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

    #[test]
    fn test_calculate_backoff_exponential_growth_and_cap() {
        let base = Duration::from_secs(1);
        // attempt 1: 1 * 2^0 = 1s
        assert_eq!(calculate_backoff(base, 1), Duration::from_secs(1));
        // attempt 2: 1 * 2^1 = 2s
        assert_eq!(calculate_backoff(base, 2), Duration::from_secs(2));
        // attempt 3: 1 * 2^2 = 4s
        assert_eq!(calculate_backoff(base, 3), Duration::from_secs(4));
        // attempt 10: 1 * 2^9 = 512s，但应被 60s 上限截断
        assert_eq!(calculate_backoff(base, 10), Duration::from_secs(60));
    }

    #[test]
    fn test_is_retryable_error_rules() {
        // 用户主动取消不可重试
        assert!(!is_retryable_error(&UpdateError::Cancelled));

        // 404 Not Found 不可重试
        assert!(!is_retryable_error(&UpdateError::HttpStatus {
            status_code: 404,
            message: "Not Found".to_string(),
        }));

        // 408 Timeout 可重试
        assert!(is_retryable_error(&UpdateError::HttpStatus {
            status_code: 408,
            message: "Request Timeout".to_string(),
        }));

        // 429 Too Many Requests 可重试
        assert!(is_retryable_error(&UpdateError::HttpStatus {
            status_code: 429,
            message: "Too Many Requests".to_string(),
        }));

        // 502 Bad Gateway 可重试
        assert!(is_retryable_error(&UpdateError::HttpStatus {
            status_code: 502,
            message: "Bad Gateway".to_string(),
        }));

        // 普通网络连接错误可重试
        assert!(is_retryable_error(&UpdateError::Network(
            "连接超时重置".to_string()
        )));
    }
}
