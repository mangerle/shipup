//! 同步阻塞下载实现模块。
//!
//! # 模块职责
//! 提供基于 `reqwest::blocking` 的更新包下载能力，供不引入异步运行时的传统桌面与命令行宿主使用：
//! - [`download_file_blocking`]：单流式下载，支持 HTTP Range 断点续传与指数退避重试；
//! - [`download_file_chunked_blocking`]：大文件多镜像分片并行下载与拼装，不满足条件时平滑降级为单流下载；
//! - 其余函数为上述两条链路的内部协作单元（分片工作线程、进度汇总、本地文件复制、流式管道）。
//!
//! # 设计原理
//! - **实现初衷**：同步宿主没有协作式调度器，因此分片并发只能借助操作系统原生线程实现。
//! - **核心优势**：分片任务通过 `Mutex<VecDeque>` 组成「工作窃取式」共享队列，
//!   先完成的分片线程立即领取下一个分片，天然实现负载均衡，无需静态切分任务；
//!   线程生命周期由 `std::thread::scope` 约束，退出作用域即回收，不存在线程泄漏。
//! - **代价与局限**：并发度直接对应原生线程数，过高会带来线程栈与上下文切换开销，
//!   因此内部将并发度截断在 `1..=16`；此外阻塞式 HTTP 请求一旦进入网络 IO 便无法被中途强杀，
//!   取消信号只能在分片边界与单次读取之间生效。
//!
//! # 安全契约
//! 分片下载完成后必须重新校验整体体积与哈希；任一分片体积不符即判定失败并删除临时文件。

#![cfg_attr(not(feature = "blocking"), allow(unused))]

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::signature::verify_sha256_file;
use reqwest::StatusCode;
use reqwest::header::RANGE;
use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{
    BUFFER_SIZE, ChunkWorkerMessage, ChunkedDownloadOptions, DownloadOptions,
    DownloadProgressTracker, FileChunkRange, RateLimiter, StreamPipeContext, calculate_backoff,
    check_disk_space_available, collect_candidate_urls, is_file_url, is_retryable_error,
    parse_file_url_to_path, split_file_into_chunks, try_hit_local_cache,
};

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
    if try_hit_local_cache(
        options.target_path,
        options.expected_checksum,
        &mut event_callback,
    ) {
        return Ok(());
    }

    if let Some(exp_size) = options.expected_size {
        check_disk_space_available(options.target_path, exp_size.saturating_mul(2))?;
    }

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
                event_callback(UpdateEvent::Retrying {
                    attempt: attempts,
                    max_retries: options.max_retries,
                    delay: backoff,
                    error: e.to_string(),
                });
                std::thread::sleep(backoff);
            }
        }
    }
}

#[cfg(feature = "blocking")]
fn verify_chunked_payload_file(options: &DownloadOptions<'_>) -> Result<()> {
    if let Some(expected_size) = options.expected_size {
        let actual_size = fs::metadata(options.target_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if actual_size != expected_size {
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::PayloadSizeMismatch {
                expected: expected_size,
                actual: actual_size,
            });
        }
    }
    if let Some(checksum) = options.expected_checksum {
        verify_sha256_file(options.target_path, checksum)?;
    }
    Ok(())
}

#[cfg(feature = "blocking")]
fn probe_range_support_blocking(client: &reqwest::blocking::Client, url: &str) -> bool {
    client
        .get(url)
        .header(RANGE, "bytes=0-0")
        .send()
        .map(|resp| resp.status() == StatusCode::PARTIAL_CONTENT)
        .unwrap_or(false)
}

#[cfg(feature = "blocking")]
/// 同步分片并行下载大文件更新包（支持多镜像流量分发、原地预分配与自动降级）
///
/// # 设计原理
/// - **实现初衷**：突破单 HTTP 连接吞吐上限，跨多个镜像源分摊大文件下载流量。
/// - **核心优势**：自动探测服务端 Range 兼容性；原地预分配磁盘扇区；Worker 原地 Seek 零碎片写入；
///   遇非兼容场景自动降级为常规流式下载。
/// - **代价与局限**：创建多个 OS 线程与并发 HTTP 连接。
///
/// # Errors
/// 当下载中断且无法重试、哈希校验失败或用户主动取消时返回对应错误。
pub fn download_file_chunked_blocking<F>(
    client: &reqwest::blocking::Client,
    options: &ChunkedDownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    if try_hit_local_cache(
        options.base.target_path,
        options.base.expected_checksum,
        &mut event_callback,
    ) {
        return Ok(());
    }

    if is_file_url(options.base.url) {
        return copy_local_file_blocking(&options.base, &mut event_callback);
    }

    let Some(total_size) = options.base.expected_size else {
        log::info!("未提供文件总预期大小，自动降级为常规流式下载");
        return download_file_blocking(client, &options.base, event_callback);
    };

    let min_chunked_threshold = (options.chunk_size as u64).saturating_mul(2);
    if total_size < min_chunked_threshold {
        log::info!(
            "文件体积 ({} 字节) 小于分片加速阈值，直接使用常规单流下载",
            total_size
        );
        return download_file_blocking(client, &options.base, event_callback);
    }

    check_disk_space_available(options.base.target_path, total_size.saturating_mul(2))?;

    if !probe_range_support_blocking(client, options.base.url) {
        log::warn!("远端服务器不支持 HTTP Range 协议，平滑降级为常规单流下载");
        return download_file_blocking(client, &options.base, event_callback);
    }

    execute_chunked_download_blocking(client, options, total_size, event_callback)
}

#[cfg(feature = "blocking")]
fn execute_chunked_download_blocking<F>(
    client: &reqwest::blocking::Client,
    options: &ChunkedDownloadOptions<'_>,
    total_size: u64,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    if let Some(parent) = options.base.target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let prealloc_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(options.base.target_path)?;
    prealloc_file.set_len(total_size)?;
    drop(prealloc_file);

    event_callback(UpdateEvent::DownloadStarted {
        total_bytes: Some(total_size),
    });

    let chunks = split_file_into_chunks(total_size, options.chunk_size);
    let total_chunks = chunks.len();
    let queue = Mutex::new(VecDeque::from(chunks));
    let candidate_urls = collect_candidate_urls(options.base.url, options.mirrors);
    let (tx, rx) = std::sync::mpsc::channel();
    let concurrency = options.concurrency.clamp(1, 16);

    std::thread::scope(|s| {
        for _ in 0..concurrency {
            let tx_clone = tx.clone();
            let q_ref = &queue;
            let urls_ref = &candidate_urls;
            s.spawn(move || {
                run_chunk_worker_blocking(
                    client,
                    options.base.target_path,
                    urls_ref,
                    q_ref,
                    options.base.cancel_flag.as_ref(),
                    tx_clone,
                );
            });
        }
        drop(tx);
        monitor_chunked_progress_blocking(rx, total_chunks, total_size, &mut event_callback)
    })?;

    verify_chunked_payload_file(&options.base)?;
    log::info!(
        "分片并行下载与拼装完成，临时文件: {}",
        options.base.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "blocking")]
fn run_chunk_worker_blocking(
    client: &reqwest::blocking::Client,
    target_path: &Path,
    candidate_urls: &[&str],
    queue: &Mutex<VecDeque<FileChunkRange>>,
    cancel_flag: Option<&Arc<AtomicBool>>,
    tx: std::sync::mpsc::Sender<ChunkWorkerMessage>,
) {
    loop {
        if let Some(flag) = cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            let _ = tx.send(ChunkWorkerMessage::Failed(UpdateError::Cancelled));
            return;
        }
        let chunk = match queue.lock() {
            Ok(mut guard) => guard.pop_front(),
            Err(_) => return,
        };
        let Some(chunk) = chunk else {
            return;
        };

        if let Err(e) = download_single_chunk_blocking(
            client,
            target_path,
            candidate_urls,
            chunk,
            cancel_flag,
            &tx,
        ) {
            let _ = tx.send(ChunkWorkerMessage::Failed(e));
            return;
        }
        let _ = tx.send(ChunkWorkerMessage::ChunkCompleted);
    }
}

#[cfg(feature = "blocking")]
fn download_single_chunk_blocking(
    client: &reqwest::blocking::Client,
    target_path: &Path,
    candidate_urls: &[&str],
    chunk: FileChunkRange,
    cancel_flag: Option<&Arc<AtomicBool>>,
    tx: &std::sync::mpsc::Sender<ChunkWorkerMessage>,
) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(target_path)?;
    file.seek(SeekFrom::Start(chunk.start))?;

    let primary_idx = chunk.index % candidate_urls.len();
    let mut last_err = None;

    for offset in 0..candidate_urls.len() {
        let url = candidate_urls[(primary_idx + offset) % candidate_urls.len()];
        match fetch_chunk_stream_blocking(client, url, chunk, cancel_flag, &mut file, tx) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if matches!(e, UpdateError::Cancelled) {
                    return Err(e);
                }
                log::warn!(
                    "镜像 {} 下载分片 #{} 遇到异常: {}，尝试后续备选源",
                    url,
                    chunk.index,
                    e
                );
                last_err = Some(e);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| UpdateError::Network(format!("分片 #{} 全部镜像下载失败", chunk.index))))
}

#[cfg(feature = "blocking")]
fn fetch_chunk_stream_blocking(
    client: &reqwest::blocking::Client,
    url: &str,
    chunk: FileChunkRange,
    cancel_flag: Option<&Arc<AtomicBool>>,
    file: &mut File,
    tx: &std::sync::mpsc::Sender<ChunkWorkerMessage>,
) -> Result<()> {
    let range_header = format!("bytes={}-{}", chunk.start, chunk.end);
    let mut response = client
        .get(url)
        .header(RANGE, range_header)
        .send()
        .map_err(|e| UpdateError::Network(format!("分片请求失败: {}", e)))?;

    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(UpdateError::HttpStatus {
            status_code: response.status().as_u16(),
            message: format!("分片响应未返回 206 状态码: {}", response.status()),
        });
    }

    let mut buffer = [0u8; BUFFER_SIZE];
    let mut written_for_chunk = 0u64;
    let expected_len = chunk.len();

    loop {
        if let Some(flag) = cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            return Err(UpdateError::Cancelled);
        }
        let n = response.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n])?;
        written_for_chunk = written_for_chunk.saturating_add(n as u64);
        let _ = tx.send(ChunkWorkerMessage::BytesRead(n));
    }

    if written_for_chunk != expected_len {
        return Err(UpdateError::PayloadSizeMismatch {
            expected: expected_len,
            actual: written_for_chunk,
        });
    }
    file.flush()?;
    Ok(())
}

#[cfg(feature = "blocking")]
fn monitor_chunked_progress_blocking<F>(
    rx: std::sync::mpsc::Receiver<ChunkWorkerMessage>,
    total_chunks: usize,
    total_size: u64,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let mut completed_chunks = 0usize;
    let mut downloaded_bytes = 0u64;
    let mut tracker = DownloadProgressTracker::new(Some(total_size));

    while completed_chunks < total_chunks {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(ChunkWorkerMessage::BytesRead(bytes)) => {
                downloaded_bytes = downloaded_bytes.saturating_add(bytes as u64);
                let (percent, speed, eta) = tracker.update(downloaded_bytes);
                event_callback(UpdateEvent::DownloadProgress {
                    downloaded_bytes,
                    total_bytes: Some(total_size),
                    percent,
                    speed_bytes_per_sec: speed,
                    eta,
                });
            }
            Ok(ChunkWorkerMessage::ChunkCompleted) => {
                completed_chunks = completed_chunks.saturating_add(1);
            }
            Ok(ChunkWorkerMessage::Failed(e)) => return Err(e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let (percent, speed, eta) = tracker.update(downloaded_bytes);
                event_callback(UpdateEvent::DownloadProgress {
                    downloaded_bytes,
                    total_bytes: Some(total_size),
                    percent,
                    speed_bytes_per_sec: speed,
                    eta,
                });
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if completed_chunks < total_chunks {
        return Err(UpdateError::Network(
            "分片下载工作线程非预期提前退出".to_string(),
        ));
    }
    event_callback(UpdateEvent::DownloadProgress {
        downloaded_bytes: total_size,
        total_bytes: Some(total_size),
        percent: Some(100.0),
        speed_bytes_per_sec: tracker.current_speed,
        eta: Some(Duration::ZERO),
    });
    Ok(())
}

#[cfg(feature = "blocking")]
/// 以流式复制方式把本地 `file://` 源文件搬运到目标暂存路径。
///
/// # 设计原理
/// - **实现初衷**：离线仓库场景下源文件与目标路径可能位于不同介质（U 盘、网络共享盘），
///   直接 `fs::copy` 无法派发进度事件，也无法响应取消信号与带宽限速。
/// - **核心优势**：复用与网络下载完全相同的流式管道，因此进度回调、限速与取消语义在
///   离线与在线两种场景下表现一致。
///
/// # Errors
/// 当源文件缺失、体积与清单声明不符、写入失败或用户主动取消时返回对应错误。
pub(super) fn copy_local_file_blocking<F>(
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent),
{
    let src_path = parse_file_url_to_path(options.url)?;
    let mut src_file = File::open(&src_path)?;
    let total_bytes = src_file.metadata()?.len();

    if let Some(expected) = options.expected_size
        && total_bytes != expected
    {
        return Err(UpdateError::PayloadSizeMismatch {
            expected,
            actual: total_bytes,
        });
    }

    if let Some(parent) = options.target_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(options.target_path)?;

    event_callback(UpdateEvent::DownloadStarted {
        total_bytes: Some(total_bytes),
    });

    let ctx = StreamPipeContext {
        file,
        initial_downloaded: 0,
        total_bytes: Some(total_bytes),
        expected_size: options.expected_size,
        rate_limiter: options.max_bytes_per_sec.map(RateLimiter::new),
        cancel_flag: options.cancel_flag.as_ref(),
        event_callback,
    };
    pipe_blocking_stream(&mut src_file, ctx)?;

    log::info!(
        "本地文件流式复制完成，源文件: {}，目标临时文件: {}",
        src_path.display(),
        options.target_path.display()
    );
    Ok(())
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
    if is_file_url(options.url) {
        return copy_local_file_blocking(options, event_callback);
    }

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

    if let (Some(expected), Some(actual_total)) = (options.expected_size, total_bytes)
        && actual_total != expected
    {
        log::error!(
            "HTTP 响应声明的包体积 ({} 字节) 与清单期望值 ({} 字节) 不符",
            actual_total,
            expected
        );
        return Err(UpdateError::PayloadSizeMismatch {
            expected,
            actual: actual_total,
        });
    }

    event_callback(UpdateEvent::DownloadStarted { total_bytes });
    let ctx = StreamPipeContext {
        file,
        initial_downloaded,
        total_bytes,
        expected_size: options.expected_size,
        rate_limiter: options.max_bytes_per_sec.map(RateLimiter::new),
        cancel_flag: options.cancel_flag.as_ref(),
        event_callback,
    };
    pipe_blocking_stream(&mut response, ctx)?;

    if let Some(expected) = options.expected_size {
        let final_len = fs::metadata(options.target_path)
            .map(|m| m.len())
            .unwrap_or(0);
        if final_len != expected {
            let _ = fs::remove_file(options.target_path);
            return Err(UpdateError::PayloadSizeMismatch {
                expected,
                actual: final_len,
            });
        }
    }

    log::info!(
        "更新包同步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}
#[cfg(feature = "blocking")]
fn pipe_blocking_stream<R, F>(source: &mut R, mut ctx: StreamPipeContext<'_, File, F>) -> Result<()>
where
    R: Read,
    F: FnMut(UpdateEvent),
{
    let mut downloaded_bytes: u64 = ctx.initial_downloaded;
    let mut tracker = DownloadProgressTracker::new(ctx.total_bytes);
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        if let Some(flag) = ctx.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消下载信号，保留已下载文件以供断点续传");
            return Err(UpdateError::Cancelled);
        }

        let read_bytes = match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(UpdateError::Io(e)),
        };

        downloaded_bytes = downloaded_bytes.saturating_add(read_bytes as u64);
        if let Some(expected) = ctx.expected_size
            && downloaded_bytes > expected
        {
            return Err(UpdateError::PayloadSizeMismatch {
                expected,
                actual: downloaded_bytes,
            });
        }

        if let Err(e) = ctx.file.write_all(&buffer[..read_bytes]) {
            return Err(UpdateError::Io(e));
        }

        if let Some(ref mut limiter) = ctx.rate_limiter {
            limiter.record_and_throttle_blocking(read_bytes);
        }

        let (percent, speed_bytes_per_sec, eta) = tracker.update(downloaded_bytes);

        (ctx.event_callback)(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes: ctx.total_bytes,
            percent,
            speed_bytes_per_sec,
            eta,
        });
    }

    ctx.file.flush()?;
    Ok(())
}
