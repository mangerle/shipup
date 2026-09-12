//! 异步非阻塞下载实现模块。
//!
//! # 模块职责
//! 提供基于 `reqwest` + `tokio` 的更新包下载能力，供 GPUI、Tokio 后端等异步宿主使用：
//! - [`download_file_async`]：单流式异步下载，支持 HTTP Range 断点续传与指数退避重试；
//! - [`download_file_chunked_async`]：大文件多镜像分片并发下载与拼装，不满足条件时平滑降级为单流下载；
//! - 其余函数为上述两条链路的内部协作单元（分片任务、进度汇总、本地文件复制、流式管道）。
//!
//! # 设计原理
//! - **实现初衷**：异步宿主已有协作式调度器，若仍像同步实现那样为每个分片派生原生线程，
//!   会白白浪费运行时的调度能力并抬高内存占用。
//! - **核心优势**：并发度改由 [`tokio::sync::Semaphore`] 约束，分片以轻量级任务形式提交，
//!   单线程运行时即可承载全部并发；任务句柄被集中持有，胜出或失败后可统一取消，杜绝任务泄漏。
//! - **代价与局限**：校验阶段涉及同步文件哈希计算，必须通过 `spawn_blocking` 调度到阻塞线程池，
//!   避免长时间占用异步工作线程。
//!
//! # 安全契约
//! 分片下载完成后必须重新校验整体体积与哈希；体积校验与哈希计算均在阻塞线程池中执行，
//! 以避免阻塞 Tokio 事件循环。

#![cfg_attr(not(feature = "async"), allow(unused))]

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::signature::verify_sha256_file;
use reqwest::StatusCode;
use reqwest::header::RANGE;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::{
    BUFFER_SIZE, ChunkWorkerMessage, ChunkedDownloadOptions, DownloadOptions,
    DownloadProgressTracker, FileChunkRange, RateLimiter, StreamPipeContext, calculate_backoff,
    check_disk_space_available, collect_candidate_urls, is_file_url, is_retryable_error,
    parse_file_url_to_path, split_file_into_chunks, try_hit_local_cache,
};

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
                event_callback(UpdateEvent::Retrying {
                    attempt: attempts,
                    max_retries: options.max_retries,
                    delay: backoff,
                    error: e.to_string(),
                });
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[cfg(feature = "async")]
async fn probe_range_support_async(client: &reqwest::Client, url: &str) -> bool {
    client
        .get(url)
        .header(RANGE, "bytes=0-0")
        .send()
        .await
        .map(|resp| resp.status() == StatusCode::PARTIAL_CONTENT)
        .unwrap_or(false)
}

#[cfg(feature = "async")]
/// 异步分片并行下载大文件更新包（支持多镜像流量分发、原地预分配与自动降级）
///
/// # 设计原理
/// - **实现初衷**：在异步事件驱动模型中实现大文件多镜像源并发分流与拼装，不阻塞工作线程。
/// - **核心优势**：自动探测服务端 Range 兼容性；原地预分配文件；基于信号量限流的高并发原地写入。
/// - **代价与局限**：回调函数需满足 `Send` 约束。
///
/// # Errors
/// 当下载中断且无法重试、哈希校验失败或用户主动取消时返回对应错误。
pub async fn download_file_chunked_async<F>(
    client: &reqwest::Client,
    options: &ChunkedDownloadOptions<'_>,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    if try_hit_local_cache(
        options.base.target_path,
        options.base.expected_checksum,
        &mut event_callback,
    ) {
        return Ok(());
    }

    if is_file_url(options.base.url) {
        return copy_local_file_async(&options.base, &mut event_callback).await;
    }

    let Some(total_size) = options.base.expected_size else {
        log::info!("未提供文件总预期大小，自动降级为常规异步流式下载");
        return download_file_async(client, &options.base, event_callback).await;
    };

    let min_chunked_threshold = (options.chunk_size as u64).saturating_mul(2);
    if total_size < min_chunked_threshold {
        log::info!(
            "文件体积 ({} 字节) 小于分片加速阈值，直接使用常规单流异步下载",
            total_size
        );
        return download_file_async(client, &options.base, event_callback).await;
    }

    check_disk_space_available(options.base.target_path, total_size.saturating_mul(2))?;

    if !probe_range_support_async(client, options.base.url).await {
        log::warn!("远端服务器不支持 HTTP Range 协议，平滑降级为常规单流异步下载");
        return download_file_async(client, &options.base, event_callback).await;
    }

    execute_chunked_download_async(client, options, total_size, event_callback).await
}

#[cfg(feature = "async")]
async fn execute_chunked_download_async<F>(
    client: &reqwest::Client,
    options: &ChunkedDownloadOptions<'_>,
    total_size: u64,
    mut event_callback: F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    if let Some(parent) = options.base.target_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let prealloc_file = tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(options.base.target_path)
        .await?;
    prealloc_file.set_len(total_size).await?;
    drop(prealloc_file);

    event_callback(UpdateEvent::DownloadStarted {
        total_bytes: Some(total_size),
    });

    let chunks = split_file_into_chunks(total_size, options.chunk_size);
    let total_chunks = chunks.len();
    let candidate_urls: Vec<String> = collect_candidate_urls(options.base.url, options.mirrors)
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let concurrency = options.concurrency.clamp(1, 16);
    let (tx, rx) = tokio::sync::mpsc::channel(concurrency * 4);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));

    let mut handles = Vec::with_capacity(total_chunks);
    let target_path_buf = options.base.target_path.to_path_buf();
    let cancel_flag = options.base.cancel_flag.clone();

    for chunk in chunks {
        let sem = semaphore.clone();
        let client_clone = client.clone();
        let path_clone = target_path_buf.clone();
        let urls_clone = candidate_urls.clone();
        let cancel_clone = cancel_flag.clone();
        let tx_clone = tx.clone();

        handles.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return,
            };
            if let Err(e) = download_single_chunk_async(
                &client_clone,
                &path_clone,
                &urls_clone,
                chunk,
                cancel_clone,
                tx_clone.clone(),
            )
            .await
            {
                let _ = tx_clone.send(ChunkWorkerMessage::Failed(e)).await;
                return;
            }
            let _ = tx_clone.send(ChunkWorkerMessage::ChunkCompleted).await;
        }));
    }
    drop(tx);

    monitor_chunked_progress_async(rx, total_chunks, total_size, &mut event_callback).await?;

    for handle in handles {
        let _ = handle.await;
    }

    let target_path = options.base.target_path.to_path_buf();
    let expected_checksum = options.base.expected_checksum.map(|s| s.to_string());
    let expected_size = options.base.expected_size;

    tokio::task::spawn_blocking(move || {
        if let Some(exp_size) = expected_size {
            let actual = fs::metadata(&target_path).map(|m| m.len()).unwrap_or(0);
            if actual != exp_size {
                let _ = fs::remove_file(&target_path);
                return Err(UpdateError::PayloadSizeMismatch {
                    expected: exp_size,
                    actual,
                });
            }
        }
        if let Some(ref cs) = expected_checksum {
            verify_sha256_file(&target_path, cs)?;
        }
        Ok(())
    })
    .await
    .map_err(|e| UpdateError::SelfReplace(format!("异步分片校验后台任务中止: {}", e)))??;

    log::info!(
        "异步分片并行下载与拼装完成，临时文件: {}",
        options.base.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "async")]
async fn download_single_chunk_async(
    client: &reqwest::Client,
    target_path: &Path,
    candidate_urls: &[String],
    chunk: FileChunkRange,
    cancel_flag: Option<Arc<AtomicBool>>,
    tx: tokio::sync::mpsc::Sender<ChunkWorkerMessage>,
) -> Result<()> {
    use std::io::SeekFrom;
    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(target_path)
        .await?;
    file.seek(SeekFrom::Start(chunk.start)).await?;

    let primary_idx = chunk.index % candidate_urls.len();
    let mut last_err = None;

    for offset in 0..candidate_urls.len() {
        let url = &candidate_urls[(primary_idx + offset) % candidate_urls.len()];
        match fetch_chunk_stream_async(client, url, chunk, cancel_flag.as_ref(), &mut file, &tx)
            .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                if matches!(e, UpdateError::Cancelled) {
                    return Err(e);
                }
                log::warn!(
                    "异步镜像 {} 下载分片 #{} 遇到异常: {}，尝试后续备选源",
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

#[cfg(feature = "async")]
async fn fetch_chunk_stream_async(
    client: &reqwest::Client,
    url: &str,
    chunk: FileChunkRange,
    cancel_flag: Option<&Arc<AtomicBool>>,
    file: &mut tokio::fs::File,
    tx: &tokio::sync::mpsc::Sender<ChunkWorkerMessage>,
) -> Result<()> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;

    let range_header = format!("bytes={}-{}", chunk.start, chunk.end);
    let response = client
        .get(url)
        .header(RANGE, range_header)
        .send()
        .await
        .map_err(|e| UpdateError::Network(format!("异步分片请求失败: {}", e)))?;

    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(UpdateError::HttpStatus {
            status_code: response.status().as_u16(),
            message: format!("分片响应未返回 206 状态码: {}", response.status()),
        });
    }

    let mut stream = response.bytes_stream();
    let mut written_for_chunk = 0u64;
    let expected_len = chunk.len();

    while let Some(item) = stream.next().await {
        if let Some(flag) = cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            return Err(UpdateError::Cancelled);
        }
        let bytes = item.map_err(|e| UpdateError::Network(format!("读取分片字节流失败: {}", e)))?;
        file.write_all(&bytes).await?;
        written_for_chunk = written_for_chunk.saturating_add(bytes.len() as u64);
        let _ = tx.send(ChunkWorkerMessage::BytesRead(bytes.len())).await;
    }

    if written_for_chunk != expected_len {
        return Err(UpdateError::PayloadSizeMismatch {
            expected: expected_len,
            actual: written_for_chunk,
        });
    }
    file.flush().await?;
    Ok(())
}

#[cfg(feature = "async")]
async fn monitor_chunked_progress_async<F>(
    mut rx: tokio::sync::mpsc::Receiver<ChunkWorkerMessage>,
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
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Some(ChunkWorkerMessage::BytesRead(bytes))) => {
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
            Ok(Some(ChunkWorkerMessage::ChunkCompleted)) => {
                completed_chunks = completed_chunks.saturating_add(1);
            }
            Ok(Some(ChunkWorkerMessage::Failed(e))) => return Err(e),
            Ok(None) => break,
            Err(_) => {
                let (percent, speed, eta) = tracker.update(downloaded_bytes);
                event_callback(UpdateEvent::DownloadProgress {
                    downloaded_bytes,
                    total_bytes: Some(total_size),
                    percent,
                    speed_bytes_per_sec: speed,
                    eta,
                });
            }
        }
    }

    if completed_chunks < total_chunks {
        return Err(UpdateError::Network(
            "分片异步下载工作任务非预期提前退出".to_string(),
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

#[cfg(feature = "async")]
async fn copy_local_file_async<F>(
    options: &DownloadOptions<'_>,
    event_callback: &mut F,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    use tokio::io::AsyncReadExt;
    let src_path = parse_file_url_to_path(options.url)?;
    let mut src_file = tokio::fs::File::open(&src_path).await?;
    let total_bytes = src_file.metadata().await?.len();

    if let Some(expected) = options.expected_size
        && total_bytes != expected
    {
        return Err(UpdateError::PayloadSizeMismatch {
            expected,
            actual: total_bytes,
        });
    }

    if let Some(parent) = options.target_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut file = tokio::fs::File::create(options.target_path).await?;

    event_callback(UpdateEvent::DownloadStarted {
        total_bytes: Some(total_bytes),
    });

    let mut downloaded_bytes: u64 = 0;
    let mut tracker = DownloadProgressTracker::new(Some(total_bytes));
    let mut rate_limiter = options.max_bytes_per_sec.map(RateLimiter::new);
    let mut buffer = [0u8; BUFFER_SIZE];

    loop {
        if let Some(flag) = options.cancel_flag.as_ref()
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消本地文件复制信号");
            return Err(UpdateError::Cancelled);
        }

        let read_bytes = match src_file.read(&mut buffer).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(UpdateError::Io(e)),
        };

        downloaded_bytes = downloaded_bytes.saturating_add(read_bytes as u64);
        tokio::io::AsyncWriteExt::write_all(&mut file, &buffer[..read_bytes]).await?;

        if let Some(ref mut limiter) = rate_limiter {
            limiter.record_and_throttle_async(read_bytes).await;
        }

        let (percent, speed_bytes_per_sec, eta) = tracker.update(downloaded_bytes);
        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes,
            total_bytes: Some(total_bytes),
            percent,
            speed_bytes_per_sec,
            eta,
        });
    }

    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    log::info!(
        "异步本地文件流式复制完成，源文件: {}，目标临时文件: {}",
        src_path.display(),
        options.target_path.display()
    );
    Ok(())
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
    if is_file_url(options.url) {
        return copy_local_file_async(options, event_callback).await;
    }

    let existing_len = match tokio::fs::metadata(options.target_path).await {
        Ok(m) => m.len(),
        Err(_) => 0,
    };

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
        let _ = tokio::fs::remove_file(options.target_path).await;
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
        tokio::fs::create_dir_all(parent).await?;
    }

    let (file, initial_downloaded, total_bytes) = if status == StatusCode::PARTIAL_CONTENT {
        let remaining = response.content_length();
        let total = remaining.map(|r| existing_len.saturating_add(r));
        let f = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(options.target_path)
            .await?;
        (f, existing_len, total)
    } else {
        let total = response.content_length();
        let f = tokio::fs::File::create(options.target_path).await?;
        (f, 0, total)
    };

    if let (Some(expected), Some(actual_total)) = (options.expected_size, total_bytes)
        && actual_total != expected
    {
        log::error!(
            "异步 HTTP 响应声明的包体积 ({} 字节) 与清单期望值 ({} 字节) 不符",
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
    pipe_async_stream(response, ctx).await?;

    if let Some(expected) = options.expected_size {
        let final_len = match tokio::fs::metadata(options.target_path).await {
            Ok(m) => m.len(),
            Err(_) => 0,
        };
        if final_len != expected {
            let _ = tokio::fs::remove_file(options.target_path).await;
            return Err(UpdateError::PayloadSizeMismatch {
                expected,
                actual: final_len,
            });
        }
    }

    log::info!(
        "更新包异步下载完成，临时路径: {}",
        options.target_path.display()
    );
    Ok(())
}

#[cfg(feature = "async")]
async fn pipe_async_stream<F>(
    response: reqwest::Response,
    mut ctx: StreamPipeContext<'_, tokio::fs::File, F>,
) -> Result<()>
where
    F: FnMut(UpdateEvent) + Send,
{
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let mut downloaded_bytes: u64 = ctx.initial_downloaded;
    let mut tracker = DownloadProgressTracker::new(ctx.total_bytes);
    let mut stream = response.bytes_stream();

    while let Some(chunk_res) = stream.next().await {
        if let Some(flag) = ctx.cancel_flag
            && flag.load(Ordering::Relaxed)
        {
            log::warn!("检测到用户主动取消异步下载信号，保留已下载文件以供断点续传");
            return Err(UpdateError::Cancelled);
        }

        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => return Err(UpdateError::Network(format!("下载数据流中断: {}", e))),
        };

        downloaded_bytes = downloaded_bytes.saturating_add(chunk.len() as u64);
        if let Some(expected) = ctx.expected_size
            && downloaded_bytes > expected
        {
            return Err(UpdateError::PayloadSizeMismatch {
                expected,
                actual: downloaded_bytes,
            });
        }

        if let Err(e) = ctx.file.write_all(&chunk).await {
            return Err(UpdateError::Io(e));
        }

        if let Some(ref mut limiter) = ctx.rate_limiter {
            limiter.record_and_throttle_async(chunk.len()).await;
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

    ctx.file.flush().await?;
    Ok(())
}
