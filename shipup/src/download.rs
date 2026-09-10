#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

// shipup 跨平台自更新系统 - 流式下载引擎（支持进度派发与主动取消）

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
#[cfg(feature = "blocking")]
use std::collections::VecDeque;
use std::fs;
#[cfg(feature = "blocking")]
use std::fs::File;
#[cfg(feature = "blocking")]
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "blocking")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::StatusCode;
#[cfg(any(feature = "blocking", feature = "async"))]
use reqwest::header::RANGE;

use crate::signature::verify_sha256_file;

#[cfg(any(feature = "blocking", feature = "async"))]
const BUFFER_SIZE: usize = 64 * 1024; // 64KB 缓冲区

/// 检查指定 URL 是否为本地或共享文件协议（file://，忽略 Scheme 大小写）
#[inline]
pub(crate) fn is_file_url(url: &str) -> bool {
    crate::offline::is_file_protocol(url)
}

/// 解析 file:// 协议 URL 为跨平台本地绝对路径
#[inline]
pub(crate) fn parse_file_url_to_path(url: &str) -> Result<PathBuf> {
    crate::offline::file_url_to_path(url)
}

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
    pub(crate) fn new(max_bytes_per_sec: u64) -> Self {
        Self {
            max_bytes_per_sec,
            last_check: Instant::now(),
            bytes_in_window: 0,
        }
    }

    #[cfg(feature = "blocking")]
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

/// 检查指定目标路径所在磁盘分区的可用存储空间
///
/// # 设计原理
/// - **实现初衷**：在下载和解包前核验磁盘剩余容量，避免半途写满磁盘导致进程或操作系统崩溃。
/// - **容错降级**：若系统接口调用失败或环境受限，以警告日志记录并降级放行，杜绝误杀正常更新。
pub(crate) fn check_disk_space_available(target_path: &Path, required_bytes: u64) -> Result<()> {
    if required_bytes == 0 {
        return Ok(());
    }
    match get_available_disk_space(target_path) {
        Ok(available) => {
            if available < required_bytes {
                log::error!(
                    "目标磁盘可用存储空间不足: 需要 {} 字节，实际仅剩余 {} 字节",
                    required_bytes,
                    available
                );
                return Err(UpdateError::InsufficientDiskSpace {
                    required: required_bytes,
                    available,
                });
            }
            Ok(())
        }
        Err(e) => {
            log::warn!("探测磁盘可用空间失败: {}，降级跳过预检直接尝试写入", e);
            Ok(())
        }
    }
}

#[cfg(windows)]
fn get_available_disk_space(target_path: &Path) -> std::io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    let dir = if target_path.is_dir() {
        target_path
    } else {
        target_path.parent().unwrap_or_else(|| Path::new("."))
    };
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);

    let mut free_bytes_available = 0u64;
    let mut total_number_of_bytes = 0u64;
    let mut total_number_of_free_bytes = 0u64;

    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            lp_directory_name: *const u16,
            lp_free_bytes_available_to_caller: *mut u64,
            lp_total_number_of_bytes: *mut u64,
            lp_total_number_of_free_bytes: *mut u64,
        ) -> i32;
    }

    let ret = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_bytes_available,
            &mut total_number_of_bytes,
            &mut total_number_of_free_bytes,
        )
    };

    if ret == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(free_bytes_available)
    }
}

#[cfg(unix)]
// 64 位 Linux/macOS 上 statvfs 字段已是 u64，32 位平台需要转换；
// 统一在函数级放行，避免特定 target 报 useless_conversion。
#[allow(clippy::useless_conversion)]
fn get_available_disk_space(target_path: &Path) -> std::io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let dir = if target_path.is_dir() {
        target_path
    } else {
        target_path.parent().unwrap_or_else(|| Path::new("."))
    };

    let c_path = CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    let res = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if res == 0 {
        let stat = unsafe { stat.assume_init() };
        let frsize: u64 = if stat.f_frsize > 0 {
            u64::try_from(stat.f_frsize).unwrap_or(0)
        } else {
            u64::try_from(stat.f_bsize).unwrap_or(0)
        };
        let bavail = u64::try_from(stat.f_bavail).unwrap_or(0);
        Ok(bavail.saturating_mul(frsize))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, unix)))]
fn get_available_disk_space(_target_path: &Path) -> std::io::Result<u64> {
    Ok(u64::MAX)
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
    /// 预期的 SHA-256 完整性哈希（用于直接比对本地已有文件实现秒级缓存命中）
    pub expected_checksum: Option<&'a str>,
    /// 预期的物理文件大小（字节，用于流式与落盘硬校验及磁盘空间预检）
    pub expected_size: Option<u64>,
    /// 最大允许下载带宽（字节/秒，用于后台平滑下载流控，若为 None 则不限速）
    pub max_bytes_per_sec: Option<u64>,
}

/// 默认分片并发 Worker 数量（4）
pub const DEFAULT_CHUNKED_CONCURRENCY: usize = 4;
/// 默认单个分片大小（4MB）
pub const DEFAULT_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// 单个文件分片 Range 字节区间
///
/// # 设计原理
/// - **实现初衷**：以标准 HTTP Range 闭区间 `[start, end]` 描述大文件的单个切片。
/// - **核心优势**：携带全局切片序号与起止边界，便于多工作线程/协程原地 seek 并发写入。
/// - **代价与局限**：调用端需保证区间合法性。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileChunkRange {
    /// 分片全局从零递增索引
    pub index: usize,
    /// 起始字节绝对偏移（包含）
    pub start: u64,
    /// 截止字节绝对偏移（包含）
    pub end: u64,
}

impl FileChunkRange {
    /// 计算该分片涵盖的总字节长度
    #[inline]
    pub fn len(&self) -> u64 {
        if self.start > self.end {
            0
        } else {
            (self.end - self.start).saturating_add(1)
        }
    }

    /// 判断分片是否为空
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start > self.end
    }
}

/// 将指定总字节长度等分为若干 Range 切片
///
/// # 设计原理
/// - **实现初衷**：在已知文件总长度前提下，将大文件划分为若干等长连续字节切片。
/// - **核心优势**：纯算法计算，使用饱和算术防溢出，末尾不足一片时自动收敛。
/// - **代价与局限**：若总大小为 0 或切片大小为 0 则返回空集合。
pub fn split_file_into_chunks(total_size: u64, chunk_size: usize) -> Vec<FileChunkRange> {
    if total_size == 0 || chunk_size == 0 {
        return Vec::new();
    }
    let chunk_size_u64 = chunk_size as u64;
    let num_chunks = total_size.div_ceil(chunk_size_u64) as usize;
    let mut chunks = Vec::with_capacity(num_chunks);
    let mut start = 0u64;
    let mut index = 0usize;

    while start < total_size {
        let end = start
            .saturating_add(chunk_size_u64)
            .saturating_sub(1)
            .min(total_size - 1);
        chunks.push(FileChunkRange { index, start, end });
        start = end.saturating_add(1);
        index = index.saturating_add(1);
    }

    chunks
}

/// 分片并行下载专属配置选项
///
/// # 设计原理
/// - **实现初衷**：采用参数对象模式收敛并发度、分片大小与多镜像源列表，避免方法入参过度平铺。
/// - **核心优势**：内嵌基础 [`DownloadOptions`]，与基础下载参数完全无缝复用。
/// - **代价与局限**：生命周期借用绑定。
#[derive(Debug, Clone)]
pub struct ChunkedDownloadOptions<'a> {
    /// 基础下载配置选项（目标临时文件路径、主直链、预期大小、预期哈希等）
    pub base: DownloadOptions<'a>,
    /// 备用镜像源直链列表（用于并发流量分流与故障转移）
    pub mirrors: &'a [String],
    /// 并发 Worker 数量（默认 4）
    pub concurrency: usize,
    /// 单个分片切片字节大小（默认 4MB）
    pub chunk_size: usize,
}

/// 收集并去重候选直链列表（主直链优先，附带非空镜像源）
pub(crate) fn collect_candidate_urls<'a>(main_url: &'a str, mirrors: &'a [String]) -> Vec<&'a str> {
    let mut list = Vec::with_capacity(1 + mirrors.len());
    list.push(main_url);
    for m in mirrors {
        let trimmed = m.trim();
        if !trimmed.is_empty() && trimmed != main_url && !list.contains(&trimmed) {
            list.push(trimmed);
        }
    }
    list
}

/// 分片 Worker 内部通信事件
#[derive(Debug)]
enum ChunkWorkerMessage {
    BytesRead(usize),
    ChunkCompleted,
    Failed(UpdateError),
}

pub(crate) fn try_hit_local_cache<F>(
    target_path: &Path,
    expected_checksum: Option<&str>,
    event_callback: &mut F,
) -> bool
where
    F: FnMut(UpdateEvent),
{
    if let Some(checksum) = expected_checksum
        && target_path.exists()
        && verify_sha256_file(target_path, checksum).is_ok()
    {
        let file_size = fs::metadata(target_path).map(|m| m.len()).ok();
        log::info!(
            "本地已有安装包完整性校验（SHA-256）一致，命中本地缓存，直接跳过网络下载，文件路径: {}",
            target_path.display()
        );
        event_callback(UpdateEvent::DownloadStarted {
            total_bytes: file_size,
        });
        event_callback(UpdateEvent::DownloadProgress {
            downloaded_bytes: file_size.unwrap_or(0),
            total_bytes: file_size,
            percent: Some(100.0),
            speed_bytes_per_sec: None,
            eta: Some(Duration::ZERO),
        });
        return true;
    }
    false
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
fn copy_local_file_blocking<F>(options: &DownloadOptions<'_>, event_callback: &mut F) -> Result<()>
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

/// 流式传输上下文对象
struct StreamPipeContext<'a, TFile, F> {
    file: TFile,
    initial_downloaded: u64,
    total_bytes: Option<u64>,
    expected_size: Option<u64>,
    rate_limiter: Option<RateLimiter>,
    cancel_flag: Option<&'a Arc<AtomicBool>>,
    event_callback: &'a mut F,
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

        // 校验和不匹配不可重试
        assert!(!is_retryable_error(&UpdateError::ChecksumMismatch {
            expected: "sha256:aaa".to_string(),
            actual: "bbb".to_string(),
        }));

        // 签名无效不可重试
        assert!(!is_retryable_error(&UpdateError::InvalidSignature));

        // 权限拒绝 IO 错误不可重试
        assert!(!is_retryable_error(&UpdateError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "拒绝访问"
        ))));
    }

    #[test]
    fn test_try_hit_local_cache() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join(format!("shipup_cache_test_{}.bin", std::process::id()));
        let content = b"hello shipup cached update package";
        fs::write(&test_file, content).unwrap();

        let mut events = Vec::new();

        // 1. 哈希不匹配时不能命中缓存
        let not_hit =
            try_hit_local_cache(&test_file, Some("wrong_hash"), &mut |ev| events.push(ev));
        assert!(!not_hit);
        assert!(events.is_empty());

        // 2. 哈希匹配时成功命中缓存并派发 100% 进度
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(content);
        let mut expected_hash = String::new();
        for b in hash {
            use std::fmt::Write;
            let _ = write!(expected_hash, "{b:02x}");
        }

        let hit = try_hit_local_cache(&test_file, Some(&expected_hash), &mut |ev| events.push(ev));
        assert!(hit);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], UpdateEvent::DownloadStarted { .. }));
        if let UpdateEvent::DownloadProgress { percent, .. } = &events[1] {
            assert_eq!(*percent, Some(100.0));
        } else {
            panic!("预期收到 100% DownloadProgress 事件");
        }

        let _ = fs::remove_file(&test_file);
    }

    #[test]
    fn test_update_event_variants_retrying_failed_completed() {
        let retrying_ev = UpdateEvent::Retrying {
            attempt: 1,
            max_retries: 3,
            delay: Duration::from_millis(500),
            error: "连接超时".to_string(),
        };
        let failed_ev = UpdateEvent::Failed {
            reason: "哈希校验失败".to_string(),
        };
        let completed_ev = UpdateEvent::Completed;

        assert_eq!(
            retrying_ev,
            UpdateEvent::Retrying {
                attempt: 1,
                max_retries: 3,
                delay: Duration::from_millis(500),
                error: "连接超时".to_string(),
            }
        );
        assert_eq!(
            failed_ev,
            UpdateEvent::Failed {
                reason: "哈希校验失败".to_string()
            }
        );
        assert_eq!(completed_ev, UpdateEvent::Completed);
    }

    #[test]
    fn test_check_disk_space_available_thresholds() {
        let temp_dir = std::env::temp_dir();
        // 1. 0 字节需求恒成功
        assert!(check_disk_space_available(&temp_dir, 0).is_ok());

        // 2. 10KB 需求在正常操作系统环境下必定满足
        let small_req = 10 * 1024;
        assert!(check_disk_space_available(&temp_dir, small_req).is_ok());

        // 3. 天文数字容量需求应当触发 InsufficientDiskSpace 错误
        let impossible_req = 1_000_000_000_000_000_000u64;
        let err = check_disk_space_available(&temp_dir, impossible_req);
        match err {
            Err(UpdateError::InsufficientDiskSpace {
                required,
                available: _,
            }) => {
                assert_eq!(required, impossible_req);
            }
            other => panic!("预期返回 InsufficientDiskSpace 错误，实际为: {:?}", other),
        }
    }

    #[test]
    fn test_rate_limiter_record_and_throttle() {
        let mut limiter = RateLimiter::new(1024 * 1024); // 1MB/s
        let start = Instant::now();
        limiter.record_and_throttle_blocking(512);
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_parse_file_url_to_path() {
        // 非 file:// 报错
        assert!(parse_file_url_to_path("https://example.com/test").is_err());

        // 带 localhost
        let _parsed = parse_file_url_to_path("file://localhost/path/to/file.txt").unwrap();
        #[cfg(not(windows))]
        assert_eq!(_parsed, PathBuf::from("/path/to/file.txt"));

        // 百分号解码
        let decoded = parse_file_url_to_path("file:///path/to/my%20file.txt").unwrap();
        assert!(decoded.to_string_lossy().contains("my file.txt"));

        #[cfg(windows)]
        {
            let win_path = parse_file_url_to_path("file:///C:/Windows/notepad.exe").unwrap();
            assert_eq!(win_path, PathBuf::from("C:/Windows/notepad.exe"));
        }
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_copy_local_file_blocking_and_events() {
        let temp_dir = std::env::temp_dir();
        let src_file = temp_dir.join(format!("shipup_src_{}.bin", std::process::id()));
        let dst_file = temp_dir.join(format!("shipup_dst_{}.bin", std::process::id()));
        let data = b"offline package payload test content";
        fs::write(&src_file, data).unwrap();

        let src_url = if cfg!(windows) {
            format!(
                "file:///{}",
                src_file.display().to_string().replace('\\', "/")
            )
        } else {
            format!("file://{}", src_file.display())
        };

        let mut events = Vec::new();
        let options = DownloadOptions {
            url: &src_url,
            target_path: &dst_file,
            cancel_flag: None,
            max_retries: 1,
            retry_delay: Duration::from_millis(10),
            expected_checksum: None,
            expected_size: Some(data.len() as u64),
            max_bytes_per_sec: None,
        };

        let res = copy_local_file_blocking(&options, &mut |ev| events.push(ev));
        assert!(res.is_ok());
        assert_eq!(fs::read(&dst_file).unwrap(), data);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
        );

        let _ = fs::remove_file(&src_file);
        let _ = fs::remove_file(&dst_file);
    }

    #[test]
    fn test_file_chunk_range_methods() {
        let chunk = FileChunkRange {
            index: 0,
            start: 0,
            end: 99,
        };
        assert_eq!(chunk.len(), 100);
        assert!(!chunk.is_empty());

        let empty_chunk = FileChunkRange {
            index: 1,
            start: 10,
            end: 5,
        };
        assert_eq!(empty_chunk.len(), 0);
        assert!(empty_chunk.is_empty());
    }

    #[test]
    fn test_split_file_into_chunks_edge_cases() {
        // 1. 空文件或 0 切片大小
        assert!(split_file_into_chunks(0, 1024).is_empty());
        assert!(split_file_into_chunks(100, 0).is_empty());

        // 2. 恰好整除：100 字节，切片 25 字节 -> 4 个分片
        let chunks = split_file_into_chunks(100, 25);
        assert_eq!(chunks.len(), 4);
        assert_eq!(
            chunks[0],
            FileChunkRange {
                index: 0,
                start: 0,
                end: 24
            }
        );
        assert_eq!(
            chunks[1],
            FileChunkRange {
                index: 1,
                start: 25,
                end: 49
            }
        );
        assert_eq!(
            chunks[2],
            FileChunkRange {
                index: 2,
                start: 50,
                end: 74
            }
        );
        assert_eq!(
            chunks[3],
            FileChunkRange {
                index: 3,
                start: 75,
                end: 99
            }
        );

        // 3. 有余数：105 字节，切片 25 字节 -> 5 个分片，末尾为 5 字节
        let chunks_rem = split_file_into_chunks(105, 25);
        assert_eq!(chunks_rem.len(), 5);
        assert_eq!(
            chunks_rem[4],
            FileChunkRange {
                index: 4,
                start: 100,
                end: 104
            }
        );
        assert_eq!(chunks_rem[4].len(), 5);

        // 4. 单切片大于等于总大小
        let chunks_single = split_file_into_chunks(50, 100);
        assert_eq!(chunks_single.len(), 1);
        assert_eq!(
            chunks_single[0],
            FileChunkRange {
                index: 0,
                start: 0,
                end: 49
            }
        );
    }

    #[test]
    fn test_collect_candidate_urls() {
        let mirrors = vec![
            "https://mirror1.example.com/app.tar.gz".to_string(),
            "   ".to_string(),
            "https://main.example.com/app.tar.gz".to_string(), // 与主 URL 重复
            "https://mirror2.example.com/app.tar.gz".to_string(),
        ];
        let result = collect_candidate_urls("https://main.example.com/app.tar.gz", &mirrors);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "https://main.example.com/app.tar.gz");
        assert_eq!(result[1], "https://mirror1.example.com/app.tar.gz");
        assert_eq!(result[2], "https://mirror2.example.com/app.tar.gz");
    }

    #[cfg(feature = "blocking")]
    fn run_mock_range_server(
        payload: Arc<Vec<u8>>,
        support_range: bool,
    ) -> (String, Arc<AtomicBool>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let url = format!("http://127.0.0.1:{}", port);

        std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            while running_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let mut buf = [0u8; 2048];
                        let n = stream.read(&mut buf).unwrap_or(0);
                        let req_str = String::from_utf8_lossy(&buf[..n]);

                        let mut range = None;
                        if support_range {
                            for line in req_str.lines() {
                                if line.to_ascii_lowercase().starts_with("range: bytes=") {
                                    let parts: Vec<&str> = line[13..].trim().split('-').collect();
                                    if parts.len() == 2 {
                                        let start = parts[0].parse::<usize>().unwrap_or(0);
                                        let end = parts[1]
                                            .parse::<usize>()
                                            .unwrap_or(payload.len().saturating_sub(1));
                                        range = Some((start, end));
                                    }
                                }
                            }
                        }

                        if let Some((start, end)) = range {
                            let end = end.min(payload.len().saturating_sub(1));
                            let chunk = if start <= end && start < payload.len() {
                                &payload[start..=end]
                            } else {
                                &[]
                            };
                            let header = format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                                chunk.len(),
                                start,
                                end,
                                payload.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(chunk);
                        } else {
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                payload.len()
                            );
                            let _ = stream.write_all(header.as_bytes());
                            let _ = stream.write_all(&payload);
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (url, running)
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_download_file_chunked_blocking_full_flow() {
        let payload = Arc::new(vec![42u8; 128]); // 128 字节测试负载
        let (server_url, server_guard) = run_mock_range_server(payload.clone(), true);

        let temp_dir = std::env::temp_dir();
        let target_file = temp_dir.join(format!("shipup_chunked_test_{}.bin", std::process::id()));
        let _ = fs::remove_file(&target_file);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut events = Vec::new();
        let options = ChunkedDownloadOptions {
            base: DownloadOptions {
                url: &server_url,
                target_path: &target_file,
                cancel_flag: None,
                max_retries: 2,
                retry_delay: Duration::from_millis(10),
                expected_checksum: None,
                expected_size: Some(128),
                max_bytes_per_sec: None,
            },
            mirrors: &[],
            concurrency: 2,
            chunk_size: 32, // 4 个分片
        };

        let result = download_file_chunked_blocking(&client, &options, |ev| events.push(ev));
        assert!(result.is_ok());
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), *payload);

        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
        );

        server_guard.store(false, Ordering::Relaxed);
        let _ = fs::remove_file(&target_file);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_download_file_chunked_blocking_fallback_on_unsupported_range() {
        let payload = Arc::new(vec![99u8; 128]);
        // 服务端配置不支持 Range，直接返回 200 OK
        let (server_url, server_guard) = run_mock_range_server(payload.clone(), false);

        let temp_dir = std::env::temp_dir();
        let target_file = temp_dir.join(format!("shipup_chunked_fb_{}.bin", std::process::id()));
        let _ = fs::remove_file(&target_file);

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let mut events = Vec::new();
        let options = ChunkedDownloadOptions {
            base: DownloadOptions {
                url: &server_url,
                target_path: &target_file,
                cancel_flag: None,
                max_retries: 1,
                retry_delay: Duration::from_millis(10),
                expected_checksum: None,
                expected_size: Some(128),
                max_bytes_per_sec: None,
            },
            mirrors: &[],
            concurrency: 2,
            chunk_size: 32,
        };

        let result = download_file_chunked_blocking(&client, &options, |ev| events.push(ev));
        assert!(result.is_ok());
        assert!(target_file.exists());
        assert_eq!(fs::read(&target_file).unwrap(), *payload);

        server_guard.store(false, Ordering::Relaxed);
        let _ = fs::remove_file(&target_file);
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn test_download_file_chunked_cancellation() {
        let payload = Arc::new(vec![7u8; 128]);
        let (server_url, server_guard) = run_mock_range_server(payload, true);

        let temp_dir = std::env::temp_dir();
        let target_file =
            temp_dir.join(format!("shipup_chunked_cancel_{}.bin", std::process::id()));
        let _ = fs::remove_file(&target_file);

        let cancel_flag = Arc::new(AtomicBool::new(true)); // 初始即为取消状态

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let options = ChunkedDownloadOptions {
            base: DownloadOptions {
                url: &server_url,
                target_path: &target_file,
                cancel_flag: Some(cancel_flag),
                max_retries: 1,
                retry_delay: Duration::from_millis(10),
                expected_checksum: None,
                expected_size: Some(128),
                max_bytes_per_sec: None,
            },
            mirrors: &[],
            concurrency: 2,
            chunk_size: 32,
        };

        let result = download_file_chunked_blocking(&client, &options, |_| {});
        assert!(matches!(result, Err(UpdateError::Cancelled)));

        server_guard.store(false, Ordering::Relaxed);
        let _ = fs::remove_file(&target_file);
    }

    #[cfg(feature = "async")]
    #[test]
    fn test_download_file_chunked_async_full_flow() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let payload = Arc::new(vec![88u8; 128]);
            let (server_url, server_guard) = run_mock_range_server(payload.clone(), true);

            let temp_dir = std::env::temp_dir();
            let target_file =
                temp_dir.join(format!("shipup_chunked_async_{}.bin", std::process::id()));
            let _ = fs::remove_file(&target_file);

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap();

            let mut events = Vec::new();
            let options = ChunkedDownloadOptions {
                base: DownloadOptions {
                    url: &server_url,
                    target_path: &target_file,
                    cancel_flag: None,
                    max_retries: 2,
                    retry_delay: Duration::from_millis(10),
                    expected_checksum: None,
                    expected_size: Some(128),
                    max_bytes_per_sec: None,
                },
                mirrors: &[],
                concurrency: 2,
                chunk_size: 32,
            };

            let result = download_file_chunked_async(&client, &options, |ev| events.push(ev)).await;
            assert!(result.is_ok(), "async chunked download error: {:?}", result);
            assert!(target_file.exists());
            assert_eq!(fs::read(&target_file).unwrap(), *payload);

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, UpdateEvent::DownloadStarted { .. }))
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, UpdateEvent::DownloadProgress { .. }))
            );

            server_guard.store(false, Ordering::Relaxed);
            let _ = fs::remove_file(&target_file);
        });
    }
}
