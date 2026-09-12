//! 更新包流式下载引擎模块。
//!
//! # 模块职责
//! 本模块按「同步 / 异步」与「共享逻辑」三层组织，负责把远端更新包可靠地拉取到本地暂存路径：
//! - 本文件：与运行模式无关的共享设施——下载选项、进度与速率统计、磁盘空间预检、
//!   分片区间切分、本地缓存命中、指数退避与可重试错误判定、流式管道上下文；
//! - [`blocking`]：基于 `reqwest::blocking` 的同步实现，供传统桌面与命令行宿主使用；
//! - [`asynchronous`]：基于 `reqwest` + `tokio` 的异步实现，供异步运行时宿主使用。
//!
//! # 设计原理
//! - **实现初衷**：同步与异步两条链路在语义上完全对称（Range 断点续传、指数退避重试、多镜像分流、
//!   主动取消），若各自复制一份共享算法必然产生行为漂移。因此把纯计算与纯状态部分上提到本模块，
//!   两种运行模式只保留「如何读写字节」的差异。
//! - **核心优势**：
//!   - 进度与速率统计（[`DownloadProgressTracker`]）基于时间窗口平滑采样，避免高频回调导致速率剧烈抖动；
//!   - 限速器（[`RateLimiter`]）采用秒级滑动窗口自适应休眠，既平滑又不会频繁陷入系统调度；
//!   - 磁盘空间预检在探测失败时降级放行，杜绝因系统接口受限而误杀正常更新。
//! - **代价与局限**：共享设施全部为「无 I/O 的纯逻辑」，因此调用方必须自行负责文件句柄与网络流的具体读写。
//!
//! # 安全契约
//! - 本地缓存命中必须同时满足「文件存在」与「SHA-256 完全一致」两个条件，杜绝仅凭文件名或体积误判；
//! - 分片下载完成后必须重新校验整体体积与哈希，防范镜像源返回被篡改或截断的分片。

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use crate::error::{Result, UpdateError};
use crate::event::UpdateEvent;
use crate::signature::verify_sha256_file;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

#[cfg(feature = "async")]
pub(crate) mod asynchronous;
#[cfg(feature = "blocking")]
pub(crate) mod blocking;

// 保持原有的公开函数路径不变（`shipup::download::download_file_blocking` 等），
// 使子模块拆分对下游调用方完全透明。
#[cfg(feature = "async")]
pub use asynchronous::{download_file_async, download_file_chunked_async};
#[cfg(feature = "blocking")]
pub use blocking::{download_file_blocking, download_file_chunked_blocking};

/// 流式读写缓冲区大小（64 KiB）。
///
/// # 设计原理
/// - **实现初衷**：单次读取块过小会导致系统调用次数暴涨，过大则会显著抬高单次内存占用与首字节延迟。
/// - **核心优势**：64 KiB 在主流操作系统页缓存粒度与 TCP 分片尺寸之间取得平衡，
///   既能摊薄系统调用开销，又不会对内存紧张的低端设备造成压力。
#[cfg(any(feature = "blocking", feature = "async"))]
pub(super) const BUFFER_SIZE: usize = 64 * 1024;

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
pub(super) enum ChunkWorkerMessage {
    BytesRead(usize),
    ChunkCompleted,
    Failed(UpdateError),
}

/// 尝试命中本地缓存，命中时派发 100% 进度事件并返回 `true`。
///
/// # 设计原理
/// - **实现初衷**：跨进程断点续传或重复发布同一版本时，本地暂存文件往往已经完整，
///   重新下载纯属浪费带宽。
/// - **核心优势**：命中判定要求「文件存在」且「SHA-256 与清单声明完全一致」两个条件同时成立，
///   仅凭文件名或体积绝不放行，从而杜绝把损坏或陈旧文件误判为已完成下载。
/// - **代价与局限**：校验需完整读取一次文件，对超大包体会产生一次与体积成正比的磁盘读开销，
///   但仍远低于重新下载的网络成本。
///
/// # 契约
/// 未提供预期哈希时（`expected_checksum` 为 `None`）本函数必定返回 `false`，
/// 因为缺乏可信基准时无法安全地宣称缓存有效。
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
/// 流式传输上下文对象
pub(super) struct StreamPipeContext<'a, TFile, F> {
    file: TFile,
    initial_downloaded: u64,
    total_bytes: Option<u64>,
    expected_size: Option<u64>,
    rate_limiter: Option<RateLimiter>,
    cancel_flag: Option<&'a Arc<AtomicBool>>,
    event_callback: &'a mut F,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[cfg(any(feature = "blocking", feature = "async"))]
    use std::io::{Read, Write};

    #[cfg(feature = "async")]
    use crate::download::asynchronous::download_file_chunked_async;
    #[cfg(feature = "blocking")]
    use crate::download::blocking::{copy_local_file_blocking, download_file_chunked_blocking};

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

    #[cfg(feature = "blocking")]
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

    #[cfg(any(feature = "blocking", feature = "async"))]
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
