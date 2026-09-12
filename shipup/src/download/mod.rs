//! 更新包流式下载引擎模块。
//!
//! # 模块职责
//! 本模块按「同步 / 异步」与「共享逻辑」分层组织，负责把远端更新包可靠地拉取到本地暂存路径：
//! - 本文件：下载选项门面与对外/对内符号重导出；
//! - [`progress`]：进度与速率平滑采样；
//! - [`rate_limit`]：带宽限速；
//! - [`disk`]：磁盘空间预检；
//! - [`chunk`]：分片区间切分与镜像收集；
//! - [`cache`]：本地缓存命中与 file:// 探测；
//! - [`retry`]：指数退避与可重试错误判定；
//! - [`stream`]：流式管道上下文；
//! - [`blocking`]：基于 `reqwest::blocking` 的同步实现；
//! - [`asynchronous`]：基于 `reqwest` + `tokio` 的异步实现。
//!
//! # 设计原理
//! - **实现初衷**：同步与异步两条链路在语义上完全对称（Range 断点续传、指数退避重试、多镜像分流、
//!   主动取消），若各自复制一份共享算法必然产生行为漂移。因此把纯计算与纯状态部分上提到共享子模块，
//!   两种运行模式只保留「如何读写字节」的差异。
//! - **核心优势**：
//!   - 进度与速率统计基于时间窗口平滑采样，避免高频回调导致速率剧烈抖动；
//!   - 限速器采用秒级滑动窗口自适应休眠，既平滑又不会频繁陷入系统调度；
//!   - 磁盘空间预检在探测失败时降级放行，杜绝因系统接口受限而误杀正常更新。
//! - **代价与局限**：共享设施为「无网络 I/O 的纯逻辑」，调用方必须自行负责文件句柄与网络流读写。
//!
//! # 同步/异步修改契约
//! 修改 [`blocking`] 中任一下载入口时，必须同步检查 [`asynchronous`] 中语义对称的函数，
//! 避免「同步已修复、异步仍旧」的行为漂移。成对函数见两模块文档中的「兄弟模块导航」。
//!
//! # 安全契约
//! - 本地缓存命中必须同时满足「文件存在」与「SHA-256 完全一致」两个条件；
//! - 分片下载完成后必须重新校验整体体积与哈希。

#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(unused))]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

mod cache;
mod chunk;
mod disk;
mod progress;
mod rate_limit;
mod retry;
mod stream;

#[cfg(feature = "async")]
pub(crate) mod asynchronous;
#[cfg(feature = "blocking")]
pub(crate) mod blocking;

pub(crate) use cache::{is_file_url, parse_file_url_to_path, try_hit_local_cache};
pub(crate) use chunk::{ChunkWorkerMessage, collect_candidate_urls};
pub use chunk::{
    DEFAULT_CHUNK_SIZE, DEFAULT_CHUNKED_CONCURRENCY, FileChunkRange, split_file_into_chunks,
};
pub(crate) use disk::check_disk_space_available;
pub(crate) use progress::DownloadProgressTracker;
pub(crate) use rate_limit::RateLimiter;
pub(crate) use retry::{calculate_backoff, is_retryable_error};
#[cfg(any(feature = "blocking", feature = "async"))]
pub(crate) use stream::BUFFER_SIZE;
pub(crate) use stream::StreamPipeContext;

// 保持原有的公开函数路径不变（`shipup::download::download_file_blocking` 等），
// 使子模块拆分对下游调用方完全透明。
#[cfg(feature = "async")]
pub use asynchronous::{download_file_async, download_file_chunked_async};
#[cfg(feature = "blocking")]
pub use blocking::{download_file_blocking, download_file_chunked_blocking};

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

#[cfg(test)]
mod tests;
