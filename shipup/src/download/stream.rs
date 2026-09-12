//! 流式读写管道共享上下文模块。
//!
//! # 模块职责
//! 定义同步/异步流式下载共用的 [`StreamPipeContext`] 与读缓冲常量，
//! 使「如何读写字节」之外的进度、限速、取消逻辑完全一致。
//!
//! # 设计原理
//! - **实现初衷**：同步与异步流式管道语义必须对称，状态字段集中一处避免漏改。
//! - **核心优势**：泛型文件句柄与回调，可同时服务 `std::fs::File` 与 `tokio::fs::File`。
//! - **代价与局限**：字段均为 `pub(super)`，仅下载子模块可见。

use super::RateLimiter;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

/// 流式读写缓冲区大小（64 KiB）。
///
/// # 设计原理
/// - **实现初衷**：单次读取块过小会导致系统调用次数暴涨，过大则会显著抬高单次内存占用与首字节延迟。
/// - **核心优势**：64 KiB 在主流操作系统页缓存粒度与 TCP 分片尺寸之间取得平衡，
///   既能摊薄系统调用开销，又不会对内存紧张的低端设备造成压力。
#[cfg(any(feature = "blocking", feature = "async"))]
pub(crate) const BUFFER_SIZE: usize = 64 * 1024;

/// 流式传输上下文对象
pub(crate) struct StreamPipeContext<'a, TFile, F> {
    pub(crate) file: TFile,
    pub(crate) initial_downloaded: u64,
    pub(crate) total_bytes: Option<u64>,
    pub(crate) expected_size: Option<u64>,
    pub(crate) rate_limiter: Option<RateLimiter>,
    pub(crate) cancel_flag: Option<&'a Arc<AtomicBool>>,
    pub(crate) event_callback: &'a mut F,
}
