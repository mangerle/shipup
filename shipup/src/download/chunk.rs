//! HTTP 分片区间切分与候选镜像收集模块。
//!
//! # 模块职责
//! 提供与运行模式无关的分片纯算法：Range 区间模型、总长度等分、镜像 URL 去重收集。
//!
//! # 设计原理
//! - **实现初衷**：同步与异步分片下载必须使用完全相同的切分结果，否则拼装会出现字节错位。
//! - **核心优势**：纯函数、可单测；使用饱和算术防溢出。
//! - **代价与局限**：若总大小或切片大小为 0 则返回空集合，由调用方决定是否降级单流。

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
pub(crate) enum ChunkWorkerMessage {
    BytesRead(usize),
    ChunkCompleted,
    Failed(crate::error::UpdateError),
}
