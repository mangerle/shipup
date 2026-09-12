//! 本地缓存命中与 file:// 协议探测模块。
//!
//! # 模块职责
//! 判断下载目标是否已可本地命中，以及 URL 是否为 file:// 本地/共享协议。
//!
//! # 安全契约
//! 缓存命中必须同时满足「文件存在」与「SHA-256 一致」；未提供预期哈希时必定返回 `false`。

use crate::error::Result;
use crate::event::UpdateEvent;
use crate::signature::verify_sha256_file;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
