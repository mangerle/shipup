//! 解压安全预算计量（防解压炸弹）。
//!
//! # 模块职责
//! 提供 [`ExtractionBudget`]: 在归档条目逐块落盘过程中累计已写入体积，
//! 超出上限时立即熔断，避免「解压炸弹」耗尽目标磁盘。
//!
//! # 设计原理
//! - **实现初衷**：归档条目声明的原始大小可被伪造，必须以实际写入字节为准做硬性截断。
//! - **核心优势**：累计使用饱和加法，杜绝计数器回绕；一旦越限即刻返回领域错误，不再继续读取后续数据。
//! - **代价与局限**：仅按体积熔断，不做文件数 / 嵌套深度限额。

use crate::error::{Result, UpdateError};

/// 默认解压后最大允许解压膨胀倍数（防解压炸弹）
pub(super) const MAX_EXPANSION_RATIO: u64 = 10;

/// 默认解压体积硬上限（1GB）
pub(super) const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

/// 解压安全预算计量器（防解压炸弹）
pub(super) struct ExtractionBudget {
    extracted: u64,
    max_allowed: u64,
}

impl ExtractionBudget {
    pub(super) fn new(max_allowed: u64) -> Self {
        Self {
            extracted: 0,
            max_allowed,
        }
    }

    /// 累计本次写入字节数，并在越限时返回错误
    pub(super) fn check_and_add(&mut self, bytes: u64) -> Result<()> {
        self.extracted = self.extracted.saturating_add(bytes);
        if self.extracted > self.max_allowed {
            return Err(UpdateError::ArchiveExtract(
                "解压后体积超出安全阈值，防解压炸弹机制已熔断".to_string(),
            ));
        }
        Ok(())
    }
}
