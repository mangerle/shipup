//! RFC 3339 时间戳解析工具子模块。
//!
//! # 模块职责
//! 提供将 RFC 3339 UTC 格式时间戳字符串解析为 Unix 秒数的纯函数
//! [`parse_rfc3339_to_unix`]，供 Manifest 的 `expires_at` 时效性校验与反序列化入口使用。
//!
//! # 兄弟模块导航
//! - [`super::model`]：清单数据模型，在 `from_json_str` 中调用本模块校验时间格式；
//! - [`super::verify`]：在 `verify_freshness` 中调用本模块完成过期判定。
//!
//! # 设计原理
//! - **实现初衷**：避免为单一时间解析引入庞大外部依赖（如 `chrono` 全量特性），
//!   以纯 Rust 实现覆盖本项目所需的严格 RFC 3339 子集。
//! - **核心优势**：遵循格里高利历闰年规则，严格校验日期时间边界，拒绝非法时间格式，零堆分配热路径。
//! - **代价与局限**：仅支持 UTC（`Z` 后缀）格式，不处理任意时区偏移；小数秒部分被截断忽略。

/// 将 RFC 3339 UTC 格式的时间戳字符串（如 "2026-09-10T12:00:00Z"）解析为 Unix 时间戳秒数
///
/// # 设计原理
/// - **实现初衷**：为 Manifest 的 `expires_at` 提供无需庞大外部依赖的高性能纯 Rust 解析器。
/// - **核心优势**：遵循格里高利历闰年规则，严格校验日期时间边界，拒绝非法时间格式。
pub fn parse_rfc3339_to_unix(s: &str) -> Option<u64> {
    let clean = s.trim();
    if clean.len() < 20 {
        return None;
    }
    let parts: Vec<&str> = clean.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let year: i32 = date_parts[0].parse().ok()?;
    let month: u32 = date_parts[1].parse().ok()?;
    let day: u32 = date_parts[2].parse().ok()?;

    let time_str = parts[1].trim_end_matches('Z');
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() < 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec_str = time_parts[2].split('.').next()?;
    let sec: u32 = sec_str.parse().ok()?;

    if year < 1970
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 60
    {
        return None;
    }

    let mut total_days: i64 = 0;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        total_days += if is_leap { 366 } else { 365 };
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    for m in 1..month {
        total_days += days_in_months[(m - 1) as usize] as i64;
    }
    total_days += (day - 1) as i64;

    let total_secs = total_days * 86400 + (hour as i64 * 3600) + (min as i64 * 60) + (sec as i64);
    if total_secs < 0 {
        None
    } else {
        Some(total_secs as u64)
    }
}
