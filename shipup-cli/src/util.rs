//! 通用工具模块：时间格式化、时长解析、哈希签名与体积展示。
//!
//! # 模块职责
//! 提供发布端各子命令共用的无状态工具函数：
//! - 时间：[`current_utc_rfc3339`]、[`format_timestamp_rfc3339`]、[`resolve_expires_at`]；
//! - 解析：[`parse_duration_str`]（把 `7d`、`24h` 等人类可读时长转为绝对过期时刻）；
//! - 完整性：[`compute_payload_integrity`]（计算包体哈希并生成签名）；
//! - 展示：[`format_human_size`]（把字节数格式化为 `MiB` / `GiB` 等易读单位）。
//!
//! # 设计原理
//! - **实现初衷**：这些能力被发布、校验、运维三条链路反复使用，
//!   若各自实现一份，极易出现「发布端按 UTC 写入、校验端按本地时区解析」这类跨模块不一致。
//! - **核心优势**：
//!   - 时间输出统一采用 RFC 3339 且强制 UTC，杜绝时区歧义导致的清单误判为过期；
//!   - 时长解析对非法输入返回带上下文的错误而非静默取默认值，
//!     避免用户误填 `--expires 7x` 后清单被意外设为永不过期。
//! - **代价与局限**：`parse_duration_str` 只支持 `s` / `m` / `h` / `d` 四种单位，
//!   不支持组合表达式（如 `1d12h`）。
//!
//! # 契约
//! 本模块所有函数均为纯函数或只读计算，不得产生任何文件系统副作用。

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 获取当前系统 UTC 时间的 RFC 3339 格式字符串（例如 "2026-09-09T12:00:00Z"）
///
/// # 设计原理
/// - **实现初衷**：避免为简单的日期格式化引入庞大的第三方依赖，基于标准库 `SystemTime` 原生计算。
/// - **算法保障**：遵循格里高利历标准闰年规则，精确将自 1970 年 UNIX 纪元以来的秒数转为标准时间戳。
pub(crate) fn current_utc_rfc3339() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp_rfc3339(duration.as_secs())
}

/// 将自 UNIX 纪元以来的秒数格式化为 RFC 3339 字符串
pub(crate) fn format_timestamp_rfc3339(total_secs: u64) -> String {
    let sec = (total_secs % 60) as u32;
    let total_mins = total_secs / 60;
    let min = (total_mins % 60) as u32;
    let total_hours = total_mins / 60;
    let hour = (total_hours % 24) as u32;
    let mut days = (total_hours / 24) as i64;

    let mut year = 1970i32;
    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
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

    let mut month = 1u32;
    for &dim in &days_in_months {
        if days >= dim as i64 {
            days -= dim as i64;
            month += 1;
        } else {
            break;
        }
    }
    let day = (days + 1) as u32;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// 解析相对时长字符串（例如 "30d", "24h", "60m", "3600s"）为 Duration
///
/// # 设计原理
/// - **实现初衷**：为 CLI 发布者提供人性化的 `--expires-in 30d` 语法糖，无须手动换算绝对时间戳。
/// - **核心优势**：支持常用时间单位（天/小时/分钟/秒），饱和乘法杜绝整数溢出。
/// - **代价与局限**：仅支持单级单位（如 "30d"），不支持复杂复合表达式（如 "1d2h"）。
pub(crate) fn parse_duration_str(s: &str) -> Result<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("时长字符串不能为空");
    }
    let (num_part, unit) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit())
            .ok_or_else(|| anyhow!("缺少时间单位后缀（支持 d/h/m/s），输入: {}", s))?,
    );
    let num: u64 = num_part
        .parse()
        .with_context(|| format!("解析时长数值失败: {}", num_part))?;
    let secs = match unit.trim().to_ascii_lowercase().as_str() {
        "d" | "day" | "days" => num.saturating_mul(86400),
        "h" | "hour" | "hours" => num.saturating_mul(3600),
        "m" | "min" | "mins" | "minute" | "minutes" => num.saturating_mul(60),
        "s" | "sec" | "secs" | "second" | "seconds" => num,
        other => anyhow::bail!("不支持的时间单位 '{}'，可选: d, h, m, s", other),
    };
    Ok(std::time::Duration::from_secs(secs))
}

/// 计算并裁决最终的 expires_at RFC 3339 字符串
///
/// # 设计原理
/// - **实现初衷**：统一绝对时间戳 `--expires-at` 与相对时长 `--expires-in` 的计算规则。
/// - **优先级策略**：若同时提供，优先采用显式绝对时间戳 `--expires-at`。
pub(crate) fn resolve_expires_at(
    expires_at: Option<&str>,
    expires_in: Option<&str>,
) -> Result<Option<String>> {
    if let Some(exp) = expires_at {
        Ok(Some(exp.to_string()))
    } else if let Some(in_str) = expires_in {
        let dur = parse_duration_str(in_str)?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let target_secs = now_secs.saturating_add(dur.as_secs());
        Ok(Some(format_timestamp_rfc3339(target_secs)))
    } else {
        Ok(None)
    }
}

/// 流式读取发布包计算 SHA-256 哈希值，并在提供私钥时生成 Ed25519 数字签名
///
/// # 设计原理
/// - **实现初衷**：为防止发布大型安装包时将全量文件直接读入内存导致 OOM，采用 64KB 固定缓冲区流式计算 SHA-256。
/// - **内存保护**：对包体 32 字节 SHA-256 摘要进行 Ed25519 签名，消除文件读取内存占用与体积上限。
pub(crate) fn compute_payload_integrity(
    package_path: &Path,
    key_path: Option<&Path>,
) -> Result<(String, Option<String>)> {
    let file = fs::File::open(package_path)
        .with_context(|| format!("打开发布包文件失败: {}", package_path.display()))?;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .with_context(|| format!("流式读取发布包数据失败: {}", package_path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    let mut hex = String::with_capacity(hash.len() * 2);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    let checksum = format!("sha256:{hex}");

    let signature = if let Some(kp) = key_path {
        let key_str = fs::read_to_string(kp)
            .with_context(|| format!("读取私钥文件失败: {}", kp.display()))?;
        let key_bytes = BASE64
            .decode(key_str.trim())
            .with_context(|| format!("解码 Base64 私钥失败: {}", kp.display()))?;
        let key_array: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
            anyhow!(
                "私钥字节长度不正确: 期望 32 字节，实际为 {} 字节",
                key_bytes.len()
            )
        })?;
        let signing_key = SigningKey::from_bytes(&key_array);
        let sig = signing_key.sign(&hash);
        Some(BASE64.encode(sig.to_bytes()))
    } else {
        None
    };

    Ok((checksum, signature))
}

/// 将字节数值转换为人类易读格式（如 12.34 MB）
pub(crate) fn format_human_size(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB ({} 字节)", b / GB, bytes)
    } else if b >= MB {
        format!("{:.2} MB ({} 字节)", b / MB, bytes)
    } else if b >= KB {
        format!("{:.2} KB ({} 字节)", b / KB, bytes)
    } else {
        format!("{} 字节", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_rfc3339_unix_epoch() {
        assert_eq!(format_timestamp_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp_rfc3339(1767225600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_current_utc_rfc3339_format() {
        let ts = current_utc_rfc3339();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
    }

    #[test]
    fn test_compute_payload_integrity_streaming() -> Result<()> {
        let temp_file = std::env::temp_dir().join(format!(
            "test_shipup_cli_integrity_{}.bin",
            std::process::id()
        ));
        let content = b"Shipup streaming sha256 test content repeated block";
        fs::write(&temp_file, content)?;

        let (checksum, signature) = compute_payload_integrity(&temp_file, None)?;
        let _ = fs::remove_file(&temp_file);

        assert!(signature.is_none());
        assert!(checksum.starts_with("sha256:"));

        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hasher.finalize();
        let mut expected_hex = String::new();
        for b in hash {
            use std::fmt::Write;
            let _ = write!(expected_hex, "{b:02x}");
        }
        assert_eq!(checksum, format!("sha256:{expected_hex}"));
        Ok(())
    }

    #[test]
    fn test_parse_duration_and_resolve_expires_at() -> Result<()> {
        assert_eq!(
            parse_duration_str("30d")?,
            std::time::Duration::from_secs(30 * 86400)
        );
        assert_eq!(
            parse_duration_str("24h")?,
            std::time::Duration::from_secs(24 * 3600)
        );
        assert_eq!(
            parse_duration_str("60m")?,
            std::time::Duration::from_secs(60 * 60)
        );
        assert_eq!(
            parse_duration_str("3600s")?,
            std::time::Duration::from_secs(3600)
        );

        let res_explicit = resolve_expires_at(Some("2026-10-01T00:00:00Z"), Some("30d"))?;
        assert_eq!(res_explicit.as_deref(), Some("2026-10-01T00:00:00Z"));

        let res_relative = resolve_expires_at(None, Some("1d"))?;
        assert!(res_relative.is_some());
        let rel_ts = res_relative.unwrap();
        assert_eq!(rel_ts.len(), 20);
        assert!(rel_ts.ends_with('Z'));
        Ok(())
    }

    #[test]
    fn test_format_human_size_units() {
        assert_eq!(format_human_size(512), "512 字节");
        assert!(format_human_size(2048).contains("KB"));
        assert!(format_human_size(3 * 1024 * 1024).contains("MB"));
        assert!(format_human_size(2u64 * 1024 * 1024 * 1024).contains("GB"));
    }
}
