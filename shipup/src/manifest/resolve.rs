//! Manifest 通道裁决与平台 Target 匹配子模块。
//!
//! # 模块职责
//! 承载 [`Manifest::resolve`] 的完整路由逻辑：
//! - 优先命中指定独立发布通道（如 beta），未配置通道时回退顶层主通道；
//! - 目标平台 Triple 精确匹配与常见别名归一化模糊匹配；
//! - 强制升级判定与灰度放量比例合并；
//! - 编译期目标平台 Triple 探测 [`current_target_triple`]。
//!
//! # 兄弟模块导航
//! - [`super::model`]：被依赖的清单数据模型与路由选项；
//! - [`super::verify`]：时效性与签名校验，调用顺序须先 `verify_freshness` 再验签；
//! - [`super::time`]：时间戳解析工具。
//!
//! # 设计原理
//! - **实现初衷**：对「配置了通道但清单未声明该通道」直接报错，杜绝非预期的静默回退到默认通道，
//!   避免安装非预期版本。
//! - **核心优势**：单份 Manifest 即可维护多通道发行矩阵；别名归一化兼容常见发布平台简写，
//!   同时严格保留 Linux 下 glibc 与 musl 运行时差异，防止非兼容 libc 二进制错配。
//! - **代价与局限**：Target 别名匹配采用启发式规则，极端自定义命名需调用端使用完全一致的 Triple。

use crate::error::{Result, UpdateError};
use std::collections::BTreeMap;

use super::model::{Manifest, PackageInfo, ResolveOptions, ResolvedRelease};

impl Manifest {
    /// 根据路由选项进行通道选择与平台 Target 匹配
    ///
    /// # 设计原理
    /// - **实现初衷**：优先命中指定独立发布通道（如 beta），若未配置或未提供相应包则平滑回退至默认主通道。
    /// - **核心优势**：单份 Manifest 即可维护多通道发行矩阵，降低维护成本。
    ///
    /// # Errors
    /// 当 Manifest 中未找到与目标平台匹配的发布包配置时，返回 [`UpdateError::PlatformNotFound`]。
    pub fn resolve(&self, options: &ResolveOptions<'_>) -> Result<ResolvedRelease> {
        let current_version = options.current_version;

        // 1. 如果指定了特定通道，严格在指定通道内进行匹配，杜绝静默回退导致安装非预期版本
        if let Some(ch) = options.channel {
            let channel_info = self.channels.get(ch).ok_or_else(|| {
                UpdateError::ManifestParse(format!("Manifest 中未找到指定的发布通道: {}", ch))
            })?;

            let package =
                match_package(&channel_info.packages, options.target).ok_or_else(|| {
                    UpdateError::PlatformNotFound(format!(
                        "当前目标平台 ({}) 在指定通道 ({}) 中未找到适配的安装包",
                        options.target, ch
                    ))
                })?;

            let is_mandatory = channel_info.force_update
                || channel_info
                    .min_supported_version
                    .as_ref()
                    .is_some_and(|min_ver| current_version < min_ver);

            let rollout_percentage = channel_info.rollout_percentage.or(self.rollout_percentage);

            return Ok(ResolvedRelease {
                version: channel_info.version.clone(),
                min_supported_version: channel_info.min_supported_version.clone(),
                is_mandatory,
                pub_date: channel_info.pub_date.clone(),
                notes: channel_info.notes.clone(),
                package: package.clone(),
                rollout_percentage,
            });
        }

        // 2. 未指定通道时，使用顶层默认主通道配置进行匹配
        let package = match_package(&self.packages, options.target)
            .ok_or_else(|| UpdateError::PlatformNotFound(options.target.to_string()))?;

        let is_mandatory = self.force_update
            || self
                .min_supported_version
                .as_ref()
                .is_some_and(|min_ver| current_version < min_ver);

        Ok(ResolvedRelease {
            version: self.version.clone(),
            min_supported_version: self.min_supported_version.clone(),
            is_mandatory,
            pub_date: self.pub_date.clone(),
            notes: self.notes.clone(),
            package: package.clone(),
            rollout_percentage: self.rollout_percentage,
        })
    }
}

/// 在平台包字典中匹配目标 Triple 或别名
pub(crate) fn match_package<'a>(
    packages: &'a BTreeMap<String, PackageInfo>,
    target: &str,
) -> Option<&'a PackageInfo> {
    // 首先完全精确匹配
    if let Some(pkg) = packages.get(target) {
        return Some(pkg);
    }

    // 尝试常见别名模糊匹配（如 windows-x86_64 匹配 x86_64-pc-windows-msvc）
    for (k, v) in packages {
        if normalize_target(k) == normalize_target(target) {
            return Some(v);
        }
    }

    None
}

/// 标准化 Target 别名归一化处理
///
/// # 设计原理
/// - **实现初衷**：兼容常见的发布平台命名简写（如 windows-x64、macos-arm64），
///   同时严格保留 Linux 下的 glibc（gnu）与 musl 运行时差异，防止非兼容 libc 二进制错配。
pub(crate) fn normalize_target(target: &str) -> String {
    let lower = target.to_ascii_lowercase().replace('_', "-");
    if lower.contains("windows") || lower.contains("win") {
        let env_suffix = if lower.contains("gnu") || lower.contains("mingw") {
            "-gnu"
        } else if lower.contains("msvc") {
            "-msvc"
        } else {
            ""
        };

        if lower.contains("x86-64") || lower.contains("x64") {
            return format!("windows-x86-64{}", env_suffix);
        }
        if lower.contains("aarch64") || lower.contains("arm64") {
            return format!("windows-arm64{}", env_suffix);
        }
    } else if lower.contains("darwin") || lower.contains("macos") || lower.contains("apple") {
        if lower.contains("aarch64") || lower.contains("arm64") {
            return "macos-arm64".to_string();
        }
        if lower.contains("x86-64") || lower.contains("x64") {
            return "macos-x86-64".to_string();
        }
    } else if lower.contains("linux") {
        let libc_suffix = if lower.contains("musl") {
            "-musl"
        } else if lower.contains("gnu") || lower.contains("glibc") {
            "-gnu"
        } else {
            ""
        };

        if lower.contains("x86-64") || lower.contains("x64") {
            return format!("linux-x86-64{}", libc_suffix);
        }
        if lower.contains("aarch64") || lower.contains("arm64") {
            return format!("linux-arm64{}", libc_suffix);
        }
    }
    lower
}

/// 获取当前编译运行环境的标准 Target Triple 字符串
///
/// # 设计原理
/// - **实现初衷**：在编译期通过条件编译宏直接映射到 Rust 官方 Target Triple，为客户端提供开箱即用的免配置平台定位。
/// - **核心优势**：直接返回 `'static str` 静态字符串切片，零运行期堆分配与字符串拼接开销。
/// - **代价与局限**：覆盖了主流 Windows、macOS 与 Linux 架构；对于稀有交叉编译目标会返回 `"unknown-target"`，需要调用端通过 Builder 手动指定。
pub fn current_target_triple() -> &'static str {
    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "msvc"))]
    return "x86_64-pc-windows-msvc";

    #[cfg(all(target_arch = "x86_64", target_os = "windows", target_env = "gnu"))]
    return "x86_64-pc-windows-gnu";

    #[cfg(all(target_arch = "aarch64", target_os = "windows"))]
    return "aarch64-pc-windows-msvc";

    #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
    return "x86_64-apple-darwin";

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    return "aarch64-apple-darwin";

    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
    return "x86_64-unknown-linux-gnu";

    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    return "x86_64-unknown-linux-musl";

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
    return "aarch64-unknown-linux-gnu";

    #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "musl"))]
    return "aarch64-unknown-linux-musl";

    #[cfg(not(any(
        all(target_arch = "x86_64", target_os = "windows"),
        all(target_arch = "aarch64", target_os = "windows"),
        all(target_arch = "x86_64", target_os = "macos"),
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux"),
        all(target_arch = "aarch64", target_os = "linux")
    )))]
    return "unknown-target";
}
