// shipup 跨平台自更新系统 - Manifest 协议模型与路由解析

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// 更新安装包模式类型
///
/// # 设计原理
/// - **实现初衷**：覆盖从轻量级单二进制替换到大型桌面软件安装器的全谱系更新形态。
/// - **核心优势**：通过强类型枚举彻底排除非法安装策略组合，指导下载与部署引擎选择正确的安全分支。
/// - **代价与局限**：安装形态由发布端在 Manifest 中静态确定，客户端不可在运行期动态随意覆写。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageType {
    /// 裸可执行文件，用于单文件原地原子替换
    Binary,
    /// 压缩包（.zip 或 .tar.gz），需解压并提取指定的可执行文件或 Bundle
    Archive,
    /// 外部独立安装程序（如 .exe, .msi, .pkg 等），下载后派生子进程执行
    Installer,
}

impl fmt::Display for PackageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary => write!(f, "binary"),
            Self::Archive => write!(f, "archive"),
            Self::Installer => write!(f, "installer"),
        }
    }
}

impl FromStr for PackageType {
    type Err = UpdateError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "binary" => Ok(Self::Binary),
            "archive" => Ok(Self::Archive),
            "installer" => Ok(Self::Installer),
            other => Err(UpdateError::ManifestParse(format!(
                "不支持的更新包类型: {}",
                other
            ))),
        }
    }
}

/// 针对特定平台的发布包配置信息
///
/// # 设计原理
/// - **实现初衷**：承载单个操作系统与 CPU 架构的发布包元数据，包含下载直链、签名、哈希与启动参数。
/// - **核心优势**：通过 `#[serde(default)]` 实现向前与向后兼容，外部新增可选字段不破坏已有反序列化。
/// - **代价与局限**：对不可选字段（如 `url`）保持严格强契约。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    /// 更新包公网下载直链
    pub url: String,

    /// Ed25519 数字签名（Base64 编码，通常为 64 字节签名）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// 完整性校验哈希，格式如 "sha256:<hex_digest>"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,

    /// 安装包模式（binary / archive / installer）
    pub package_type: PackageType,

    /// 启动安装器时的静默参数列表（如 ["/S"]）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_args: Vec<String>,

    /// 当模式为 archive 时，压缩包内目标主程序的相对路径（如 "myapp.exe" 或 "MyApp.app"）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
}

/// 单独发布通道中的更新信息
///
/// # 设计原理
/// - **实现初衷**：支持灰度、内测（Beta）、金丝雀（Canary）等通道在单 Manifest 文件中并行维护。
/// - **核心优势**：通道可独立定义最低支持版本与强制升级策略，与稳定主通道解耦。
/// - **代价与局限**：客户端需在构建时或运行期明确指定匹配通道名称。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelInfo {
    /// 目标发布版本号（严格遵循 SemVer 2.0）
    pub version: Version,

    /// 最低支持版本（低于该版本自动触发强制升级）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_supported_version: Option<Version>,

    /// 是否全局强制更新
    #[serde(default)]
    pub force_update: bool,

    /// 版本发布时间戳（ISO 8601 字符串）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pub_date: Option<String>,

    /// 更新日志详情（支持 Markdown 或纯文本）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// 针对不同平台的发布包字典
    #[serde(default)]
    pub packages: HashMap<String, PackageInfo>,
}

/// Manifest 根数据规范模型
///
/// # 设计原理
/// - **实现初衷**：作为更新源与客户端通信的唯一元数据契约，统一承载版本比对、通道路由与平台发布包分发。
/// - **核心优势**：单文件支持全平台多通道部署，兼容性高且支持离线测试验证。
/// - **代价与局限**：所有平台包汇总于同一文件，当支持平台极端庞大时文件体积稍有膨胀（通常仍 < 10KB）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// 目标默认发布版本号（严格遵循 SemVer 2.0）
    pub version: Version,

    /// 最低支持版本
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_supported_version: Option<Version>,

    /// 全局强制更新标记
    #[serde(default)]
    pub force_update: bool,

    /// 发布时间戳
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pub_date: Option<String>,

    /// 更新日志详情
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    /// 针对不同平台的发布包字典
    #[serde(default)]
    pub packages: HashMap<String, PackageInfo>,

    /// 多通道扩展块字典（如 "beta", "alpha", "nightly"）
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub channels: HashMap<String, ChannelInfo>,
}

/// 解析路由后最终用于执行更新的结构体
///
/// # 设计原理
/// - **实现初衷**：将复杂的通道路由、最低版本判定及 Target 别名归一化计算收敛为平铺的只读结果对象。
/// - **核心优势**：后续下载与部署流程无需反复重新评估通道逻辑，消除状态多重解释。
/// - **代价与局限**：创建时产生了必要的数据克隆。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRelease {
    /// 目标新版本号
    pub version: Version,
    /// 最低支持版本
    pub min_supported_version: Option<Version>,
    /// 是否为强制更新
    pub is_mandatory: bool,
    /// 发布时间戳
    pub pub_date: Option<String>,
    /// 更新说明日志
    pub notes: Option<String>,
    /// 匹配到的目标平台安装包配置
    pub package: PackageInfo,
}

/// Manifest 解析与通道路由选项结构体
///
/// # 设计原理
/// - **实现初衷**：遵循参数对象模式（Parameter Object Pattern），将通道、目标平台与本地版本收敛至统一结构体，避免平铺参数。
/// - **核心优势**：后续若扩展如客户端语言、架构补丁等维度时保持向后兼容，且调用端语义更清晰。
/// - **代价与局限**：生命周期借用绑定了传入的字符串切片与版本引用。
#[derive(Debug, Clone, Copy)]
pub struct ResolveOptions<'a> {
    /// 目标发布通道（如 Some("beta")，为 None 时使用默认顶层通道）
    pub channel: Option<&'a str>,
    /// 目标平台 Triple 标识
    pub target: &'a str,
    /// 客户端本地当前版本
    pub current_version: &'a Version,
}

impl Manifest {
    /// 从 JSON 字符串反序列化解析 Manifest 元数据
    ///
    /// # 设计原理
    /// - **实现初衷**：在数据进入系统时立即解析为强类型，实现“解析，而非验证”原则。
    ///
    /// # Errors
    /// 当 JSON 文本不符合规范格式时，返回 [`UpdateError::ManifestParse`]。
    pub fn from_json_str(content: &str) -> Result<Self> {
        serde_json::from_str(content)
            .map_err(|e| UpdateError::ManifestParse(format!("JSON 结构解析失败: {}", e)))
    }

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

        // 1. 如果指定了特定通道且存在该通道配置，优先匹配通道
        if let Some(ch) = options.channel
            && let Some(channel_info) = self.channels.get(ch)
            && let Some(package) = match_package(&channel_info.packages, options.target)
        {
            let is_mandatory = channel_info.force_update
                || channel_info
                    .min_supported_version
                    .as_ref()
                    .is_some_and(|min_ver| current_version < min_ver);

            return Ok(ResolvedRelease {
                version: channel_info.version.clone(),
                min_supported_version: channel_info.min_supported_version.clone(),
                is_mandatory,
                pub_date: channel_info.pub_date.clone(),
                notes: channel_info.notes.clone(),
                package: package.clone(),
            });
        }

        // 2. 回退到顶层默认配置进行匹配
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
        })
    }
}

/// 在平台包字典中匹配目标 Triple 或别名
fn match_package<'a>(
    packages: &'a HashMap<String, PackageInfo>,
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
fn normalize_target(target: &str) -> String {
    let lower = target.to_ascii_lowercase().replace('_', "-");
    if lower.contains("windows") || lower.contains("win") {
        if lower.contains("x86-64") || lower.contains("x64") || lower.contains("x86_64") {
            return "windows-x86-64".to_string();
        }
        if lower.contains("aarch64") || lower.contains("arm64") {
            return "windows-arm64".to_string();
        }
    } else if lower.contains("darwin") || lower.contains("macos") || lower.contains("apple") {
        if lower.contains("aarch64") || lower.contains("arm64") {
            return "macos-arm64".to_string();
        }
        if lower.contains("x86-64") || lower.contains("x64") || lower.contains("x86_64") {
            return "macos-x86-64".to_string();
        }
    } else if lower.contains("linux") {
        if lower.contains("x86-64") || lower.contains("x64") || lower.contains("x86_64") {
            return "linux-x86-64".to_string();
        }
        if lower.contains("aarch64") || lower.contains("arm64") {
            return "linux-arm64".to_string();
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
