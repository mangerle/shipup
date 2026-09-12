//! Manifest 协议数据模型子模块。
//!
//! # 模块职责
//! 定义发布清单（Manifest）的全部强类型数据结构与基础行为：
//! - 安装包形态枚举 [`PackageType`]、[`InstallMode`]；
//! - 签名条目 [`SignatureEntry`] 与平台包配置 [`PackageInfo`]；
//! - 通道元数据 [`ChannelInfo`]、根模型 [`Manifest`]；
//! - 解析产物 [`ResolvedRelease`] 与路由选项 [`ResolveOptions`]；
//! - 构造入口 [`Manifest::from_json_str`] 与访问器/序列化特型实现。
//!
//! # 兄弟模块导航
//! - [`super::time`]：RFC 3339 时间戳解析工具（本模块反序列化时依赖）；
//! - [`super::resolve`]：通道裁决与平台 Target 匹配逻辑；
//! - [`super::verify`]：时效性校验与 TUF 门限签名验证。
//!
//! # 设计原理
//! - **实现初衷**：Manifest 是外部不可信输入，必须在系统边界一次性解析为强类型，
//!   内部各层此后只处理已确认合法的数据，避免松散字符串校验散布调用链。
//! - **核心优势**：对外部字段一律 `#[serde(default)]` 兜底，上游协议增删字段不会导致客户端反序列化崩溃。
//! - **代价与局限**：清单本身不携带平台原生版本号语义，跨平台差异由发布端在 `packages` 分支内显式声明。

use crate::error::{Result, UpdateError};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use super::time::parse_rfc3339_to_unix;

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

/// 外部安装程序的交互与显示模式
///
/// # 设计原理
/// - **实现初衷**：统一抽象不同平台外部安装器（如 MSI、NSIS）的界面交互与静默级别，避免参数混乱。
/// - **核心优势**：支持在 Manifest 元数据中声明，并由平台层自动映射为对应的标准 CLI 参数序列。
/// - **代价与局限**：具体呈现效果依赖底层安装包本身的打包规范。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum InstallMode {
    /// 被动安装模式（显示基础进度条界面，无需用户手动交互确认）
    Passive,
    /// 完全静默模式（无任何弹窗与界面，后台静默完成安装）
    Quiet,
    /// 基础 UI 模式（显示简易安装向导界面）
    BasicUi,
}

/// TUF 风格的单个数字签名条目
///
/// # 设计原理
/// - **实现初衷**：遵循 TUF (The Update Framework) 门限多签规范，支持多实体联合签署更新清单或安装包。
/// - **核心优势**：包含可选的 `key_id`（密钥标识符/指纹）与 Base64 编码的数字签名，支持精准公钥索引与快速验证。
/// - **代价与局限**：调用端需维护信任公钥列表并声明门限阈值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEntry {
    /// 签名者公钥标识符（如 Key ID 或公钥指纹，可选）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// Base64 编码的 64 字节 Ed25519 数字签名
    pub signature: String,
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

    /// 备用镜像源下载直链列表（用于并发分片下载流量分流与故障转移）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mirrors: Vec<String>,

    /// Ed25519 数字签名（Base64 编码，通常为 64 字节签名）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// TUF 风格的安装包体门限多签名条目列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SignatureEntry>,

    /// 完整性校验哈希，格式如 "sha256:<hex_digest>"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,

    /// 安装包模式（binary / archive / installer）
    pub package_type: PackageType,

    /// 安装器交互模式（如 passive / quiet / basicUi）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_mode: Option<InstallMode>,

    /// 启动安装器时的静默或附加参数列表（如 ["/S"]）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub install_args: Vec<String>,

    /// 当模式为 archive 时，压缩包内目标主程序的相对路径（如 "myapp.exe" 或 "MyApp.app"）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,

    /// 是否需要操作系统管理员提权（UAC / Sudo）执行（针对 Windows 安装器等场景）
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_elevation: bool,

    /// 是否等待外部安装器退出并校验退出码（默认 false，派生后立即返回）
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub wait_for_exit: bool,

    /// 归档解压后的关键文件完整性校验表（相对路径 -> sha256:<hex>）
    ///
    /// # 设计原理
    /// - **实现初衷**：归档整体签名只能证明压缩包字节未被篡改，无法防御解压器实现缺陷导致的落盘内容偏差。
    /// - **核心优势**：解压后对声明的关键文件逐个复核 SHA-256，形成“包体签名 + 关键文件哈希”双重防线。
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub payload_checksums: BTreeMap<String, String>,

    /// 更新包物理文件大小（字节，用于硬校验与目标磁盘空间预检）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

impl PackageInfo {
    /// 收集针对该安装包体的所有可用候选数字签名列表（合并单签与多签）
    pub fn all_signatures(&self) -> Vec<SignatureEntry> {
        let mut list =
            Vec::with_capacity(self.signatures.len() + usize::from(self.signature.is_some()));
        if let Some(ref sig) = self.signature {
            list.push(SignatureEntry {
                key_id: None,
                signature: sig.clone(),
            });
        }
        list.extend(self.signatures.iter().cloned());
        list
    }
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
    pub packages: BTreeMap<String, PackageInfo>,

    /// 灰度放量比例（0..=100，若未配置则默认全量放行）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_percentage: Option<u8>,
}

/// Manifest 根数据规范模型
///
/// # 设计原理
/// - **实现初衷**：作为更新源与客户端通信的唯一元数据契约，统一承载版本比对、通道路由与平台发布包分发。
/// - **核心优势**：单文件支持全平台多通道部署，兼容性高且支持离线测试验证；采用 BTreeMap 确保序列化字节跨进程确定性。
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

    /// 针对不同平台的发布包字典（使用 BTreeMap 保证序列化顺序确定性）
    #[serde(default)]
    pub packages: BTreeMap<String, PackageInfo>,

    /// 多通道扩展块字典（如 "beta", "alpha", "nightly"，使用 BTreeMap 保证序列化顺序确定性）
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub channels: BTreeMap<String, ChannelInfo>,

    /// Manifest 元数据自身的数字签名（Base64 编码，可选）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// TUF 风格的清单门限多签名条目列表
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signatures: Vec<SignatureEntry>,

    /// 默认主通道灰度放量比例（0..=100，若未配置则默认全量放行）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_percentage: Option<u8>,

    /// 清单过期失效时间戳（RFC 3339 格式，如 "2026-09-10T12:00:00Z"），用于防御重放攻击
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// 单调递增的清单版本序号，用于防范版本降级与重放攻击
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_seq: Option<u64>,
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
    /// 灰度放量比例（0..=100）
    pub rollout_percentage: Option<u8>,
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
        let manifest: Self = serde_json::from_str(content)
            .map_err(|e| UpdateError::ManifestParse(format!("JSON 结构解析失败: {}", e)))?;
        if let Some(ref exp) = manifest.expires_at
            && parse_rfc3339_to_unix(exp).is_none()
        {
            return Err(UpdateError::ManifestParse(format!(
                "Manifest expires_at 时间戳格式非法: {}",
                exp
            )));
        }
        Ok(manifest)
    }
}
