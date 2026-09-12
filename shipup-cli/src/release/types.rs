//! 发布相关共享类型定义：清单条目、合并上下文与包信息构造参数。
//!
//! # 模块职责
//! 集中声明发布链路各子模块共用的数据载体：
//! - [`ManifestReleaseEntry`]：待写入清单的单个平台发布条目；
//! - [`ManifestUpdateContext`]：清单合并所需的批次级元数据（通道、灰度、过期等），
//!   用于替代原先「回造完整 `ReleaseArgs`」的冗余传参方式；
//! - [`PackageInfoParams`]：构造 [`PackageInfo`] 所需的字段集合，
//!   收敛单包与批量两条路径中几乎相同的包信息组装逻辑。
//!
//! # 设计原理
//! - **实现初衷**：单包发布与批量发布在「构造 `PackageInfo`」与「更新清单元数据」
//!   两个环节存在大量字段级重复。把这些字段收敛为专用参数结构体后，
//!   两条路径只需填充各自来源的字段，共用同一套组装与合并逻辑。
//! - **核心优势**：新增字段时只需修改本模块的结构体定义与唯一的构造函数，
//!   不必在单包、批量两处分别同步，杜绝漏改导致的字段缺失。
//! - **代价与局限**：引入了额外的中间类型，阅读时需从参数结构体跳转到最终类型；
//!   但换来的是字段来源清晰、clone 面积大幅缩小。
//!
//! # 兄弟导航
//! - [`super::manifest_io`]：基于本模块类型完成清单读写与合并；
//! - [`super::single`] / [`super::batch`]：分别从命令行参数与 TOML 配置填充本模块类型。

use crate::cli::ReleaseArgs;
use crate::util::resolve_expires_at;
use semver::Version;
use shipup::{InstallMode, PackageInfo, PackageType};

/// 待写入清单的发布包实体信息。
///
/// 将「版本元数据」与「单个平台的包信息」捆绑为一个原子单元，
/// 确保两者在合并过程中始终配套出现，避免版本与包体错位。
pub(crate) struct ManifestReleaseEntry {
    /// 目标版本号（SemVer）
    pub(crate) version: Version,
    /// 最低支持版本号（低于该版本将触发强制更新）
    pub(crate) min_supported_version: Option<Version>,
    /// 发布日期（RFC 3339）
    pub(crate) pub_date: String,
    /// 单个平台的完整包信息
    pub(crate) package_info: PackageInfo,
}

/// 清单合并所需的批次级元数据上下文（参数对象模式）。
///
/// # 设计原理
/// - **实现初衷**：原先 [`update_manifest_entries`](super::manifest_io::update_manifest_entries)
///   直接接收完整的 [`ReleaseArgs`]，导致批量路径必须回造一份十余字段的假参数对象，
///   既浪费 clone 开销，又让「哪些字段真正参与合并」变得不可读。
/// - **核心优势**：只保留合并逻辑实际读取的 7 个字段，单包路径从 `ReleaseArgs` 转换、
///   批量路径从 `BatchReleaseConfig` 转换，两条路径共享同一套合并语义。
/// - **代价与局限**：新增合并相关字段时需同步扩展本结构体与两处 `From` 实现。
pub(crate) struct ManifestUpdateContext {
    /// 发布通道标识（不指定则写入默认主通道）
    pub(crate) channel: Option<String>,
    /// 是否标记为强制更新
    pub(crate) force_update: bool,
    /// 版本更新日志说明内容
    pub(crate) notes: Option<String>,
    /// 灰度放量比例（0..=100）
    pub(crate) rollout_percentage: Option<u8>,
    /// 清单过期失效时间戳（RFC 3339）
    pub(crate) expires_at: Option<String>,
    /// 相对当前时间的清单有效时长（例如 30d、24h）
    pub(crate) expires_in: Option<String>,
    /// 单调递增的清单版本序号（防重放）
    pub(crate) version_seq: Option<u64>,
}

impl From<&ReleaseArgs> for ManifestUpdateContext {
    /// 从单包发布的命令行参数中提取合并所需的批次级元数据。
    fn from(args: &ReleaseArgs) -> Self {
        Self {
            channel: args.channel.clone(),
            force_update: args.force_update,
            notes: args.notes.clone(),
            rollout_percentage: args.rollout_percentage,
            expires_at: args.expires_at.clone(),
            expires_in: args.expires_in.clone(),
            version_seq: args.version_seq,
        }
    }
}

impl ManifestUpdateContext {
    /// 解析本上下文中声明的清单过期时间。
    ///
    /// 同时支持绝对时间戳（`expires_at`）与相对时长（`expires_in`）两种声明方式，
    /// 语义与命令行参数保持一致。
    ///
    /// # Errors
    /// 时间戳格式非法或时长字符串无法解析时返回中文错误。
    pub(crate) fn resolve_expires(&self) -> anyhow::Result<Option<String>> {
        resolve_expires_at(self.expires_at.as_deref(), self.expires_in.as_deref())
    }
}

/// 构造 [`PackageInfo`] 所需的字段集合（参数对象模式）。
///
/// # 设计原理
/// 单包发布与批量发布在组装 `PackageInfo` 时仅数据来源不同，字段结构完全一致。
/// 收敛为参数结构体后，[`build_package_info`](super::manifest_io::build_package_info)
/// 成为唯一的构造入口，镜像列表、签名列表、载荷哈希等固定默认值只声明一次。
pub(crate) struct PackageInfoParams {
    /// 下载直链地址
    pub(crate) url: String,
    /// Ed25519 数字签名（未提供密钥时为 `None`）
    pub(crate) signature: Option<String>,
    /// SHA-256 校验和（带 `sha256:` 前缀）
    pub(crate) checksum: String,
    /// 更新包类型
    pub(crate) package_type: PackageType,
    /// 安装器交互模式
    pub(crate) install_mode: Option<InstallMode>,
    /// 启动外部安装器的静默参数
    pub(crate) install_args: Vec<String>,
    /// 压缩包内的主程序相对路径
    pub(crate) executable_path: Option<String>,
    /// 是否需要操作系统管理员提权执行安装
    pub(crate) require_elevation: bool,
    /// 是否等待外部安装器退出并校验退出码
    pub(crate) wait_for_exit: bool,
    /// 发布包物理文件体积（字节）
    pub(crate) package_size: u64,
}
