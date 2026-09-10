// shipup-cli - 命令行参数与子命令定义

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// shipup 开发者与发布端工具链入口
#[derive(Parser)]
#[command(
    name = "shipup-cli",
    author,
    version,
    about = "shipup 开发者与发布端工具链"
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

/// 支持的全部子命令
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// 生成 Ed25519 密钥对（包含私钥与公钥）
    Keygen {
        /// 密钥输出目录，默认为 ./keys
        #[arg(short, long, default_value = "./keys")]
        out_dir: PathBuf,
    },

    /// 签名更新包并自动创建或合并 Manifest 元数据文件（支持单包参数或 --config 批量发布）
    Release(Box<ReleaseArgs>),

    /// 校验 Manifest 元数据与本地物理更新包的匹配性（SHA-256、文件大小与数字签名）
    Verify(VerifyArgs),

    /// 查看并格式化解析 Manifest 元数据详情
    Inspect(InspectArgs),

    /// 快速初始化生成发布配置模板文件
    Init(InitArgs),

    /// 对指定安装包物理文件直接生成 SHA-256 摘要与 Ed25519 数字签名
    Sign(SignArgs),

    /// 查看目标环境下的更新偏好、崩溃自愈观察状态与历史回滚矩阵
    Status(StatusArgs),

    /// 手动执行版本回滚至指定的历史版本或上一可用版本
    Rollback(RollbackArgs),

    /// 安全清理目标目录下的历史旧版本备份文件与更新残留碎片
    Clean(CleanArgs),

    /// 针对离线内网更新仓库执行全量一致性与完整性安全审计
    VerifyRepo(VerifyRepoArgs),
}

/// 发布签名与元数据合并参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct ReleaseArgs {
    /// 批量发布配置文件路径（例如 shipup.toml），若指定则批量发布 packages 中定义的所有架构
    #[arg(short, long)]
    pub(crate) config: Option<PathBuf>,

    /// 发布版本号（遵循 SemVer 2.0，例如 1.2.0）
    #[arg(long, required_unless_present = "config")]
    pub(crate) version: Option<String>,

    /// 目标操作系统与架构 Target Triple（例如 x86_64-pc-windows-msvc）
    #[arg(long, required_unless_present = "config")]
    pub(crate) target: Option<String>,

    /// 更新包物理文件路径（例如 ./dist/myapp-1.2.0-setup.exe）
    #[arg(
        long,
        visible_alias = "package-path",
        required_unless_present = "config"
    )]
    pub(crate) package: Option<PathBuf>,

    /// 更新包类型（binary / archive / installer）
    #[arg(long, required_unless_present = "config")]
    pub(crate) package_type: Option<String>,

    /// 下载直链地址
    #[arg(long, required_unless_present = "config")]
    pub(crate) url: Option<String>,

    /// Ed25519 私钥文件路径（若不提供则跳过数字签名）
    #[arg(short, long, visible_alias = "key-path")]
    pub(crate) key: Option<PathBuf>,

    /// 版本更新日志说明内容
    #[arg(long)]
    pub(crate) notes: Option<String>,

    /// 版本发布时间（ISO 8601 / RFC 3339 格式，如未指定则自动注入当前 UTC 时间）
    #[arg(long)]
    pub(crate) pub_date: Option<String>,

    /// 最低支持版本（低于该版本将触发强制更新）
    #[arg(long)]
    pub(crate) min_supported_version: Option<String>,

    /// 是否标记为强制更新
    #[arg(long, default_value_t = false)]
    pub(crate) force_update: bool,

    /// 安装器交互模式（passive / quiet / basicUi，仅在 installer 模式下有效）
    #[arg(long)]
    pub(crate) install_mode: Option<String>,

    /// 启动外部安装器的静默参数（仅在 installer 模式下有效）
    #[arg(long)]
    pub(crate) install_args: Vec<String>,

    /// 压缩包内的主程序相对路径（仅在 archive 模式下有效）
    #[arg(long)]
    pub(crate) executable_path: Option<String>,

    /// 发布通道标识（如 beta、nightly，不指定则写入默认稳定通道）
    #[arg(long)]
    pub(crate) channel: Option<String>,

    /// 是否需要操作系统管理员提权（UAC / Sudo）执行安装（默认 false）
    #[arg(long, default_value_t = false)]
    pub(crate) require_elevation: bool,

    /// 是否等待外部安装器退出并校验退出码（默认 false）
    #[arg(long, default_value_t = false)]
    pub(crate) wait_for_exit: bool,

    /// 灰度放量比例（0..=100，若不指定则全量发布）
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    pub(crate) rollout_percentage: Option<u8>,

    /// 清单过期失效时间戳（RFC 3339 格式，例如 2026-10-01T00:00:00Z）
    #[arg(long)]
    pub(crate) expires_at: Option<String>,

    /// 相对当前时间的清单有效时长（例如 30d、24h、60m，自动换算为 expires_at）
    #[arg(long)]
    pub(crate) expires_in: Option<String>,

    /// 单调递增的清单版本序号（防重放与版本逆向）
    #[arg(long)]
    pub(crate) version_seq: Option<u64>,

    /// Manifest JSON 输出或合并文件路径
    #[arg(short, long, default_value = "latest.json")]
    pub(crate) manifest: PathBuf,
}

/// 校验 Manifest 与发布包匹配性参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct VerifyArgs {
    /// Manifest JSON 元数据文件路径（默认为 latest.json）
    #[arg(short, long, default_value = "latest.json")]
    pub(crate) manifest: PathBuf,

    /// 待校验的本地物理安装包路径
    #[arg(short, long)]
    pub(crate) package: PathBuf,

    /// 目标平台 Target Triple（若未提供则自动探测当前机器平台）
    #[arg(short, long)]
    pub(crate) target: Option<String>,

    /// 发布通道标识（可选，默认稳定主通道）
    #[arg(short, long)]
    pub(crate) channel: Option<String>,

    /// Ed25519 验签公钥文件路径（可选）
    #[arg(long)]
    pub(crate) public_key_file: Option<PathBuf>,

    /// Ed25519 验签公钥 Base64 字符串（可选）
    #[arg(long)]
    pub(crate) public_key: Option<String>,
}

/// 查看解析 Manifest 详情参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct InspectArgs {
    /// Manifest JSON 元数据文件路径（默认为 latest.json）
    #[arg(short, long, default_value = "latest.json")]
    pub(crate) manifest: PathBuf,

    /// 过滤查看的通道标识（可选）
    #[arg(short, long)]
    pub(crate) channel: Option<String>,
}

/// 快速初始化发布配置脚手架参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct InitArgs {
    /// 配置文件输出路径（默认为 ./shipup.toml）
    #[arg(short, long, default_value = "shipup.toml")]
    pub(crate) output: PathBuf,

    /// 是否强制覆盖已存在的目标文件
    #[arg(short, long, default_value_t = false)]
    pub(crate) force: bool,
}

/// 独立安装包物理文件签名参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct SignArgs {
    /// 待签名的安装包物理文件路径
    #[arg(short, long)]
    pub(crate) file: PathBuf,

    /// Ed25519 私钥文件路径
    #[arg(short, long, visible_alias = "key-path")]
    pub(crate) key: PathBuf,

    /// 签名输出文件路径（可选，若未指定则输出至标准终端）
    #[arg(short, long)]
    pub(crate) output: Option<PathBuf>,
}

/// 客户端更新状态矩阵查看参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct StatusArgs {
    /// 状态数据存放目录（若未指定则自动探测系统默认数据目录或当前目录）
    #[arg(short, long)]
    pub(crate) dir: Option<PathBuf>,
}

/// 手动版本回滚参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct RollbackArgs {
    /// 目标回滚版本号（SemVer，例如 1.1.0；若未指定则自动回退至上一可用版本）
    #[arg(short, long)]
    pub(crate) target: Option<String>,

    /// 目标宿主程序可执行文件路径（可选，默认为当前可执行程序）
    #[arg(short, long)]
    pub(crate) exe: Option<PathBuf>,

    /// 回滚历史与状态存储目录（可选）
    #[arg(short, long)]
    pub(crate) dir: Option<PathBuf>,
}

/// 孤儿旧版本备份与碎片清理参数结构体
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct CleanArgs {
    /// 待清理的目标目录（默认为当前工作目录）
    #[arg(short, long, default_value = ".")]
    pub(crate) dir: PathBuf,

    /// 是否仅演练显示待清理文件，不执行实际磁盘物理删除
    #[arg(short, long, default_value_t = false)]
    pub(crate) dry_run: bool,
}

/// 离线更新仓库一致性核验命令参数
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct VerifyRepoArgs {
    /// 离线更新源仓库根目录（包含 manifest.json 与安装包）
    #[arg(value_name = "REPO_DIR")]
    pub(crate) repo_dir: PathBuf,

    /// 清单文件名，默认为 manifest.json
    #[arg(short, long, default_value = "manifest.json")]
    pub(crate) manifest: String,

    /// 用于校验清单与安装包签名的 Ed25519 公钥（Base64 编码，可重复指定）
    #[arg(short = 'k', long = "public-key")]
    pub(crate) public_keys: Vec<String>,

    /// TUF 门限签名最少达标数，默认为 1
    #[arg(short, long, default_value_t = 1)]
    pub(crate) threshold: usize,

    /// 强制要求所有安装包均必须附带数字签名
    #[arg(long)]
    pub(crate) require_signature: bool,
}
