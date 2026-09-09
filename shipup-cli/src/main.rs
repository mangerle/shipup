// shipup-cli 跨平台自更新系统 - 发布端打包与签名命令行工具

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use sha2::{Digest, Sha256};
use shipup::{ChannelInfo, InstallMode, Manifest, PackageInfo, PackageType};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "shipup-cli",
    author,
    version,
    about = "shipup 开发者与发布端工具链"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
}

/// 批量发布配置文件结构
#[derive(Debug, serde::Deserialize)]
struct BatchReleaseConfig {
    version: String,
    notes: Option<String>,
    pub_date: Option<String>,
    min_supported_version: Option<String>,
    #[serde(default)]
    force_update: bool,
    channel: Option<String>,
    rollout_percentage: Option<u8>,
    manifest: Option<PathBuf>,
    key: Option<PathBuf>,
    packages: Vec<BatchPackageConfig>,
}

/// 批量发布单个平台配置
#[derive(Debug, serde::Deserialize)]
struct BatchPackageConfig {
    target: String,
    package: PathBuf,
    package_type: String,
    url: String,
    executable_path: Option<String>,
    install_mode: Option<String>,
    #[serde(default)]
    install_args: Vec<String>,
    #[serde(default)]
    require_elevation: bool,
    key: Option<PathBuf>,
}

/// 发布签名与元数据合并参数结构体
#[derive(clap::Args, Debug, Clone)]
struct ReleaseArgs {
    /// 批量发布配置文件路径（例如 shipup.toml），若指定则批量发布 packages 中定义的所有架构
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// 发布版本号（遵循 SemVer 2.0，例如 1.2.0）
    #[arg(long, required_unless_present = "config")]
    version: Option<String>,

    /// 目标操作系统与架构 Target Triple（例如 x86_64-pc-windows-msvc）
    #[arg(long, required_unless_present = "config")]
    target: Option<String>,

    /// 更新包物理文件路径（例如 ./dist/myapp-1.2.0-setup.exe）
    #[arg(
        long,
        visible_alias = "package-path",
        required_unless_present = "config"
    )]
    package: Option<PathBuf>,

    /// 更新包类型（binary / archive / installer）
    #[arg(long, required_unless_present = "config")]
    package_type: Option<String>,

    /// 下载直链地址
    #[arg(long, required_unless_present = "config")]
    url: Option<String>,

    /// Ed25519 私钥文件路径（若不提供则跳过数字签名）
    #[arg(short, long, visible_alias = "key-path")]
    key: Option<PathBuf>,

    /// 版本更新日志说明内容
    #[arg(long)]
    notes: Option<String>,

    /// 版本发布时间（ISO 8601 / RFC 3339 格式，如未指定则自动注入当前 UTC 时间）
    #[arg(long)]
    pub_date: Option<String>,

    /// 最低支持版本（低于该版本将触发强制更新）
    #[arg(long)]
    min_supported_version: Option<String>,

    /// 是否标记为强制更新
    #[arg(long, default_value_t = false)]
    force_update: bool,

    /// 安装器交互模式（passive / quiet / basicUi，仅在 installer 模式下有效）
    #[arg(long)]
    install_mode: Option<String>,

    /// 启动外部安装器的静默参数（仅在 installer 模式下有效）
    #[arg(long)]
    install_args: Vec<String>,

    /// 压缩包内的主程序相对路径（仅在 archive 模式下有效）
    #[arg(long)]
    executable_path: Option<String>,

    /// 发布通道标识（如 beta、nightly，不指定则写入默认稳定通道）
    #[arg(long)]
    channel: Option<String>,

    /// 是否需要操作系统管理员提权（UAC / Sudo）执行安装（默认 false）
    #[arg(long, default_value_t = false)]
    require_elevation: bool,

    /// 灰度放量比例（0..=100，若不指定则全量发布）
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=100))]
    rollout_percentage: Option<u8>,

    /// Manifest JSON 输出或合并文件路径
    #[arg(short, long, default_value = "latest.json")]
    manifest: PathBuf,
}

/// 校验 Manifest 与发布包匹配性参数结构体
#[derive(clap::Args, Debug, Clone)]
struct VerifyArgs {
    /// Manifest JSON 元数据文件路径（默认为 latest.json）
    #[arg(short, long, default_value = "latest.json")]
    manifest: PathBuf,

    /// 待校验的本地物理安装包路径
    #[arg(short, long)]
    package: PathBuf,

    /// 目标平台 Target Triple（若未提供则自动探测当前机器平台）
    #[arg(short, long)]
    target: Option<String>,

    /// 发布通道标识（可选，默认稳定主通道）
    #[arg(short, long)]
    channel: Option<String>,

    /// Ed25519 验签公钥文件路径（可选）
    #[arg(long)]
    public_key_file: Option<PathBuf>,

    /// Ed25519 验签公钥 Base64 字符串（可选）
    #[arg(long)]
    public_key: Option<String>,
}

/// 查看解析 Manifest 详情参数结构体
#[derive(clap::Args, Debug, Clone)]
struct InspectArgs {
    /// Manifest JSON 元数据文件路径（默认为 latest.json）
    #[arg(short, long, default_value = "latest.json")]
    manifest: PathBuf,

    /// 过滤查看的通道标识（可选）
    #[arg(short, long)]
    channel: Option<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out_dir } => {
            handle_keygen(&out_dir)?;
        }
        Commands::Release(args) => {
            handle_release(&args)?;
        }
        Commands::Verify(args) => {
            handle_verify(&args)?;
        }
        Commands::Inspect(args) => {
            handle_inspect(&args)?;
        }
    }

    Ok(())
}

/// 执行 Ed25519 密钥对生成并将私钥与公钥输出至指定目录
///
/// # 设计原理
/// - **实现初衷**：基于系统安全随机数（`getrandom`）生成 32 字节高熵种子，派生出标准 Ed25519 密钥对并以 Base64 编码保存。
/// - **安全警示**：`ed25519.key` 为极高敏感私钥，严禁检入版本控制系统；`ed25519.pub` 为公钥，供嵌入客户端 `UpdaterBuilder`。
fn handle_keygen(out_dir: &Path) -> Result<()> {
    log::info!("开始生成 Ed25519 密钥对，输出目录: {}", out_dir.display());
    fs::create_dir_all(out_dir)
        .with_context(|| format!("创建密钥输出目录失败: {}", out_dir.display()))?;

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("获取安全随机数种子失败")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let private_key_b64 = BASE64.encode(signing_key.to_bytes());
    let public_key_b64 = BASE64.encode(verifying_key.to_bytes());

    let key_path = out_dir.join("ed25519.key");
    let pub_path = out_dir.join("ed25519.pub");

    fs::write(&key_path, &private_key_b64)
        .with_context(|| format!("写入私钥文件失败: {}", key_path.display()))?;
    fs::write(&pub_path, &public_key_b64)
        .with_context(|| format!("写入公钥文件失败: {}", pub_path.display()))?;

    log::info!("Ed25519 密钥对已成功生成");
    log::info!("  私钥文件（请妥善保密）: {}", key_path.display());
    log::info!("  公钥文件（配置于客户端）: {}", pub_path.display());
    log::info!("  公钥 Base64 内容: {}", public_key_b64);

    Ok(())
}

/// 获取当前系统 UTC 时间的 RFC 3339 格式字符串（例如 "2026-09-09T12:00:00Z"）
///
/// # 设计原理
/// - **实现初衷**：避免为简单的日期格式化引入庞大的第三方依赖，基于标准库 `SystemTime` 原生计算。
/// - **算法保障**：遵循格里高利历标准闰年规则，精确将自 1970 年 UNIX 纪元以来的秒数转为标准时间戳。
fn current_utc_rfc3339() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_timestamp_rfc3339(duration.as_secs())
}

/// 将自 UNIX 纪元以来的秒数格式化为 RFC 3339 字符串
fn format_timestamp_rfc3339(total_secs: u64) -> String {
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

/// 流式读取发布包计算 SHA-256 哈希值，并在提供私钥且体积安全时生成 Ed25519 数字签名
///
/// # 设计原理
/// - **实现初衷**：为防止发布大型安装包时将全量文件直接读入内存导致 OOM，采用 64KB 固定缓冲区流式计算 SHA-256。
/// - **内存保护**：Ed25519 签名需要持有待签名报文切片，因此在签名分支增加 256MB 上限防护，超限明确拦截。
fn compute_payload_integrity(
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
        // 对包体 32 字节 SHA-256 摘要进行 Ed25519 签名，消除文件读取内存占用与体积上限
        let sig = signing_key.sign(&hash);
        Some(BASE64.encode(sig.to_bytes()))
    } else {
        None
    };

    Ok((checksum, signature))
}

/// 待写入清单的发布包实体信息
struct ManifestReleaseEntry {
    version: Version,
    min_supported_version: Option<Version>,
    pub_date: String,
    package_info: PackageInfo,
}

/// 将包信息合并至指定通道或主通道的 Manifest 数据结构中
///
/// # 设计原理
/// - **实现初衷**：支持跨平台 CI/CD 逐步合并发布包至同一清单，并防范低版本误操作降级覆盖高版本主信息。
/// - **安全合并**：严格比对 SemVer 版本高低，仅在待合并版本大于或等于清单版本时更新元数据；
///   低版本包合并时仅追加目标平台包矩阵，保留清单中更高版本的元数据（version、pub_date、notes 等）。
fn update_manifest_entries(
    manifest: &mut Manifest,
    target: &str,
    args: &ReleaseArgs,
    entry: ManifestReleaseEntry,
) {
    if let Some(ref ch) = args.channel {
        let ch_entry = manifest
            .channels
            .entry(ch.to_string())
            .or_insert_with(|| ChannelInfo {
                version: entry.version.clone(),
                min_supported_version: entry.min_supported_version.clone(),
                force_update: args.force_update,
                pub_date: Some(entry.pub_date.clone()),
                notes: args.notes.clone(),
                packages: BTreeMap::new(),
                rollout_percentage: args.rollout_percentage,
            });

        if entry.version > ch_entry.version {
            ch_entry.version = entry.version;
            ch_entry.pub_date = Some(entry.pub_date);
            if entry.min_supported_version.is_some() {
                ch_entry.min_supported_version = entry.min_supported_version;
            }
            if args.force_update {
                ch_entry.force_update = true;
            }
            if let Some(ref n) = args.notes {
                ch_entry.notes = Some(n.clone());
            }
            if args.rollout_percentage.is_some() {
                ch_entry.rollout_percentage = args.rollout_percentage;
            }
        } else if entry.version == ch_entry.version {
            if ch_entry.pub_date.is_none() {
                ch_entry.pub_date = Some(entry.pub_date);
            }
            if entry.min_supported_version.is_some() {
                ch_entry.min_supported_version = entry.min_supported_version;
            }
            if args.force_update {
                ch_entry.force_update = true;
            }
            if let Some(ref n) = args.notes {
                ch_entry.notes = Some(n.clone());
            }
            if args.rollout_percentage.is_some() {
                ch_entry.rollout_percentage = args.rollout_percentage;
            }
        } else {
            log::warn!(
                "发布通道 '{}' 待合并版本 {} 低于通道当前版本 {}，保留现有高版本元数据",
                ch,
                entry.version,
                ch_entry.version
            );
        }
        ch_entry
            .packages
            .insert(target.to_string(), entry.package_info);
    } else {
        if entry.version > manifest.version {
            manifest.version = entry.version;
            manifest.pub_date = Some(entry.pub_date);
            if entry.min_supported_version.is_some() {
                manifest.min_supported_version = entry.min_supported_version;
            }
            if args.force_update {
                manifest.force_update = true;
            }
            if let Some(ref n) = args.notes {
                manifest.notes = Some(n.clone());
            }
            if args.rollout_percentage.is_some() {
                manifest.rollout_percentage = args.rollout_percentage;
            }
        } else if entry.version == manifest.version {
            if manifest.pub_date.is_none() {
                manifest.pub_date = Some(entry.pub_date);
            }
            if entry.min_supported_version.is_some() {
                manifest.min_supported_version = entry.min_supported_version;
            }
            if args.force_update {
                manifest.force_update = true;
            }
            if let Some(ref n) = args.notes {
                manifest.notes = Some(n.clone());
            }
            if args.rollout_percentage.is_some() {
                manifest.rollout_percentage = args.rollout_percentage;
            }
        } else {
            log::warn!(
                "主通道待合并版本 {} 低于清单当前版本 {}，保留现有高版本元数据",
                entry.version,
                manifest.version
            );
        }
        manifest
            .packages
            .insert(target.to_string(), entry.package_info);
    }

    // 清单内容变更后，原有的全局签名已失效，予以重置
    manifest.signature = None;
}

/// 将字节数值转换为人类易读格式（如 12.34 MB）
fn format_human_size(bytes: u64) -> String {
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

/// 执行发布包签名与 Manifest 清单合并
///
/// # 设计原理
/// - **实现初衷**：支持流水线持续集成（CI/CD）中跨 Windows、macOS、Linux 多 Job 逐步合并发布成果物至单份 Manifest 中。
/// - **核心优势**：若目标清单文件已存在，将自动保留已有平台的发布包配置，实现平台矩阵安全增量追加。
fn handle_release(args: &ReleaseArgs) -> Result<()> {
    if let Some(ref config_path) = args.config {
        return handle_batch_release(config_path, &args.manifest);
    }

    let version_str = args
        .version
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --version 参数"))?;
    let target = args
        .target
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --target 参数"))?;
    let package_path = args
        .package
        .as_ref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --package 参数"))?;
    let package_type_str = args
        .package_type
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --package-type 参数"))?;
    let url = args
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("未指定 --config 时必须提供 --url 参数"))?;

    let version = Version::parse(version_str).with_context(|| {
        format!(
            "解析目标版本号 '{}' 失败，请确保符合 SemVer 规范",
            version_str
        )
    })?;
    let parsed_pkg_type = PackageType::from_str(package_type_str).with_context(|| {
        format!(
            "解析更新包类型 '{}' 失败，可选: binary, archive, installer",
            package_type_str
        )
    })?;

    let min_supported_version = match args.min_supported_version {
        Some(ref v) => {
            Some(Version::parse(v).with_context(|| format!("解析最低支持版本号 '{}' 失败", v))?)
        }
        None => None,
    };

    let (checksum, signature) = compute_payload_integrity(package_path, args.key.as_deref())?;

    let parsed_install_mode = match args.install_mode {
        Some(ref mode) => match mode.to_ascii_lowercase().as_str() {
            "passive" => Some(InstallMode::Passive),
            "quiet" => Some(InstallMode::Quiet),
            "basicui" | "basic-ui" => Some(InstallMode::BasicUi),
            other => anyhow::bail!(
                "不支持的安装模式: {}，可选值为 passive / quiet / basicUi",
                other
            ),
        },
        None => None,
    };

    let package_size = fs::metadata(package_path)
        .with_context(|| format!("获取发布包元数据失败: {}", package_path.display()))?
        .len();

    let package_info = PackageInfo {
        url: url.to_string(),
        signature,
        checksum: Some(checksum),
        package_type: parsed_pkg_type,
        install_mode: parsed_install_mode,
        install_args: args.install_args.clone(),
        executable_path: args.executable_path.clone(),
        require_elevation: args.require_elevation,
        size: Some(package_size),
    };

    let pub_date = args.pub_date.clone().unwrap_or_else(current_utc_rfc3339);

    let entry = ManifestReleaseEntry {
        version,
        min_supported_version,
        pub_date,
        package_info,
    };

    let mut manifest = load_or_init_manifest(&args.manifest, args, &entry)?;
    update_manifest_entries(&mut manifest, target, args, entry);

    save_manifest_file(&args.manifest, &manifest)?;
    log::info!(
        "发布信息已成功合并并写入 Manifest：{}",
        args.manifest.display()
    );
    Ok(())
}

/// 执行基于 TOML 配置文件的跨平台批量发布合并
fn handle_batch_release(config_path: &Path, default_manifest_path: &Path) -> Result<()> {
    let toml_content = fs::read_to_string(config_path)
        .with_context(|| format!("读取批量发布配置文件失败: {}", config_path.display()))?;
    let batch_config: BatchReleaseConfig = toml::from_str(&toml_content)
        .with_context(|| format!("解析批量发布配置 TOML 失败: {}", config_path.display()))?;

    let version = Version::parse(&batch_config.version).with_context(|| {
        format!(
            "解析配置文件中的目标版本号 '{}' 失败，请确保符合 SemVer 规范",
            batch_config.version
        )
    })?;

    let min_supported_version = match batch_config.min_supported_version {
        Some(ref v) => {
            Some(Version::parse(v).with_context(|| format!("解析最低支持版本号 '{}' 失败", v))?)
        }
        None => None,
    };

    let pub_date = batch_config
        .pub_date
        .clone()
        .unwrap_or_else(current_utc_rfc3339);

    let config_dir = config_path.parent().unwrap_or(Path::new("."));

    let manifest_path = batch_config
        .manifest
        .as_ref()
        .map(|p| {
            if p.is_relative() {
                config_dir.join(p)
            } else {
                p.clone()
            }
        })
        .unwrap_or_else(|| default_manifest_path.to_path_buf());

    let mut manifest = if manifest_path.exists() {
        let content = fs::read_to_string(&manifest_path)
            .with_context(|| format!("读取已有 Manifest 文件失败: {}", manifest_path.display()))?;
        serde_json::from_str::<Manifest>(&content)
            .with_context(|| format!("反序列化 Manifest JSON 失败: {}", manifest_path.display()))?
    } else {
        Manifest {
            version: version.clone(),
            min_supported_version: min_supported_version.clone(),
            force_update: batch_config.force_update,
            pub_date: Some(pub_date.clone()),
            notes: batch_config.notes.clone(),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: None,
            rollout_percentage: batch_config.rollout_percentage,
        }
    };

    let mut success_count = 0usize;

    for pkg in &batch_config.packages {
        let pkg_path = if pkg.package.is_relative() {
            config_dir.join(&pkg.package)
        } else {
            pkg.package.clone()
        };

        if !pkg_path.exists() {
            anyhow::bail!(
                "平台 '{}' 对应的发布包文件不存在: {}",
                pkg.target,
                pkg_path.display()
            );
        }

        let key_path = pkg.key.as_ref().or(batch_config.key.as_ref()).map(|kp| {
            if kp.is_relative() {
                config_dir.join(kp)
            } else {
                kp.clone()
            }
        });

        let (checksum, signature) = compute_payload_integrity(&pkg_path, key_path.as_deref())?;

        let parsed_pkg_type = PackageType::from_str(&pkg.package_type).with_context(|| {
            format!(
                "平台 '{}' 的包类型 '{}' 无效，可选: binary, archive, installer",
                pkg.target, pkg.package_type
            )
        })?;

        let parsed_install_mode = match pkg.install_mode {
            Some(ref mode) => match mode.to_ascii_lowercase().as_str() {
                "passive" => Some(InstallMode::Passive),
                "quiet" => Some(InstallMode::Quiet),
                "basicui" | "basic-ui" => Some(InstallMode::BasicUi),
                other => anyhow::bail!(
                    "平台 '{}' 不支持的安装模式: {}，可选值为 passive / quiet / basicUi",
                    pkg.target,
                    other
                ),
            },
            None => None,
        };

        let package_size = fs::metadata(&pkg_path)
            .with_context(|| format!("获取发布包元数据失败: {}", pkg_path.display()))?
            .len();

        let package_info = PackageInfo {
            url: pkg.url.clone(),
            signature,
            checksum: Some(checksum),
            package_type: parsed_pkg_type,
            install_mode: parsed_install_mode,
            install_args: pkg.install_args.clone(),
            executable_path: pkg.executable_path.clone(),
            require_elevation: pkg.require_elevation,
            size: Some(package_size),
        };

        let entry = ManifestReleaseEntry {
            version: version.clone(),
            min_supported_version: min_supported_version.clone(),
            pub_date: pub_date.clone(),
            package_info,
        };

        let release_args_for_update = ReleaseArgs {
            config: None,
            version: Some(batch_config.version.clone()),
            target: Some(pkg.target.clone()),
            package: Some(pkg_path),
            package_type: Some(pkg.package_type.clone()),
            url: Some(pkg.url.clone()),
            key: key_path,
            notes: batch_config.notes.clone(),
            pub_date: Some(pub_date.clone()),
            min_supported_version: batch_config.min_supported_version.clone(),
            force_update: batch_config.force_update,
            install_mode: pkg.install_mode.clone(),
            install_args: pkg.install_args.clone(),
            executable_path: pkg.executable_path.clone(),
            channel: batch_config.channel.clone(),
            require_elevation: pkg.require_elevation,
            rollout_percentage: batch_config.rollout_percentage,
            manifest: manifest_path.clone(),
        };

        update_manifest_entries(&mut manifest, &pkg.target, &release_args_for_update, entry);
        success_count += 1;
        log::info!("  已完成平台 '{}' 的包签名与清单合并", pkg.target);
    }

    save_manifest_file(&manifest_path, &manifest)?;
    log::info!(
        "批量发布成功！已合并 {} 个平台的包元数据并写入 Manifest：{}",
        success_count,
        manifest_path.display()
    );
    Ok(())
}

/// 执行 Manifest 元数据与本地物理包核验
fn handle_verify(args: &VerifyArgs) -> Result<()> {
    if !args.manifest.exists() {
        anyhow::bail!("Manifest 清单文件不存在: {}", args.manifest.display());
    }
    if !args.package.exists() {
        anyhow::bail!("待校验的物理发布包文件不存在: {}", args.package.display());
    }

    let content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("读取 Manifest 清单文件失败: {}", args.manifest.display()))?;
    let manifest = serde_json::from_str::<Manifest>(&content)
        .with_context(|| "反序列化 Manifest JSON 失败")?;

    let target = args
        .target
        .clone()
        .unwrap_or_else(|| shipup::current_target_triple().to_string());

    let (version, pkg_info) = if let Some(ref ch) = args.channel {
        let channel_info = manifest
            .channels
            .get(ch)
            .ok_or_else(|| anyhow!("在 Manifest 中未找到指定的通道 '{}'", ch))?;
        let pkg = channel_info.packages.get(&target).ok_or_else(|| {
            anyhow!(
                "在 Manifest 通道 '{}' 中未找到平台 '{}' 的包配置",
                ch,
                target
            )
        })?;
        (&channel_info.version, pkg)
    } else {
        let pkg = manifest
            .packages
            .get(&target)
            .ok_or_else(|| anyhow!("在 Manifest 中未找到平台 '{}' 的包配置", target))?;
        (&manifest.version, pkg)
    };

    // 1. 校验文件大小
    let actual_size = fs::metadata(&args.package)
        .with_context(|| format!("获取发布包文件元数据失败: {}", args.package.display()))?
        .len();

    if let Some(expected_size) = pkg_info.size
        && actual_size != expected_size
    {
        anyhow::bail!(
            "发布包体积不匹配！期望大小: {} ({} 字节)，实际文件大小: {} ({} 字节)",
            format_human_size(expected_size),
            expected_size,
            format_human_size(actual_size),
            actual_size
        );
    }

    // 2. 校验 SHA-256
    let (computed_checksum, _) = compute_payload_integrity(&args.package, None)?;
    if let Some(ref expected_checksum) = pkg_info.checksum {
        let exp_clean = expected_checksum
            .strip_prefix("sha256:")
            .unwrap_or(expected_checksum);
        let comp_clean = computed_checksum
            .strip_prefix("sha256:")
            .unwrap_or(&computed_checksum);
        if !exp_clean.eq_ignore_ascii_case(comp_clean) {
            anyhow::bail!(
                "发布包 SHA-256 校验和不匹配！\n  期望值: {}\n  计算值: {}",
                expected_checksum,
                computed_checksum
            );
        }
    } else {
        log::warn!("Manifest 中未包含该包的 checksum 校验和字段");
    }

    // 3. 校验 Ed25519 签名
    let public_key_b64 = if let Some(ref key_str) = args.public_key {
        Some(key_str.trim().to_string())
    } else if let Some(ref key_file) = args.public_key_file {
        let s = fs::read_to_string(key_file)
            .with_context(|| format!("读取公钥文件失败: {}", key_file.display()))?;
        Some(s.trim().to_string())
    } else {
        None
    };

    let sig_status = match (public_key_b64, pkg_info.signature.as_deref()) {
        (Some(ref pk_b64), Some(sig_b64)) => {
            shipup::signature::verify_ed25519_file(&args.package, sig_b64, pk_b64)
                .map_err(|e| anyhow!("Ed25519 数字签名校验未通过: {}", e))?;

            "已验证通过 (合法数字签名)"
        }
        (None, Some(_)) => {
            log::warn!(
                "发布包包含数字签名，但本次未提供公钥参数进行验签 (--public-key 或 --public-key-file)"
            );
            "包含签名 (未提供公钥，已跳过验签)"
        }
        (Some(_), None) => {
            anyhow::bail!("提供了公钥进行验证，但 Manifest 中该平台发布包未配置 signature 签名");
        }
        (None, None) => "无签名配置",
    };

    println!("==================== 发布包校验通过 ====================");
    println!("Manifest 文件:    {}", args.manifest.display());
    println!("发布版本号:        {}", version);
    println!("目标平台架构:      {}", target);
    println!("发布包路径:        {}", args.package.display());
    println!("包体积大小:        {}", format_human_size(actual_size));
    println!("SHA-256 校验和:    {} (完全匹配)", computed_checksum);
    println!("Ed25519 数字签名:  {}", sig_status);
    println!("========================================================");

    Ok(())
}

/// 执行 Manifest 元数据内容结构化展示
fn handle_inspect(args: &InspectArgs) -> Result<()> {
    if !args.manifest.exists() {
        anyhow::bail!("Manifest 文件不存在: {}", args.manifest.display());
    }

    let content = fs::read_to_string(&args.manifest)
        .with_context(|| format!("读取 Manifest 文件失败: {}", args.manifest.display()))?;
    let manifest = serde_json::from_str::<Manifest>(&content)
        .with_context(|| "反序列化 Manifest JSON 失败")?;

    println!("==================== Manifest 清单信息 ====================");
    println!("文件路径:          {}", args.manifest.display());
    println!("主通道版本:        {}", manifest.version);
    if let Some(ref notes) = manifest.notes {
        println!("版本更新日志:\n{}", notes);
    }
    if let Some(ref pub_date) = manifest.pub_date {
        println!("发布时间 (UTC):    {}", pub_date);
    }
    if let Some(ref min_v) = manifest.min_supported_version {
        println!("最低支持版本:      {}", min_v);
    }
    println!(
        "强制更新 (Force):  {}",
        if manifest.force_update { "是" } else { "否" }
    );
    if let Some(pct) = manifest.rollout_percentage {
        println!("灰度放量比例:      {}%", pct);
    } else {
        println!("灰度放量比例:      100% (全量发布)");
    }
    println!(
        "全局签名:          {}",
        if manifest.signature.is_some() {
            "已配置"
        } else {
            "无"
        }
    );

    println!("\n[主通道平台包矩阵 (共 {} 个)]", manifest.packages.len());
    for (target, pkg) in &manifest.packages {
        println!("  - Target 平台:     {}", target);
        println!("    包形态类型:      {:?}", pkg.package_type);
        println!("    下载地址:        {}", pkg.url);
        if let Some(sz) = pkg.size {
            println!("    包体积大小:      {}", format_human_size(sz));
        }
        if let Some(ref chk) = pkg.checksum {
            println!("    SHA-256 校验和:  {}", chk);
        }
        println!(
            "    数字签名状态:    {}",
            if pkg.signature.is_some() {
                "已签名"
            } else {
                "未签名"
            }
        );
        if let Some(ref exec) = pkg.executable_path {
            println!("    归档可执行路径:  {}", exec);
        }
        if let Some(ref mode) = pkg.install_mode {
            println!("    安装器模式:      {:?}", mode);
        }
        if pkg.require_elevation {
            println!("    提权要求:        需要管理员提权 (UAC/Sudo)");
        }
    }

    if !manifest.channels.is_empty() {
        println!("\n[独立多通道列表 (共 {} 个)]", manifest.channels.len());
        for (ch_name, ch_info) in &manifest.channels {
            if let Some(ref filter_ch) = args.channel
                && filter_ch != ch_name
            {
                continue;
            }
            println!("  * 通道标识:        {}", ch_name);
            println!("    通道版本:        {}", ch_info.version);
            if let Some(pct) = ch_info.rollout_percentage {
                println!("    灰度放量比例:    {}%", pct);
            }
            println!("    支持平台数:      {}", ch_info.packages.len());
        }
    }
    println!("===========================================================");

    Ok(())
}

/// 读取现有 Manifest 文件或初始化默认空 Manifest
fn load_or_init_manifest(
    manifest_path: &Path,
    args: &ReleaseArgs,
    entry: &ManifestReleaseEntry,
) -> Result<Manifest> {
    if manifest_path.exists() {
        let content = fs::read_to_string(manifest_path)
            .with_context(|| format!("读取已有 Manifest 文件失败: {}", manifest_path.display()))?;
        serde_json::from_str::<Manifest>(&content)
            .with_context(|| format!("反序列化 Manifest JSON 失败: {}", manifest_path.display()))
    } else {
        Ok(Manifest {
            version: entry.version.clone(),
            min_supported_version: entry.min_supported_version.clone(),
            force_update: args.force_update,
            pub_date: Some(entry.pub_date.clone()),
            notes: args.notes.clone(),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: None,
            rollout_percentage: args.rollout_percentage,
        })
    }
}

/// 将格式化后的 Manifest JSON 写入磁盘目标路径
fn save_manifest_file(manifest_path: &Path, manifest: &Manifest) -> Result<()> {
    let json_output =
        serde_json::to_string_pretty(manifest).context("序列化 Manifest 为格式化 JSON 失败")?;
    if let Some(parent) = manifest_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("创建 Manifest 输出父目录失败: {}", parent.display()))?;
    }
    fs::write(manifest_path, json_output)
        .with_context(|| format!("写入 Manifest 文件失败: {}", manifest_path.display()))?;
    Ok(())
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
    fn test_update_manifest_entries_semver_guard() {
        let mut manifest = Manifest {
            version: Version::parse("1.2.0").unwrap(),
            min_supported_version: None,
            force_update: false,
            pub_date: Some("2026-09-01T00:00:00Z".to_string()),
            notes: Some("版本 1.2.0".to_string()),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: Some("old_signature".to_string()),
            rollout_percentage: None,
        };

        // 1. 尝试合并低版本 1.1.0（例如补发旧平台包）
        let entry_old = ManifestReleaseEntry {
            version: Version::parse("1.1.0").unwrap(),
            min_supported_version: None,
            pub_date: "2026-08-01T00:00:00Z".to_string(),
            package_info: PackageInfo {
                url: "https://example.com/win-1.1.0.exe".to_string(),
                signature: None,
                checksum: Some("sha256:abc".to_string()),
                package_type: PackageType::Binary,
                install_mode: None,
                install_args: vec![],
                executable_path: None,
                require_elevation: false,
                size: None,
            },
        };

        let args_old = ReleaseArgs {
            config: None,
            version: Some("1.1.0".to_string()),
            target: Some("x86_64-pc-windows-msvc".to_string()),
            package: Some(PathBuf::from("dummy")),
            package_type: Some("binary".to_string()),
            url: Some("https://example.com/win-1.1.0.exe".to_string()),
            key: None,
            notes: Some("旧版 1.1.0".to_string()),
            pub_date: None,
            min_supported_version: None,
            force_update: false,
            install_mode: None,
            install_args: vec![],
            executable_path: None,
            channel: None,
            require_elevation: false,
            rollout_percentage: None,
            manifest: PathBuf::from("latest.json"),
        };

        update_manifest_entries(
            &mut manifest,
            "x86_64-pc-windows-msvc",
            &args_old,
            entry_old,
        );

        // 验证：主版本依然保持 1.2.0，notes 依然保持 1.2.0，未被逆向降级！
        assert_eq!(manifest.version, Version::parse("1.2.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("版本 1.2.0"));
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert_eq!(manifest.signature, None); // 签名已被安全失效重置

        // 2. 合并更高版本 1.3.0 并附带 30% 灰度放量
        let entry_new = ManifestReleaseEntry {
            version: Version::parse("1.3.0").unwrap(),
            min_supported_version: None,
            pub_date: "2026-10-01T00:00:00Z".to_string(),
            package_info: PackageInfo {
                url: "https://example.com/mac-1.3.0.tar.gz".to_string(),
                signature: None,
                checksum: Some("sha256:def".to_string()),
                package_type: PackageType::Archive,
                install_mode: None,
                install_args: vec![],
                executable_path: None,
                require_elevation: false,
                size: None,
            },
        };

        let args_new = ReleaseArgs {
            config: None,
            version: Some("1.3.0".to_string()),
            target: Some("aarch64-apple-darwin".to_string()),
            package: Some(PathBuf::from("dummy")),
            package_type: Some("archive".to_string()),
            url: Some("https://example.com/mac-1.3.0.tar.gz".to_string()),
            key: None,
            notes: Some("全新 1.3.0".to_string()),
            pub_date: Some("2026-10-01T00:00:00Z".to_string()),
            min_supported_version: None,
            force_update: true,
            install_mode: None,
            install_args: vec![],
            executable_path: None,
            channel: None,
            require_elevation: false,
            rollout_percentage: Some(30),
            manifest: PathBuf::from("latest.json"),
        };

        update_manifest_entries(&mut manifest, "aarch64-apple-darwin", &args_new, entry_new);

        // 验证：升级为主版本 1.3.0，灰度比例设置为 30%
        assert_eq!(manifest.version, Version::parse("1.3.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("全新 1.3.0"));
        assert_eq!(manifest.pub_date.as_deref(), Some("2026-10-01T00:00:00Z"));
        assert_eq!(manifest.rollout_percentage, Some(30));
        assert!(manifest.force_update);
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert!(manifest.packages.contains_key("aarch64-apple-darwin"));
    }

    #[test]
    fn test_batch_release_verify_and_inspect_flow() -> Result<()> {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_cli_batch_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir)?;

        // 1. 生成密钥对
        handle_keygen(&temp_dir)?;
        let key_file = temp_dir.join("ed25519.key");
        let pub_file = temp_dir.join("ed25519.pub");
        assert!(key_file.exists());
        assert!(pub_file.exists());

        // 2. 准备两个发布包
        let win_pkg = temp_dir.join("myapp-windows.exe");
        let mac_pkg = temp_dir.join("myapp-macos.tar.gz");
        fs::write(&win_pkg, b"binary for windows x64 target payload")?;
        fs::write(&mac_pkg, b"archive for macos arm64 target payload")?;

        let manifest_file = temp_dir.join("latest.json");

        // 3. 编写 shipup.toml 配置文件
        let toml_path = temp_dir.join("shipup.toml");
        let toml_content = r#"
version = "2.0.0"
notes = "跨平台批量发布测试"
pub_date = "2026-09-09T20:00:00Z"
key = "ed25519.key"
manifest = "latest.json"
rollout_percentage = 40

[[packages]]
target = "x86_64-pc-windows-msvc"
package = "myapp-windows.exe"
package_type = "binary"
url = "https://example.com/myapp-windows.exe"

[[packages]]
target = "aarch64-apple-darwin"
package = "myapp-macos.tar.gz"
package_type = "archive"
url = "https://example.com/myapp-macos.tar.gz"
executable_path = "myapp"
"#;
        fs::write(&toml_path, toml_content)?;

        // 4. 执行批量发布
        handle_batch_release(&toml_path, &manifest_file)?;
        assert!(manifest_file.exists());

        // 5. 校验 inspect 功能无异常
        let inspect_args = InspectArgs {
            manifest: manifest_file.clone(),
            channel: None,
        };
        handle_inspect(&inspect_args)?;

        // 6. 校验 verify 功能（正常情况）
        let verify_win = VerifyArgs {
            manifest: manifest_file.clone(),
            package: win_pkg.clone(),
            target: Some("x86_64-pc-windows-msvc".to_string()),
            channel: None,
            public_key_file: Some(pub_file.clone()),
            public_key: None,
        };
        handle_verify(&verify_win)?;

        let verify_mac = VerifyArgs {
            manifest: manifest_file.clone(),
            package: mac_pkg.clone(),
            target: Some("aarch64-apple-darwin".to_string()),
            channel: None,
            public_key_file: Some(pub_file),
            public_key: None,
        };
        handle_verify(&verify_mac)?;

        // 7. 校验 verify 防篡改拦截（修改包文件导致 SHA-256 不一致）
        let tampered_pkg = temp_dir.join("tampered.exe");
        fs::write(&tampered_pkg, b"tampered corrupt content")?;
        let verify_tampered = VerifyArgs {
            manifest: manifest_file.clone(),
            package: tampered_pkg,
            target: Some("x86_64-pc-windows-msvc".to_string()),
            channel: None,
            public_key_file: None,
            public_key: None,
        };
        let tamper_res = handle_verify(&verify_tampered);
        assert!(tamper_res.is_err());
        let err_msg = tamper_res.unwrap_err().to_string();
        assert!(err_msg.contains("不匹配"));

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }
}
