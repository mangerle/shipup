// shipup-cli 跨平台自更新系统 - 发布端打包与签名命令行工具

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use sha2::{Digest, Sha256};
use shipup::{ChannelInfo, InstallMode, Manifest, PackageInfo, PackageType};
use std::collections::HashMap;
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

    /// 签名更新包并自动创建或合并 Manifest 元数据文件
    Release(Box<ReleaseArgs>),
}

/// 发布签名与元数据合并参数结构体
#[derive(clap::Args)]
struct ReleaseArgs {
    /// 发布版本号（遵循 SemVer 2.0，例如 1.2.0）
    #[arg(long)]
    version: String,

    /// 目标操作系统与架构 Target Triple（例如 x86_64-pc-windows-msvc）
    #[arg(long)]
    target: String,

    /// 更新包物理文件路径（例如 ./dist/myapp-1.2.0-setup.exe）
    #[arg(long, visible_alias = "package-path")]
    package: PathBuf,

    /// 更新包类型（binary / archive / installer）
    #[arg(long)]
    package_type: String,

    /// 下载直链地址
    #[arg(long)]
    url: String,

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

    /// Manifest JSON 输出或合并文件路径
    #[arg(short, long, default_value = "latest.json")]
    manifest: PathBuf,
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

/// 最大支持 Ed25519 内存签名的发布包体积上限（256MB）
const MAX_SIGNING_PAYLOAD_SIZE: u64 = 256 * 1024 * 1024;

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
    let metadata = file
        .metadata()
        .with_context(|| format!("获取发布包元数据失败: {}", package_path.display()))?;
    let file_size = metadata.len();

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
        if file_size > MAX_SIGNING_PAYLOAD_SIZE {
            anyhow::bail!(
                "发布包文件体积 ({} 字节) 超过 Ed25519 单次内存签名安全上限 ({} 字节)",
                file_size,
                MAX_SIGNING_PAYLOAD_SIZE
            );
        }

        let package_bytes = fs::read(package_path)
            .with_context(|| format!("读取待签名发布包失败: {}", package_path.display()))?;
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
        let sig = signing_key.sign(&package_bytes);
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
                packages: HashMap::new(),
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
            .insert(args.target.clone(), entry.package_info);
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
        } else {
            log::warn!(
                "主通道待合并版本 {} 低于清单当前版本 {}，保留现有高版本元数据",
                entry.version,
                manifest.version
            );
        }
        manifest
            .packages
            .insert(args.target.clone(), entry.package_info);
    }

    // 清单内容变更后，原有的全局签名已失效，予以重置
    manifest.signature = None;
}

/// 执行发布包签名与 Manifest 清单合并
///
/// # 设计原理
/// - **实现初衷**：支持流水线持续集成（CI/CD）中跨 Windows、macOS、Linux 多 Job 逐步合并发布成果物至单份 Manifest 中。
/// - **核心优势**：若目标清单文件已存在，将自动保留已有平台的发布包配置，实现平台矩阵安全增量追加。
fn handle_release(args: &ReleaseArgs) -> Result<()> {
    let version = Version::parse(&args.version).with_context(|| {
        format!(
            "解析目标版本号 '{}' 失败，请确保符合 SemVer 规范",
            args.version
        )
    })?;
    let parsed_pkg_type = PackageType::from_str(&args.package_type).with_context(|| {
        format!(
            "解析更新包类型 '{}' 失败，可选: binary, archive, installer",
            args.package_type
        )
    })?;

    let min_supported_version = match args.min_supported_version {
        Some(ref v) => {
            Some(Version::parse(v).with_context(|| format!("解析最低支持版本号 '{}' 失败", v))?)
        }
        None => None,
    };

    let (checksum, signature) = compute_payload_integrity(&args.package, args.key.as_deref())?;

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

    let package_size = fs::metadata(&args.package)
        .with_context(|| format!("获取发布包元数据失败: {}", args.package.display()))?
        .len();

    let package_info = PackageInfo {
        url: args.url.clone(),
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
    update_manifest_entries(&mut manifest, args, entry);

    save_manifest_file(&args.manifest, &manifest)?;
    log::info!(
        "发布信息已成功合并并写入 Manifest：{}",
        args.manifest.display()
    );
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
            packages: HashMap::new(),
            channels: HashMap::new(),
            signature: None,
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
            packages: HashMap::new(),
            channels: HashMap::new(),
            signature: Some("old_signature".to_string()),
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
            version: "1.1.0".to_string(),
            target: "x86_64-pc-windows-msvc".to_string(),
            package: PathBuf::from("dummy"),
            package_type: "binary".to_string(),
            url: "https://example.com/win-1.1.0.exe".to_string(),
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
            manifest: PathBuf::from("latest.json"),
        };

        update_manifest_entries(&mut manifest, &args_old, entry_old);

        // 验证：主版本依然保持 1.2.0，notes 依然保持 1.2.0，未被逆向降级！
        assert_eq!(manifest.version, Version::parse("1.2.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("版本 1.2.0"));
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert_eq!(manifest.signature, None); // 签名已被安全失效重置

        // 2. 合并更高版本 1.3.0
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
            version: "1.3.0".to_string(),
            target: "aarch64-apple-darwin".to_string(),
            package: PathBuf::from("dummy"),
            package_type: "archive".to_string(),
            url: "https://example.com/mac-1.3.0.tar.gz".to_string(),
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
            manifest: PathBuf::from("latest.json"),
        };

        update_manifest_entries(&mut manifest, &args_new, entry_new);

        // 验证：升级为主版本 1.3.0
        assert_eq!(manifest.version, Version::parse("1.3.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("全新 1.3.0"));
        assert_eq!(manifest.pub_date.as_deref(), Some("2026-10-01T00:00:00Z"));
        assert!(manifest.force_update);
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert!(manifest.packages.contains_key("aarch64-apple-darwin"));
    }
}
