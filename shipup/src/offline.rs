// shipup 离线更新与本地文件协议适配器
//! 提供离线内网与本地镜像源的高可靠支持，覆盖 URI 规范化、路径解析、相对路径展开与离线镜像自检。

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Result, UpdateError};
use crate::manifest::{Manifest, PackageInfo, PackageType};
use crate::signature::{compute_file_sha256_digest, verify_ed25519_file_any_key};

/// 检查指定 URL 是否属于 file:// 协议（忽略大小写）
#[must_use]
pub fn is_file_protocol(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.len() >= 7 {
        trimmed[..7].eq_ignore_ascii_case("file://")
    } else {
        false
    }
}

/// 将本地文件路径规范化转换为标准 RFC 8089 格式的 `file://` URL
///
/// # 设计原理
/// - **实现初衷**：在单机离线环境或企业内网网络共享（UNC）中，不同的操作系统具有异构的路径表示方式。
///   需要统一转换为标准的 `file://` URL，以便在整个更新流水线中保持端点一致性。
/// - **核心优势**：自动识别并安全处理 Windows 驱动器盘符（如 `C:\...` -> `file:///C:/...`）以及
///   网络共享 UNC 路径（如 `\\server\share\...` -> `file://server/share/...`），同时对空格与特殊字符进行百分号转义。
/// - **代价与局限**：若传入相对路径，将结合当前工作目录进行绝对化解析。
///
/// # Errors
/// - 无法获取当前工作目录或路径存在不可解析字符时返回错误。
pub fn path_to_file_url(path: &Path) -> Result<String> {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let path_str = abs_path.to_string_lossy();

    #[cfg(windows)]
    {
        // 识别 Windows UNC 网络共享路径（以 \\ 或 // 开头）
        if path_str.starts_with(r"\\") || path_str.starts_with("//") {
            let unc_trimmed = &path_str[2..];
            let normalized = unc_trimmed.replace('\\', "/");
            let encoded = percent_encode_path(&normalized);
            return Ok(format!("file://{encoded}"));
        }

        // Windows 驱动器绝对路径（如 C:\path）
        let normalized = path_str.replace('\\', "/");
        let encoded = percent_encode_path(&normalized);
        if !encoded.starts_with('/') {
            Ok(format!("file:///{encoded}"))
        } else {
            Ok(format!("file://{encoded}"))
        }
    }

    #[cfg(not(windows))]
    {
        let encoded = percent_encode_path(&path_str);
        if !encoded.starts_with('/') {
            Ok(format!("file:///{encoded}"))
        } else {
            Ok(format!("file://{encoded}"))
        }
    }
}

/// 解析 `file://` 协议 URL 为跨平台本地绝对文件路径
///
/// # 设计原理
/// - **实现初衷**：将 `file://` 协议端点转换为操作系统底层安全的文件系统路径，支持本地与 UNC 文件操作。
/// - **核心优势**：鲁棒支持 Windows 驱动器字母格式（`file:///C:/...` 与 `file://C:/...`）、
///   localhost 域名前缀以及 UNC 网络共享路径（`file://server/share/...`），且具备百分号解码支持。
/// - **代价与局限**：不支持跨主机的非 UNC 远程主机别名解析。
///
/// # Errors
/// - 传入的 URL 非 `file://` 协议格式时返回 [`UpdateError::FileProtocolNotAllowed`]。
pub fn file_url_to_path(url: &str) -> Result<PathBuf> {
    let trimmed = url.trim();
    if !is_file_protocol(trimmed) {
        return Err(UpdateError::FileProtocolNotAllowed(url.to_string()));
    }

    let after_scheme = &trimmed[7..];
    // 剥离 localhost 域名前缀（如 file://localhost/path 保留 /path）
    let path_part =
        if after_scheme.len() >= 9 && after_scheme[..9].eq_ignore_ascii_case("localhost") {
            &after_scheme[9..]
        } else {
            after_scheme
        };

    let decoded = percent_decode(path_part);

    #[cfg(windows)]
    {
        // 兼容 Windows 格式：file:///C:/path 或 file://C:/path
        if decoded.starts_with('/') && decoded.len() >= 3 {
            let bytes = decoded.as_bytes();
            if bytes[1].is_ascii_alphabetic() && bytes[2] == b':' {
                let win_path = decoded[1..].replace('/', "\\");
                return Ok(PathBuf::from(win_path));
            }
        }

        if decoded.len() >= 2 {
            let bytes = decoded.as_bytes();
            if bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                let win_path = decoded.replace('/', "\\");
                return Ok(PathBuf::from(win_path));
            }
        }

        // UNC 网络共享路径（file://server/share/path 或 file:////server/share/path）
        let unc_content = decoded.trim_start_matches('/');
        let win_unc = format!(r"\\{}", unc_content.replace('/', "\\"));
        Ok(PathBuf::from(win_unc))
    }

    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(decoded))
    }
}

/// 将相对包路径在本地离线 Manifest 上下文中解析为绝对 `file://` URL
///
/// # 设计原理
/// - **实现初衷**：在制作离线更新介质（如 USB 驱动器或内网目录）时，`manifest.json` 内部的 `package.url`
///   通常写入相对文件名（如 `app-1.2.0.zip`），避免预先硬编码绝对盘符或挂载点。
/// - **核心优势**：自动识别相对路径，并基于当前 Manifest 的实际 `file://` 位置展开为完整的绝对端点。
/// - **代价与局限**：若目标包路径已经为绝对网络协议头（`http://` 或 `https://`），将直接保持原样返回。
///
/// # Errors
/// - 当本地基础清单路径无法定位父目录时返回解析错误。
pub fn resolve_relative_file_url(
    base_manifest_url: &str,
    package_url_or_relative: &str,
) -> Result<String> {
    let raw = package_url_or_relative.trim();
    if raw.contains("://") {
        return Ok(raw.to_string());
    }

    if !is_file_protocol(base_manifest_url) {
        return Ok(raw.to_string());
    }

    let manifest_path = file_url_to_path(base_manifest_url)?;
    let base_dir = manifest_path.parent().unwrap_or(&manifest_path);
    let target_package_path = base_dir.join(raw);

    path_to_file_url(&target_package_path)
}

/// 离线更新源一致性核验配置选项
#[derive(Debug, Clone)]
pub struct OfflineVerifyOptions<'a> {
    /// 离线更新源仓库根目录
    pub repository_dir: &'a Path,
    /// 清单文件名（默认为 `manifest.json`）
    pub manifest_filename: Option<&'a str>,
    /// 用于校验数字签名的 Ed25519 公钥列表（Base64 编码）
    pub public_keys: &'a [String],
    /// TUF 门限签名最少需要达标的签名个数（默认为 1）
    pub signature_threshold: usize,
    /// 是否强制要求所有安装包均必须包含数字签名
    pub require_package_signatures: bool,
}

impl<'a> OfflineVerifyOptions<'a> {
    /// 创建离线验证配置默认构建器
    #[must_use]
    pub fn new(repository_dir: &'a Path) -> Self {
        Self {
            repository_dir,
            manifest_filename: None,
            public_keys: &[],
            signature_threshold: 1,
            require_package_signatures: false,
        }
    }
}

/// 单个安装包的离线完整性核验状态
#[derive(Debug, Clone)]
pub struct OfflinePackageReport {
    /// 目标平台 Triple 标识
    pub target: String,
    /// 所在发布通道（若为根通道则为 None）
    pub channel: Option<String>,
    /// 清单中声明的包相对或绝对地址
    pub declared_url: String,
    /// 本地文件系统中定位到的绝对文件路径
    pub resolved_local_path: Option<PathBuf>,
    /// 包分发格式类型
    pub package_type: PackageType,
    /// 包文件是否存在
    pub file_exists: bool,
    /// 文件体积是否完全匹配
    pub size_matched: bool,
    /// 实际文件体积（字节）
    pub actual_size: u64,
    /// 清单中声明的期望体积（字节）
    pub expected_size: Option<u64>,
    /// SHA-256 完整性摘要是否匹配
    pub checksum_matched: bool,
    /// 实际计算出的 SHA-256 摘要（十六进制小写）
    pub actual_checksum: Option<String>,
    /// 清单中声明的期望 SHA-256 摘要
    pub expected_checksum: Option<String>,
    /// 数字签名验证结果（None 表示未执行，Some(true) 表示通过）
    pub signature_verified: Option<bool>,
    /// 详细异常描述说明
    pub failure_reason: Option<String>,
}

impl OfflinePackageReport {
    /// 当前安装包是否完全符合离线部署安全规范
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.file_exists
            && self.size_matched
            && self.checksum_matched
            && self.signature_verified.unwrap_or(true)
            && self.failure_reason.is_none()
    }
}

/// 离线更新源仓库全量一致性审计报告
#[derive(Debug, Clone)]
pub struct OfflineVerifyReport {
    /// 清单文件本地绝对路径
    pub manifest_path: PathBuf,
    /// 清单文本解析及自身签名是否完全有效
    pub manifest_valid: bool,
    /// 清单自身的错误或异常说明
    pub manifest_error: Option<String>,
    /// 清单声明的目标版本号
    pub version: Option<String>,
    /// 仓库内发现的总发布通道数
    pub channel_count: usize,
    /// 所有架构安装包的细粒度核验结果列表
    pub package_reports: Vec<OfflinePackageReport>,
}

impl OfflineVerifyReport {
    /// 检查整个离线源仓库是否处于 100% 可用且无损状态
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.manifest_valid
            && self.manifest_error.is_none()
            && !self.package_reports.is_empty()
            && self
                .package_reports
                .iter()
                .all(OfflinePackageReport::is_valid)
    }
}

/// 对指定的本地离线更新源目录执行全量安全性与一致性核验
///
/// # 设计原理
/// - **实现初衷**：在将安装包与更新清单刻录到隔离介质或部署到内网只读挂载源前，需快速确认
///   清单与底层所有二进制包的强一致性，防止因文件损坏或签名脱漏导致更新大面积故障。
/// - **核心优势**：静态离线遍历，全流程流式哈希计算，支持 TUF 门限验签，不触发任何真实网络请求。
/// - **代价与局限**：对大体积包（如数 GB 镜像）计算 SHA-256 需要依赖本地磁盘读取耗时。
///
/// # Errors
/// - 当读取离线目录或清单文件发生 IO 异常时返回错误。
pub fn verify_offline_repository(
    options: &OfflineVerifyOptions<'_>,
) -> Result<OfflineVerifyReport> {
    let manifest_file_name = options.manifest_filename.unwrap_or("manifest.json");
    let manifest_path = options.repository_dir.join(manifest_file_name);

    if !manifest_path.exists() {
        return Ok(OfflineVerifyReport {
            manifest_path: manifest_path.clone(),
            manifest_valid: false,
            manifest_error: Some(format!("清单文件不存在: {}", manifest_path.display())),
            version: None,
            channel_count: 0,
            package_reports: Vec::new(),
        });
    }

    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest = match Manifest::from_json_str(&manifest_content) {
        Ok(m) => m,
        Err(e) => {
            return Ok(OfflineVerifyReport {
                manifest_path,
                manifest_valid: false,
                manifest_error: Some(format!("清单反序列化解析失败: {e}")),
                version: None,
                channel_count: 0,
                package_reports: Vec::new(),
            });
        }
    };

    // 校验清单自身签名
    let mut manifest_valid = true;
    let mut manifest_error = None;

    if !options.public_keys.is_empty() {
        let all_sigs = manifest.all_signatures();
        if all_sigs.is_empty() {
            if options.require_package_signatures {
                manifest_valid = false;
                manifest_error = Some("清单未包含任何数字签名，被安全策略阻断".to_string());
            }
        } else if let Err(e) =
            manifest.verify_signatures_threshold(options.public_keys, options.signature_threshold)
        {
            manifest_valid = false;
            manifest_error = Some(format!("清单签名门限校验未通过: {e}"));
        }
    }

    let version = Some(manifest.version.to_string());
    let channel_count = manifest.channels.len();
    let mut package_reports = Vec::new();

    // 1. 核验根级默认包
    for (target, pkg) in &manifest.packages {
        let report = verify_single_offline_package(
            options.repository_dir,
            None,
            target,
            pkg,
            options.public_keys,
            options.require_package_signatures,
        );
        package_reports.push(report);
    }

    // 2. 核验各独立发布通道包
    for (channel_name, ch_info) in &manifest.channels {
        for (target, pkg) in &ch_info.packages {
            let report = verify_single_offline_package(
                options.repository_dir,
                Some(channel_name),
                target,
                pkg,
                options.public_keys,
                options.require_package_signatures,
            );
            package_reports.push(report);
        }
    }

    Ok(OfflineVerifyReport {
        manifest_path,
        manifest_valid,
        manifest_error,
        version,
        channel_count,
        package_reports,
    })
}

/// 内部私有辅助：核验单个包文件一致性与有效性
fn verify_single_offline_package(
    repository_dir: &Path,
    channel: Option<&str>,
    target: &str,
    pkg: &PackageInfo,
    public_keys: &[String],
    require_signature: bool,
) -> OfflinePackageReport {
    let local_file_path = resolve_local_package_path(repository_dir, &pkg.url);
    let mut report = OfflinePackageReport {
        target: target.to_string(),
        channel: channel.map(ToString::to_string),
        declared_url: pkg.url.clone(),
        resolved_local_path: local_file_path.clone(),
        package_type: pkg.package_type,
        file_exists: false,
        size_matched: false,
        actual_size: 0,
        expected_size: pkg.size,
        checksum_matched: false,
        actual_checksum: None,
        expected_checksum: pkg.checksum.clone(),
        signature_verified: None,
        failure_reason: None,
    };

    let Some(path) = local_file_path else {
        report.failure_reason = Some("包声明为不可离线解析的远程网络路径".to_string());
        return report;
    };

    if !path.exists() {
        report.failure_reason = Some(format!("安装包文件在本地磁盘缺失: {}", path.display()));
        return report;
    }
    report.file_exists = true;

    // 1. 体积校验
    let actual_size = match fs::metadata(&path) {
        Ok(meta) => meta.len(),
        Err(e) => {
            report.failure_reason = Some(format!("获取文件元数据失败: {e}"));
            return report;
        }
    };
    report.actual_size = actual_size;
    report.size_matched = match pkg.size {
        Some(expected) => expected == actual_size,
        None => true,
    };
    if !report.size_matched {
        report.failure_reason = Some(format!(
            "文件体积不匹配: 期望 {} 字节，实际 {} 字节",
            pkg.size.unwrap_or(0),
            actual_size
        ));
        return report;
    }

    // 2. SHA-256 完整性校验
    let actual_checksum = match compute_file_sha256_digest(&path) {
        Ok(digest) => bytes_to_hex(&digest),
        Err(e) => {
            report.failure_reason = Some(format!("计算 SHA-256 哈希失败: {e}"));
            return report;
        }
    };
    report.actual_checksum = Some(actual_checksum.clone());
    report.checksum_matched = match pkg.checksum.as_deref() {
        Some(expected) => expected.eq_ignore_ascii_case(&actual_checksum),
        None => true,
    };
    if !report.checksum_matched {
        report.failure_reason = Some("SHA-256 完整性校验和不匹配".to_string());
        return report;
    }

    // 3. 数字签名校验
    if !public_keys.is_empty() || require_signature {
        if let Some(ref sig) = pkg.signature {
            match verify_ed25519_file_any_key(&path, sig, public_keys) {
                Ok(()) => {
                    report.signature_verified = Some(true);
                }
                Err(e) => {
                    report.signature_verified = Some(false);
                    report.failure_reason = Some(format!("安装包 Ed25519 签名验证未通过: {e}"));
                }
            }
        } else if require_signature {
            report.signature_verified = Some(false);
            report.failure_reason =
                Some("策略要求必须包含签名，但包配置未声明数字签名".to_string());
        }
    }

    report
}

/// 解析相对包路径或本地 file:// 得到物理磁盘绝对路径
fn resolve_local_package_path(base_dir: &Path, raw_url: &str) -> Option<PathBuf> {
    let trimmed = raw_url.trim();
    if is_file_protocol(trimmed) {
        file_url_to_path(trimmed).ok()
    } else if !trimmed.contains("://") {
        let candidate = base_dir.join(trimmed);
        Some(candidate)
    } else {
        None
    }
}

/// 路径字符串的轻量百分号转义
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':' => {
                out.push(byte as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// 百分号解码辅助实现
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = hex_to_nibble(bytes[i + 1]);
            let low = hex_to_nibble(bytes[i + 2]);
            if let (Some(h), Some(l)) = (high, low) {
                decoded.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        decoded.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| input.to_string())
}

#[inline]
fn hex_to_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 将字节切片无依赖格式化为十六进制小写字符串
fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use semver::Version;
    use std::collections::BTreeMap;

    #[test]
    fn test_path_to_file_url_and_back() {
        let temp_dir = std::env::temp_dir();
        let sample_file = temp_dir.join("shipup_offline_test.bin");
        let file_url = path_to_file_url(&sample_file).expect("生成 file:// URL 失败");
        assert!(file_url.starts_with("file://"));

        let roundtrip_path = file_url_to_path(&file_url).expect("解析 file:// URL 失败");
        assert_eq!(roundtrip_path.file_name(), sample_file.file_name());
    }

    #[test]
    fn test_resolve_relative_file_url() {
        let base_url = "file:///tmp/releases/manifest.json";
        let relative_pkg = "myapp-1.0.0.tar.gz";
        let resolved = resolve_relative_file_url(base_url, relative_pkg).unwrap();
        assert!(resolved.contains("myapp-1.0.0.tar.gz"));
        assert!(resolved.starts_with("file://"));

        // 绝对网络 URL 原样返回
        let remote_url = "https://cdn.example.com/myapp.zip";
        let resolved_remote = resolve_relative_file_url(base_url, remote_url).unwrap();
        assert_eq!(resolved_remote, remote_url);
    }

    #[test]
    fn test_verify_offline_repository_complete_flow() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_offline_repo_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        // 1. 创建模拟二进制包文件
        let pkg_filename = "app-v2.0.0-x86_64.tar.gz";
        let pkg_path = temp_dir.join(pkg_filename);
        let pkg_content = b"Simulated application binary payload for offline testing";
        fs::write(&pkg_path, pkg_content).unwrap();

        let sha256 = bytes_to_hex(&compute_file_sha256_digest(&pkg_path).unwrap());
        let size = pkg_content.len() as u64;

        // 2. 构造离线 Manifest 清单
        let mut packages = BTreeMap::new();
        packages.insert(
            "x86_64-unknown-linux-gnu".to_string(),
            PackageInfo {
                url: pkg_filename.to_string(),
                size: Some(size),
                checksum: Some(sha256),
                signature: None,
                signatures: Vec::new(),
                package_type: PackageType::Archive,
                executable_path: None,
                install_args: Vec::new(),
                require_elevation: false,
                install_mode: None,
            },
        );

        let manifest = Manifest {
            version: Version::parse("2.0.0").unwrap(),
            min_supported_version: None,
            force_update: false,
            pub_date: None,
            notes: Some("离线测试更新".to_string()),
            packages,
            channels: BTreeMap::new(),
            signature: None,
            signatures: Vec::new(),
            rollout_percentage: None,
            expires_at: None,
            version_seq: Some(10),
        };

        let manifest_file = temp_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(&manifest_file, manifest_json).unwrap();

        // 3. 执行离线仓库完整性核验
        let options = OfflineVerifyOptions::new(&temp_dir);
        let report = verify_offline_repository(&options).unwrap();

        assert!(report.manifest_valid);
        assert_eq!(report.version.as_deref(), Some("2.0.0"));
        assert_eq!(report.package_reports.len(), 1);

        let pkg_rep = &report.package_reports[0];
        assert!(pkg_rep.file_exists);
        assert!(pkg_rep.size_matched);
        assert!(pkg_rep.checksum_matched);
        assert!(pkg_rep.is_valid());
        assert!(report.all_passed());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_verify_offline_repository_detects_tampering_and_missing() {
        let temp_dir =
            std::env::temp_dir().join(format!("test_offline_tamper_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let mut packages = BTreeMap::new();
        packages.insert(
            "x86_64-unknown-linux-gnu".to_string(),
            PackageInfo {
                url: "missing_file.zip".to_string(),
                size: Some(100),
                checksum: Some(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
                ),
                signature: None,
                signatures: Vec::new(),
                package_type: PackageType::Archive,
                executable_path: None,
                install_args: Vec::new(),
                require_elevation: false,
                install_mode: None,
            },
        );

        let manifest = Manifest {
            version: Version::parse("2.0.0").unwrap(),
            min_supported_version: None,
            force_update: false,
            pub_date: None,
            notes: None,
            packages,
            channels: BTreeMap::new(),
            signature: None,
            signatures: Vec::new(),
            rollout_percentage: None,
            expires_at: None,
            version_seq: None,
        };

        let manifest_file = temp_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(&manifest_file, manifest_json).unwrap();

        let options = OfflineVerifyOptions::new(&temp_dir);
        let report = verify_offline_repository(&options).unwrap();

        assert!(report.manifest_valid);
        assert!(!report.package_reports.is_empty());
        assert!(!report.package_reports[0].file_exists);
        assert!(!report.all_passed());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
