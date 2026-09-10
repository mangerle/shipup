// shipup-cli - 校验相关：Manifest 核验、清单展示与离线仓库审计

use crate::cli::{InspectArgs, VerifyArgs, VerifyRepoArgs};
use crate::util::{compute_payload_integrity, format_human_size};
use anyhow::{Context, Result, anyhow};
use shipup::Manifest;
use std::fs;

/// 执行 Manifest 元数据与本地物理包核验
pub(crate) fn handle_verify(args: &VerifyArgs) -> Result<()> {
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
pub(crate) fn handle_inspect(args: &InspectArgs) -> Result<()> {
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
    if let Some(ref exp) = manifest.expires_at {
        println!("失效时间 (Expires): {}", exp);
    }
    if let Some(seq) = manifest.version_seq {
        println!("版本序号 (Seq):     {}", seq);
    }

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

/// 执行离线更新源仓库的全量一致性安全审计
///
/// # 设计原理
/// - **实现初衷**：在单机离线环境或内网只读挂载源发布前，快速检验清单结构合法性、签名有效性及安装包完整性。
/// - **核心优势**：支持 TUF 门限验签，全流程流式哈希计算，输出清晰的架构与包健康度状态表。
/// - **代价与局限**：对大体积安装包计算校验和需消耗本地磁盘读取时间。
pub(crate) fn handle_verify_repo(args: &VerifyRepoArgs) -> Result<()> {
    log::info!(
        "开始对离线仓库执行全量一致性审计，目录: {}",
        args.repo_dir.display()
    );
    let mut options = shipup::OfflineVerifyOptions::new(&args.repo_dir);
    options.manifest_filename = Some(&args.manifest);
    options.public_keys = &args.public_keys;
    options.signature_threshold = args.threshold;
    options.require_package_signatures = args.require_signature;

    let report = shipup::verify_offline_repository(&options)
        .with_context(|| format!("离线仓库一致性审计执行失败: {}", args.repo_dir.display()))?;

    print_offline_verify_report(&report);

    if !report.all_passed() {
        return Err(anyhow!("离线更新仓库审计存在未通过项，禁止交付或部署"));
    }

    println!("所有安装包与元数据均通过强一致性核验，离线更新源状态健康");
    Ok(())
}

fn print_offline_verify_report(report: &shipup::OfflineVerifyReport) {
    println!("================= shipup 离线仓库一致性审计报告 =================");
    println!("清单路径:     {}", report.manifest_path.display());
    println!(
        "清单状态:     {}",
        if report.manifest_valid {
            "有效"
        } else {
            "非法 / 校验失败"
        }
    );
    if let Some(ref ver) = report.version {
        println!("目标版本:     {ver}");
    }
    if let Some(ref err) = report.manifest_error {
        println!("清单异常:     {err}");
    }
    println!("发布通道数:   {}", report.channel_count);
    println!("待核验安装包: {} 个", report.package_reports.len());
    println!("-----------------------------------------------------------------");

    for (idx, pkg) in report.package_reports.iter().enumerate() {
        let status_str = if pkg.is_valid() {
            "通过"
        } else {
            "未通过"
        };
        println!(
            "[{:02}] [{}] 架构: {} | 地址: {} | 格式: {:?}",
            idx + 1,
            status_str,
            pkg.target,
            pkg.declared_url,
            pkg.package_type
        );
        println!(
            "     文件存在: {} | 体积: {} 字节 (期望: {:?}) | SHA-256: {}",
            if pkg.file_exists { "是" } else { "缺失" },
            pkg.actual_size,
            pkg.expected_size,
            if pkg.checksum_matched {
                "匹配"
            } else {
                "不匹配"
            }
        );
        if let Some(sig_ok) = pkg.signature_verified {
            println!(
                "     数字签名: {}",
                if sig_ok {
                    "验证有效"
                } else {
                    "验签失败"
                }
            );
        }
        if let Some(ref reason) = pkg.failure_reason {
            println!("     阻断原因: {reason}");
        }
    }
    println!("=================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::handle_keygen;
    use semver::Version;
    use sha2::{Digest, Sha256};
    use shipup::{PackageInfo, PackageType};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn test_cli_verify_repo_command() -> Result<()> {
        let temp_dir =
            std::env::temp_dir().join(format!("test_cli_verify_repo_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        let pkg_file = temp_dir.join("sample-app-1.0.0.tar.gz");
        let pkg_bytes = b"sample content for offline repo verify";
        fs::write(&pkg_file, pkg_bytes)?;

        let mut hasher = Sha256::new();
        hasher.update(pkg_bytes);
        let hash = hasher.finalize();
        let mut sha256_hex = String::with_capacity(64);
        for b in hash {
            use std::fmt::Write;
            let _ = write!(sha256_hex, "{b:02x}");
        }

        let mut packages = BTreeMap::new();
        packages.insert(
            "x86_64-pc-windows-msvc".to_string(),
            PackageInfo {
                url: "sample-app-1.0.0.tar.gz".to_string(),
                mirrors: Vec::new(),
                size: Some(pkg_bytes.len() as u64),
                checksum: Some(sha256_hex),
                signature: None,
                signatures: Vec::new(),
                package_type: PackageType::Archive,
                executable_path: None,
                install_args: Vec::new(),
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                install_mode: None,
            },
        );

        let manifest = Manifest {
            version: Version::parse("1.0.0").unwrap(),
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
            version_seq: Some(1),
        };

        let manifest_path = temp_dir.join("manifest.json");
        let manifest_json = serde_json::to_string_pretty(&manifest)?;
        fs::write(&manifest_path, manifest_json)?;

        handle_verify_repo(&VerifyRepoArgs {
            repo_dir: temp_dir.clone(),
            manifest: "manifest.json".to_string(),
            public_keys: Vec::new(),
            threshold: 1,
            require_signature: false,
        })?;

        fs::write(&pkg_file, b"tampered content")?;
        let err = handle_verify_repo(&VerifyRepoArgs {
            repo_dir: temp_dir.clone(),
            manifest: "manifest.json".to_string(),
            public_keys: Vec::new(),
            threshold: 1,
            require_signature: false,
        });
        assert!(err.is_err());

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_handle_verify_checksum_mismatch() -> Result<()> {
        let temp_dir =
            std::env::temp_dir().join(format!("test_cli_verify_mismatch_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        let pkg = temp_dir.join("app.bin");
        fs::write(&pkg, b"actual-content")?;

        let mut packages = BTreeMap::new();
        packages.insert(
            shipup::current_target_triple().to_string(),
            PackageInfo {
                url: "https://example.com/app.bin".to_string(),
                mirrors: Vec::new(),
                size: None,
                checksum: Some("sha256:00".to_string()),
                signature: None,
                signatures: Vec::new(),
                package_type: PackageType::Binary,
                executable_path: None,
                install_args: Vec::new(),
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                install_mode: None,
            },
        );

        let manifest = Manifest {
            version: Version::parse("1.0.0").unwrap(),
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
        let manifest_path = temp_dir.join("manifest.json");
        fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

        let res = handle_verify(&VerifyArgs {
            manifest: manifest_path,
            package: pkg,
            target: Some(shipup::current_target_triple().to_string()),
            channel: None,
            public_key_file: None,
            public_key: None,
        });
        assert!(res.is_err());

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_handle_keygen_creates_keypair() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!("test_cli_keygen_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        handle_keygen(&temp_dir)?;
        assert!(temp_dir.join("ed25519.key").exists());
        assert!(temp_dir.join("ed25519.pub").exists());
        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    // 保持 PathBuf 引用避免未使用告警（测试内部路径构造）
    #[allow(dead_code)]
    fn _unused(_: PathBuf) {}
}
