//! Manifest 模块单元测试。
//!
//! # 模块职责
//! 覆盖 Target 别名归一化、通道路由严格性、包字段默认值反序列化、
//! 规范化字节确定性、单签/门限多签验签、RFC 3339 解析与清单时效性校验。

use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use std::collections::BTreeMap;

use super::resolve::normalize_target;
use crate::error::UpdateError;

#[test]
fn test_normalize_target_libc_and_env_distinction() {
    // 验证 Linux 下保留 musl 与 gnu 区分
    assert_eq!(
        normalize_target("x86_64-unknown-linux-musl"),
        "linux-x86-64-musl"
    );
    assert_eq!(
        normalize_target("x86_64-unknown-linux-gnu"),
        "linux-x86-64-gnu"
    );
    assert_ne!(
        normalize_target("x86_64-unknown-linux-musl"),
        normalize_target("x86_64-unknown-linux-gnu")
    );

    // 验证 Windows 下保留 msvc 与 gnu 区分
    assert_eq!(
        normalize_target("x86_64-pc-windows-msvc"),
        "windows-x86-64-msvc"
    );
    assert_eq!(
        normalize_target("x86_64-pc-windows-gnu"),
        "windows-x86-64-gnu"
    );
    assert_ne!(
        normalize_target("x86_64-pc-windows-msvc"),
        normalize_target("x86_64-pc-windows-gnu")
    );
}

#[test]
fn test_channel_resolution_strictness() {
    let mut packages = BTreeMap::new();
    packages.insert(
        "x86_64-pc-windows-msvc".to_string(),
        PackageInfo {
            url: "https://example.com/app.exe".to_string(),
            mirrors: vec![],
            signature: None,
            signatures: vec![],
            checksum: None,
            package_type: PackageType::Binary,
            install_mode: None,
            install_args: vec![],
            executable_path: None,
            require_elevation: false,
            wait_for_exit: false,
            payload_checksums: Default::default(),
            size: None,
        },
    );

    let mut channels = BTreeMap::new();
    let mut beta_packages = BTreeMap::new();
    beta_packages.insert(
        "x86_64-unknown-linux-gnu".to_string(),
        PackageInfo {
            url: "https://example.com/app-linux.tar.gz".to_string(),
            mirrors: vec![],
            signature: None,
            signatures: vec![],
            checksum: None,
            package_type: PackageType::Archive,
            install_mode: None,
            install_args: vec![],
            executable_path: None,
            require_elevation: false,
            wait_for_exit: false,
            payload_checksums: Default::default(),
            size: None,
        },
    );

    channels.insert(
        "beta".to_string(),
        ChannelInfo {
            version: Version::parse("2.0.0-beta.1").unwrap(),
            min_supported_version: None,
            force_update: false,
            pub_date: None,
            notes: None,
            packages: beta_packages,
            rollout_percentage: None,
        },
    );

    let manifest = Manifest {
        version: Version::parse("1.0.0").unwrap(),
        min_supported_version: None,
        force_update: false,
        pub_date: None,
        notes: None,
        packages,
        channels,
        signature: None,
        signatures: vec![],
        rollout_percentage: None,
        expires_at: None,
        version_seq: None,
    };

    let current_ver = Version::parse("1.0.0").unwrap();

    // 1. 指定不存在的通道，应返回错误而不是静默穿透回退
    let not_found_channel = manifest.resolve(&ResolveOptions {
        channel: Some("alpha"),
        target: "x86_64-pc-windows-msvc",
        current_version: &current_ver,
    });
    assert!(matches!(
        not_found_channel,
        Err(UpdateError::ManifestParse(_))
    ));

    // 2. 通道存在但无当前目标平台的更新包，严禁静默回退到稳定版主通道
    let platform_missing = manifest.resolve(&ResolveOptions {
        channel: Some("beta"),
        target: "x86_64-pc-windows-msvc",
        current_version: &current_ver,
    });
    assert!(matches!(
        platform_missing,
        Err(UpdateError::PlatformNotFound(_))
    ));

    // 3. 通道与平台均匹配，成功返回
    let matched = manifest.resolve(&ResolveOptions {
        channel: Some("beta"),
        target: "x86_64-unknown-linux-gnu",
        current_version: &current_ver,
    });
    assert!(matched.is_ok());
    assert_eq!(
        matched.unwrap().version,
        Version::parse("2.0.0-beta.1").unwrap()
    );
}

#[test]
fn test_package_info_require_elevation_default_and_deserialize() {
    // 旧版本 JSON 不含 require_elevation 时默认反序列化为 false
    let legacy_json = r#"{"url":"https://example.com/setup.exe","package_type":"installer"}"#;
    let pkg: PackageInfo = serde_json::from_str(legacy_json).unwrap();
    assert!(!pkg.require_elevation);

    // 新版本 JSON 显式指定 require_elevation 为 true
    let elevated_json = r#"{"url":"https://example.com/setup.exe","package_type":"installer","require_elevation":true}"#;
    let elevated_pkg: PackageInfo = serde_json::from_str(elevated_json).unwrap();
    assert!(elevated_pkg.require_elevation);
}

#[test]
fn test_package_info_install_mode_deserialize() {
    // 1. 未配置 install_mode 默认解析为 None
    let default_json = r#"{"url":"https://example.com/setup.msi","package_type":"installer"}"#;
    let default_pkg: PackageInfo = serde_json::from_str(default_json).unwrap();
    assert_eq!(default_pkg.install_mode, None);

    // 2. 显式配置 passive
    let passive_json = r#"{"url":"https://example.com/setup.msi","package_type":"installer","install_mode":"passive"}"#;
    let passive_pkg: PackageInfo = serde_json::from_str(passive_json).unwrap();
    assert_eq!(passive_pkg.install_mode, Some(InstallMode::Passive));

    // 3. 显式配置 quiet
    let quiet_json = r#"{"url":"https://example.com/setup.msi","package_type":"installer","install_mode":"quiet"}"#;
    let quiet_pkg: PackageInfo = serde_json::from_str(quiet_json).unwrap();
    assert_eq!(quiet_pkg.install_mode, Some(InstallMode::Quiet));

    // 4. 显式配置 basicUi (camelCase)
    let basic_json = r#"{"url":"https://example.com/setup.msi","package_type":"installer","install_mode":"basicUi"}"#;
    let basic_pkg: PackageInfo = serde_json::from_str(basic_json).unwrap();
    assert_eq!(basic_pkg.install_mode, Some(InstallMode::BasicUi));
}

#[test]
fn test_manifest_self_signature_verification() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer, SigningKey};

    let mut signing_seed = [0u8; 32];
    getrandom::fill(&mut signing_seed).unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = BASE64.encode(verifying_key.to_bytes());

    let mut manifest = Manifest {
        version: Version::parse("3.0.0").unwrap(),
        min_supported_version: None,
        force_update: false,
        pub_date: None,
        notes: Some("清单签名测试".to_string()),
        packages: BTreeMap::new(),
        channels: BTreeMap::new(),
        signature: None,
        signatures: vec![],
        rollout_percentage: None,
        expires_at: None,
        version_seq: None,
    };

    // 计算规范字节并进行签名
    let canonical_bytes = manifest.compute_canonical_bytes().unwrap();
    let sig = signing_key.sign(&canonical_bytes);
    manifest.signature = Some(BASE64.encode(sig.to_bytes()));

    // 验证签名通过
    assert!(manifest.verify_signature(&[pubkey_b64]).is_ok());

    // 篡改清单版本号后验签失败
    manifest.version = Version::parse("3.0.1").unwrap();
    assert!(manifest.verify_signature(&["invalid_key"]).is_err());
}

#[test]
fn test_cross_instance_manifest_canonical_determinism_and_verification() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ed25519_dalek::{Signer, SigningKey};

    let mut signing_seed = [0u8; 32];
    getrandom::fill(&mut signing_seed).unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = BASE64.encode(verifying_key.to_bytes());

    // 模拟包含多个乱序平台与通道的 JSON 清单文本
    let manifest_json = r#"{
        "version": "1.5.0",
        "force_update": false,
        "packages": {
            "x86_64-pc-windows-msvc": {
                "url": "https://example.com/app-win-x64.exe",
                "package_type": "binary"
            },
            "aarch64-unknown-linux-gnu": {
                "url": "https://example.com/app-linux-arm64.tar.gz",
                "package_type": "archive"
            },
            "x86_64-apple-darwin": {
                "url": "https://example.com/app-mac-x64.zip",
                "package_type": "archive"
            },
            "aarch64-apple-darwin": {
                "url": "https://example.com/app-mac-arm64.zip",
                "package_type": "archive"
            }
        },
        "channels": {
            "beta": {
                "version": "1.6.0-beta.1",
                "force_update": false,
                "packages": {
                    "x86_64-pc-windows-msvc": {
                        "url": "https://example.com/app-beta.exe",
                        "package_type": "binary"
                    }
                }
            }
        }
    }"#;

    // 跨实例反序列化实例 A 与实例 B
    let instance_a: Manifest = serde_json::from_str(manifest_json).unwrap();
    let mut instance_b: Manifest = serde_json::from_str(manifest_json).unwrap();

    // 断言规范化字节序列跨实例具备绝对确定性
    let bytes_a = instance_a.compute_canonical_bytes().unwrap();
    let bytes_b = instance_b.compute_canonical_bytes().unwrap();
    assert_eq!(bytes_a, bytes_b, "不同实例生成的规范化字节序列必须完全一致");

    // 由实例 A 的字节生成数字签名
    let sig = signing_key.sign(&bytes_a);
    let sig_b64 = BASE64.encode(sig.to_bytes());

    // 将签名赋予新实例 B，验证其实例跨越反序列化仍可成功验签
    instance_b.signature = Some(sig_b64);
    assert!(
        instance_b.verify_signature(&[pubkey_b64]).is_ok(),
        "跨实例反序列化后验签必须成功通过"
    );
}

#[test]
fn test_parse_rfc3339_to_unix() {
    // 标准纪元原点
    assert_eq!(parse_rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
    // 2026 年已知时间戳 (1767225600)
    assert_eq!(
        parse_rfc3339_to_unix("2026-01-01T00:00:00Z"),
        Some(1767225600)
    );
    // 边界非法格式返回 None
    assert_eq!(parse_rfc3339_to_unix("invalid-timestamp"), None);
    assert_eq!(parse_rfc3339_to_unix("1969-12-31T23:59:59Z"), None);
}

#[test]
fn test_manifest_expires_at_and_freshness_verification() {
    let mut manifest = Manifest {
        version: Version::parse("2.0.0").unwrap(),
        min_supported_version: None,
        force_update: false,
        pub_date: None,
        notes: None,
        packages: BTreeMap::new(),
        channels: BTreeMap::new(),
        signature: None,
        signatures: vec![],
        rollout_percentage: None,
        expires_at: Some("2026-01-01T00:00:00Z".to_string()),
        version_seq: Some(10),
    };

    // 1. 在过期时间之前评估，应当成功通过
    assert!(manifest.verify_freshness(1767225599).is_ok());

    // 2. 达到或超过过期时间评估，应当返回 ManifestExpired
    let err = manifest.verify_freshness(1767225601);
    assert!(matches!(err, Err(UpdateError::ManifestExpired(_))));

    // 3. 未设置 expires_at 时恒定放行
    manifest.expires_at = None;
    assert!(manifest.verify_freshness(9999999999).is_ok());
}

#[test]
fn test_manifest_threshold_signatures() {
    let key1 = SigningKey::from_bytes(&[101u8; 32]);
    let key2 = SigningKey::from_bytes(&[102u8; 32]);
    let key3 = SigningKey::from_bytes(&[103u8; 32]);

    let pk1 = BASE64.encode(key1.verifying_key().to_bytes());
    let pk2 = BASE64.encode(key2.verifying_key().to_bytes());
    let pk3 = BASE64.encode(key3.verifying_key().to_bytes());

    let mut manifest = Manifest {
        version: Version::parse("4.0.0").unwrap(),
        min_supported_version: None,
        force_update: false,
        pub_date: None,
        notes: Some("门限多签清单测试".to_string()),
        packages: BTreeMap::new(),
        channels: BTreeMap::new(),
        signature: None,
        signatures: vec![],
        rollout_percentage: None,
        expires_at: None,
        version_seq: None,
    };

    let canonical = manifest.compute_canonical_bytes().unwrap();
    let sig1 = BASE64.encode(key1.sign(&canonical).to_bytes());
    let sig2 = BASE64.encode(key2.sign(&canonical).to_bytes());

    manifest.signatures = vec![
        SignatureEntry {
            key_id: Some("signer-1".to_string()),
            signature: sig1,
        },
        SignatureEntry {
            key_id: Some("signer-2".to_string()),
            signature: sig2,
        },
    ];

    // 2-of-3 门限多签验证成功
    assert!(
        manifest
            .verify_signatures_threshold(&[pk1.clone(), pk2.clone(), pk3.clone()], 2)
            .is_ok()
    );

    // 门限提高为 3（需要 3 个签名），验证必须失败
    let err_3 = manifest.verify_signatures_threshold(&[pk1, pk2, pk3], 3);
    assert!(matches!(err_3, Err(UpdateError::ThresholdNotMet { .. })));
}

#[test]
fn test_package_info_mirrors_deserialize_and_default() {
    // 1. 未显式提供 mirrors 时，默认解析为空向量
    let json_default = r#"{
        "url": "https://example.com/app.tar.gz",
        "package_type": "archive"
    }"#;
    let pkg_default: PackageInfo = serde_json::from_str(json_default).unwrap();
    assert!(pkg_default.mirrors.is_empty());

    // 2. 显式提供 mirrors 数组时正常反序列化
    let json_mirrors = r#"{
        "url": "https://example.com/app.tar.gz",
        "mirrors": [
            "https://mirror1.example.com/app.tar.gz",
            "https://mirror2.example.com/app.tar.gz"
        ],
        "package_type": "archive"
    }"#;
    let pkg_mirrors: PackageInfo = serde_json::from_str(json_mirrors).unwrap();
    assert_eq!(pkg_mirrors.mirrors.len(), 2);
    assert_eq!(
        pkg_mirrors.mirrors[0],
        "https://mirror1.example.com/app.tar.gz"
    );
    assert_eq!(
        pkg_mirrors.mirrors[1],
        "https://mirror2.example.com/app.tar.gz"
    );
}
