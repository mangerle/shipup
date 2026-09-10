// shipup 跨平台自更新系统 - Manifest 跨实例与多源交叉验签防回归护栏测试

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use shipup::manifest::{ChannelInfo, Manifest, PackageInfo, PackageType, ResolveOptions};
use std::collections::BTreeMap;

#[test]
fn test_heterogeneous_json_field_ordering_canonical_determinism() {
    let mut signing_seed = [0u8; 32];
    getrandom::fill(&mut signing_seed).unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = BASE64.encode(verifying_key.to_bytes());

    // JSON A: 字段与包按照 Windows -> Linux -> macOS 排布
    let json_a = r#"{
        "version": "2.1.0",
        "force_update": true,
        "packages": {
            "x86_64-pc-windows-msvc": {
                "url": "https://cdn.example.com/app-win.exe",
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "package_type": "installer"
            },
            "x86_64-unknown-linux-gnu": {
                "url": "https://cdn.example.com/app-linux.tar.gz",
                "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "package_type": "archive"
            },
            "aarch64-apple-darwin": {
                "url": "https://cdn.example.com/app-mac.zip",
                "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "package_type": "archive"
            }
        },
        "channels": {
            "beta": {
                "version": "2.2.0-beta.1",
                "packages": {
                    "x86_64-pc-windows-msvc": {
                        "url": "https://cdn.example.com/beta-win.exe",
                        "package_type": "installer"
                    }
                }
            }
        }
    }"#;

    // JSON B: 故意打乱所有键值顺序（macOS -> Windows -> Linux），并调整顶层字段顺序
    let json_b = r#"{
        "channels": {
            "beta": {
                "packages": {
                    "x86_64-pc-windows-msvc": {
                        "package_type": "installer",
                        "url": "https://cdn.example.com/beta-win.exe"
                    }
                },
                "version": "2.2.0-beta.1"
            }
        },
        "force_update": true,
        "packages": {
            "aarch64-apple-darwin": {
                "package_type": "archive",
                "hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "url": "https://cdn.example.com/app-mac.zip"
            },
            "x86_64-pc-windows-msvc": {
                "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "url": "https://cdn.example.com/app-win.exe",
                "package_type": "installer"
            },
            "x86_64-unknown-linux-gnu": {
                "package_type": "archive",
                "url": "https://cdn.example.com/app-linux.tar.gz",
                "hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        },
        "version": "2.1.0"
    }"#;

    let instance_a = Manifest::from_json_str(json_a).unwrap();
    let mut instance_b = Manifest::from_json_str(json_b).unwrap();

    let bytes_a = instance_a.compute_canonical_bytes().unwrap();
    let bytes_b = instance_b.compute_canonical_bytes().unwrap();

    // 防回归核心断言：无论来源 JSON 文本中的键值如何排列，基于 BTreeMap 生成的规范化序列化字节必须逐字节恒等
    assert_eq!(
        bytes_a, bytes_b,
        "异构乱序 JSON 经独立反序列化生成的规范化字节序列必须完全一致"
    );

    // 由实例 A 的字节生成签名并附加至实例 B
    let signature = signing_key.sign(&bytes_a);
    instance_b.signature = Some(BASE64.encode(signature.to_bytes()));

    // 实例 B 验签必须顺利通过
    assert!(
        instance_b.verify_signature(&[&pubkey_b64]).is_ok(),
        "乱序 JSON 实例之间交叉验签必须成功放行"
    );
}

#[test]
fn test_tamper_detection_on_any_nested_manifest_component() {
    let mut signing_seed = [0u8; 32];
    getrandom::fill(&mut signing_seed).unwrap();
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = BASE64.encode(verifying_key.to_bytes());

    let mut base_manifest = Manifest {
        version: Version::parse("1.0.0").unwrap(),
        min_supported_version: None,
        force_update: false,
        pub_date: Some("2026-09-09T00:00:00Z".to_string()),
        notes: Some("初始版本说明".to_string()),
        packages: {
            let mut m = BTreeMap::new();
            m.insert(
                "x86_64-pc-windows-msvc".to_string(),
                PackageInfo {
                    url: "https://example.com/app.exe".to_string(),
                    mirrors: vec![],
                    signature: None,
                    signatures: vec![],
                    checksum: Some("abcd".to_string()),
                    package_type: PackageType::Installer,
                    install_mode: None,
                    install_args: vec!["/S".to_string()],
                    executable_path: None,
                    require_elevation: false,
                    wait_for_exit: false,
                    payload_checksums: Default::default(),
                    size: None,
                },
            );
            m
        },
        channels: {
            let mut c = BTreeMap::new();
            c.insert(
                "beta".to_string(),
                ChannelInfo {
                    version: Version::parse("1.1.0-beta.1").unwrap(),
                    min_supported_version: None,
                    force_update: false,
                    pub_date: None,
                    notes: None,
                    packages: BTreeMap::new(),
                    rollout_percentage: None,
                },
            );
            c
        },
        signature: None,
        signatures: vec![],
        rollout_percentage: Some(50),
        expires_at: Some("2030-01-01T00:00:00Z".to_string()),
        version_seq: Some(1),
    };

    let canonical_bytes = base_manifest.compute_canonical_bytes().unwrap();
    let sig_b64 = BASE64.encode(signing_key.sign(&canonical_bytes).to_bytes());
    base_manifest.signature = Some(sig_b64);

    // 初始合法状态验签通过
    assert!(base_manifest.verify_signature(&[&pubkey_b64]).is_ok());

    // 1. 篡改顶层字段
    {
        let mut t = base_manifest.clone();
        t.version = Version::parse("1.0.1").unwrap();
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }
    {
        let mut t = base_manifest.clone();
        t.force_update = true;
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }
    {
        let mut t = base_manifest.clone();
        t.rollout_percentage = Some(100);
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }

    // 2. 篡改深层 package 内部字段
    {
        let mut t = base_manifest.clone();
        t.packages.get_mut("x86_64-pc-windows-msvc").unwrap().url =
            "https://hacked.com/evil.exe".to_string();
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }
    {
        let mut t = base_manifest.clone();
        t.packages
            .get_mut("x86_64-pc-windows-msvc")
            .unwrap()
            .install_args = vec!["/SILENT".to_string(), "--malicious".to_string()];
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }

    // 3. 篡改 channel 内部字段
    {
        let mut t = base_manifest.clone();
        t.channels.get_mut("beta").unwrap().version = Version::parse("1.1.0-beta.2").unwrap();
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }

    // 4. 增删包字典项
    {
        let mut t = base_manifest.clone();
        t.packages.insert(
            "aarch64-apple-darwin".to_string(),
            PackageInfo {
                url: "https://example.com/app-mac.zip".to_string(),
                mirrors: vec![],
                signature: None,
                signatures: vec![],
                checksum: None,
                package_type: PackageType::Archive,
                install_mode: None,
                install_args: Vec::new(),
                executable_path: None,
                require_elevation: false,
                wait_for_exit: false,
                payload_checksums: Default::default(),
                size: None,
            },
        );
        assert!(t.verify_signature(&[&pubkey_b64]).is_err());
    }
}

#[test]
fn test_end_to_end_publisher_client_cross_sign_and_verify() {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let signing_key = SigningKey::from_bytes(&seed);
    let pubkey_b64 = BASE64.encode(signing_key.verifying_key().to_bytes());

    // 模拟服务端构建发布清单
    let mut server_manifest = Manifest {
        version: Version::parse("3.0.0").unwrap(),
        min_supported_version: Some(Version::parse("1.0.0").unwrap()),
        force_update: false,
        pub_date: Some("2026-09-09T12:00:00Z".to_string()),
        notes: Some("新版正式发布".to_string()),
        packages: {
            let mut pkgs = BTreeMap::new();
            pkgs.insert(
                "x86_64-unknown-linux-gnu".to_string(),
                PackageInfo {
                    url: "https://release.example.com/app-v3.0.0-linux.tar.gz".to_string(),
                    mirrors: vec![],
                    signature: None,
                    signatures: vec![],
                    checksum: Some(
                        "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
                            .to_string(),
                    ),
                    package_type: PackageType::Archive,
                    install_mode: None,
                    executable_path: Some("bin/app".to_string()),
                    install_args: Vec::new(),
                    require_elevation: false,
                    wait_for_exit: false,
                    payload_checksums: Default::default(),
                    size: None,
                },
            );
            pkgs
        },
        channels: BTreeMap::new(),
        signature: None,
        signatures: vec![],
        rollout_percentage: None,
        expires_at: Some("2028-12-31T23:59:59Z".to_string()),
        version_seq: Some(100),
    };

    // 发布端签名
    let canonical = server_manifest.compute_canonical_bytes().unwrap();
    let sig = signing_key.sign(&canonical);
    server_manifest.signature = Some(BASE64.encode(sig.to_bytes()));

    // 服务端序列化为最终通过网络发布的 JSON 字符串
    let published_json = serde_json::to_string_pretty(&server_manifest).unwrap();

    // 客户端接收并解析该 JSON 字符串
    let client_manifest = Manifest::from_json_str(&published_json).unwrap();

    // 客户端执行候选公钥验签
    assert!(client_manifest.verify_signature(&[&pubkey_b64]).is_ok());

    // 客户端解析版本路由
    let current_ver = Version::parse("2.5.0").unwrap();
    let opts = ResolveOptions {
        channel: None,
        target: "x86_64-unknown-linux-gnu",
        current_version: &current_ver,
    };
    let release = client_manifest.resolve(&opts).unwrap();
    assert_eq!(release.version, Version::parse("3.0.0").unwrap());
    assert_eq!(
        release.package.url,
        "https://release.example.com/app-v3.0.0-linux.tar.gz"
    );
}
