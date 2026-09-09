// shipup 跨平台自更新系统 - 核心逻辑单元与集成测试

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use semver::Version;
use shipup::Updater;
use shipup::manifest::{ChannelInfo, Manifest, PackageInfo, PackageType};
use shipup::signature::{verify_ed25519, verify_sha256};
use std::collections::HashMap;

#[test]
fn test_manifest_serialization_and_routing() {
    let mut packages = HashMap::new();
    packages.insert(
        "x86_64-pc-windows-msvc".to_string(),
        PackageInfo {
            url: "https://example.com/app-1.2.0.exe".to_string(),
            signature: Some("test-signature".to_string()),
            checksum: Some("sha256:abcd".to_string()),
            package_type: PackageType::Binary,
            install_args: vec![],
            executable_path: None,
            require_elevation: false,
        },
    );

    let mut channels = HashMap::new();
    let mut beta_packages = HashMap::new();
    beta_packages.insert(
        "x86_64-pc-windows-msvc".to_string(),
        PackageInfo {
            url: "https://example.com/app-1.3.0-beta.exe".to_string(),
            signature: None,
            checksum: None,
            package_type: PackageType::Installer,
            install_args: vec!["/S".to_string()],
            executable_path: None,
            require_elevation: true,
        },
    );

    channels.insert(
        "beta".to_string(),
        ChannelInfo {
            version: Version::parse("1.3.0-beta.1").unwrap(),
            min_supported_version: Some(Version::parse("1.1.0").unwrap()),
            force_update: false,
            pub_date: None,
            notes: Some("测试 Beta 通道".to_string()),
            packages: beta_packages,
        },
    );

    let manifest = Manifest {
        version: Version::parse("1.2.0").unwrap(),
        min_supported_version: Some(Version::parse("1.0.0").unwrap()),
        force_update: false,
        pub_date: Some("2026-09-08T12:00:00Z".to_string()),
        notes: Some("常规版本更新".to_string()),
        packages,
        channels,
    };

    // 序列化为 JSON
    let json_str = serde_json::to_string_pretty(&manifest).expect("序列化失败");
    let deserialized: Manifest = Manifest::from_json_str(&json_str).expect("反序列化失败");

    assert_eq!(deserialized.version, Version::parse("1.2.0").unwrap());

    // 路由默认稳定版
    let current_ver = Version::parse("1.0.5").unwrap();
    let release = deserialized
        .resolve(&shipup::ResolveOptions {
            channel: None,
            target: "x86_64-pc-windows-msvc",
            current_version: &current_ver,
        })
        .expect("路由失败");
    assert_eq!(release.version, Version::parse("1.2.0").unwrap());
    assert!(!release.is_mandatory);

    // 路由测试低于 min_supported_version 时的强制更新判定
    let old_ver = Version::parse("0.9.0").unwrap();
    let release_mandatory = deserialized
        .resolve(&shipup::ResolveOptions {
            channel: None,
            target: "x86_64-pc-windows-msvc",
            current_version: &old_ver,
        })
        .expect("路由失败");
    assert!(release_mandatory.is_mandatory);

    // 路由特定通道 (beta)
    let release_beta = deserialized
        .resolve(&shipup::ResolveOptions {
            channel: Some("beta"),
            target: "x86_64-pc-windows-msvc",
            current_version: &current_ver,
        })
        .expect("路由 beta 失败");
    assert_eq!(
        release_beta.version,
        Version::parse("1.3.0-beta.1").unwrap()
    );
    assert_eq!(release_beta.package.package_type, PackageType::Installer);
}

#[test]
fn test_sha256_verification() {
    let payload = b"Hello, shipup auto updater!";
    // echo -n "Hello, shipup auto updater!" | sha256sum
    // a1542f53d7ca906fddb26be2378f8cb080b08faeefbe5d5a711ef06e1291b5c4
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let hash = hasher.finalize();
    let mut hex = String::with_capacity(hash.len() * 2);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    let expected = format!("sha256:{hex}");

    assert!(verify_sha256(payload, &expected).is_ok());
    assert!(
        verify_sha256(
            payload,
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )
        .is_err()
    );
}

#[test]
fn test_ed25519_sign_and_verify() {
    let payload = b"critical-binary-content-to-be-updated";

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("获取随机数种子失败");
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let sig = signing_key.sign(payload);
    let sig_b64 = BASE64.encode(sig.to_bytes());
    let pub_b64 = BASE64.encode(verifying_key.to_bytes());

    // 验证正常签名
    let result = verify_ed25519(payload, &sig_b64, &pub_b64);
    assert!(result.is_ok(), "Ed25519 验签应当成功通过");

    // 篡改数据内容后验签应当失败
    let tampered = b"tampered-binary-content";
    let tampered_result = verify_ed25519(tampered, &sig_b64, &pub_b64);
    assert!(tampered_result.is_err(), "篡改数据后验签必须失败");
}

#[test]
fn test_updater_builder_configuration() {
    let builder = Updater::builder()
        .current_version("1.0.0")
        .unwrap()
        .manifest_url("https://updates.example.com/latest.json")
        .channel("beta")
        .header("Authorization", "Bearer token-abc")
        .proxy("http://127.0.0.1:8888")
        .allow_downgrade(true);

    let updater = builder.build().expect("构建 Updater 失败");
    // 验证构建成功
    drop(updater);
}

#[test]
fn test_zip_slip_attack_prevention() {
    use std::fs::{self, File};
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    let temp_dir = std::env::temp_dir().join(format!("shipup_zip_slip_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let malicious_zip = temp_dir.join("malicious.zip");
    let sandbox = temp_dir.join("sandbox");
    fs::create_dir_all(&sandbox).unwrap();

    // 构造包含路径逃逸的 Zip 文件
    {
        let file = File::create(&malicious_zip).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default();
        zip.start_file("../evil.exe", options).unwrap();
        zip.write_all(b"malicious payload").unwrap();
        zip.finish().unwrap();
    }

    // 尝试解压恶意 Zip，验证 Zip Slip 防护生效
    let res = shipup::archive::extract_archive(&malicious_zip, &sandbox, Some("evil.exe"));
    assert!(res.is_err());
    match res {
        Err(shipup::UpdateError::ZipSlipViolation(path)) => {
            assert!(path.contains("evil.exe"));
        }
        other => panic!("期望 ZipSlipViolation 错误，实际为: {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_decompression_bomb_mitigation() {
    use std::fs::{self, File};
    use std::io::Write;
    use zip::CompressionMethod;
    use zip::write::SimpleFileOptions;

    let temp_dir = std::env::temp_dir().join(format!("shipup_bomb_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let bomb_zip = temp_dir.join("bomb.zip");
    let sandbox = temp_dir.join("sandbox");
    fs::create_dir_all(&sandbox).unwrap();

    // 构造高压缩比的解压炸弹（500KB 重复数据）
    {
        let file = File::create(&bomb_zip).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("large.bin", options).unwrap();
        let zero_buffer = [0u8; 1024];
        for _ in 0..500 {
            zip.write_all(&zero_buffer).unwrap();
        }
        zip.finish().unwrap();
    }

    // 解压时体积膨胀倍率将超过 10 倍的安全上限，触发熔断
    let res = shipup::archive::extract_archive(&bomb_zip, &sandbox, Some("large.bin"));
    assert!(res.is_err());
    match res {
        Err(shipup::UpdateError::ArchiveExtract(msg)) => {
            assert!(msg.contains("防解压炸弹机制已熔断"));
        }
        other => panic!("期望解压炸弹熔断错误，实际为: {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_invalid_signature_and_checksum_mismatch() {
    use shipup::UpdateError;

    let payload = b"legitimate application data";
    // 篡改校验值
    let invalid_checksum = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let chk_res = verify_sha256(payload, invalid_checksum);
    assert!(matches!(chk_res, Err(UpdateError::ChecksumMismatch { .. })));

    // 伪造公钥或篡改签名内容
    let dummy_sig = BASE64.encode([1u8; 64]);
    let dummy_pub = BASE64.encode([2u8; 32]);
    let sig_res = verify_ed25519(payload, &dummy_sig, &dummy_pub);
    assert!(matches!(sig_res, Err(UpdateError::InvalidSignature)));
}
