// shipup 跨平台自更新系统 - 核心逻辑单元与集成测试

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::OsRng;
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
    let expected = format!("sha256:{:x}", hasher.finalize());

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

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
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
        .allow_downgrade(true);

    let updater = builder.build().expect("构建 Updater 失败");
    // 验证构建成功
    drop(updater);
}
