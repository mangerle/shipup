//! 发布相关命令模块：密钥生成、单包/批量发布、独立签名与配置脚手架。
//!
//! # 模块职责
//! 实现 `keygen`、`release`、`init`、`sign` 四个子命令，
//! 覆盖从首次接入到日常发布的完整链路：
//! 生成 Ed25519 密钥对、计算包体哈希并写入清单、对既有清单做增量更新、生成发布配置脚手架。
//!
//! # 子模块划分
//! - [`keygen`]：Ed25519 密钥对生成；
//! - [`single`]：单包命令行发布路径（`release` 未指定 `--config` 时）；
//! - [`batch`]：基于 TOML 配置的跨平台批量发布；
//! - [`sign`]：对既有包体补充独立签名；
//! - [`init`]：生成发布配置脚手架；
//! - [`manifest_io`]：清单读写、条目合并与通用解析工具；
//! - [`types`]：发布链路共享的数据类型定义。
//!
//! # 设计原理
//! - **实现初衷**：发布动作必须是「可重复、可校验、可增量」的：
//!   同一版本反复发布不应产生内容漂移，多平台发布不应互相覆盖，补发单个平台不应重算全部平台。
//! - **核心优势**：
//!   - 批量发布以平台为键合并写入，已存在的其他平台条目原样保留，天然支持「分平台分流水线发布」；
//!   - 清单读取失败时区分「文件不存在」与「内容损坏」两种情况：
//!     前者允许初始化新清单，后者必须报错，杜绝静默覆盖既有发布记录；
//!   - 私钥仅在签署瞬间读取，不写入任何日志或错误上下文。
//! - **代价与局限**：批量模式按顺序处理配置中的平台条目，超大发布矩阵下耗时线性增长。
//!
//! # 安全契约
//! 私钥文件路径与内容严禁出现在任何日志输出中；
//! 生成的清单必须经过一次自校验（签名可验证、包体哈希可复算）后才允许落盘覆盖。

mod batch;
mod init;
mod keygen;
mod manifest_io;
mod sign;
mod single;
mod types;

pub(crate) use init::handle_init;
pub(crate) use keygen::handle_keygen;
pub(crate) use sign::handle_sign;
pub(crate) use single::handle_release;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{InitArgs, InspectArgs, SignArgs, VerifyArgs};
    use crate::util::compute_payload_integrity;
    use crate::verify::{handle_inspect, handle_verify};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use semver::Version;
    use sha2::{Digest, Sha256};
    use shipup::{Manifest, PackageInfo, PackageType};
    use std::collections::BTreeMap;
    use std::fs;

    use crate::release::batch::handle_batch_release;
    use crate::release::manifest_io::update_manifest_entries;
    use crate::release::types::{ManifestReleaseEntry, ManifestUpdateContext};

    /// 构造用于测试的空清单骨架。
    fn empty_manifest_for_test(version: &str, notes: Option<&str>) -> Manifest {
        Manifest {
            version: Version::parse(version).unwrap(),
            min_supported_version: None,
            force_update: false,
            pub_date: Some("2026-09-01T00:00:00Z".to_string()),
            notes: notes.map(|s| s.to_string()),
            packages: BTreeMap::new(),
            channels: BTreeMap::new(),
            signature: Some("old_signature".to_string()),
            signatures: vec![],
            rollout_percentage: None,
            expires_at: None,
            version_seq: None,
        }
    }

    /// 构造用于测试的包信息骨架。
    fn test_package_info(url: &str, checksum: &str, pkg_type: PackageType) -> PackageInfo {
        PackageInfo {
            url: url.to_string(),
            mirrors: vec![],
            signature: None,
            signatures: vec![],
            checksum: Some(checksum.to_string()),
            package_type: pkg_type,
            install_mode: None,
            install_args: vec![],
            executable_path: None,
            require_elevation: false,
            wait_for_exit: false,
            payload_checksums: Default::default(),
            size: None,
        }
    }

    #[test]
    fn test_update_manifest_entries_semver_guard() {
        let mut manifest = empty_manifest_for_test("1.2.0", Some("版本 1.2.0"));

        let entry_old = ManifestReleaseEntry {
            version: Version::parse("1.1.0").unwrap(),
            min_supported_version: None,
            pub_date: "2026-08-01T00:00:00Z".to_string(),
            package_info: test_package_info(
                "https://example.com/win-1.1.0.exe",
                "sha256:abc",
                PackageType::Binary,
            ),
        };

        let ctx_old = ManifestUpdateContext {
            channel: None,
            force_update: false,
            notes: Some("旧版 1.1.0".to_string()),
            rollout_percentage: None,
            expires_at: None,
            expires_in: None,
            version_seq: None,
        };

        update_manifest_entries(&mut manifest, "x86_64-pc-windows-msvc", &ctx_old, entry_old);

        assert_eq!(manifest.version, Version::parse("1.2.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("版本 1.2.0"));
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert_eq!(manifest.signature, None);

        let entry_new = ManifestReleaseEntry {
            version: Version::parse("1.3.0").unwrap(),
            min_supported_version: None,
            pub_date: "2026-10-01T00:00:00Z".to_string(),
            package_info: test_package_info(
                "https://example.com/mac-1.3.0.tar.gz",
                "sha256:def",
                PackageType::Archive,
            ),
        };

        let ctx_new = ManifestUpdateContext {
            channel: None,
            force_update: true,
            notes: Some("全新 1.3.0".to_string()),
            rollout_percentage: Some(30),
            expires_at: Some("2026-12-31T00:00:00Z".to_string()),
            expires_in: None,
            version_seq: Some(10),
        };

        update_manifest_entries(&mut manifest, "aarch64-apple-darwin", &ctx_new, entry_new);

        assert_eq!(manifest.version, Version::parse("1.3.0").unwrap());
        assert_eq!(manifest.notes.as_deref(), Some("全新 1.3.0"));
        assert_eq!(manifest.pub_date.as_deref(), Some("2026-10-01T00:00:00Z"));
        assert_eq!(manifest.rollout_percentage, Some(30));
        assert_eq!(manifest.expires_at.as_deref(), Some("2026-12-31T00:00:00Z"));
        assert_eq!(manifest.version_seq, Some(10));
        assert!(manifest.force_update);
        assert!(manifest.packages.contains_key("x86_64-pc-windows-msvc"));
        assert!(manifest.packages.contains_key("aarch64-apple-darwin"));
    }

    #[test]
    fn test_batch_release_verify_and_inspect_flow() -> Result<(), anyhow::Error> {
        let temp_dir =
            std::env::temp_dir().join(format!("shipup_cli_batch_{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir)?;

        handle_keygen(&temp_dir)?;
        let key_file = temp_dir.join("ed25519.key");
        let pub_file = temp_dir.join("ed25519.pub");
        assert!(key_file.exists());
        assert!(pub_file.exists());

        let win_pkg = temp_dir.join("myapp-windows.exe");
        let mac_pkg = temp_dir.join("myapp-macos.tar.gz");
        fs::write(&win_pkg, b"binary for windows x64 target payload")?;
        fs::write(&mac_pkg, b"archive for macos arm64 target payload")?;

        let manifest_file = temp_dir.join("latest.json");

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

        handle_batch_release(&toml_path, &manifest_file)?;
        assert!(manifest_file.exists());

        let inspect_args = InspectArgs {
            manifest: manifest_file.clone(),
            channel: None,
        };
        handle_inspect(&inspect_args)?;

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

    #[test]
    fn test_cli_init_command() -> Result<(), anyhow::Error> {
        let temp_dir = std::env::temp_dir().join(format!("test_cli_init_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;
        let out_toml = temp_dir.join("shipup.toml");

        handle_init(&InitArgs {
            output: out_toml.clone(),
            force: false,
        })?;
        assert!(out_toml.exists());
        let content = fs::read_to_string(&out_toml)?;
        assert!(content.contains("version = \"1.0.0\""));
        assert!(content.contains("[[packages]]"));

        let err = handle_init(&InitArgs {
            output: out_toml.clone(),
            force: false,
        });
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("已存在"));

        handle_init(&InitArgs {
            output: out_toml,
            force: true,
        })?;

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_cli_sign_command() -> Result<(), anyhow::Error> {
        let temp_dir = std::env::temp_dir().join(format!("test_cli_sign_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        let keys_dir = temp_dir.join("keys");
        handle_keygen(&keys_dir)?;
        let key_path = keys_dir.join("ed25519.key");
        let pub_path = keys_dir.join("ed25519.pub");

        let test_bin = temp_dir.join("app.bin");
        fs::write(&test_bin, b"binary content for signing test")?;

        let sig_out = temp_dir.join("app.bin.sig");
        handle_sign(&SignArgs {
            file: test_bin.clone(),
            key: key_path,
            output: Some(sig_out.clone()),
        })?;

        assert!(sig_out.exists());
        let sig_b64 = fs::read_to_string(&sig_out)?;
        let pub_b64 = fs::read_to_string(&pub_path)?;

        let pub_bytes = BASE64.decode(pub_b64.trim())?;
        let pub_array: [u8; 32] = pub_bytes.as_slice().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pub_array).unwrap();

        let sig_bytes = BASE64.decode(sig_b64.trim())?;
        let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let (checksum, _) = compute_payload_integrity(&test_bin, None)?;
        let hex_str = checksum.strip_prefix("sha256:").unwrap();
        let mut raw_digest = [0u8; 32];
        for i in 0..32 {
            raw_digest[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
        }

        verifying_key
            .verify_strict(&raw_digest, &signature)
            .expect("生成的 Ed25519 签名验证应当通过");

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_compute_payload_integrity_matches_sha256() -> Result<(), anyhow::Error> {
        let temp_file = std::env::temp_dir().join(format!(
            "test_cli_integrity_match_{}.bin",
            std::process::id()
        ));
        let content = b"payload for release module integrity";
        fs::write(&temp_file, content)?;
        let (checksum, _) = compute_payload_integrity(&temp_file, None)?;
        let _ = fs::remove_file(&temp_file);

        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash = hasher.finalize();
        let mut hex = String::new();
        for b in hash {
            use std::fmt::Write;
            let _ = write!(hex, "{b:02x}");
        }
        assert_eq!(checksum, format!("sha256:{hex}"));
        Ok(())
    }
}
