//! 归档模块单元测试。

use super::*;
use crate::error::UpdateError;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_sync_extracted_payload_copies_assets_and_excludes_binary() {
    let temp_base =
        std::env::temp_dir().join(format!("shipup_archive_test_{}", std::process::id()));
    let payload_dir = temp_base.join("payload");
    let target_dir = temp_base.join("install_dir");

    let _ = fs::remove_dir_all(&temp_base);
    fs::create_dir_all(&payload_dir).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    // 构造沙箱内的文件树
    let exe_path = payload_dir.join("myapp.exe");
    let dll_path = payload_dir.join("core.dll");
    let assets_dir = payload_dir.join("assets");
    fs::create_dir_all(&assets_dir).unwrap();
    let asset_file = assets_dir.join("logo.png");

    File::create(&exe_path)
        .unwrap()
        .write_all(b"new-exe")
        .unwrap();
    File::create(&dll_path)
        .unwrap()
        .write_all(b"new-dll")
        .unwrap();
    File::create(&asset_file)
        .unwrap()
        .write_all(b"new-logo")
        .unwrap();

    // 执行资产同步，排除 myapp.exe
    let res = sync_extracted_payload(&payload_dir, &target_dir, &exe_path);
    assert!(res.is_ok());

    // 验证主程序未被该方法直接覆盖（由原子替换接管）
    assert!(!target_dir.join("myapp.exe").exists());
    // 验证动态库与子目录资源已成功同步并完整保留
    assert!(target_dir.join("core.dll").exists());
    assert_eq!(fs::read(target_dir.join("core.dll")).unwrap(), b"new-dll");
    assert!(target_dir.join("assets").join("logo.png").exists());
    assert_eq!(
        fs::read(target_dir.join("assets").join("logo.png")).unwrap(),
        b"new-logo"
    );

    let _ = fs::remove_dir_all(&temp_base);
}

#[test]
fn test_detect_archive_format_by_magic_and_extension() {
    let temp_dir = std::env::temp_dir().join(format!("shipup_detect_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // 1. 测试扩展名推断
    let zip_path = temp_dir.join("test.zip");
    File::create(&zip_path).unwrap();
    assert_eq!(detect_archive_format(&zip_path), ArchiveFormat::Zip);

    let targz_path = temp_dir.join("test.tar.gz");
    File::create(&targz_path).unwrap();
    assert_eq!(detect_archive_format(&targz_path), ArchiveFormat::TarGz);

    let tarzst_path = temp_dir.join("test.tar.zst");
    File::create(&tarzst_path).unwrap();
    assert_eq!(detect_archive_format(&tarzst_path), ArchiveFormat::TarZst);

    let tarxz_path = temp_dir.join("test.tar.xz");
    File::create(&tarxz_path).unwrap();
    assert_eq!(detect_archive_format(&tarxz_path), ArchiveFormat::TarXz);

    // 2. 测试基于魔数识别（无扩展名文件）
    let magic_zst = temp_dir.join("package_zst_no_ext");
    fs::write(&magic_zst, [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00]).unwrap();
    assert_eq!(detect_archive_format(&magic_zst), ArchiveFormat::TarZst);

    let magic_xz = temp_dir.join("package_xz_no_ext");
    fs::write(&magic_xz, [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]).unwrap();
    assert_eq!(detect_archive_format(&magic_xz), ArchiveFormat::TarXz);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(feature = "archive-tar-xz")]
#[test]
fn test_extract_tar_xz_and_magic_sniffing() {
    let temp_dir = std::env::temp_dir().join(format!("shipup_tar_xz_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // 打包单个可执行文件进 tar
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    let payload_content = b"hello tar.xz payload binary";
    header.set_path("my_xz_app.exe").unwrap();
    header.set_size(payload_content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar_builder.append(&header, &payload_content[..]).unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    // 使用 lzma_rs 压缩为 xz 流
    let mut xz_bytes = Vec::new();
    lzma_rs::xz_compress(&mut std::io::Cursor::new(tar_bytes), &mut xz_bytes).unwrap();

    // 写入无扩展名文件，验证魔数识别自动触发 xz 解压
    let archive_file = temp_dir.join("unnamed_archive_bundle");
    fs::write(&archive_file, xz_bytes).unwrap();

    let sandbox = temp_dir.join("sandbox");
    let extracted_exe = extract_archive(&archive_file, &sandbox, Some("my_xz_app.exe")).unwrap();

    assert!(extracted_exe.exists());
    assert_eq!(fs::read(extracted_exe).unwrap(), payload_content);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(feature = "archive-tar-zst")]
#[test]
fn test_extract_tar_zst_and_magic_sniffing() {
    let temp_dir = std::env::temp_dir().join(format!("shipup_tar_zst_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // 打包单个可执行文件进 tar
    let mut tar_builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    let payload_content = b"hello tar.zst payload binary";
    header.set_path("my_zst_app.exe").unwrap();
    header.set_size(payload_content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar_builder.append(&header, &payload_content[..]).unwrap();
    let tar_bytes = tar_builder.into_inner().unwrap();

    // 使用 ruzstd 压缩为 zstd 帧
    let zst_bytes = ruzstd::encoding::compress_to_vec(
        &tar_bytes[..],
        ruzstd::encoding::CompressionLevel::Fastest,
    );

    // 写入无扩展名文件，验证魔数识别自动触发 zstd 解压
    let archive_file = temp_dir.join("unnamed_zst_archive_bundle");
    fs::write(&archive_file, zst_bytes).unwrap();

    let sandbox = temp_dir.join("sandbox");
    let extracted_exe = extract_archive(&archive_file, &sandbox, Some("my_zst_app.exe")).unwrap();

    assert!(extracted_exe.exists());
    assert_eq!(fs::read(extracted_exe).unwrap(), payload_content);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_verify_extracted_payload_checksums_success_and_failure() {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let temp_dir = std::env::temp_dir().join(format!(
        "shipup_payload_checksum_test_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("bin")).unwrap();

    let content = b"critical-binary-content";
    let file_path = temp_dir.join("bin/app.exe");
    fs::write(&file_path, content).unwrap();

    let mut hasher = Sha256::new();
    hasher.update(content);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }

    let mut expected = BTreeMap::new();
    expected.insert("bin/app.exe".to_string(), format!("sha256:{hex}"));

    // 正常路径应通过
    assert!(verify_extracted_payload_checksums(&temp_dir, &expected).is_ok());

    // 篡改文件内容后应失败
    fs::write(&file_path, b"tampered").unwrap();
    assert!(matches!(
        verify_extracted_payload_checksums(&temp_dir, &expected),
        Err(UpdateError::ChecksumMismatch { .. })
    ));

    // 还原正确内容后，声明不存在的关键文件应失败
    fs::write(&file_path, content).unwrap();
    expected.insert("bin/missing.dll".to_string(), format!("sha256:{hex}"));
    assert!(matches!(
        verify_extracted_payload_checksums(&temp_dir, &expected),
        Err(UpdateError::ArchiveExtract(_))
    ));

    // 路径逃逸应被拦截
    let mut escape_map = BTreeMap::new();
    escape_map.insert("../outside.exe".to_string(), format!("sha256:{hex}"));
    assert!(verify_extracted_payload_checksums(&temp_dir, &escape_map).is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}
