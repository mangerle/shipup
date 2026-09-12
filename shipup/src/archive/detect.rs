//! 归档格式识别（魔数嗅探 + 扩展名回退）。
//!
//! # 模块职责
//! 基于文件头魔数（magic bytes）与文件扩展名，自动判定归档包的具体格式。

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// 归档格式类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// 标准 Zip 压缩归档
    Zip,
    /// Gzip 压缩的 Tar 归档 (.tar.gz / .tgz)
    TarGz,
    /// Zstandard 压缩的 Tar 归档 (.tar.zst / .tzst)
    TarZst,
    /// XZ / LZMA2 压缩的 Tar 归档 (.tar.xz / .txz)
    TarXz,
    /// 无法从魔数或扩展名推断的格式
    Unknown,
}

/// 基于文件魔数（前 6 字节）与扩展名自动嗅探归档文件格式
pub fn detect_archive_format(path: &Path) -> ArchiveFormat {
    // 1. 优先读取文件头魔数进行精准特征匹配
    if let Ok(mut file) = File::open(path) {
        let mut magic = [0u8; 6];
        if let Ok(n) = Read::read(&mut file, &mut magic) {
            if n >= 4 && magic[..4] == [0x50, 0x4B, 0x03, 0x04] {
                return ArchiveFormat::Zip;
            }
            if n >= 2 && magic[..2] == [0x1F, 0x8B] {
                return ArchiveFormat::TarGz;
            }
            if n >= 4 && magic[..4] == [0x28, 0xB5, 0x2F, 0xFD] {
                return ArchiveFormat::TarZst;
            }
            if n >= 6 && magic[..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00] {
                return ArchiveFormat::TarXz;
            }
        }
    }

    // 2. 魔数未命中时回退到文件扩展名判定
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if file_name.ends_with(".zip") {
        ArchiveFormat::Zip
    } else if file_name.ends_with(".tar.gz") || file_name.ends_with(".tgz") {
        ArchiveFormat::TarGz
    } else if file_name.ends_with(".tar.zst")
        || file_name.ends_with(".tzst")
        || file_name.ends_with(".zst")
    {
        ArchiveFormat::TarZst
    } else if file_name.ends_with(".tar.xz")
        || file_name.ends_with(".txz")
        || file_name.ends_with(".xz")
    {
        ArchiveFormat::TarXz
    } else {
        ArchiveFormat::Unknown
    }
}
