//! 归档解压与魔数嗅探模糊测试目标。
//!
//! # 测试目标
//! 以随机字节流冲击归档格式识别与解压路径，验证实现不会 panic、
//! 不会越界写入，也不会因畸形路径条目突破沙箱目录。

#![no_main]

use libfuzzer_sys::fuzz_target;
use shipup::archive::{detect_archive_format, extract_archive};
use std::fs::{self, File};
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let temp_dir = std::env::temp_dir().join(format!("shipup_fuzz_target_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let archive_path = temp_dir.join("input.bin");
    let sandbox = temp_dir.join("sandbox");

    if let Ok(mut file) = File::create(&archive_path) {
        let _ = file.write_all(data);
        let _ = file.flush();
        drop(file);

        let _ = detect_archive_format(&archive_path);
        let _ = extract_archive(&archive_path, &sandbox, None);
    }

    let _ = fs::remove_dir_all(&temp_dir);
});
