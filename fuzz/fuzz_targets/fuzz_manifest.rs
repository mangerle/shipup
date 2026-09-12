//! Manifest 反序列化与解析模糊测试目标。
//!
//! # 测试目标
//! 以随机字节流冲击清单解析入口，验证任何畸形输入都只产生 `Err` 而非 panic，
//! 从而保证恶意更新源无法通过构造坏清单使客户端崩溃。

#![no_main]

use libfuzzer_sys::fuzz_target;
use shipup::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Manifest::from_json_str(s);
    }
    let _ = serde_json::from_slice::<Manifest>(data);
});
