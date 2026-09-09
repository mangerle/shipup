// shipup 跨平台自更新系统 - Manifest 反序列化与解析模糊测试目标
#![no_main]

use libfuzzer_sys::fuzz_target;
use shipup::manifest::Manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Manifest::from_json_str(s);
    }
    let _ = serde_json::from_slice::<Manifest>(data);
});
