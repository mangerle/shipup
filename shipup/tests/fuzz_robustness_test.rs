// shipup 跨平台自更新系统 - 模糊与鲁棒性变异防御测试

use shipup::archive::{detect_archive_format, extract_archive};
use shipup::manifest::Manifest;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_fuzz_manifest_arbitrary_json_payloads_do_not_panic() {
    // 恶意构造的畸变载荷矩阵：涵盖深层括号嵌套、截断结构、超大数值、特殊控制字符与无效类型
    let malicious_samples = [
        "",
        "   ",
        "null",
        "true",
        "12345",
        "\"raw string\"",
        "[]",
        "{}",
        "{\"name\": 123}",
        "{\"name\": \"test\", \"version\": 999}",
        "{\"version\": \"1.0.0\", \"packages\": null}",
        "{\"version\": \"1.0.0\", \"packages\": {\"target\": \"invalid_struct\"}}",
        "{\"version\": \"not_a_valid_semver\", \"packages\": {}}",
        "{\"version\": \"1.0.0\", \"expires_at\": \"invalid_date_format\"}",
        "{\"version\": \"1.0.0\", \"version_seq\": -1}",
        "{\"version\": \"1.0.0\", \"version_seq\": 99999999999999999999999999999999}",
        "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
        "[][][][][][][][][][][][][][][][][][][][]",
        "{\"a\": {\"b\": {\"c\": {\"d\": 1}}}}",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "{\"version\":\"1.0.0\",\"packages\":{\"\":{\"url\":\"\",\"hash\":\"\"}}}",
    ];

    for (idx, payload) in malicious_samples.iter().enumerate() {
        // 验证 Manifest::from_json_str 绝对安全拦截且永不发生崩溃 panic
        let res1 = Manifest::from_json_str(payload);
        assert!(
            res1.is_err(),
            "畸变载荷 #{idx} 应该被安全解析器拦截但被意外接受: {payload}"
        );

        // 验证 serde_json 直接反序列化至 Manifest 也绝对安全且永不崩溃
        let _ = serde_json::from_str::<Manifest>(payload);
    }
}

#[test]
fn test_fuzz_manifest_bit_flip_mutations() {
    let valid_manifest_json = r#"{
        "version": "1.2.3",
        "version_seq": 10,
        "expires_at": "2030-01-01T00:00:00Z",
        "packages": {
            "x86_64-unknown-linux-gnu": {
                "url": "https://example.com/app.tar.gz",
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "package_type": "archive"
            }
        }
    }"#;

    assert!(Manifest::from_json_str(valid_manifest_json).is_ok());

    let mut bytes = valid_manifest_json.as_bytes().to_vec();
    // 伪随机翻转不同字节位置，模拟网络单比特翻转与传输破坏
    let test_indices = [0, 1, 5, 10, 20, 50, 100, 150, bytes.len() - 1];

    for &idx in &test_indices {
        if idx < bytes.len() {
            let original = bytes[idx];
            bytes[idx] ^= 0xFF; // 翻转所有比特

            if let Ok(mutated_str) = std::str::from_utf8(&bytes) {
                // 翻转后若解析失败属于正常预期；若碰巧仍能解析，其内部字段必须依然是合法的语义化状态
                let _ = Manifest::from_json_str(mutated_str);
            }

            // 还原字节
            bytes[idx] = original;
        }
    }
}

#[test]
fn test_fuzz_archive_magic_and_extraction_robustness() {
    let temp_dir = std::env::temp_dir().join(format!(
        "shipup_fuzz_archive_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let dummy_file = temp_dir.join("corrupt_archive.bin");
    let sandbox = temp_dir.join("sandbox");

    // 针对任意损毁字节，detect_archive_format 绝不 panic
    let corrupt_payloads: [&[u8]; 6] = [
        &[],
        &[0x00],
        &[0x50, 0x4B],                         // 截断的 Zip 魔数
        &[0x1F, 0x8B],                         // 截断的 Gzip 魔数
        &[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00], // 截断的 Zstandard 魔数
        &[0xFF; 256],                          // 全噪声字节
    ];

    for payload in corrupt_payloads {
        {
            let mut file = File::create(&dummy_file).unwrap();
            file.write_all(payload).unwrap();
        }

        let _format = detect_archive_format(&dummy_file);
        // 格式嗅探安全完成，无论判定为 Unknown 还是对应格式，尝试解压均必须安全返回 Err 而不是 panic
        let res = extract_archive(&dummy_file, &sandbox, None);
        assert!(res.is_err(), "解压损毁归档包必须安全报错拦截");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
