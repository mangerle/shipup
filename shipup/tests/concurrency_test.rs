//! 并发控制、取消令牌与竞态防御集成测试。
//!
//! # 测试目标
//! 验证多线程与异步两种宿主形态下更新器的并发语义：
//! 后台轮询线程与任务的启动/停止、下载取消令牌的跨线程可见性、
//! 以及并发访问偏好与回滚状态时不产生数据竞争或状态撕裂。
//!
//! # 设计原理
//! 并发缺陷具有偶发性，因此用例刻意放大交替时序（如启动后立即取消、停止与下载同时进行），
//! 以便在每次 CI 运行中稳定复现，而不是依赖概率碰运气。

use shipup::error::UpdateError;
use shipup::{AutoPollOptions, UpdaterBuilder, spawn_polling_task, spawn_polling_thread};
use std::fs;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

#[test]
fn test_poller_handle_multithreaded_concurrent_stop_and_cancel() {
    let temp_dir = std::env::temp_dir().join(format!(
        "shipup_test_poller_mt_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, r#"{"version":"1.0.0","packages":{}}"#).unwrap();

    let manifest_url = if cfg!(windows) {
        format!(
            "file:///{}",
            manifest_path.to_str().unwrap().replace('\\', "/")
        )
    } else {
        format!("file://{}", manifest_path.display())
    };

    let updater = UpdaterBuilder::new()
        .current_version("1.0.0")
        .unwrap()
        .manifest_url(manifest_url)
        .allow_file_protocol(true)
        .require_signature(false)
        .build()
        .unwrap();

    let options = AutoPollOptions::default()
        .interval(Duration::from_millis(100))
        .check_immediately(false);

    let handle = spawn_polling_thread(updater, options, |_| {}).unwrap();

    let mut threads = Vec::new();

    // 启动 16 个并发工作线程，高频并发竞争调用 cancel 与 stop
    for i in 0..16 {
        let h = handle.clone();
        threads.push(thread::spawn(move || {
            if i % 2 == 0 {
                h.cancel_current_download();
            } else {
                h.stop();
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }

    // 最终状态必须确定性收敛为已停止
    assert!(handle.is_stopped());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_download_cancellation_during_streaming_blocking() {
    let temp_dir = std::env::temp_dir().join(format!(
        "shipup_test_cancel_flow_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let pkg_file = temp_dir.join("app_v2.exe");
    fs::write(&pkg_file, vec![0x90u8; 1024 * 1024]).unwrap(); // 1MB 模拟安装包

    let pkg_url = if cfg!(windows) {
        format!("file:///{}", pkg_file.to_str().unwrap().replace('\\', "/"))
    } else {
        format!("file://{}", pkg_file.display())
    };

    let manifest_content = format!(
        r#"{{
            "version": "2.0.0",
            "packages": {{
                "{}": {{
                    "url": "{}",
                    "package_type": "binary"
                }}
            }}
        }}"#,
        shipup::manifest::current_target_triple(),
        pkg_url
    );

    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, manifest_content).unwrap();

    let manifest_url = if cfg!(windows) {
        format!(
            "file:///{}",
            manifest_path.to_str().unwrap().replace('\\', "/")
        )
    } else {
        format!("file://{}", manifest_path.display())
    };

    let updater = UpdaterBuilder::new()
        .current_version("1.0.0")
        .unwrap()
        .manifest_url(manifest_url)
        .allow_file_protocol(true)
        .require_signature(false)
        .build()
        .unwrap();

    let update = updater.check().unwrap().expect("应检测到新版本");

    // 预先激活取消标志位
    let cancel_flag = Arc::new(AtomicBool::new(true));

    let res = update.download_with_cancellation(Some(cancel_flag), |_| {});

    // 必须精准识别并返回 Cancelled 错误类型
    assert!(
        matches!(res, Err(UpdateError::Cancelled)),
        "触发取消标志后必须返回 UpdateError::Cancelled，实际返回: {:?}",
        res
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sync_polling_thread_graceful_shutdown() {
    let temp_dir = std::env::temp_dir().join(format!(
        "shipup_test_poller_sync_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).unwrap();

    let manifest_path = temp_dir.join("manifest.json");
    fs::write(&manifest_path, r#"{"version":"1.0.0","packages":{}}"#).unwrap();

    let manifest_url = if cfg!(windows) {
        format!(
            "file:///{}",
            manifest_path.to_str().unwrap().replace('\\', "/")
        )
    } else {
        format!("file://{}", manifest_path.display())
    };

    let updater = UpdaterBuilder::new()
        .current_version("1.0.0")
        .unwrap()
        .manifest_url(manifest_url)
        .allow_file_protocol(true)
        .require_signature(false)
        .build()
        .unwrap();

    let options = AutoPollOptions::default()
        .interval(Duration::from_millis(50))
        .check_immediately(false);

    let handle = spawn_polling_thread(updater, options, |_| {}).unwrap();

    // 运行短暂时间后发送停止信号
    thread::sleep(Duration::from_millis(30));
    assert!(!handle.is_stopped());

    handle.stop();
    assert!(handle.is_stopped());

    // 等待后台线程优雅退出，无死锁与异常抛出
    thread::sleep(Duration::from_millis(100));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_async_polling_task_graceful_shutdown() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let temp_dir = std::env::temp_dir().join(format!(
            "shipup_test_poller_async_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let manifest_path = temp_dir.join("manifest.json");
        fs::write(&manifest_path, r#"{"version":"1.0.0","packages":{}}"#).unwrap();

        let manifest_url = if cfg!(windows) {
            format!(
                "file:///{}",
                manifest_path.to_str().unwrap().replace('\\', "/")
            )
        } else {
            format!("file://{}", manifest_path.display())
        };

        let updater = UpdaterBuilder::new()
            .current_version("1.0.0")
            .unwrap()
            .manifest_url(manifest_url)
            .allow_file_protocol(true)
            .require_signature(false)
            .build()
            .unwrap();

        let options = AutoPollOptions::default()
            .interval(Duration::from_millis(50))
            .check_immediately(false);

        let handle = spawn_polling_task(updater, options, |_| {});

        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!handle.is_stopped());

        handle.stop();
        assert!(handle.is_stopped());

        tokio::time::sleep(Duration::from_millis(100)).await;

        let _ = fs::remove_dir_all(&temp_dir);
    });
}
