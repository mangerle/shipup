//! 版本自愈与回滚引擎单元测试。

use super::health::check_and_recover;
use super::state::UpdateState;
use super::*;
use crate::error::UpdateError;
use semver::Version;
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn test_record_and_confirm_update_state() {
    let temp_dir = env::temp_dir().join(format!("shipup_rec_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let dummy_backup = temp_dir.join("app.shipup.old");
    fs::write(&dummy_backup, b"old-binary").unwrap();

    // 1. 记录更新状态
    record_update_state(&temp_dir, "2.0.0", &dummy_backup).unwrap();
    let state_file = temp_dir.join(UPDATE_STATE_FILENAME);
    assert!(state_file.exists());

    // 2. 第一次自检启动尝试，仍处于观察期
    let dummy_exe = temp_dir.join("app.exe");
    fs::write(&dummy_exe, b"new-binary").unwrap();
    let status1 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
    assert_eq!(
        status1,
        HealthCheckStatus::PendingConfirmation { attempts: 1 }
    );

    // 3. 显式确认成功，备份文件与状态标记均被清理
    let confirmed = confirm_update_success_in_dir(&temp_dir).unwrap();
    assert!(confirmed);
    assert!(!state_file.exists());
    assert!(!dummy_backup.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_crash_loop_triggers_rollback() {
    let temp_dir = env::temp_dir().join(format!("shipup_crash_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let dummy_backup = temp_dir.join("app.shipup.old");
    fs::write(&dummy_backup, b"old-stable-binary").unwrap();

    let dummy_exe = temp_dir.join("app.exe");
    fs::write(&dummy_exe, b"broken-new-binary").unwrap();

    record_update_state(&temp_dir, "2.0.1", &dummy_backup).unwrap();

    // 第 1 次启动崩溃后重启（attempts = 1 <= 2）
    let s1 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
    assert_eq!(s1, HealthCheckStatus::PendingConfirmation { attempts: 1 });

    // 第 2 次启动崩溃后重启（attempts = 2 <= 2）
    let s2 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
    assert_eq!(s2, HealthCheckStatus::PendingConfirmation { attempts: 2 });

    // 第 3 次启动，超过上限 2 次，触发自愈回滚！
    let s3 = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
    assert_eq!(
        s3,
        HealthCheckStatus::RolledBack {
            from_version: "2.0.1".to_string(),
        }
    );

    // 验证目标可执行文件已成功被备份文件还原为稳定版本
    assert_eq!(fs::read(&dummy_exe).unwrap(), b"old-stable-binary");
    // 历史备份文件已被消费清理
    assert!(!dummy_backup.exists());
    // 状态标记已被自动清理
    assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_healthy_interval_clears_recovery_state() {
    let temp_dir = env::temp_dir().join(format!("shipup_healthy_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let dummy_backup = temp_dir.join("app.shipup.old");
    fs::write(&dummy_backup, b"old-binary").unwrap();
    let dummy_exe = temp_dir.join("app.exe");
    fs::write(&dummy_exe, b"new-binary").unwrap();

    let state_file = temp_dir.join(UPDATE_STATE_FILENAME);
    let past_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_sub(60); // 模拟 60 秒前启动过

    let state = UpdateState {
        target_version: "2.1.0".to_string(),
        backup_path: dummy_backup.clone(),
        updated_at: past_time * 1000,
        launch_attempts: 1,
        last_attempt_at: Some(past_time),
    };
    fs::write(&state_file, serde_json::to_string(&state).unwrap()).unwrap();

    // 执行检查：由于距上次启动已过去 60 秒（>= 30 秒阈值），判定平稳运行，自动确认成功
    let status = check_and_recover(&temp_dir, &dummy_exe, 2).unwrap();
    assert_eq!(status, HealthCheckStatus::Normal);

    // 状态标记与历史备份均被自动清理
    assert!(!state_file.exists());
    assert!(!dummy_backup.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_record_rollback_history_and_prune() {
    let temp_dir = env::temp_dir().join(format!("shipup_hist_test_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let v1_backup = temp_dir.join("app.shipup.1.0.0.old");
    let v2_backup = temp_dir.join("app.shipup.1.1.0.old");
    let v3_backup = temp_dir.join("app.shipup.1.2.0.old");
    fs::write(&v1_backup, b"v1-binary").unwrap();
    fs::write(&v2_backup, b"v2-binary").unwrap();
    fs::write(&v3_backup, b"v3-binary").unwrap();

    let v1 = Version::parse("1.0.0").unwrap();
    let v2 = Version::parse("1.1.0").unwrap();
    let v3 = Version::parse("1.2.0").unwrap();

    // 容量限制为 2
    record_rollback_version(&temp_dir, &v1, &v1_backup, 2).unwrap();
    record_rollback_version(&temp_dir, &v2, &v2_backup, 2).unwrap();

    let available = list_available_rollback_versions(&temp_dir);
    assert_eq!(available, vec![v2.clone(), v1.clone()]);
    assert!(v1_backup.exists());
    assert!(v2_backup.exists());

    // 插入第 3 个版本，应自动淘汰最古老的 v1
    record_rollback_version(&temp_dir, &v3, &v3_backup, 2).unwrap();
    let available2 = list_available_rollback_versions(&temp_dir);
    assert_eq!(available2, vec![v3.clone(), v2.clone()]);

    // 最旧的 v1 物理文件已被自动淘汰清理
    assert!(!v1_backup.exists());
    assert!(v2_backup.exists());
    assert!(v3_backup.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_manual_rollback_to_specific_version() {
    let temp_dir = env::temp_dir().join(format!("shipup_manual_rb_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let v1_backup = temp_dir.join("app.shipup.1.0.0.old");
    let current_exe = temp_dir.join("app.exe");
    fs::write(&v1_backup, b"v1-stable-code").unwrap();
    fs::write(&current_exe, b"v2-broken-code").unwrap();

    let v1 = Version::parse("1.0.0").unwrap();
    record_rollback_version(&temp_dir, &v1, &v1_backup, 2).unwrap();

    // 模拟当前存在自愈状态
    record_update_state(&temp_dir, "2.0.0", &v1_backup).unwrap();
    assert!(temp_dir.join(UPDATE_STATE_FILENAME).exists());

    // 执行主动回滚至 1.0.0
    execute_manual_rollback_to(&temp_dir, &current_exe, &v1).unwrap();

    // 验证当前二进制已被成功还原为 v1
    assert_eq!(fs::read(&current_exe).unwrap(), b"v1-stable-code");
    // 验证自愈状态标记已被安全清除
    assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());
    // 验证可用历史中已无该条目
    let available = list_available_rollback_versions(&temp_dir);
    assert!(available.is_empty());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_manual_rollback_version_not_found() {
    let temp_dir = env::temp_dir().join(format!("shipup_rb_nf_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let current_exe = temp_dir.join("app.exe");
    fs::write(&current_exe, b"current-code").unwrap();

    let non_existent = Version::parse("9.9.9").unwrap();
    let result = execute_manual_rollback_to(&temp_dir, &current_exe, &non_existent);
    assert!(result.is_err());
    match result {
        Err(UpdateError::RollbackVersionNotFound(v)) => {
            assert_eq!(v, "9.9.9");
        }
        other => panic!("预期 RollbackVersionNotFound，但获得 {:?}", other),
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_confirm_update_keeps_registered_history() {
    let temp_dir = env::temp_dir().join(format!("shipup_keep_hist_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let dummy_backup = temp_dir.join("app.shipup.1.0.0.old");
    fs::write(&dummy_backup, b"old-binary").unwrap();
    let v1 = Version::parse("1.0.0").unwrap();

    // 登记入版本历史并记录更新状态
    record_rollback_version(&temp_dir, &v1, &dummy_backup, 2).unwrap();
    record_update_state(&temp_dir, "2.0.0", &dummy_backup).unwrap();

    // 确认升级成功
    let confirmed = confirm_update_success_in_dir(&temp_dir).unwrap();
    assert!(confirmed);
    // 状态标记已被清理
    assert!(!temp_dir.join(UPDATE_STATE_FILENAME).exists());
    // 物理备份因登记在版本历史中而被妥善保留供后续手动回滚！
    assert!(dummy_backup.exists());

    let _ = fs::remove_dir_all(&temp_dir);
}
