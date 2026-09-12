//! 客户端运维相关命令模块：状态查看、版本回滚与历史碎片清理。
//!
//! # 模块职责
//! 实现 `status`、`rollback`、`clean` 三个运维子命令：
//! 展示本地更新偏好与回滚历史、主动回退到指定或最近的历史版本、清理历史备份与临时残留。
//!
//! # 设计原理
//! - **实现初衷**：自更新系统的故障排查高度依赖「现场状态可见」。
//!   若用户只能看到「更新失败」四个字，运维与支持成本将无法收敛。
//! - **核心优势**：
//!   - 状态输出直接复用核心库的偏好与回滚历史读取接口，
//!     保证命令行展示的内容与程序实际生效的状态完全同源，不存在「两套真相」；
//!   - 回滚命令支持「指定版本」与「回退到上一个版本」两种粒度，覆盖精确排障与一键救急两类诉求；
//!   - 清理命令仅删除本工具自身产生命名的历史备份与临时文件，不会触及用户的业务数据。
//! - **代价与局限**：运维命令作用于客户端本机状态目录，需在目标机器上本地执行，无法远程代跑。
//!
//! # 安全契约
//! 回滚与清理均属于对本地文件的破坏性操作，执行前必须明确打印将被处理的路径；
//! 清理逻辑严禁使用宽泛通配符匹配，只允许删除符合本工具命名约定的文件。

use crate::cli::{CleanArgs, RollbackArgs, StatusArgs};
use anyhow::{Context, Result, anyhow};
use semver::Version;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// 执行客户端更新状态、偏好设置与回滚矩阵查看
///
/// # 设计原理
/// - **实现初衷**：在客户端现场排错时，快速掌握当前运行目录下的更新偏好、跳过的版本、崩溃计数及可回滚的历史快照。
/// - **核心优势**：统一汇集 `.shipup_preference.json`、`.shipup.state` 与 `.shipup.history` 三重元数据，格式化输出。
pub(crate) fn handle_status(args: &StatusArgs) -> Result<()> {
    let state_dir = args
        .dir
        .clone()
        .unwrap_or_else(|| shipup::resolve_safe_data_dir().unwrap_or_else(|| PathBuf::from(".")));

    println!("================= shipup 客户端运行状态矩阵 =================");
    println!("数据探测目录:     {}", state_dir.display());

    // 1. 读取更新偏好设置（文件名与库侧 PREFERENCE_FILENAME 保持一致）
    let pref_path = state_dir.join(shipup::PREFERENCE_FILENAME);
    if pref_path.exists() {
        let pref = shipup::UpdatePreference::load_from_file(&pref_path);
        println!(
            "客户端唯一 ID:    {}",
            pref.client_id.as_deref().unwrap_or("未生成")
        );
        println!(
            "已知清单版本序号: {}",
            pref.last_version_seq
                .map(|s| s.to_string())
                .unwrap_or_else(|| "无记录".to_string())
        );
        let skipped_str = if pref.skipped_versions.is_empty() {
            "无".to_string()
        } else {
            pref.skipped_versions
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!("跳过的版本列表:   {}", skipped_str);
        let snooze_str = if let Some(ts) = pref.snooze_until {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if ts > now {
                format!("静默中（截止时间戳: {}）", ts)
            } else {
                "已过期".to_string()
            }
        } else {
            "未设置".to_string()
        };
        println!("稍后提醒静默期:   {}", snooze_str);
    } else {
        println!("更新偏好文件:     未生成（默认空）");
    }

    // 2. 读取崩溃自愈观察期状态
    let state_path = state_dir.join(".shipup.state");
    if state_path.exists() {
        let content = fs::read_to_string(&state_path).unwrap_or_default();
        if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
            let target = state["target_version"].as_str().unwrap_or("未知");
            let attempts = state["launch_attempts"].as_u64().unwrap_or(0);
            println!(
                "更新自愈观察期:   处于观察期（目标版本: {}, 启动计数: {}）",
                target, attempts
            );
        } else {
            println!("更新自愈观察期:   状态文件格式解析异常");
        }
    } else {
        println!("更新自愈观察期:   正常（无未确认的更新状态）");
    }

    // 3. 读取历史回滚记录
    let history = shipup::load_rollback_history(&state_dir);
    println!("可回滚历史版本数: {}", history.entries.len());
    for (i, entry) in history.entries.iter().enumerate() {
        let exists_str = if entry.backup_path.exists() {
            "物理文件正常"
        } else {
            "备份文件缺失"
        };
        println!(
            "  [{}] 版本: {} | 备份时间戳: {} | 状态: {} | 路径: {}",
            i + 1,
            entry.version,
            entry.backed_up_at,
            exists_str,
            entry.backup_path.display()
        );
    }
    println!("===========================================================");

    Ok(())
}

/// 执行手动版本回滚
///
/// # 设计原理
/// - **实现初衷**：在生产环境中为运维人员提供确定的命令行一键回滚手段，不必等待连续崩溃被动自愈。
/// - **核心优势**：自动校验物理备份文件完整性，执行原地原子替换，并在完成后自动解除观察期标记。
pub(crate) fn handle_rollback(args: &RollbackArgs) -> Result<()> {
    let state_dir = args
        .dir
        .clone()
        .unwrap_or_else(|| shipup::resolve_safe_data_dir().unwrap_or_else(|| PathBuf::from(".")));

    let target_version = if let Some(ref ver_str) = args.target {
        Version::parse(ver_str).with_context(|| format!("解析目标回滚版本号失败: {}", ver_str))?
    } else {
        let available = shipup::list_available_rollback_versions(&state_dir);
        available.first().cloned().ok_or_else(|| {
            anyhow!(
                "在目标目录 '{}' 中未发现任何可用的历史备份版本",
                state_dir.display()
            )
        })?
    };

    let exe_path = if let Some(ref p) = args.exe {
        p.clone()
    } else {
        std::env::current_exe().context("获取当前运行可执行文件路径失败，请显式提供 --exe 参数")?
    };

    log::info!(
        "开始执行手动版本回滚: 目标版本 {}, 宿主程序 {}",
        target_version,
        exe_path.display()
    );

    shipup::execute_manual_rollback_to(&state_dir, &exe_path, &target_version)
        .with_context(|| format!("回滚至版本 {} 失败", target_version))?;

    println!(
        "版本回滚执行成功: 已将程序恢复至历史稳定版本 {}",
        target_version
    );
    Ok(())
}

/// 执行孤儿备份与历史替换碎片清理
///
/// # 设计原理
/// - **实现初衷**：自更新完成后遗留的 `.old`、`.bak` 临时文件在长期运行后可能占用磁盘空间，提供安全清理工具。
/// - **核心优势**：支持 `--dry-run` 预览待清理清单，避免误删正在被自愈系统跟踪引用的活跃备份。
pub(crate) fn handle_clean(args: &CleanArgs) -> Result<()> {
    if !args.dir.exists() {
        return Err(anyhow!("目标清理目录不存在: {}", args.dir.display()));
    }

    let entries =
        fs::read_dir(&args.dir).with_context(|| format!("读取目录失败: {}", args.dir.display()))?;

    let mut clean_targets = Vec::new();
    let mut total_bytes = 0u64;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            let is_match = file_name.ends_with(".old")
                || file_name.ends_with(".bak")
                || file_name.starts_with(".shipup_tmp_")
                || file_name.contains(".shipup_old_");

            if is_match {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                total_bytes = total_bytes.saturating_add(size);
                clean_targets.push((path, size));
            }
        }
    }

    if clean_targets.is_empty() {
        println!(
            "目录 '{}' 中未检测到任何可清理的历史备份或临时碎片文件",
            args.dir.display()
        );
        return Ok(());
    }

    println!("================= shipup 历史备份清理扫描 =================");
    println!("扫描目录:       {}", args.dir.display());
    println!("匹配碎片文件数: {}", clean_targets.len());
    println!("预计释放空间:   {} 字节", total_bytes);
    println!("-----------------------------------------------------------");

    for (p, s) in &clean_targets {
        println!("  - {} ({} 字节)", p.display(), s);
    }
    println!("===========================================================");

    if args.dry_run {
        println!("提示: 当前处于演练模式 (--dry-run)，未执行实际删除");
        return Ok(());
    }

    let mut success_count = 0usize;
    for (p, _) in clean_targets {
        if let Err(e) = fs::remove_file(&p) {
            log::warn!("清理文件失败: {}, 错误: {}", p.display(), e);
        } else {
            success_count = success_count.saturating_add(1);
        }
    }

    println!(
        "清理完毕: 成功删除 {} 个历史文件，释放约 {} 字节",
        success_count, total_bytes
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_status_rollback_and_clean_flow() -> Result<()> {
        let temp_dir = std::env::temp_dir().join(format!("test_cli_ops_{}", std::process::id()));
        fs::create_dir_all(&temp_dir)?;

        let exe_path = temp_dir.join("myapp.exe");
        fs::write(&exe_path, b"v2.0.0 corrupted current binary")?;

        let backup_v1 = temp_dir.join("myapp.v1.0.0.bak");
        fs::write(&backup_v1, b"v1.0.0 healthy backup binary")?;

        shipup::record_rollback_version(
            &temp_dir,
            &Version::parse("1.0.0").unwrap(),
            &backup_v1,
            3,
        )?;

        handle_status(&StatusArgs {
            dir: Some(temp_dir.clone()),
        })?;

        handle_rollback(&RollbackArgs {
            target: Some("1.0.0".to_string()),
            exe: Some(exe_path.clone()),
            dir: Some(temp_dir.clone()),
        })?;

        let restored_content = fs::read(&exe_path)?;
        assert_eq!(restored_content, b"v1.0.0 healthy backup binary");

        let orphan_file1 = temp_dir.join("test_orphan.old");
        let orphan_file2 = temp_dir.join(".shipup_tmp_123");
        fs::write(&orphan_file1, b"orphan old")?;
        fs::write(&orphan_file2, b"orphan tmp")?;

        handle_clean(&CleanArgs {
            dir: temp_dir.clone(),
            dry_run: true,
        })?;
        assert!(orphan_file1.exists());
        assert!(orphan_file2.exists());

        handle_clean(&CleanArgs {
            dir: temp_dir.clone(),
            dry_run: false,
        })?;
        assert!(!orphan_file1.exists());
        assert!(!orphan_file2.exists());

        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    }

    #[test]
    fn test_handle_clean_missing_dir_errors() {
        let missing =
            std::env::temp_dir().join(format!("test_cli_clean_missing_{}", std::process::id()));
        let _ = fs::remove_dir_all(&missing);
        let res = handle_clean(&CleanArgs {
            dir: missing,
            dry_run: false,
        });
        assert!(res.is_err());
    }
}
