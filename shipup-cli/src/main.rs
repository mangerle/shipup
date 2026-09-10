// shipup-cli 跨平台自更新系统 - 发布端打包与签名命令行工具
//
// 模块划分：
// - `cli`：命令行参数与子命令定义
// - `util`：时间、时长、哈希签名与体积格式化等通用工具
// - `release`：密钥生成、单包/批量发布、独立签名与配置脚手架
// - `verify`：Manifest 核验、清单展示与离线仓库审计
// - `ops`：客户端状态查看、版本回滚与历史碎片清理

mod cli;
mod ops;
mod release;
mod util;
mod verify;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out_dir } => {
            release::handle_keygen(&out_dir)?;
        }
        Commands::Release(args) => {
            release::handle_release(&args)?;
        }
        Commands::Verify(args) => {
            verify::handle_verify(&args)?;
        }
        Commands::Inspect(args) => {
            verify::handle_inspect(&args)?;
        }
        Commands::Init(args) => {
            release::handle_init(&args)?;
        }
        Commands::Sign(args) => {
            release::handle_sign(&args)?;
        }
        Commands::Status(args) => {
            ops::handle_status(&args)?;
        }
        Commands::Rollback(args) => {
            ops::handle_rollback(&args)?;
        }
        Commands::Clean(args) => {
            ops::handle_clean(&args)?;
        }
        Commands::VerifyRepo(args) => {
            verify::handle_verify_repo(&args)?;
        }
    }

    Ok(())
}
