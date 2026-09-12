//! shipup 发布端打包与签名命令行工具（`shipup-cli`）的可执行入口。
//!
//! # 模块职责
//! 解析命令行参数并把各子命令分派到对应的处理模块，是发布流水线与客户端运维的统一入口。
//!
//! # 子命令分组
//! - 发布链路：`keygen`（生成 Ed25519 密钥对）、`release`（单包发布并签署清单）、
//!   `init`（生成发布配置脚手架）、`sign`（对既有包体补充签名）、`verify`（核验清单与包体一致性）；
//! - 运维链路：`inspect`（展示清单内容）、`status`（查看客户端更新与回滚状态）、
//!   `rollback`（主动回退到历史版本）、`clean`（清理历史碎片与残留备份）、
//!   `verify-repo`（审计离线镜像仓库完整性）。
//!
//! # 设计原理
//! - **实现初衷**：发布端与客户端共享同一套 Manifest 协议与签名算法，
//!   把两者收拢在同一 workspace 内可直接复用核心库类型，避免协议在两个仓库间漂移。
//! - **核心优势**：分派逻辑保持为扁平的 `match`，
//!   每个分支只做参数转换与错误上抛，具体实现全部下沉到子模块，便于单独测试。
//! - **代价与局限**：本工具面向发布方与运维人员，需在受信环境中运行；
//!   涉及私钥的命令（`release` / `sign`）会直接读取本地私钥文件，不应在不可信主机上执行。
//!
//! # 模块划分
//! - [`cli`]：命令行参数与子命令定义；
//! - [`util`]：时间、时长、哈希签名与体积格式化等通用工具；
//! - [`release`]：密钥生成、单包/批量发布、独立签名与配置脚手架；
//! - [`verify`]：Manifest 核验、清单展示与离线仓库审计；
//! - [`ops`]：客户端状态查看、版本回滚与历史碎片清理。

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
