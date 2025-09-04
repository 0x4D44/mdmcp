//! # mdmcpsrvr - MCP Server
//!
//! A minimal, policy-driven Model Context Protocol (MCP) server that provides
//! secure file system and command execution capabilities. The server enforces
//! strict policy controls on all operations and maintains comprehensive audit logs.
//!
//! ## Architecture
//!
//! The server is built around several core components:
//! - JSON-RPC 2.0 transport layer for MCP protocol communication
//! - Policy-based security enforcement for all operations
//! - Platform-specific filesystem safety checks
//! - Sandboxed command execution with resource limits
//! - Comprehensive audit logging with content hashing

use anyhow::{Context, Result};
use clap::Parser;
use mdmcp_policy::CompiledPolicy;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::{error, info};

mod audit;
mod cmd_catalog;
mod fs_safety;
mod policy;
mod rpc;
mod sandbox;
mod server;

#[derive(Parser)]
#[command(name = "mdmcpsrvr")]
#[command(about = "MCP Server - Minimal, policy-driven Model Context Protocol server")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Path to policy configuration file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Use stdio transport (default and currently only supported)
    #[arg(long, default_value = "true")]
    stdio: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level)?;

    info!("Starting mdmcpsrvr v{}", env!("CARGO_PKG_VERSION"));

    // Load and compile policy
    let config_path = cli.config.context("Configuration file path is required")?;
    let policy = load_policy(&config_path).await?;
    info!(
        "Loaded policy with {} allowed roots, {} commands, hash: {}",
        policy.allowed_roots_canonical.len(),
        policy.commands_by_id.len(),
        &policy.policy_hash[..8]
    );

    // Create server instance
    let server = server::Server::new(Arc::new(policy)).await?;

    if cli.stdio {
        run_stdio_server(server).await?;
    } else {
        return Err(anyhow::anyhow!(
            "Only stdio transport is currently supported"
        ));
    }

    Ok(())
}

async fn load_policy(path: &PathBuf) -> Result<CompiledPolicy> {
    let policy = mdmcp_policy::Policy::load(path)
        .with_context(|| format!("Failed to load policy from {}", path.display()))?;

    policy.compile().context("Failed to compile policy")
}

async fn run_stdio_server(server: server::Server) -> Result<()> {
    info!("Starting stdio transport");

    // Send handshake notification
    server.send_handshake().await?;

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("EOF received, shutting down");
                break;
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                if let Err(e) = server.handle_request_line(line).await {
                    error!("Error handling request: {}", e);
                }
            }
            Err(e) => {
                error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn init_logging(level: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("mdmcpsrvr={}", level)));

    tracing_subscriber::fmt()
        .with_target(false)
        .without_time() // stdio mode doesn't need timestamps
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    Ok(())
}
