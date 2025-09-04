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
use tracing::{debug, error, info};

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
    eprintln!("DEBUG: Starting main function");
    
    // Set up panic handler to catch crashes
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("PANIC: Server crashed: {:?}", panic_info);
    }));
    let cli = Cli::parse();
    eprintln!("DEBUG: Parsed CLI arguments");

    // Initialize logging
    init_logging(&cli.log_level)?;
    eprintln!("DEBUG: Initialized logging");

    info!("Starting mdmcpsrvr v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("DEBUG: Logged startup message");

    // Load and compile policy
    let config_path = cli.config.context("Configuration file path is required")?;
    eprintln!("DEBUG: Got config path: {:?}", config_path);
    
    let policy = load_policy(&config_path).await?;
    eprintln!("DEBUG: Loaded and compiled policy");
    
    info!(
        "Loaded policy with {} allowed roots, {} commands, hash: {}",
        policy.allowed_roots_canonical.len(),
        policy.commands_by_id.len(),
        &policy.policy_hash[..8]
    );

    // Create server instance
    eprintln!("DEBUG: About to create server instance");
    let server = server::Server::new(Arc::new(policy)).await?;
    eprintln!("DEBUG: Created server instance");

    if cli.stdio {
        eprintln!("DEBUG: About to run stdio server");
        let result = run_stdio_server(server).await;
        eprintln!("DEBUG: Stdio server returned: {:?}", result);
        result?;
    } else {
        return Err(anyhow::anyhow!(
            "Only stdio transport is currently supported"
        ));
    }

    eprintln!("DEBUG: Main function completing normally");
    Ok(())
}

async fn load_policy(path: &PathBuf) -> Result<CompiledPolicy> {
    let policy = mdmcp_policy::Policy::load(path)
        .with_context(|| format!("Failed to load policy from {}", path.display()))?;

    policy.compile().context("Failed to compile policy")
}

async fn run_stdio_server(server: server::Server) -> Result<()> {
    info!("Starting stdio transport");
    eprintln!("DEBUG: Starting stdio transport");

    let stdin = io::stdin();
    eprintln!("DEBUG: Got stdin handle");
    
    let mut reader = BufReader::new(stdin);
    eprintln!("DEBUG: Created BufReader");
    
    let mut line = String::new();
    eprintln!("DEBUG: About to enter main loop");

    loop {
        line.clear();
        debug!("Waiting for next line from stdin...");
        eprintln!("DEBUG: About to read line from stdin");
        
        // Add a small delay to let any pending output flush
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        eprintln!("DEBUG: About to call read_line");
        
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("EOF received from stdin, shutting down gracefully");
                eprintln!("DEBUG: EOF received from stdin - client closed connection");
                break;
            }
            Ok(n) => {
                eprintln!("DEBUG: Successfully read {} bytes", n);
                let line = line.trim();
                debug!("Read {} bytes from stdin: '{}'", n, line);
                eprintln!("DEBUG: Line content: '{}'", line);
                
                if line.is_empty() {
                    debug!("Received empty line, continuing...");
                    eprintln!("DEBUG: Empty line, continuing");
                    continue;
                }

                debug!("Processing request: {}", line);
                eprintln!("DEBUG: About to process message: {}", line);
                if let Err(e) = server.handle_request_line(line).await {
                    error!("Error handling request: {}", e);
                    eprintln!("Server error handling request: {}", e);
                } else {
                    eprintln!("DEBUG: Message processed successfully");
                }
                debug!("Request processed successfully");
            }
            Err(e) => {
                error!("Error reading from stdin: {}", e);
                eprintln!("Server shutting down: Error reading from stdin: {}", e);
                break;
            }
        }
    }

    info!("Server main loop ended, exiting");
    eprintln!("Server main loop ended, process exiting");

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
