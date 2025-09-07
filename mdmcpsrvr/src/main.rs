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
    // Set up panic handler to catch crashes
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("PANIC: Server crashed: {:?}", panic_info);
    }));
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.log_level)?;

    info!("Starting mdmcpsrvr v{}", env!("CARGO_PKG_VERSION"));

    // Load and compile policy
    let config_path = cli.config.context("Configuration file path is required")?;
    let policy = load_policy(&config_path).await?;
    
    // Log policy summary with detailed allowed directories and commands
    info!("Loaded policy hash: {}", &policy.policy_hash[..16]);
    
    info!("Allowed directories ({} total):", policy.allowed_roots_canonical.len());
    for (i, root) in policy.allowed_roots_canonical.iter().enumerate().take(10) {
        info!("  {} - {}", i + 1, root.display());
    }
    if policy.allowed_roots_canonical.len() > 10 {
        info!("  ... and {} more directories", policy.allowed_roots_canonical.len() - 10);
    }
    
    info!("Available commands ({} total):", policy.commands_by_id.len());
    for (i, (cmd_id, cmd_rule)) in policy.commands_by_id.iter().enumerate().take(10) {
        info!("  {} - '{}' -> {}", i + 1, cmd_id, cmd_rule.rule.exec);
        if !cmd_rule.rule.args.allow.is_empty() {
            info!("      allowed args: {:?}", cmd_rule.rule.args.allow);
        }
    }
    if policy.commands_by_id.len() > 10 {
        info!("  ... and {} more commands", policy.commands_by_id.len() - 10);
    }

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
    info!("Starting stdio transport - ready for MCP requests");

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        debug!("Waiting for next line from stdin...");
        
        // Add a small delay to let any pending output flush
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Client disconnected - shutting down gracefully");
                break;
            }
            Ok(_) => {
                let line = line.trim();
                debug!("Processing request: {}", line);
                
                if line.is_empty() {
                    debug!("Received empty line, continuing...");
                    continue;
                }

                if let Err(e) = server.handle_request_line(line).await {
                    error!("Error handling request: {}", e);
                }
                debug!("Request processed successfully");
            }
            Err(e) => {
                error!("Error reading from stdin: {}", e);
                break;
            }
        }
    }

    info!("Server shutdown complete");
    Ok(())
}

fn init_logging(level: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(format!("mdmcpsrvr={}", level)));

    tracing_subscriber::fmt()
        .with_target(false)
        .with_ansi(false) // Disable ANSI color codes
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .event_format(CustomFormatter)
        .init();

    Ok(())
}

struct CustomFormatter;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for CustomFormatter
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        use std::process;
        use chrono::Utc;
        
        let timestamp = Utc::now().format("%Y-%m-%d:%H:%M:%S%.3f");
        let pid = process::id();
        let _level = event.metadata().level();
        
        write!(writer, "{}-MDMCPsrvr-{}: ", timestamp, pid)?;
        
        // Format the message
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        
        writeln!(writer)
    }
}
