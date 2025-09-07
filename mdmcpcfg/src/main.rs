//! # mdmcpcfg - MCP Server Configuration CLI
//!
//! This is the configuration CLI tool for mdmcp, a minimal, policy-driven Model Context Protocol (MCP) server.
//! The CLI provides commands to install, update, configure, and manage the MCP server and its policies.
//!
//! ## Commands
//! - `install`: Download and install the MCP server binary with Claude Desktop integration
//! - `update`: Update the server binary to the latest version
//! - `policy`: Manage policy files (show, edit, validate, add roots/commands)
//! - `doctor`: Run diagnostics to check system health and configuration
//! - `run`: Send test JSON-RPC requests to the server for smoke testing

use anyhow::Result;
use clap::{Parser, Subcommand};

mod commands;
mod io;

use commands::{doctor, install, policy};

#[derive(Parser)]
#[command(name = "mdmcpcfg")]
#[command(about = "Configuration tool for mdmcp MCP server")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the MCP server binary and configure Claude Desktop
    Install {
        /// Installation directory (default: platform-specific)
        #[arg(long)]
        dest: Option<String>,
        /// Skip Claude Desktop configuration
        #[arg(long)]
        no_claude_config: bool,
        /// Install from local binary instead of downloading
        #[arg(long)]
        local: bool,
        /// Path to local binary (default: same directory as mdmcpcfg)
        #[arg(long)]
        local_path: Option<String>,
    },
    /// Update the MCP server binary
    Update {
        /// Update channel (stable, beta)
        #[arg(long, default_value = "stable")]
        channel: String,
        /// Rollback to previous version
        #[arg(long)]
        rollback: bool,
        /// Force update even if versions match
        #[arg(long)]
        force: bool,
    },
    /// Manage policy configuration
    #[command(subcommand)]
    Policy(PolicyCommands),
    /// Run system diagnostics
    Doctor,
    /// Uninstall the MCP server binary and optionally clean config
    Uninstall {
        /// Also remove the policy file
        #[arg(long)]
        remove_policy: bool,
        /// Also remove the Claude Desktop configuration entry
        #[arg(long)]
        remove_claude_config: bool,
        /// Do not prompt for confirmation
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Send test requests to the server
    Run {
        /// JSON-RPC file to send
        jsonrpc_file: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show current policy configuration
    Show,
    /// Edit policy in default editor
    Edit,
    /// Validate policy file against schema
    Validate {
        /// Policy file path (default: system config location)
        #[arg(long)]
        file: Option<String>,
    },
    /// Add an allowed root directory
    AddRoot {
        /// Path to add as allowed root
        path: String,
        /// Also allow writing to this path
        #[arg(long)]
        write: bool,
    },
    /// Add a command to the catalog
    AddCommand {
        /// Command ID
        id: String,
        /// Executable path
        #[arg(long)]
        exec: String,
        /// Allowed arguments
        #[arg(long = "allow", action = clap::ArgAction::Append)]
        allow_args: Vec<String>,
        /// Regex patterns for arguments
        #[arg(long = "pattern", action = clap::ArgAction::Append)]
        patterns: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Install {
            dest,
            no_claude_config,
            local,
            local_path,
        } => install::run(dest, !no_claude_config, local, local_path).await,
        Commands::Update {
            channel,
            rollback,
            force,
        } => install::update(channel, rollback, force).await,
        Commands::Policy(policy_cmd) => match policy_cmd {
            PolicyCommands::Show => policy::show().await,
            PolicyCommands::Edit => policy::edit().await,
            PolicyCommands::Validate { file } => policy::validate(file).await,
            PolicyCommands::AddRoot { path, write } => policy::add_root(path, write).await,
            PolicyCommands::AddCommand {
                id,
                exec,
                allow_args,
                patterns,
            } => policy::add_command(id, exec, allow_args, patterns).await,
        },
        Commands::Doctor => doctor::run().await,
        Commands::Uninstall {
            remove_policy,
            remove_claude_config,
            yes,
        } => install::uninstall(remove_policy, remove_claude_config, yes).await,
        Commands::Run { jsonrpc_file } => {
            // TODO: Implement run command for smoke testing
            println!("Running smoke test with {}", jsonrpc_file);
            Ok(())
        }
    }
}
