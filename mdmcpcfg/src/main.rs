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
use clap::{CommandFactory, Parser, Subcommand};

mod commands;
mod io;

use commands::docs;
use commands::{doctor, install, policy};

#[derive(Parser)]
#[command(name = "mdmcpcfg")]
#[command(about = "Configuration tool for mdmcp MCP server")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the MCP server binary and configure Claude Desktop
    Install {
        /// Installation directory (default: platform-specific)
        #[arg(long)]
        dest: Option<String>,
        /// Skip Claude Desktop configuration
        #[arg(long, alias = "no-claude")]
        no_claude_config: bool,
        /// Server target when WSL is available: windows | linux | auto
        #[arg(long, default_value = "auto")]
        server_target: String,
        /// Install plugins (yes|no). Default: yes
        #[arg(long)]
        plugins: Option<String>,
        /// WSL distro name to target when installing Linux server
        #[arg(long)]
        wsl_distro: Option<String>,
        /// Accept defaults and skip interactive prompts
        #[arg(long, short = 'y')]
        yes: bool,
        /// Install from local binary instead of downloading
        #[arg(long)]
        local: bool,
        /// Path to local binary (default: same directory as mdmcpcfg)
        #[arg(long)]
        local_path: Option<String>,
        /// Skip release signature/hash verification (NOT recommended)
        #[arg(long)]
        insecure_skip_verify: bool,
        /// Override minisign public key path (testing only)
        #[arg(long)]
        verify_key: Option<String>,
    },
    /// Internal: helper process to self-upgrade mdmcpcfg
    #[command(hide = true)]
    SelfUpgradeHelper {
        /// PID of the parent mdmcpcfg process
        #[arg(long)]
        pid: u32,
        /// Path to the original mdmcpcfg executable to replace
        #[arg(long)]
        orig: String,
        /// Path to the new mdmcpcfg executable to install
        #[arg(long)]
        new: String,
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
        /// Skip release signature/hash verification (NOT recommended)
        #[arg(long)]
        insecure_skip_verify: bool,
        /// Override minisign public key path (testing only)
        #[arg(long)]
        verify_key: Option<String>,
    },
    /// Build and cache documentation for tools and commands
    Docs {
        /// Build the documentation cache now
        #[arg(long)]
        build: bool,
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
    /// Upsert a command's exec path (update if exists, add minimal if missing)
    SetExec {
        /// Command ID
        id: String,
        /// Executable path
        #[arg(long)]
        exec: String,
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
    /// Reload policy by restarting the MCP client (Claude Desktop)
    Reload,
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
    /// Set static environment variables for a command (NAME=VALUE)
    SetEnv {
        /// Command ID
        id: String,
        /// One or more NAME=VALUE pairs
        #[arg(num_args = 1..)]
        kv: Vec<String>,
    },
    /// Unset static environment variables for a command
    UnsetEnv {
        /// Command ID
        id: String,
        /// One or more variable names to remove
        #[arg(num_args = 1..)]
        names: Vec<String>,
    },
    /// List static environment variables for a command
    ListEnv {
        /// Command ID
        id: String,
    },
    /// Upsert a command's exec path (update if exists, add minimal if missing)
    SetExec {
        /// Command ID
        id: String,
        /// Executable path
        #[arg(long)]
        exec: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // On Windows, switch console code pages to UTF-8 so emojis render correctly.
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
        const CP_UTF8: u32 = 65001;
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
    }

    let cli = Cli::parse();

    match cli.command {
        None => {
            // Print dynamic platform suffix and then standard help
            let platform = if cfg!(target_os = "windows") {
                "Windows".to_string()
            } else if cfg!(target_os = "macos") {
                "macOS".to_string()
            } else if crate::io::is_wsl() {
                "Linux/WSL".to_string()
            } else {
                "Linux".to_string()
            };
            println!("mdmcpcfg {} ({})\n", env!("CARGO_PKG_VERSION"), platform);
            Cli::command().print_help().ok();
            println!();
            return Ok(());
        }
        Some(Commands::Install {
            dest,
            no_claude_config,
            server_target,
            plugins,
            wsl_distro,
            yes,
            local,
            local_path,
            insecure_skip_verify,
            verify_key,
        }) => {
            install::run(
                dest,
                !no_claude_config,
                server_target,
                plugins,
                wsl_distro,
                yes,
                local,
                local_path,
                insecure_skip_verify,
                verify_key,
            )
            .await
        }
        Some(Commands::Update {
            channel,
            rollback,
            force,
            insecure_skip_verify,
            verify_key,
        }) => install::update(channel, rollback, force, insecure_skip_verify, verify_key).await,
        Some(Commands::Policy(policy_cmd)) => match policy_cmd {
            PolicyCommands::Show => policy::show().await,
            PolicyCommands::Edit => policy::edit().await,
            PolicyCommands::Validate { file } => policy::validate(file).await,
            PolicyCommands::Reload => policy::reload().await,
            PolicyCommands::AddRoot { path, write } => policy::add_root(path, write).await,
            PolicyCommands::AddCommand {
                id,
                exec,
                allow_args,
                patterns,
            } => policy::add_command(id, exec, allow_args, patterns).await,
            PolicyCommands::SetEnv { id, kv } => policy::set_env(id, kv).await,
            PolicyCommands::UnsetEnv { id, names } => policy::unset_env(id, names).await,
            PolicyCommands::ListEnv { id } => policy::list_env(id).await,
            PolicyCommands::SetExec { id, exec } => policy::set_exec(id, exec).await,
        },
        Some(Commands::Doctor) => doctor::run().await,
        Some(Commands::Docs { build: _ }) => docs::build().await,
        Some(Commands::Uninstall {
            remove_policy,
            remove_claude_config,
            yes,
        }) => install::uninstall(remove_policy, remove_claude_config, yes).await,
        Some(Commands::Run { jsonrpc_file }) => {
            // TODO: Implement run command for smoke testing
            println!("Running smoke test with {}", jsonrpc_file);
            Ok(())
        }
        Some(Commands::SelfUpgradeHelper { pid, orig, new }) => {
            // Delegate to self-update helper logic
            commands::install::run_self_upgrade_helper(pid, orig, new)
        }
        Some(Commands::SetExec { id, exec }) => policy::set_exec(id, exec).await,
    }
}
