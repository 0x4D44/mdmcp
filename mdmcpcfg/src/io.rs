//! # I/O utilities for mdmcpcfg
//!
//! This module provides utilities for file operations, path handling, and system interaction
//! specific to the mdmcp configuration tool.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Platform-specific paths for mdmcp installation and configuration
pub struct Paths {
    pub bin_dir: PathBuf,
    pub config_dir: PathBuf,
    pub policy_file: PathBuf,
    pub core_policy_file: PathBuf,
}

impl Paths {
    /// Get platform-specific paths for mdmcp
    pub fn new() -> Result<Self> {
        let (bin_dir, config_dir) = if cfg!(target_os = "windows") {
            let local_appdata =
                dirs::data_local_dir().context("Failed to get local AppData directory")?;
            let appdata = dirs::config_dir().context("Failed to get AppData directory")?;
            (
                local_appdata.join("mdmcp").join("bin"),
                appdata.join("mdmcp"),
            )
        } else if cfg!(target_os = "macos") {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            (
                home.join("Library")
                    .join("Application Support")
                    .join("mdmcp")
                    .join("bin"),
                home.join("Library").join("Preferences").join("mdmcp"),
            )
        } else {
            // Linux and other Unix-like systems
            let data_dir = dirs::data_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("share")))
                .context("Failed to get data directory")?;
            let config_dir = dirs::config_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
                .context("Failed to get config directory")?;
            (data_dir.join("mdmcp").join("bin"), config_dir.join("mdmcp"))
        };

        // Prefer new user policy name; fall back to legacy if present for backward compatibility
        let candidate_user = config_dir.join("policy.user.yaml");
        let legacy_user = config_dir.join("policy.yaml");
        let policy_file = if candidate_user.exists() {
            candidate_user
        } else if legacy_user.exists() {
            legacy_user
        } else {
            candidate_user
        };
        let core_policy_file = config_dir.join("policy.core.yaml");

        Ok(Self {
            bin_dir,
            config_dir,
            policy_file,
            core_policy_file,
        })
    }

    /// Get the path to the mdmcpsrvr binary
    pub fn server_binary(&self) -> PathBuf {
        if cfg!(target_os = "windows") {
            self.bin_dir.join("mdmcpsrvr.exe")
        } else {
            self.bin_dir.join("mdmcpsrvr")
        }
    }

    /// Ensure all necessary directories exist
    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.bin_dir).with_context(|| {
            format!("Failed to create bin directory: {}", self.bin_dir.display())
        })?;
        fs::create_dir_all(&self.config_dir).with_context(|| {
            format!(
                "Failed to create config directory: {}",
                self.config_dir.display()
            )
        })?;
        Ok(())
    }
}

/// Configuration for Claude Desktop MCP settings
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaudeDesktopConfig {
    #[serde(rename = "mcpServers")]
    pub mcp_servers: serde_json::Map<String, serde_json::Value>,
}

impl ClaudeDesktopConfig {
    /// Load existing Claude Desktop configuration or create default
    pub fn load_or_default() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let contents = fs::read_to_string(&config_path).with_context(|| {
                format!(
                    "Failed to read Claude Desktop config: {}",
                    config_path.display()
                )
            })?;

            if contents.trim().is_empty() {
                return Ok(Self::default());
            }

            serde_json::from_str(&contents).with_context(|| {
                format!(
                    "Failed to parse Claude Desktop config: {}",
                    config_path.display()
                )
            })
        } else {
            Ok(Self::default())
        }
    }

    /// Save the configuration to Claude Desktop's config file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Ensure the parent directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create Claude Desktop config directory: {}",
                    parent.display()
                )
            })?;
        }

        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize Claude Desktop config")?;

        fs::write(&config_path, contents).with_context(|| {
            format!(
                "Failed to write Claude Desktop config: {}",
                config_path.display()
            )
        })?;

        println!(
            "✓ Updated Claude Desktop configuration: {}",
            config_path.display()
        );
        Ok(())
    }

    /// Get the path to Claude Desktop's configuration file
    pub fn config_path() -> Result<PathBuf> {
        if cfg!(target_os = "windows") {
            let appdata = dirs::config_dir().context("Failed to get AppData directory")?;
            Ok(appdata.join("Claude").join("claude_desktop_config.json"))
        } else if cfg!(target_os = "macos") {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            Ok(home
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"))
        } else {
            // Linux
            let config_dir = dirs::config_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
                .context("Failed to get config directory")?;
            Ok(config_dir.join("Claude").join("claude_desktop_config.json"))
        }
    }

    /// Add or update the mdmcp server configuration
    pub fn add_mdmcp_server(&mut self, server_binary: &Path, policy_file: &Path) -> Result<()> {
        let server_config = serde_json::json!({
            "command": server_binary.to_string_lossy(),
            "args": ["--config", policy_file.to_string_lossy(), "--stdio"],
            "env": {}
        });

        self.mcp_servers.insert("mdmcp".to_string(), server_config);
        Ok(())
    }

    /// Remove the mdmcp server configuration
    #[allow(dead_code)]
    pub fn remove_mdmcp_server(&mut self) {
        self.mcp_servers.remove("mdmcp");
    }
}

impl Default for ClaudeDesktopConfig {
    fn default() -> Self {
        Self {
            mcp_servers: serde_json::Map::new(),
        }
    }
}

/// Read a file to a string with better error context
pub fn read_file<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = path.as_ref();
    fs::read_to_string(path).with_context(|| format!("Failed to read file: {}", path.display()))
}

/// Write content to a file with better error context
pub fn write_file<P: AsRef<Path>>(path: P, content: &str) -> Result<()> {
    let path = path.as_ref();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    fs::write(path, content).with_context(|| format!("Failed to write file: {}", path.display()))
}

/// Check if a file exists and is executable
pub fn is_executable<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    if !path.exists() {
        return false;
    }

    // On Windows, check if it's an .exe file
    if cfg!(target_os = "windows") {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("exe"))
            .unwrap_or(false)
    } else {
        // On Unix-like systems, check execute permission
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            path.metadata()
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            // For other platforms, assume it's executable if it exists
            true
        }
    }
}
