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
        // In tests, allow overriding root to a temp folder to avoid touching user dirs
        #[cfg(test)]
        if let Ok(root) = std::env::var("MDMCP_TEST_ROOT") {
            let root = PathBuf::from(root);
            let bin_dir = root.join("bin");
            let config_dir = root.join("config");
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
            return Ok(Self {
                bin_dir,
                config_dir,
                policy_file,
                core_policy_file,
            });
        }
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

/// Return true if running under Windows Subsystem for Linux
#[cfg(target_os = "linux")]
fn is_wsl() -> bool {
    // Environment variables commonly set by WSL
    if std::env::var("WSL_INTEROP").is_ok() || std::env::var("WSL_DISTRO_NAME").is_ok() {
        return true;
    }
    // Fallback: check kernel osrelease
    if let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let l = release.to_ascii_lowercase();
        if l.contains("microsoft") || l.contains("wsl") {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_wsl() -> bool {
    false
}

/// Map a Windows path like `C:\\Users\\Name\\AppData\\Roaming` into WSL mount path `/mnt/c/Users/Name/AppData/Roaming`
#[cfg(target_os = "linux")]
fn windows_path_to_wsl_mount(p: &str) -> Option<PathBuf> {
    let p = p.trim();
    if p.len() >= 3 && p.as_bytes()[1] == b':' {
        let drive = p.chars().next()?.to_ascii_lowercase();
        let rest = &p[2..];
        let rest_unescaped = rest.replace('\\', "/");
        let mut out = PathBuf::from(format!("/mnt/{}", drive));
        // If rest starts with a path separator, skip it
        let rest_trimmed = rest_unescaped.trim_start_matches(&['/', '\\'][..]);
        out.push(rest_trimmed);
        Some(out)
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn windows_path_to_wsl_mount(_p: &str) -> Option<PathBuf> {
    None
}

/// Attempt to obtain Windows Roaming AppData path from WSL using cmd.exe
#[cfg(target_os = "linux")]
fn windows_roaming_appdata_from_wsl() -> Option<PathBuf> {
    let cmd_path = "/mnt/c/Windows/System32/cmd.exe";
    if !Path::new(cmd_path).exists() {
        return None;
    }
    let output = std::process::Command::new(cmd_path)
        .args(["/C", "echo", "%APPDATA%"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    windows_path_to_wsl_mount(s)
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn windows_roaming_appdata_from_wsl() -> Option<PathBuf> {
    None
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
        // In tests, allow overriding the path to avoid touching user files
        #[cfg(test)]
        if let Ok(p) = std::env::var("MDMCP_TEST_CLAUDE_CONFIG") {
            return Ok(PathBuf::from(p));
        }
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
            // Linux (detect WSL and write to Windows Claude config if possible)
            if is_wsl() {
                if let Some(roaming) = windows_roaming_appdata_from_wsl() {
                    return Ok(roaming.join("Claude").join("claude_desktop_config.json"));
                }
            }
            // Non-WSL Linux fallback: Linux config location
            let config_dir = dirs::config_dir()
                .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
                .context("Failed to get config directory")?;
            Ok(config_dir.join("Claude").join("claude_desktop_config.json"))
        }
    }

    /// Add or update the mdmcp server configuration.
    ///
    /// - On Windows/macOS/native Linux: point directly to the server binary.
    /// - On WSL (Linux): point command to `wsl.exe` and pass Linux paths as args.
    pub fn add_mdmcp_server(&mut self, server_binary: &Path, policy_file: &Path) -> Result<()> {
        let server_config = if is_wsl() {
            // Prepare args for wsl.exe invocation
            let mut args: Vec<serde_json::Value> = Vec::new();
            if let Ok(distro) = std::env::var("WSL_DISTRO_NAME") {
                if !distro.trim().is_empty() {
                    args.push(serde_json::json!("-d"));
                    args.push(serde_json::json!(distro));
                }
            }
            args.push(serde_json::json!(server_binary.to_string_lossy()));
            args.push(serde_json::json!("--config"));
            args.push(serde_json::json!(policy_file.to_string_lossy()));
            args.push(serde_json::json!("--stdio"));

            serde_json::json!({
                "command": "wsl.exe",
                "args": args,
                "env": {}
            })
        } else {
            serde_json::json!({
                "command": server_binary.to_string_lossy(),
                "args": ["--config", policy_file.to_string_lossy(), "--stdio"],
                "env": {}
            })
        };

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
    // Atomic write: write to a temp file in the same directory, then rename
    let parent = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let mut tmp = tempfile::NamedTempFile::new_in(&parent)
        .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
    use std::io::Write as _;
    tmp.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write temp file for {}", path.display()))?;
    tmp.flush()
        .with_context(|| format!("Failed to flush temp file for {}", path.display()))?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("Failed to persist {}: {}", path.display(), e))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doc_path_and_config_join_shapes() {
        // Should point to a claude_desktop_config.json somewhere under a config directory
        let p = ClaudeDesktopConfig::config_path().expect("config path");
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some("claude_desktop_config.json")
        );
    }

    #[test]
    fn test_add_mdmcp_server_shape() {
        let mut cfg = ClaudeDesktopConfig::default();
        let server = if cfg!(target_os = "windows") {
            PathBuf::from("C:/mdmcp/bin/mdmcpsrvr.exe")
        } else {
            PathBuf::from("/opt/mdmcp/bin/mdmcpsrvr")
        };
        let policy = if cfg!(target_os = "windows") {
            PathBuf::from("C:/Users/Test/AppData/Roaming/mdmcp/policy.user.yaml")
        } else {
            PathBuf::from("/home/test/.config/mdmcp/policy.user.yaml")
        };
        cfg.add_mdmcp_server(&server, &policy).expect("add server");
        let entry = cfg.mcp_servers.get("mdmcp").expect("entry");
        let cmd = entry.get("command").and_then(|v| v.as_str()).unwrap();
        let args = entry.get("args").and_then(|v| v.as_array()).unwrap();
        if cfg!(target_os = "linux") && is_wsl() {
            // WSL path: command is wsl.exe and args contain server path and switches
            assert_eq!(cmd, "wsl.exe");
            let has_stdio = args.iter().any(|v| v.as_str() == Some("--stdio"));
            let has_config = args.iter().any(|v| v.as_str() == Some("--config"));
            assert!(has_stdio && has_config);
        } else {
            // Non-WSL: direct exec
            assert!(cmd.contains("mdmcpsrvr"));
            assert_eq!(args.first().and_then(|v| v.as_str()), Some("--config"));
            assert_eq!(args.last().and_then(|v| v.as_str()), Some("--stdio"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_windows_path_to_wsl_mount_variants() {
        let p1 = windows_path_to_wsl_mount("C:\\Users\\Name\\AppData\\Roaming").unwrap();
        assert_eq!(p1, PathBuf::from("/mnt/c/Users/Name/AppData/Roaming"));
        let p2 = windows_path_to_wsl_mount("D:/Data").unwrap();
        assert_eq!(p2, PathBuf::from("/mnt/d/Data"));
        assert!(windows_path_to_wsl_mount("/not/windows").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_wsl_env_flag() {
        // Ensure function sees WSL env flag
        std::env::set_var("WSL_DISTRO_NAME", "Ubuntu-22.04");
        assert!(is_wsl());
        std::env::remove_var("WSL_DISTRO_NAME");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_is_executable_windows_extension_rules() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool.EXE");
        std::fs::write(&exe, b"bin").unwrap();
        assert!(is_executable(&exe));
        let txt = dir.path().join("file.txt");
        std::fs::write(&txt, b"text").unwrap();
        assert!(!is_executable(&txt));
    }

    #[cfg(unix)]
    #[test]
    fn test_is_executable_unix_perm_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("script.sh");
        std::fs::write(&f, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut perms = std::fs::metadata(&f).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&f, perms.clone()).unwrap();
        assert!(!is_executable(&f));
        let mut perms = std::fs::metadata(&f).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&f, perms).unwrap();
        assert!(is_executable(&f));
    }

    #[test]
    fn test_claude_config_save_and_roundtrip_with_mdmcp_entry() {
        // Use test-only override to redirect config file
        let tmp = tempfile::tempdir().unwrap();
        let cfg_path = tmp.path().join("claude_desktop_config.json");
        std::env::set_var("MDMCP_TEST_CLAUDE_CONFIG", &cfg_path);
        // Roundtrip save/load
        let mut cfg = ClaudeDesktopConfig::load_or_default().unwrap();
        assert!(cfg.mcp_servers.is_empty());
        let server = if cfg!(target_os = "windows") {
            PathBuf::from("C:/mdmcp/bin/mdmcpsrvr.exe")
        } else {
            PathBuf::from("/opt/mdmcp/bin/mdmcpsrvr")
        };
        let policy = if cfg!(target_os = "windows") {
            PathBuf::from("C:/Users/Test/AppData/Roaming/mdmcp/policy.user.yaml")
        } else {
            PathBuf::from("/home/test/.config/mdmcp/policy.user.yaml")
        };
        cfg.add_mdmcp_server(&server, &policy).unwrap();
        cfg.save().unwrap();
        let loaded = ClaudeDesktopConfig::load_or_default().unwrap();
        assert!(loaded.mcp_servers.contains_key("mdmcp"));
        std::env::remove_var("MDMCP_TEST_CLAUDE_CONFIG");
    }
}
