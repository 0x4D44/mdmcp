//! # Installation and update commands
//!
//! This module handles downloading, installing, and updating the mdmcpsrvr binary,
//! as well as configuring Claude Desktop to use the MCP server.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::io::{is_executable, write_file, ClaudeDesktopConfig, Paths};

/// GitHub release information
#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
    prerelease: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Installation metadata
#[derive(Debug, Serialize, Deserialize)]
struct InstallationInfo {
    version: String,
    installed_at: String,
    binary_path: String,
    policy_path: String,
    binary_sha256: String,
}

impl InstallationInfo {
    fn new(version: String, paths: &Paths) -> Result<Self> {
        let binary_path = paths.server_binary();
        let binary_sha256 = if binary_path.exists() {
            calculate_sha256(&binary_path)?
        } else {
            String::new()
        };

        Ok(Self {
            version,
            installed_at: chrono::Utc::now().to_rfc3339(),
            binary_path: binary_path.to_string_lossy().to_string(),
            policy_path: paths.policy_file.to_string_lossy().to_string(),
            binary_sha256,
        })
    }

    fn new_local(version: String, paths: &Paths, source_binary: &Path) -> Result<Self> {
        let binary_path = paths.server_binary();
        let binary_sha256 = if binary_path.exists() {
            calculate_sha256(&binary_path)?
        } else {
            calculate_sha256(source_binary)?
        };

        Ok(Self {
            version: format!("{} (local)", version),
            installed_at: chrono::Utc::now().to_rfc3339(),
            binary_path: binary_path.to_string_lossy().to_string(),
            policy_path: paths.policy_file.to_string_lossy().to_string(),
            binary_sha256,
        })
    }

    fn save(&self, paths: &Paths) -> Result<()> {
        let info_file = paths.config_dir.join("install_info.json");
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize installation info")?;
        write_file(&info_file, &content)?;
        Ok(())
    }

    fn load(paths: &Paths) -> Result<Option<Self>> {
        let info_file = paths.config_dir.join("install_info.json");
        if !info_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&info_file).with_context(|| {
            format!("Failed to read installation info: {}", info_file.display())
        })?;

        let info: Self =
            serde_json::from_str(&content).context("Failed to parse installation info")?;

        Ok(Some(info))
    }
}

/// Install the MCP server binary and configure Claude Desktop
pub async fn run(
    dest_dir: Option<String>,
    configure_claude: bool,
    local: bool,
    local_path: Option<String>,
) -> Result<()> {
    println!("🔧 Installing mdmcp MCP server...");

    if local {
        // Explicit local install
        install_from_local(dest_dir, configure_claude, local_path).await
    } else {
        // Try GitHub first, fallback to local if available
        match install_from_github(dest_dir.clone(), configure_claude).await {
            Ok(()) => Ok(()),
            Err(github_error) => {
                // Log GitHub failure details
                log_github_failure(&github_error);

                // Check for local binary
                if let Some(local_binary) = detect_local_server_binary() {
                    println!("🔍 Found local server binary: {}", local_binary.display());
                    println!("❓ Would you like to install from local binary instead?");

                    // Simple stdin prompt
                    if prompt_user_confirmation()? {
                        return install_from_local_binary(
                            dest_dir,
                            configure_claude,
                            &local_binary,
                        )
                        .await;
                    }
                }

                Err(github_error)
            }
        }
    }
}

/// Update the MCP server binary
pub async fn update(channel: String, rollback: bool) -> Result<()> {
    let paths = Paths::new()?;

    if rollback {
        println!("🔄 Rolling back to previous version...");
        // TODO: Implement rollback functionality
        bail!("Rollback functionality not yet implemented");
    }

    println!("🔄 Updating mdmcp MCP server (channel: {})...", channel);

    // Check current version
    if let Some(current_info) = InstallationInfo::load(&paths)? {
        println!("📌 Current version: {}", current_info.version);

        // Verify current binary integrity
        let binary_path = Path::new(&current_info.binary_path);
        if binary_path.exists() {
            let current_hash = calculate_sha256(binary_path)?;
            if current_hash != current_info.binary_sha256 {
                println!("⚠️  Binary hash mismatch - binary may have been modified");
            }
        }
    } else {
        println!("ℹ️  No existing installation found - performing fresh install");
        return run(None, true, false, None).await;
    }

    // Try GitHub update first, fallback to local if available
    match update_from_github(channel, &paths).await {
        Ok(()) => Ok(()),
        Err(github_error) => {
            // Log GitHub failure details
            log_github_failure(&github_error);

            // Check for local binary
            if let Some(local_binary) = detect_local_server_binary() {
                println!("🔍 Found local server binary: {}", local_binary.display());
                println!("❓ Would you like to update from local binary instead?");

                // Simple stdin prompt
                if prompt_user_confirmation()? {
                    return update_from_local_binary(&paths, &local_binary).await;
                }
            }

            Err(github_error)
        }
    }
}

/// Update from GitHub (extracted from original update logic)
async fn update_from_github(channel: String, paths: &Paths) -> Result<()> {
    // Fetch latest release
    let release = if channel == "stable" {
        fetch_latest_release().await?
    } else {
        fetch_latest_prerelease().await?
    };

    println!("📦 Latest version: {}", release.tag_name);

    // Check current version and compare
    if let Some(current_info) = InstallationInfo::load(paths)? {
        println!("📌 Current version: {}", current_info.version);
        println!("🆕 Available version: {}", release.tag_name);

        if current_info.version == release.tag_name {
            println!("✅ Already up to date!");
            return Ok(());
        }
    } else {
        println!("🆕 New version: {}", release.tag_name);
    }

    // Backup current binary
    let binary_path = paths.server_binary();
    let backup_path = binary_path.with_extension("bak");
    if binary_path.exists() {
        println!("💾 Backing up current binary...");
        fs::copy(&binary_path, &backup_path).context("Failed to create backup")?;
    }

    // Download new binary
    download_binary(&release, &binary_path).await?;

    // Update installation info
    let install_info = InstallationInfo::new(release.tag_name.clone(), paths)?;
    install_info.save(paths)?;

    println!("✅ Update completed successfully!");
    println!("   New version: {}", release.tag_name);

    Ok(())
}

/// Update from local binary
async fn update_from_local_binary(paths: &Paths, source_binary: &Path) -> Result<()> {
    println!("📦 Updating from local binary: {}", source_binary.display());

    // Validate local binary
    if !source_binary.exists() {
        bail!("Local binary not found: {}", source_binary.display());
    }

    if !is_executable(source_binary) {
        bail!(
            "Local binary is not executable: {}",
            source_binary.display()
        );
    }

    // Test binary can run --version or --help
    let version = test_local_binary_version(source_binary).await?;
    println!("✅ Local binary validated - Version: {}", version);

    // Check current version and compare
    if let Some(current_info) = InstallationInfo::load(paths)? {
        let current_version = &current_info.version;
        let new_version_tag = format!("{} (local)", version);

        println!("📌 Current version: {}", current_version);
        println!("🆕 Available version: {}", new_version_tag);

        // Try to get actual version of currently installed binary for better comparison
        let current_binary = paths.server_binary();
        if current_binary.exists() {
            if let Ok(actual_current_version) = test_local_binary_version(&current_binary).await {
                println!(
                    "🔍 Current binary reports version: {}",
                    actual_current_version
                );

                // Compare the actual running versions, not just the stored metadata
                if actual_current_version == version && version != "local" {
                    println!("✅ Already up to date - both binaries report same version!");
                    return Ok(());
                }
            }
        }

        // Only skip if versions are identical AND the current installation is also local
        if current_info.version == new_version_tag && version != "local" {
            println!("✅ Already up to date with local version!");
            return Ok(());
        }

        if current_info.version == new_version_tag && version == "local" {
            println!("⚠️  Both current and new versions are detected as 'local' - proceeding with update to ensure binary is current");
        }
    } else {
        println!("🆕 New version: {} (local)", version);
    }

    // Backup current binary
    let binary_path = paths.server_binary();
    let backup_path = binary_path.with_extension("bak");
    if binary_path.exists() {
        println!("💾 Backing up current binary...");
        fs::copy(&binary_path, &backup_path).context("Failed to create backup")?;
    }

    // Copy local binary to destination
    fs::copy(source_binary, &binary_path)
        .with_context(|| format!("Failed to copy binary to: {}", binary_path.display()))?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    set_executable_permissions(&binary_path)?;

    // Update installation info
    let install_info = InstallationInfo::new_local(version.clone(), paths, source_binary)?;
    install_info.save(paths)?;

    println!("✅ Local update completed successfully!");
    println!("   New version: {} (local)", version);
    println!("   Binary: {}", binary_path.display());

    Ok(())
}

/// Install from GitHub (original logic extracted)
async fn install_from_github(dest_dir: Option<String>, configure_claude: bool) -> Result<()> {
    let paths = setup_paths(dest_dir)?;
    paths.ensure_dirs()?;

    // Download the latest release
    let release = fetch_latest_release().await?;
    println!("📦 Found release: {}", release.tag_name);

    let binary_path = paths.server_binary();
    download_binary(&release, &binary_path).await?;

    // Create default policy if it doesn't exist
    create_default_policy(&paths.policy_file).await?;

    // Configure Claude Desktop
    if configure_claude {
        configure_claude_desktop(&paths).await?;
    }

    // Save installation info
    let install_info = InstallationInfo::new(release.tag_name.clone(), &paths)?;
    install_info.save(&paths)?;

    println!("✅ mdmcp installed successfully!");
    println!("   Binary: {}", binary_path.display());
    println!("   Policy: {}", paths.policy_file.display());

    if configure_claude {
        println!("   Claude Desktop configured - restart Claude to use the MCP server");
    }

    Ok(())
}

/// Install from local binary (explicit --local flag)
async fn install_from_local(
    dest_dir: Option<String>,
    configure_claude: bool,
    local_path: Option<String>,
) -> Result<()> {
    let source_binary = if let Some(path) = local_path {
        Path::new(&path).to_path_buf()
    } else if let Some(detected) = detect_local_server_binary() {
        detected
    } else {
        bail!("No local binary specified and none found in current directory. Use --local-path to specify a binary.");
    };

    install_from_local_binary(dest_dir, configure_claude, &source_binary).await
}

/// Install from a specific local binary path
async fn install_from_local_binary(
    dest_dir: Option<String>,
    configure_claude: bool,
    source_binary: &Path,
) -> Result<()> {
    println!(
        "📦 Installing from local binary: {}",
        source_binary.display()
    );

    // Validate local binary
    if !source_binary.exists() {
        bail!("Local binary not found: {}", source_binary.display());
    }

    if !is_executable(source_binary) {
        bail!(
            "Local binary is not executable: {}",
            source_binary.display()
        );
    }

    // Test binary can run --version or --help
    let version = test_local_binary_version(source_binary).await?;
    println!("✅ Local binary validated - Version: {}", version);

    // Setup paths and copy binary
    let paths = setup_paths(dest_dir)?;
    paths.ensure_dirs()?;

    let dest_binary = paths.server_binary();
    std::fs::copy(source_binary, &dest_binary)
        .with_context(|| format!("Failed to copy binary to: {}", dest_binary.display()))?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    set_executable_permissions(&dest_binary)?;

    // Create default policy and configure Claude Desktop
    create_default_policy(&paths.policy_file).await?;

    if configure_claude {
        configure_claude_desktop(&paths).await?;
    }

    // Save installation info
    let install_info = InstallationInfo::new_local(version, &paths, source_binary)?;
    install_info.save(&paths)?;

    println!("✅ Local installation completed successfully!");
    println!("   Binary: {}", dest_binary.display());
    println!("   Policy: {}", paths.policy_file.display());

    if configure_claude {
        println!("   Claude Desktop configured - restart Claude to use the MCP server");
    }

    Ok(())
}

/// Detect local server binary in the same directory as mdmcpcfg
fn detect_local_server_binary() -> Option<PathBuf> {
    // Get the directory where mdmcpcfg is running from
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();

    let candidates = if cfg!(target_os = "windows") {
        vec!["mdmcpsrvr.exe", "mdmcp-server.exe"]
    } else {
        vec!["mdmcpsrvr", "mdmcp-server"]
    };

    // Check each candidate
    for candidate in candidates {
        let path = exe_dir.join(candidate);
        if path.exists() && is_executable(&path) {
            return Some(path);
        }
    }

    None
}

/// Test that a local binary can execute and get its version
async fn test_local_binary_version(binary_path: &Path) -> Result<String> {
    use std::process::Command;

    // Try --version first
    println!("🔍 Testing local binary: {}", binary_path.display());
    let version_result = Command::new(binary_path).arg("--version").output();

    if let Ok(output) = version_result {
        if output.status.success() {
            let version_output = String::from_utf8_lossy(&output.stdout);
            println!("📋 Version output: {}", version_output.trim());

            if let Some(version) = parse_version_from_output(&version_output) {
                println!("✅ Parsed version: {}", version);
                return Ok(version);
            } else {
                println!("⚠️  Could not parse version from output, checking stderr...");
                let stderr_output = String::from_utf8_lossy(&output.stderr);
                if !stderr_output.trim().is_empty() {
                    println!("📋 Stderr: {}", stderr_output.trim());
                }
            }
        } else {
            println!(
                "❌ --version command failed with exit code: {:?}",
                output.status.code()
            );
            let stderr_output = String::from_utf8_lossy(&output.stderr);
            if !stderr_output.trim().is_empty() {
                println!("📋 Stderr: {}", stderr_output.trim());
            }
        }
    } else {
        println!("❌ Failed to execute --version command");
    }

    // Try --help as fallback
    println!("🔄 Trying --help as fallback...");
    let help_result = Command::new(binary_path).arg("--help").output();

    if let Ok(output) = help_result {
        if output.status.success() {
            let help_output = String::from_utf8_lossy(&output.stdout);
            if let Some(version) = parse_version_from_output(&help_output) {
                println!("✅ Parsed version from help: {}", version);
                return Ok(version);
            }
            println!("✅ Binary responds to --help but no version found - using 'local'");
            return Ok("local".to_string());
        }
    }

    bail!("Local binary failed to execute: {}", binary_path.display());
}

/// Parse version from command output
fn parse_version_from_output(output: &str) -> Option<String> {
    println!("🔍 Attempting to parse version from output:");
    for (i, line) in output.lines().enumerate() {
        println!("  Line {}: '{}'", i + 1, line.trim());
    }

    // Look for version patterns like "mdmcpsrvr 0.1.0", "version 0.1.0", or standalone "v1.0.0"
    for line in output.lines() {
        let line = line.trim();

        // Check for common version keywords
        if line.to_lowercase().contains("version")
            || line.to_lowercase().contains("mdmcpsrvr")
            || line.to_lowercase().contains("mdmcp")
        {
            // Extract version number (simple pattern matching)
            let words: Vec<&str> = line.split_whitespace().collect();
            for word in words {
                // Look for semantic version pattern (digits, dots, optional 'v' prefix)
                let clean_word = word.trim_start_matches('v').trim_start_matches('V');
                if clean_word
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                    && clean_word.contains('.')
                {
                    println!("✅ Found version: {}", clean_word);
                    return Some(clean_word.to_string());
                }
            }
        }

        // Also check for standalone version patterns like "v1.0.0" at start of line
        if line.starts_with("v") || line.starts_with("V") {
            let version_part = line[1..].split_whitespace().next().unwrap_or("");
            if version_part
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && version_part.contains('.')
            {
                println!("✅ Found standalone version: {}", version_part);
                return Some(version_part.to_string());
            }
        }
    }

    println!("❌ No version found in output");
    None
}

/// Set executable permissions on Unix systems
#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

/// Log detailed GitHub failure information
fn log_github_failure(error: &anyhow::Error) {
    println!("❌ GitHub download failed:");

    // Show error chain
    let error_chain: Vec<_> = error.chain().collect();
    for (i, cause) in error_chain.iter().enumerate() {
        if i == 0 {
            println!("   Error: {}", cause);
        } else {
            println!("   Caused by: {}", cause);
        }
    }

    println!("   URLs attempted:");
    println!("     • https://api.github.com/repos/mdmcp/mdmcp/releases/latest");
    println!("   💡 This could be due to:");
    println!("     • Network connectivity issues");
    println!("     • GitHub API rate limiting");
    println!("     • Repository access restrictions");
    println!("     • No releases available for your platform");
    println!();
}

/// Prompt user for confirmation
fn prompt_user_confirmation() -> Result<bool> {
    use std::io::{self, Write};

    print!("Install from local binary? [Y/n]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    Ok(response.is_empty() || response.starts_with('y'))
}

/// Setup paths for installation (extracted common logic)
fn setup_paths(dest_dir: Option<String>) -> Result<Paths> {
    if let Some(dest) = dest_dir {
        let custom_bin_dir = Path::new(&dest).to_path_buf();
        let default_paths = Paths::new()?;
        Ok(Paths {
            bin_dir: custom_bin_dir,
            config_dir: default_paths.config_dir,
            policy_file: default_paths.policy_file,
        })
    } else {
        Paths::new()
    }
}

/// Fetch the latest stable release from GitHub
async fn fetch_latest_release() -> Result<GitHubRelease> {
    let url = "https://api.github.com/repos/mdmcp/mdmcp/releases/latest";
    let client = reqwest::Client::new();

    let response = client
        .get(url)
        .header("User-Agent", "mdmcpcfg")
        .send()
        .await
        .with_context(|| format!("Failed to fetch release information from: {}", url))?;

    if !response.status().is_success() {
        bail!(
            "GitHub API request failed: {} (URL: {})",
            response.status(),
            url
        );
    }

    response
        .json::<GitHubRelease>()
        .await
        .context("Failed to parse GitHub API response")
}

/// Fetch the latest prerelease from GitHub
async fn fetch_latest_prerelease() -> Result<GitHubRelease> {
    let url = "https://api.github.com/repos/mdmcp/mdmcp/releases";
    let client = reqwest::Client::new();

    let response = client
        .get(url)
        .header("User-Agent", "mdmcpcfg")
        .send()
        .await
        .context("Failed to fetch release information")?;

    if !response.status().is_success() {
        bail!("GitHub API request failed: {}", response.status());
    }

    let releases: Vec<GitHubRelease> = response
        .json()
        .await
        .context("Failed to parse GitHub API response")?;

    releases
        .into_iter()
        .find(|r| r.prerelease)
        .context("No prerelease found")
}

/// Download the appropriate binary for the current platform
async fn download_binary(release: &GitHubRelease, dest_path: &Path) -> Result<()> {
    let platform = get_platform_string();

    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name.contains(&platform))
        .with_context(|| format!("No binary found for platform: {}", platform))?;

    println!("⬇️  Downloading: {}", asset.name);

    let client = reqwest::Client::new();
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("Failed to download binary")?;

    if !response.status().is_success() {
        bail!("Download failed: {}", response.status());
    }

    // Download to temporary file first
    let mut temp_file = NamedTempFile::new().context("Failed to create temporary file")?;

    let content = response
        .bytes()
        .await
        .context("Failed to read download content")?;

    use std::io::Write;
    temp_file
        .write_all(&content)
        .context("Failed to write temporary file")?;

    // Move to final destination
    fs::copy(temp_file.path(), dest_path).context("Failed to move binary to destination")?;

    // Make executable on Unix-like systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest_path, perms)?;
    }

    // Verify the binary is executable
    if !is_executable(dest_path) {
        bail!(
            "Downloaded binary is not executable: {}",
            dest_path.display()
        );
    }

    println!("✅ Binary downloaded: {}", dest_path.display());
    Ok(())
}

/// Create a default policy file if it doesn't exist
async fn create_default_policy(policy_path: &Path) -> Result<()> {
    if policy_path.exists() {
        println!("ℹ️  Policy file already exists: {}", policy_path.display());
        return Ok(());
    }

    println!("📝 Creating default policy file...");

    let default_policy = create_default_policy_content()?;
    write_file(policy_path, &default_policy)?;

    println!("✅ Created default policy: {}", policy_path.display());
    Ok(())
}

/// Configure Claude Desktop to use the MCP server
async fn configure_claude_desktop(paths: &Paths) -> Result<()> {
    println!("🔧 Configuring Claude Desktop...");

    let mut config = ClaudeDesktopConfig::load_or_default()?;
    config.add_mdmcp_server(&paths.server_binary(), &paths.policy_file)?;
    config.save()?;

    Ok(())
}

/// Get the platform string for binary selection
fn get_platform_string() -> String {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "unknown"
    };

    let os = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "unknown"
    };

    format!("{}-{}", arch, os)
}

/// Calculate SHA256 hash of a file
fn calculate_sha256<P: AsRef<Path>>(path: P) -> Result<String> {
    let path = path.as_ref();
    let content = fs::read(path)
        .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;

    let hash = Sha256::digest(&content);
    Ok(hex::encode(hash))
}

/// Create the default policy file content
fn create_default_policy_content() -> Result<String> {
    let home_dir = dirs::home_dir().context("Failed to get home directory")?;

    // Convert paths to forward slashes for YAML compatibility
    let home_path = home_dir.to_string_lossy().replace('\\', "/");
    let workspace_path = home_dir
        .join("mdmcp-workspace")
        .to_string_lossy()
        .replace('\\', "/");
    let users_path = if cfg!(target_os = "windows") {
        "C:/Users"
    } else {
        "/tmp"
    };

    let policy = format!(
        r#"version: 1

deny_network_fs: true

allowed_roots:
  - "{}"
  - "{}"

write_rules:
  - path: "{}"
    recursive: true
    max_file_bytes: 10000000
    create_if_missing: true

commands:
  - id: "ls"
    exec: "/bin/ls"
    args:
      allow: ["-l", "-la", "-a", "-h", "--color=never"]
    cwd_policy: "within_root"
    env_allowlist: []
    timeout_ms: 5000
    max_output_bytes: 1000000
    platform: ["linux", "macos"]

  - id: "dir"
    exec: "C:/Windows/System32/cmd.exe"
    args:
      fixed: ["/c", "dir"]
    cwd_policy: "within_root"
    env_allowlist: []
    timeout_ms: 5000
    max_output_bytes: 1000000
    platform: ["windows"]

  - id: "cat"
    exec: "/bin/cat"
    args:
      patterns:
        - type: "regex"
          value: "^[\\w\\-\\./@:+#*?\\[\\]\\s]+$"
    cwd_policy: "within_root"
    env_allowlist: []
    timeout_ms: 10000
    max_output_bytes: 2000000
    platform: ["linux", "macos"]

  - id: "type"
    exec: "C:/Windows/System32/cmd.exe"
    args:
      fixed: ["/c", "type"]
      patterns:
        - type: "regex"
          value: "^[\\w\\-\\./@:+#*?\\[\\]\\s\\\\]+$"
    cwd_policy: "within_root"
    env_allowlist: []
    timeout_ms: 10000
    max_output_bytes: 2000000
    platform: ["windows"]

logging:
  level: "info"
  file: "~/.mdmcp/mdmcpsrvr.log.jsonl"
  redact: ["env"]

limits:
  max_read_bytes: 5000000
  max_cmd_concurrency: 2
"#,
        home_path, users_path, workspace_path
    );

    Ok(policy)
}
