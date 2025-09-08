//! # Installation and update commands
//!
//! This module handles downloading, installing, and updating the mdmcpsrvr binary,
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::io::{is_executable, write_file, ClaudeDesktopConfig, Paths};

// GitHub repository for releases
const GITHUB_RELEASES_LATEST: &str = "https://api.github.com/repos/0x4D44/mdmcp/releases/latest";
const GITHUB_RELEASES: &str = "https://api.github.com/repos/0x4D44/mdmcp/releases";

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
    println!("🛠️ Installing mdmcp MCP server...");

    // If explicitly requested local, keep previous behavior
    if local {
        return install_from_local(dest_dir, configure_claude, local_path).await;
    }

    // Probe available sources
    let github = fetch_latest_release().await.ok();
    let local_detected = detect_local_server_binary();
    let local_info = if let Some(ref bin) = local_detected {
        Some((
            bin.clone(),
            test_local_binary_version(bin)
                .await
                .unwrap_or_else(|_| "unknown".into()),
        ))
    } else {
        None
    };

    // Report availability clearly
    println!("Available installation sources:");
    if let Some(ref rel) = github {
        println!(" - GitHub release: {}", rel.tag_name);
    }
    if let Some((ref bin, ref ver)) = local_info {
        println!(" - Local binary: {} (version {})", bin.display(), ver);
    }

    if github.is_none() && local_info.is_none() {
        bail!("No installation sources available (GitHub release not reachable and no local binary detected)");
    }

    // Prompt for choice (G/L/N) based on availability
    let choice = prompt_source_choice(github.is_some(), local_info.is_some())?;

    match choice {
        Some('G') => install_from_github(dest_dir, configure_claude).await,
        Some('L') => {
            let (bin, _) = local_info.expect("local info should exist");
            install_from_local_binary(dest_dir, configure_claude, &bin).await
        }
        _ => {
            println!("✖ Installation cancelled by user.");
            Ok(())
        }
    }
}

/// Update the MCP server binary
pub async fn update(channel: String, rollback: bool, force: bool) -> Result<()> {
    let paths = Paths::new()?;

    if rollback {
        println!("⏪ Rolling back to previous version...");
        // TODO: Implement rollback functionality
        bail!("Rollback functionality not yet implemented");
    }

    println!("🔧 Updating mdmcp MCP server (channel: {})...", channel);

    // Check current version
    if let Some(current_info) = InstallationInfo::load(&paths)? {
        println!("ℹ️ Current installed version: {}", current_info.version);

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

    // Probe available sources
    let github = if channel == "stable" {
        fetch_latest_release().await.ok()
    } else {
        fetch_latest_prerelease().await.ok()
    };
    let local_detected = detect_local_server_binary();
    let local_info = if let Some(ref bin) = local_detected {
        Some((
            bin.clone(),
            test_local_binary_version(bin)
                .await
                .unwrap_or_else(|_| "unknown".into()),
        ))
    } else {
        None
    };

    println!("Available update sources:");
    if let Some(ref rel) = github {
        println!(" - GitHub release: {}", rel.tag_name);
    }
    if let Some((ref bin, ref ver)) = local_info {
        println!(" - Local binary: {} (version {})", bin.display(), ver);
    }

    if github.is_none() && local_info.is_none() {
        bail!("No update sources available (GitHub release not reachable and no local binary detected)");
    }

    let choice = prompt_source_choice(github.is_some(), local_info.is_some())?;
    match choice {
        Some('G') => {
            if !prompt_named_confirmation("Proceed with GitHub update? [Y/n]: ")? {
                println!("✖ Update cancelled.");
                return Ok(());
            }
            update_from_github(channel, &paths, force, true).await
        }
        Some('L') => {
            if !prompt_named_confirmation("Proceed with Local update? [Y/n]: ")? {
                println!("✖ Update cancelled.");
                return Ok(());
            }
            let (bin, _) = local_info.expect("local info should exist");
            update_from_local_binary(&paths, &bin, force, true).await
        }
        _ => {
            println!("✖ Update cancelled by user.");
            Ok(())
        }
    }
}

/// Update from GitHub (extracted from original update logic)
/// If `preconfirmed` is true, skip interactive prompts and extra version prints
async fn update_from_github(
    channel: String,
    paths: &Paths,
    force: bool,
    preconfirmed: bool,
) -> Result<()> {
    // Fetch latest release
    let release = if channel == "stable" {
        fetch_latest_release().await?
    } else {
        fetch_latest_prerelease().await?
    };

    // Check current version and compare
    if let Some(current_info) = InstallationInfo::load(paths)? {
        if !preconfirmed {
            println!("ℹ️ Current installed version: {}", current_info.version);
            println!("📦 Available version: {}", release.tag_name);
        }

        if current_info.version == release.tag_name && !force {
            println!("✔ Already up to date!");
            return Ok(());
        }

        if force && !preconfirmed {
            println!(
                "⚠️  Force updating to version {} (reinstall)",
                release.tag_name
            );
        }
        if !preconfirmed && !force {
            // Ask for confirmation
            println!("❓ Update to version {}?", release.tag_name);
            if !prompt_user_confirmation()? {
                println!("✖ Update cancelled");
                return Ok(());
            }
        }
    } else if !preconfirmed {
        println!("📦 Installing version: {}", release.tag_name);
    }

    // Backup current binary
    let binary_path = paths.server_binary();
    let backup_path = binary_path.with_extension("bak");
    if binary_path.exists() {
        println!("💾 Backing up current binary...");
        fs::copy(&binary_path, &backup_path).context("Failed to create backup")?;
    }

    // Download new binary
    // Download the server binary specifically
    download_binary(&release, "mdmcpsrvr", &binary_path).await?;

    // Update installation info
    let install_info = InstallationInfo::new(release.tag_name.clone(), paths)?;
    install_info.save(paths)?;

    println!("✅ Update completed successfully!");
    println!("   New version: {}", release.tag_name);

    Ok(())
}

/// Update from local binary
/// Update from local binary; if `preconfirmed` is true, skip extra prints
async fn update_from_local_binary(
    paths: &Paths,
    source_binary: &Path,
    force: bool,
    preconfirmed: bool,
) -> Result<()> {
    println!("📂 Updating from local binary: {}", source_binary.display());

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

        if !preconfirmed {
            println!("ℹ️ Current installed version: {}", current_version);
            println!("📦 Available version: {}", new_version_tag);
        }

        // Try to get actual version of currently installed binary for better comparison
        let current_binary = paths.server_binary();
        if current_binary.exists() {
            if let Ok(actual_current_version) = test_local_binary_version(&current_binary).await {
                if !preconfirmed {
                    println!(
                        "🔎 Current binary reports version: {}",
                        actual_current_version
                    );
                }

                // Compare the actual running versions, not just the stored metadata
                if actual_current_version == version && version != "local" && !force {
                    println!("✔ Already up to date - both binaries report same version!");
                    return Ok(());
                }
            }
        }

        // Only skip if versions are identical AND the current installation is also local
        if current_info.version == new_version_tag && version != "local" && !force {
            println!("✔ Already up to date with local version!");
            return Ok(());
        }

        if current_info.version == new_version_tag && version == "local" {
            println!("⚠️  Both current and new versions are detected as 'local' - proceeding with update to ensure binary is current");
        }
    } else {
        println!("📦 New version: {} (local)", version);
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
    println!("🔎 Found release: {}", release.tag_name);

    let binary_path = paths.server_binary();
    // Download the server binary specifically
    download_binary(&release, "mdmcpsrvr", &binary_path).await?;

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
        "📂 Installing from local binary: {}",
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
    let version_result = Command::new(binary_path).arg("--version").output();

    if let Ok(output) = version_result {
        if output.status.success() {
            let version_output = String::from_utf8_lossy(&output.stdout);
            if let Some(version) = parse_version_from_output(&version_output) {
                return Ok(version);
            }
        }
    }

    // Try --help as fallback
    let help_result = Command::new(binary_path).arg("--help").output();

    if let Ok(output) = help_result {
        if output.status.success() {
            let help_output = String::from_utf8_lossy(&output.stdout);
            if let Some(version) = parse_version_from_output(&help_output) {
                return Ok(version);
            }
            return Ok("local".to_string());
        }
    }

    bail!("Local binary failed to execute: {}", binary_path.display());
}

/// Parse version from command output
fn parse_version_from_output(output: &str) -> Option<String> {
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
                return Some(version_part.to_string());
            }
        }
    }

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

// (removed) log_github_failure no longer used after unified source prompt

/// Prompt user for confirmation
fn prompt_user_confirmation() -> Result<bool> {
    use std::io::{self, Write};

    print!("Proceed? [Y/n]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    Ok(response.is_empty() || response.starts_with('y'))
}

/// Prompt with a custom message and yes/no response
fn prompt_named_confirmation(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();
    Ok(response.is_empty() || response.starts_with('y'))
}

/// Prompt the user to select a source among GitHub/Local/None based on availability
fn prompt_source_choice(has_github: bool, has_local: bool) -> Result<Option<char>> {
    use std::io::{self, Write};

    let mut options = Vec::new();
    if has_github {
        options.push(('G', "GitHub"));
    }
    if has_local {
        options.push(('L', "Local"));
    }
    options.push(('N', "None"));

    let mut prompt = String::from("Choose source: ");
    for (i, (ch, label)) in options.iter().enumerate() {
        if i > 0 {
            prompt.push('/');
        }
        prompt.push('[');
        prompt.push(*ch);
        prompt.push(']');
        prompt.push_str(label);
    }
    prompt.push_str(": ");

    loop {
        print!("{}", prompt);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let ch = input.trim().chars().next().map(|c| c.to_ascii_uppercase());

        if let Some(c) = ch {
            if c == 'N' {
                return Ok(None);
            }
            if c == 'G' && has_github {
                return Ok(Some('G'));
            }
            if c == 'L' && has_local {
                return Ok(Some('L'));
            }
        }
        println!("Please enter a valid choice.");
    }
}

/// Uninstall the MCP server binary and optionally clean configuration
pub async fn uninstall(remove_policy: bool, remove_claude_config: bool, yes: bool) -> Result<()> {
    let paths = Paths::new()?;

    println!("🗑️ Uninstalling mdmcp MCP server...");
    if !yes {
        println!(
            "This will remove the server binary{}{}.",
            if remove_policy { ", policy file" } else { "" },
            if remove_claude_config {
                ", and Claude Desktop entry"
            } else {
                ""
            }
        );
        print!("Proceed? [y/N]: ");
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let resp = input.trim().to_lowercase();
        if !(resp == "y" || resp == "yes") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Remove server binary
    let bin = paths.server_binary();
    if bin.exists() {
        match std::fs::remove_file(&bin) {
            Ok(_) => println!("✅ Removed binary: {}", bin.display()),
            Err(e) => println!("⚠️  Failed to remove binary {}: {}", bin.display(), e),
        }
    } else {
        println!("ℹ️  Binary not found: {}", bin.display());
    }

    // Remove backup binary if present
    let backup = bin.with_extension("bak");
    if backup.exists() {
        let _ = std::fs::remove_file(&backup);
    }

    // Optionally remove policy file
    if remove_policy {
        if paths.policy_file.exists() {
            match std::fs::remove_file(&paths.policy_file) {
                Ok(_) => println!("✅ Removed policy: {}", paths.policy_file.display()),
                Err(e) => println!(
                    "⚠️  Failed to remove policy {}: {}",
                    paths.policy_file.display(),
                    e
                ),
            }
        } else {
            println!("ℹ️  Policy not found: {}", paths.policy_file.display());
        }
    }

    // Optionally remove Claude Desktop entry
    if remove_claude_config {
        match ClaudeDesktopConfig::load_or_default() {
            Ok(mut cfg) => {
                cfg.remove_mdmcp_server();
                if let Err(e) = cfg.save() {
                    println!("⚠️  Failed to update Claude Desktop config: {}", e);
                } else {
                    println!("✅ Removed mdmcp entry from Claude Desktop config");
                }
            }
            Err(e) => println!("⚠️  Could not load Claude Desktop config: {}", e),
        }
    }

    println!("✅ Uninstall finished.");
    Ok(())
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
    let url = GITHUB_RELEASES_LATEST;
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
    let url = GITHUB_RELEASES;
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

/// Download the appropriate binary for the current platform, matching a specific artifact prefix
async fn download_binary(
    release: &GitHubRelease,
    wanted_prefix: &str,
    dest_path: &Path,
) -> Result<()> {
    let platform = get_platform_string();
    let wanted_lower = wanted_prefix.to_ascii_lowercase();

    // Prefer assets that match both the wanted prefix (e.g., mdmcpsrvr) and platform triplet
    let mut chosen: Option<&GitHubAsset> = release.assets.iter().find(|a| {
        a.name.to_ascii_lowercase().contains(&wanted_lower) && a.name.contains(&platform)
    });

    // Fallback: match wanted prefix only (last resort if platform suffix naming differs)
    if chosen.is_none() {
        chosen = release
            .assets
            .iter()
            .find(|a| a.name.to_ascii_lowercase().contains(&wanted_lower));
    }

    // Final fallback: any asset for the platform
    if chosen.is_none() {
        chosen = release.assets.iter().find(|a| a.name.contains(&platform));
    }

    let asset = chosen.with_context(|| {
        format!(
            "No binary found for prefix '{}' and platform '{}' in release {}",
            wanted_prefix, platform, release.tag_name
        )
    })?;

    println!("📥 Downloading: {}", asset.name);

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

    println!("📦 Binary downloaded: {}", dest_path.display());
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
    println!("🧩 Configuring Claude Desktop...");

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
    use mdmcp_policy::{
        ArgsPolicy, CommandRule, CwdPolicy, LimitsConfig, LoggingConfig, Policy, WriteRule,
    };
    let home_dir = dirs::home_dir().context("Failed to get home directory")?;
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

    let mut commands: Vec<CommandRule> = Vec::new();

    // Cross-platform commands
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        commands.push(CommandRule {
            id: "ls".into(),
            exec: "/bin/ls".into(),
            args: ArgsPolicy {
                allow: vec![
                    "-l".into(),
                    "-la".into(),
                    "-a".into(),
                    "-h".into(),
                    "--color=never".into(),
                ],
                fixed: vec![],
                patterns: vec![],
            },
            cwd_policy: CwdPolicy::WithinRoot,
            env_allowlist: vec![],
            timeout_ms: 5000,
            max_output_bytes: 1_000_000,
            platform: vec!["linux".into(), "macos".into()],
            allow_any_args: true,
        });
        commands.push(CommandRule {
            id: "cat".into(),
            exec: "/bin/cat".into(),
            args: ArgsPolicy {
                allow: vec![],
                fixed: vec![],
                patterns: vec![],
            },
            cwd_policy: CwdPolicy::WithinRoot,
            env_allowlist: vec![],
            timeout_ms: 10_000,
            max_output_bytes: 2_000_000,
            platform: vec!["linux".into(), "macos".into()],
            allow_any_args: true,
        });
    }

    // Windows builtins via cmd
    if cfg!(target_os = "windows") {
        let windows_cmd = |id: &str, sub: &str| CommandRule {
            id: id.into(),
            exec: "C:/Windows/System32/cmd.exe".into(),
            args: ArgsPolicy {
                allow: vec![],
                fixed: vec!["/c".into(), sub.into()],
                patterns: vec![],
            },
            cwd_policy: CwdPolicy::WithinRoot,
            env_allowlist: vec![],
            timeout_ms: 10_000,
            max_output_bytes: 2_000_000,
            platform: vec!["windows".into()],
            allow_any_args: true,
        };
        for (id, sub) in [
            ("dir", "dir"),
            ("type", "type"),
            ("copy", "copy"),
            ("move", "move"),
            ("del", "del"),
            ("mkdir", "mkdir"),
            ("rmdir", "rmdir"),
        ] {
            commands.push(windows_cmd(id, sub));
        }

        let win_exec = |id: &str, path: &str, timeout: u64, max_bytes: u64| CommandRule {
            id: id.into(),
            exec: path.into(),
            args: ArgsPolicy {
                allow: vec![],
                fixed: vec![],
                patterns: vec![],
            },
            cwd_policy: CwdPolicy::WithinRoot,
            env_allowlist: vec![],
            timeout_ms: timeout,
            max_output_bytes: max_bytes,
            platform: vec!["windows".into()],
            allow_any_args: true,
        };
        commands.push(win_exec(
            "findstr",
            "C:/Windows/System32/findstr.exe",
            10_000,
            4_000_000,
        ));
        commands.push(win_exec(
            "where",
            "C:/Windows/System32/where.exe",
            10_000,
            2_000_000,
        ));
        commands.push(win_exec(
            "tree",
            "C:/Windows/System32/tree.com",
            10_000,
            4_000_000,
        ));
        commands.push(win_exec(
            "tasklist",
            "C:/Windows/System32/tasklist.exe",
            10_000,
            4_000_000,
        ));
        commands.push(win_exec(
            "taskkill",
            "C:/Windows/System32/taskkill.exe",
            10_000,
            2_000_000,
        ));
        commands.push(win_exec(
            "systeminfo",
            "C:/Windows/System32/systeminfo.exe",
            15_000,
            4_000_000,
        ));
        commands.push(win_exec(
            "netstat",
            "C:/Windows/System32/netstat.exe",
            15_000,
            4_000_000,
        ));
    }

    let policy = Policy {
        version: 1,
        deny_network_fs: true,
        allowed_roots: vec![home_path, users_path.into()],
        write_rules: vec![WriteRule {
            path: workspace_path,
            recursive: true,
            max_file_bytes: 10_000_000,
            create_if_missing: true,
        }],
        commands,
        logging: LoggingConfig::default(),
        limits: LimitsConfig::default(),
    };
    Ok(serde_yaml::to_string(&policy)?)
}
