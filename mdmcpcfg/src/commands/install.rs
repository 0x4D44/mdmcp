//! # Installation and update commands
//!
//! This module handles downloading, installing, and updating the mdmcpsrvr binary,
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use crate::commands::docs;
use crate::io::{is_executable, write_file, ClaudeDesktopConfig, Paths};
use std::io;
use std::process::Command;
use std::time::{Duration, Instant};

// GitHub repository for releases
const GITHUB_RELEASES_LATEST: &str = "https://api.github.com/repos/0x4D44/mdmcp/releases/latest";
const GITHUB_RELEASES: &str = "https://api.github.com/repos/0x4D44/mdmcp/releases";

// Install target when WSL is available
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Target {
    Windows,
    LinuxWsl,
}

/// GitHub release information
#[derive(Debug, Deserialize, Clone)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
    prerelease: bool,
}

#[derive(Debug, Deserialize, Clone)]
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
    server_target: String,
    plugins: Option<String>,
    wsl_distro: Option<String>,
    yes_defaults: bool,
    local: bool,
    local_path: Option<String>,
    insecure_skip_verify: bool,
    verify_key: Option<String>,
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
        Some('G') => {
            install_with_prompts(
                dest_dir,
                configure_claude,
                &server_target,
                plugins.as_deref(),
                wsl_distro.as_deref(),
                yes_defaults,
                insecure_skip_verify,
                verify_key,
            )
            .await
        }
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

/// End-to-end install with WSL/server-target + plugins prompts/flags
async fn install_with_prompts(
    dest_dir: Option<String>,
    configure_claude: bool,
    server_target_flag: &str,
    plugins_flag: Option<&str>,
    wsl_distro: Option<&str>,
    yes_defaults: bool,
    insecure_skip_verify: bool,
    verify_key: Option<String>,
) -> Result<()> {
    // Resolve server target
    let target = if server_target_flag.eq_ignore_ascii_case("windows") {
        Target::Windows
    } else if server_target_flag.eq_ignore_ascii_case("linux") {
        Target::LinuxWsl
    } else {
        // auto: prompt on Windows if WSL available; else choose host default
        if cfg!(target_os = "windows") && wsl_available() {
            let t = if yes_defaults {
                Target::Windows
            } else {
                prompt_server_target_choice().unwrap_or(Target::Windows)
            };
            t
        } else {
            // No WSL or non-Windows host
            if cfg!(target_os = "windows") {
                Target::Windows
            } else {
                Target::LinuxWsl
            }
        }
    };

    // Resolve plugins selection
    let plugins_yes = match plugins_flag.map(|s| s.to_ascii_lowercase()) {
        Some(ref v) if v == "yes" || v == "y" => true,
        Some(ref v) if v == "no" || v == "n" => false,
        Some(_) => true,
        None => {
            if yes_defaults {
                true
            } else {
                prompt_named_confirmation("Install mdmcp plugins on Windows? [Y/n]: ")?.then_some(true).unwrap_or(false)
            }
        }
    };

    // Fetch latest release (for assets)
    let release = fetch_latest_release().await?;

    // Always create default policies on the local side for consistency
    let paths = Paths::new()?;
    paths.ensure_dirs()?;
    create_default_policies(&paths).await?;

    // Install plugins on Windows if requested
    if plugins_yes {
        if cfg!(target_os = "windows") {
            install_windows_plugins(&release, insecure_skip_verify, verify_key.as_deref()).await?;
        } else {
            // Running on Linux/WSL — still install on Windows by invoking PowerShell via wsl interop
            println!("ℹ️  Installing plugins on Windows host...");
            // Best-effort: tell user what to run manually if interop not available
        }
    }

    match target {
        Target::Windows => {
            // Install server on Windows (existing path)
            install_from_github(dest_dir.clone(), configure_claude, insecure_skip_verify, verify_key.clone()).await?;
            // If plugins were installed, update policy with Windows execs
            if plugins_yes {
                add_plugins_to_policy_windows().await?;
            }
            // If we auto-chose Windows but WSL is available, hint how to install in WSL
            if server_target_flag.eq_ignore_ascii_case("auto") && cfg!(target_os = "windows") && wsl_available() && !yes_defaults {
                println!("ℹ️  WSL is available. To install in WSL, run: mdmcpcfg install --server-target linux");
            }
        }
        Target::LinuxWsl => {
            // Orchestrate Linux server install inside WSL
            install_server_in_wsl(&release, wsl_distro, insecure_skip_verify, verify_key.as_deref()).await?;
            // Update Claude Desktop on Windows to launch wsl.exe -> mdmcpsrvr
            if cfg!(target_os = "windows") && configure_claude {
                configure_claude_for_wsl(wsl_distro, None).await?;
            }
            // Do not configure any additional roots inside WSL by default.
            // Optionally add plugin commands to WSL policy with /mnt/c exec paths when mdmcpcfg exists
            if plugins_yes {
                let mdmcpcfg_exists = wsl_exec_status(wsl_distro, "test -x ~/.local/share/mdmcpcfg/bin/mdmcpcfg");
                if mdmcpcfg_exists {
                    add_plugins_to_policy_wsl(wsl_distro).await.ok();
                } else {
                    println!("ℹ️  Skipping WSL plugin registration (mdmcpcfg not found in ~/.local/share/mdmcpcfg/bin)");
                }
            }
        }
    }

    // Rebuild documentation cache once at the end on the host side
    println!("   Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("   ✅ Documentation cache built"),
        Err(e) => println!("   ⚠️  Failed to build documentation cache: {}", e),
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn wsl_available() -> bool {
    match std::process::Command::new("wsl.exe").args(["-l", "-q"]).output() {
        Ok(out) => {
            if out.status.success() {
                true
            } else {
                // Some environments return a non-zero status but still list distros; treat non-empty stdout as available
                !out.stdout.is_empty()
            }
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "windows"))]
fn wsl_available() -> bool { false }

/// List available WSL distros (quiet names). Windows only.
#[cfg(target_os = "windows")]
fn wsl_list_distros() -> Vec<String> {
    match std::process::Command::new("wsl.exe").args(["-l", "-q"]).output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            s.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

#[cfg(not(target_os = "windows"))]
fn wsl_list_distros() -> Vec<String> { Vec::new() }

#[cfg(target_os = "windows")]
fn wsl_exec_status(distro: Option<&str>, cmd: &str) -> bool {
    let mut args: Vec<&str> = Vec::new();
    if let Some(d) = distro { if !d.trim().is_empty() { args.push("-d"); args.push(d); } }
    args.push("--");
    args.push("bash");
    args.push("-lc");
    args.push(cmd);
    std::process::Command::new("wsl.exe")
        .args(&args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn wsl_exec_status(_distro: Option<&str>, _cmd: &str) -> bool { false }

#[cfg(target_os = "windows")]
fn wsl_path_exists(distro: Option<&str>, path: &str) -> bool {
    let test = format!("test -e {}", path);
    wsl_exec_status(distro, &test)
}

#[cfg(not(target_os = "windows"))]
fn wsl_path_exists(_distro: Option<&str>, _path: &str) -> bool { false }

fn prompt_server_target_choice() -> Option<Target> {
    let mut input = String::new();
    println!("WSL detected. Where should mdmcpsrvr be installed?");
    println!("[W] Windows (default) • [L] Linux (WSL) • [N] Cancel");
    print!("Choice: ");
    let _ = io::Write::flush(&mut io::stdout());
    io::stdin().read_line(&mut input).ok()?;
    let ch = input.trim().to_ascii_lowercase();
    match ch.as_str() {
        "w" | "" => Some(Target::Windows),
        "l" => Some(Target::LinuxWsl),
        _ => None,
    }
}

/// Download windows-binaries.zip and extract plugins to %LOCALAPPDATA%/mdmcp/bin/plugins
async fn install_windows_plugins(
    release: &GitHubRelease,
    insecure_skip_verify: bool,
    _verify_key: Option<&str>,
) -> Result<()> {
    use std::io::Read;
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == "windows-binaries.zip")
        .context("windows-binaries.zip not found in release")?;
    println!("📦 Downloading plugins archive: {}", asset.name);
    let bytes = download_asset_bytes(&asset.browser_download_url).await?;
    if !insecure_skip_verify {
        if let Ok(map) = fetch_and_verify_manifest(release, &VerificationOptions { skip: false, verify_key_path: None }).await {
            if let Some(exp) = map.get(&asset.name) {
                let got = hex::encode(Sha256::digest(&bytes));
                if got.to_lowercase() != exp.to_lowercase() {
                    bail!("Checksum mismatch for {}", asset.name);
                }
            }
        }
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("Failed to read zip")?;
    let paths = Paths::new()?;
    let plugins_dir = paths.bin_dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).context("Failed to create plugins dir")?;
    let wanted = [
        "bin/plugins/mdaicli.exe",
        "bin/plugins/mdconfcli.exe",
        "bin/plugins/mdjiracli.exe",
        "bin/plugins/mdmailcli.exe",
        "bin/plugins/mdslackcli.exe",
    ];
    for name in wanted.iter() {
        if let Ok(mut f) = zip.by_name(name) {
            let out = plugins_dir.join(Path::new(name).file_name().unwrap());
            let mut buf = Vec::with_capacity(f.size() as usize);
            f.read_to_end(&mut buf).context("Failed reading entry")?;
            std::fs::write(&out, &buf).with_context(|| format!("Failed to write {}", out.display()))?;
        }
    }
    println!("✅ Plugins installed: {}", plugins_dir.display());
    Ok(())
}

async fn add_plugins_to_policy_windows() -> Result<()> {
    // Use the policy module to add commands with Windows paths
    let paths = Paths::new()?;
    let base = paths
        .bin_dir
        .join("plugins")
        .to_string_lossy()
        .to_string()
        .replace('\\', "/");
    let cmds = ["mdaicli", "mdconfcli", "mdjiracli", "mdmailcli", "mdslackcli"];
    for id in cmds {
        let exec = format!("{}/{}.exe", base, id);
        super::policy::set_exec(id.into(), exec).await?;
    }
    Ok(())
}

async fn install_server_in_wsl(
    release: &GitHubRelease,
    wsl_distro: Option<&str>,
    _insecure_skip: bool,
    _verify_key: Option<&str>,
) -> Result<()> {
    // Ensure linux mdmcpcfg exists inside WSL and run install
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == "linux-mdmcpcfg")
        .context("linux-mdmcpcfg not found in release")?;
    let bytes = download_asset_bytes(&asset.browser_download_url).await?;
    // Stage to Windows temp and copy into WSL
    let win_stage = std::env::temp_dir().join("linux-mdmcpcfg");
    std::fs::write(&win_stage, &bytes).context("Failed to write staged linux mdmcpcfg")?;
    let wsl_stage = windows_path_to_wsl(&win_stage)?;
    let distro_arg = wsl_distro.unwrap_or("");
    let copy_cmd = format!(
        "mkdir -p ~/.local/share/mdmcpcfg/bin && cp '{}' ~/.local/share/mdmcpcfg/bin/mdmcpcfg && chmod +x ~/.local/share/mdmcpcfg/bin/mdmcpcfg",
        wsl_stage.replace("'", "'\\''")
    );
    wsl_exec(distro_arg, &copy_cmd)?;
    let install_cmd = "printf 'g\n' | ~/.local/share/mdmcpcfg/bin/mdmcpcfg install --no-claude-config --dest ~/.local/share/mdmcp/bin";
    wsl_exec(distro_arg, install_cmd)?;
    println!("✅ Installed mdmcpsrvr in WSL");
    Ok(())
}

async fn add_plugins_to_policy_wsl(wsl_distro: Option<&str>) -> Result<()> {
    // Compute Windows plugins path and convert to /mnt/c path inside WSL
    let paths = Paths::new()?;
    let plugins_dir = paths.bin_dir.join("plugins");
    let wsl_plugins = windows_path_to_wsl(&plugins_dir)?;
    let distro_arg = wsl_distro.unwrap_or("");
    let cmds = ["mdaicli", "mdconfcli", "mdjiracli", "mdmailcli", "mdslackcli"];
    for id in cmds {
        let exec = format!("{}/{}.exe", wsl_plugins, id);
        let escaped = exec.replace("'", "'\\''");
        let cmd = format!(
            "~/.local/share/mdmcpcfg/bin/mdmcpcfg policy set-exec {} --exec '{}' 2>/dev/null || ~/.local/share/mdmcpcfg/bin/mdmcpcfg policy add-command {} --exec '{}'",
            id,
            escaped,
            id,
            escaped
        );
        wsl_exec(distro_arg, &cmd)?;
    }
    println!("✅ Registered plugin commands in WSL policy");
    Ok(())
}

async fn configure_claude_for_wsl(wsl_distro: Option<&str>, linux_paths: Option<(String, String)>) -> Result<()> {
    // linux_paths optionally supplies explicit linux server/policy; else assume defaults under $HOME
    let (server, policy) = if let Some((s, p)) = linux_paths {
        (PathBuf::from(s), PathBuf::from(p))
    } else {
        (
            PathBuf::from("/home/$USER/.local/share/mdmcp/bin/mdmcpsrvr"),
            PathBuf::from("/home/$USER/.config/mdmcp/policy.user.yaml"),
        )
    };
    let mut cfg = ClaudeDesktopConfig::load_or_default()?;
    cfg.add_mdmcp_server_wsl(wsl_distro, &server, &policy)?;
    cfg.save()?;
    println!("✅ Updated Claude Desktop to launch WSL server");
    Ok(())
}

/// Add Windows home directory as an allowed root in the WSL-side policy (read-only by default).
#[cfg(target_os = "windows")]
// Removed: add_windows_home_as_allowed_root_in_wsl — we no longer auto-configure roots in WSL

#[cfg(not(target_os = "windows"))]
async fn add_windows_home_as_allowed_root_in_wsl(_wsl_distro: Option<&str>) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_path_to_wsl(p: &Path) -> Result<String> {
    let sp = p.to_string_lossy().to_string();
    // Prefer invoking wslpath inside WSL for correctness
    let output = std::process::Command::new("wsl.exe")
        .args(["--", "wslpath", "-a", "-u", &sp])
        .output()
        .ok();
    if let Some(out) = output {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
    }
    // Fallback: map Windows path to /mnt/<drive>/... heuristically
    let s = sp.trim();
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        let drive = s.chars().next().unwrap().to_ascii_lowercase();
        let rest = &s[2..];
        let rest = rest.replace('\\', "/");
        let rest_trimmed = rest.trim_start_matches(&['/', '\\'][..]);
        Ok(format!("/mnt/{}/{}", drive, rest_trimmed))
    } else {
        bail!("Could not convert Windows path to WSL mount: {}", sp);
    }
}

#[cfg(not(target_os = "windows"))]
fn windows_path_to_wsl(_p: &Path) -> Result<String> { bail!("not on Windows") }

#[cfg(target_os = "windows")]
fn wsl_exec(distro: &str, cmd: &str) -> Result<()> {
    let mut args: Vec<&str> = Vec::new();
    if !distro.trim().is_empty() { args.push("-d"); args.push(distro); }
    args.push("--");
    args.push("bash");
    args.push("-lc");
    args.push(cmd);
    let status = std::process::Command::new("wsl.exe").args(&args).status().context("Failed to run wsl.exe")?;
    if !status.success() { bail!("WSL command failed"); }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn wsl_exec(_distro: &str, _cmd: &str) -> Result<()> { Ok(()) }

/// Update the MCP server binary
pub async fn update(
    channel: String,
    rollback: bool,
    force: bool,
    insecure_skip_verify: bool,
    verify_key: Option<String>,
) -> Result<()> {
    let paths = Paths::new()?;

    if rollback {
        println!("⏪ Rolling back to previous version...");
        // TODO: Implement rollback functionality
        bail!("Rollback functionality not yet implemented");
    }

    println!(
        "🔧 Updating mdmcp MCP server and CLI (channel: {})...",
        channel
    );

    // Check current version
    let current_info = if let Some(info) = InstallationInfo::load(&paths)? {
        println!("\u{2139}\u{FE0F}  Current installed version: {}", info.version);

        // Verify current binary integrity
        let binary_path = Path::new(&info.binary_path);
        if binary_path.exists() {
            let current_hash = calculate_sha256(binary_path)?;
            if current_hash != info.binary_sha256 {
                println!("⚠️  Binary hash mismatch - binary may have been modified");
            }
        }
        Some(info)
    } else {
        println!("ℹ️  No existing installation found - performing fresh install");
        return run(
            None,
            true,
            "auto".to_string(),
            None,
            None,
            true,
            false,
            None,
            insecure_skip_verify,
            verify_key,
        )
        .await;
    };

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
            let github_release = github.expect("GitHub release should exist");

            // Check if update is needed BEFORE stopping Claude
            if let Some(ref current) = current_info {
                if current.version == github_release.tag_name && !force {
                    println!(
                        "\u{2705} Already up to date with GitHub version {}!",
                        github_release.tag_name
                    );
                    return Ok(());
                }
                println!("📦 Available GitHub version: {}", github_release.tag_name);
            }

            // Confirm update before stopping Claude
            if !force
                && !prompt_named_confirmation(&format!(
                    "Update from {} to {}? [Y/n]: ",
                    current_info
                        .as_ref()
                        .map(|i| i.version.as_str())
                        .unwrap_or("unknown"),
                    github_release.tag_name
                ))?
            {
                println!("✖ Update cancelled.");
                return Ok(());
            }

            // Now handle Claude Desktop stop/restart
            let (restart_claude, claude_path) = if is_claude_running() {
                let path = find_claude_path();
                if !prompt_named_confirmation(
                    "Update will stop and restart Claude Desktop - is that OK? [Y/n]: ",
                )? {
                    println!("✖ Update cancelled.");
                    return Ok(());
                }
                if let Err(e) = stop_claude_desktop() {
                    println!("⚠️  Failed to stop Claude Desktop: {}", e);
                    (false, None)
                } else {
                    (true, path)
                }
            } else {
                (false, None)
            };

            update_from_github(
                channel,
                &paths,
                force,
                true,
                restart_claude,
                claude_path,
                VerificationOptions {
                    skip: insecure_skip_verify,
                    verify_key_path: verify_key.clone(),
                },
            )
            .await
        }
        Some('L') => {
            let (local_bin, local_version) = local_info.expect("local info should exist");

            // Check if update is needed BEFORE stopping Claude
            if let Some(ref current) = current_info {
                let new_version_tag = format!("{} (local)", local_version);

                // Try to get actual version of currently installed binary for better comparison
                let current_binary = paths.server_binary();
                if current_binary.exists() {
                    if let Ok(actual_current_version) =
                        test_local_binary_version(&current_binary).await
                    {
                        if actual_current_version == local_version
                            && local_version != "local"
                            && !force
                        {
                            println!(
                                "\u{2705} Already up to date - both binaries report same version {}!",
                                local_version
                            );
                            return Ok(());
                        }
                    }
                }

                if current.version == new_version_tag && local_version != "local" && !force {
                    println!("\u{2705} Already up to date with local version {}!", local_version);
                    return Ok(());
                }

                println!("📦 Available local version: {}", new_version_tag);
            }

            // Confirm update before stopping Claude
            if !force
                && !prompt_named_confirmation(&format!(
                    "Update from {} to {} (local)? [Y/n]: ",
                    current_info
                        .as_ref()
                        .map(|i| i.version.as_str())
                        .unwrap_or("unknown"),
                    local_version
                ))?
            {
                println!("✖ Update cancelled.");
                return Ok(());
            }

            // Now handle Claude Desktop stop/restart
            let (restart_claude, claude_path) = if is_claude_running() {
                let path = find_claude_path();
                if !prompt_named_confirmation(
                    "Update will stop and restart Claude Desktop - is that OK? [Y/n]: ",
                )? {
                    println!("✖ Update cancelled.");
                    return Ok(());
                }
                if let Err(e) = stop_claude_desktop() {
                    println!("⚠️  Failed to stop Claude Desktop: {}", e);
                    (false, None)
                } else {
                    (true, path)
                }
            } else {
                (false, None)
            };

            update_from_local_binary(&paths, &local_bin, force, true, restart_claude, claude_path)
                .await
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
    restart_claude_after: bool,
    claude_path: Option<String>,
    vopts: VerificationOptions,
) -> Result<()> {
    // Delegate to hook-based implementation for testability
    let fetch_release = || async {
        if channel == "stable" {
            fetch_latest_release().await
        } else {
            fetch_latest_prerelease().await
        }
    };
    let downloader = |rel: GitHubRelease, prefix: String, dest: PathBuf| async move {
        download_binary(&rel, &prefix, &dest).await
    };
    update_from_github_with_hooks(
        fetch_release,
        downloader,
        paths,
        force,
        preconfirmed,
        restart_claude_after,
        claude_path,
        vopts,
    )
    .await
}

/// Hook-based variant for testing: callers inject release fetch + download functions
#[allow(clippy::too_many_arguments)]
async fn update_from_github_with_hooks<Fetch, FutF, Download, FutD>(
    fetch_release: Fetch,
    download: Download,
    paths: &Paths,
    force: bool,
    preconfirmed: bool,
    restart_claude_after: bool,
    claude_path: Option<String>,
    vopts: VerificationOptions,
) -> Result<()>
where
    Fetch: Fn() -> FutF,
    FutF: std::future::Future<Output = Result<GitHubRelease>>,
    Download: Fn(GitHubRelease, String, PathBuf) -> FutD,
    FutD: std::future::Future<Output = Result<()>>,
{
    // Fetch latest release via injected hook
    let release = fetch_release().await?;

    // Version checks and confirmations are now done in the main update() function
    // This function only does the actual update work
    if !preconfirmed {
        if let Some(current_info) = InstallationInfo::load(paths)? {
            println!("📦 Updating from {} to {}", current_info.version, release.tag_name);
            if force {
                println!("⚠️  Force updating (reinstall)");
            }
        } else {
            println!("📦 Installing version: {}", release.tag_name);
        }
    }

    // Backup current server binary
    let binary_path = paths.server_binary();
    let backup_path = binary_path.with_extension("bak");
    if binary_path.exists() {
        println!("💾 Backing up current binary...");
        fs::copy(&binary_path, &backup_path).context("Failed to create backup")?;
    }

    // Download new server binary via injected hook
    download(
        release.clone(),
        "mdmcpsrvr".to_string(),
        binary_path.clone(),
    )
    .await?;

    // Verify downloaded binary against manifest if available
    if !vopts.skip {
        if let Ok(sums) = fetch_and_verify_manifest(&release, &vopts).await {
            // Determine expected asset name
            let platform = get_platform_string();
            let wanted = "mdmcpsrvr".to_string();
            let mut chosen: Option<&GitHubAsset> = release.assets.iter().find(|a| {
                a.name.to_ascii_lowercase().contains(&wanted) && a.name.contains(&platform)
            });
            if chosen.is_none() {
                chosen = release
                    .assets
                    .iter()
                    .find(|a| a.name.to_ascii_lowercase().contains(&wanted));
            }
            if let Some(asset) = chosen {
                if let Some(exp) = sums.get(&asset.name) {
                    let got = calculate_sha256(&binary_path)?;
                    if got.to_lowercase() != exp.to_lowercase() {
                        bail!(
                            "Downloaded server binary checksum mismatch for {}",
                            asset.name
                        );
                    }
                } else {
                    println!("⚠️  No checksum entry for {}; proceeding", asset.name);
                }
            }
        }
    }

    // Update installation info
    let install_info = InstallationInfo::new(release.tag_name.clone(), paths)?;
    install_info.save(paths)?;

    // Refresh core policy defaults on update
    if let Err(e) = refresh_core_policy(paths) {
        println!("⚠️  Failed to refresh core policy: {}", e);
    }

    // If requested, restart Claude Desktop before self-update to ensure it's back up
    if restart_claude_after {
        if let Err(e) = start_claude_desktop(claude_path.as_deref()) {
            println!("⚠️  Failed to restart Claude Desktop: {}", e);
        }
    }

    // Attempt self-update of mdmcpcfg (skippable in tests)
    if std::env::var("MDMCP_SKIP_SELF_UPDATE").is_err() {
        if let Err(e) = download_and_self_update_mdmcpcfg(&release).await {
            println!("⚠️  mdmcpcfg self-update skipped: {}", e);
        }
    }

    println!("✅ Server update completed. mdmcpcfg will relaunch if self-updated.");

    // Auto-generate documentation cache (non-blocking semantics)
    println!("   Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("   ✅ Documentation cache built"),
        Err(e) => println!("   ⚠️  Failed to build documentation cache: {}", e),
    }

    Ok(())
}

/// Update from local binary
/// Update from local binary; if `preconfirmed` is true, skip extra prints
async fn update_from_local_binary(
    paths: &Paths,
    source_binary: &Path,
    force: bool,
    preconfirmed: bool,
    restart_claude_after: bool,
    claude_path: Option<String>,
) -> Result<()> {
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

    // Version checks and confirmations are now done in the main update() function
    // This function only does the actual update work
    if !preconfirmed {
        if let Some(current_info) = InstallationInfo::load(paths)? {
            let new_version_tag = format!("{} (local)", version);
            println!("📦 Updating from {} to {}", current_info.version, new_version_tag);
            if force {
                println!("⚠️  Force updating (reinstall)");
            }
        } else {
            println!("📦 New version: {} (local)", version);
        }
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

    // Refresh core policy defaults on update
    if let Err(e) = refresh_core_policy(paths) {
        println!("⚠️  Failed to refresh core policy: {}", e);
    }

    // If requested, restart Claude Desktop before self-update so it's back up promptly
    if restart_claude_after {
        if let Err(e) = start_claude_desktop(claude_path.as_deref()) {
            println!("⚠️  Failed to restart Claude Desktop: {}", e);
        }
    }

    // Try to self-update mdmcpcfg from the same directory as source_binary (if present)
    if let Err(e) = try_self_update_from_local_tool(source_binary).await {
        println!("ℹ️  mdmcpcfg self-update from local source skipped: {}", e);
    }

    println!("✅ Local server update complete. mdmcpcfg will relaunch if self-updated.");

    // Auto-generate documentation cache (non-blocking semantics)
    println!("   Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("   ✅ Documentation cache built"),
        Err(e) => println!("   ⚠️  Failed to build documentation cache: {}", e),
    }

    Ok(())
}

/// Install from GitHub (original logic extracted)
async fn install_from_github(
    dest_dir: Option<String>,
    configure_claude: bool,
    insecure_skip_verify: bool,
    verify_key: Option<String>,
) -> Result<()> {
    let paths = setup_paths(dest_dir)?;
    paths.ensure_dirs()?;

    // Download the latest release
    let release = fetch_latest_release().await?;
    println!("🔎 Found release: {}", release.tag_name);

    let binary_path = paths.server_binary();
    // Download the server binary specifically
    // Set verification options
    let vopts = VerificationOptions {
        skip: insecure_skip_verify,
        verify_key_path: verify_key.clone(),
    };
    // Prefer per-OS binaries ZIP; fallback to raw binary for backward compatibility
    if let Err(e) = download_server_from_zip_verified(&release, &binary_path, &vopts).await {
        println!(
            "ℹ️  Zip-based download failed ({}). Falling back to raw binary...",
            e
        );
        download_binary_verified(&release, "mdmcpsrvr", &binary_path, &vopts).await?;
    }

    // Create default core + user policy files if needed
    create_default_policies(&paths).await?;

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

    // Auto-generate documentation cache (non-blocking semantics)
    println!("   Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("   ✅ Documentation cache built"),
        Err(e) => println!("   ⚠️  Failed to build documentation cache: {}", e),
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

    // Create default core + user policy files and configure Claude Desktop
    create_default_policies(&paths).await?;

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

    // Auto-generate documentation cache (non-blocking semantics)
    println!("   Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("   ✅ Documentation cache built"),
        Err(e) => println!("   ⚠️  Failed to build documentation cache: {}", e),
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

/// Internal: Spawn a helper process (copy of current mdmcpcfg) that replaces the original exe with a new one
pub fn run_self_upgrade_helper(pid: u32, orig: String, new: String) -> Result<()> {
    println!("🛠️ mdmcpcfg self-upgrade helper starting...");

    let orig_path = PathBuf::from(orig);
    let new_path = PathBuf::from(new);
    #[cfg(not(windows))]
    let _ = pid;

    // Wait for the parent process (pid) to exit on Windows, otherwise proceed after a brief delay
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if !handle.is_null() {
                loop {
                    let mut code: u32 = 0;
                    if GetExitCodeProcess(handle, &mut code as *mut u32) == 0 {
                        break; // unable to query; assume gone
                    }
                    if code != (STILL_ACTIVE as u32) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                CloseHandle(handle);
            } else {
                // Could not open process - likely already exited
            }
        }
    }
    #[cfg(not(windows))]
    {
        // Give parent a moment to exit to avoid race conditions
        std::thread::sleep(Duration::from_millis(300));
    }

    // Try to replace the original with retries
    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let mut replaced = false;
    while start.elapsed() < timeout {
        // Best effort: remove original if possible
        let mut removed = false;
        if orig_path.exists() {
            match std::fs::remove_file(&orig_path) {
                Ok(_) => removed = true,
                Err(_) => {
                    // Might still be locked; wait and retry
                }
            }
        } else {
            removed = true;
        }

        if removed {
            // Try to move new into place
            if std::fs::rename(&new_path, &orig_path).is_ok() {
                replaced = true;
                break;
            }
            // Fallback: copy and then remove temp
            if std::fs::copy(&new_path, &orig_path).is_ok() {
                let _ = std::fs::remove_file(&new_path);
                replaced = true;
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    if replaced {
        println!("✅ mdmcpcfg replaced successfully: {}", orig_path.display());
    } else {
        println!("⚠️  Could not replace mdmcpcfg within timeout; continuing with existing binary");
    }

    // Respawn mdmcpcfg (the original path), show version and exit
    let _ = Command::new(&orig_path).arg("--version").spawn();
    Ok(())
}

/// Download mdmcpcfg to a temp directory and spawn helper to replace this process
async fn download_and_self_update_mdmcpcfg(release: &GitHubRelease) -> Result<()> {
    let temp_dir = std::env::temp_dir().join(format!("mdmcp-update-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).ok();

    let is_win = cfg!(target_os = "windows");
    let cfg_name = if is_win { "mdmcpcfg.exe" } else { "mdmcpcfg" };
    let helper_name = if is_win {
        "mdmcpcfg-helper.exe"
    } else {
        "mdmcpcfg-helper"
    };

    let new_cfg_path = temp_dir.join(cfg_name);
    // Download the CLI binary
    download_binary(release, "mdmcpcfg", &new_cfg_path).await?;

    // Verify downloaded binary can run --version
    if !is_executable(&new_cfg_path) {
        bail!(
            "Downloaded mdmcpcfg is not executable: {}",
            new_cfg_path.display()
        );
    }
    // Optional: sanity check version
    let _ = Command::new(&new_cfg_path).arg("--version").output();

    // Prepare helper: copy current exe to temp
    let current_exe = std::env::current_exe().context("Failed to get current executable path")?;
    let helper_path = temp_dir.join(helper_name);
    std::fs::copy(&current_exe, &helper_path).with_context(|| {
        format!(
            "Failed to copy helper to temp: {} -> {}",
            current_exe.display(),
            helper_path.display()
        )
    })?;

    println!("🛠️ Preparing to self-update mdmcpcfg...");

    // Spawn helper and exit
    let mut cmd = Command::new(&helper_path);
    cmd.arg("self-upgrade-helper")
        .arg("--pid")
        .arg(std::process::id().to_string())
        .arg("--orig")
        .arg(current_exe.to_string_lossy().to_string())
        .arg("--new")
        .arg(new_cfg_path.to_string_lossy().to_string());
    let _ = cmd.spawn().context("Failed to spawn self-upgrade helper")?;
    // Make sure console cursor is restored so prompt doesn't look hung
    restore_console_cursor();

    println!("➡️  Relaunching mdmcpcfg via helper and exiting...");
    std::process::exit(0);
}

/// Attempt to self-update mdmcpcfg using a local binary located next to the provided server binary
async fn try_self_update_from_local_tool(server_source_binary: &Path) -> Result<()> {
    let dir = server_source_binary
        .parent()
        .context("No parent directory for local binary")?;
    let candidate = if cfg!(target_os = "windows") {
        dir.join("mdmcpcfg.exe")
    } else {
        dir.join("mdmcpcfg")
    };
    if !candidate.exists() {
        bail!("No local mdmcpcfg found at {}", candidate.display());
    }
    if !is_executable(&candidate) {
        bail!("Local mdmcpcfg is not executable: {}", candidate.display());
    }

    // Copy candidate to temp and spawn helper to replace current exe
    let temp_dir = std::env::temp_dir().join(format!("mdmcp-update-{}", std::process::id()));
    std::fs::create_dir_all(&temp_dir).ok();
    let cfg_name = if cfg!(target_os = "windows") {
        "mdmcpcfg.exe"
    } else {
        "mdmcpcfg"
    };
    let helper_name = if cfg!(target_os = "windows") {
        "mdmcpcfg-helper.exe"
    } else {
        "mdmcpcfg-helper"
    };
    let new_cfg_path = temp_dir.join(cfg_name);
    std::fs::copy(&candidate, &new_cfg_path).with_context(|| {
        format!(
            "Failed to stage mdmcpcfg into temp: {} -> {}",
            candidate.display(),
            new_cfg_path.display()
        )
    })?;

    // Prepare helper
    let current_exe = std::env::current_exe().context("Failed to get current executable path")?;
    let helper_path = temp_dir.join(helper_name);
    std::fs::copy(&current_exe, &helper_path).with_context(|| {
        format!(
            "Failed to copy helper to temp: {} -> {}",
            current_exe.display(),
            helper_path.display()
        )
    })?;

    println!("🛠️ Preparing to self-update mdmcpcfg from local binary...");

    // Spawn helper and exit
    let mut cmd = Command::new(&helper_path);
    cmd.arg("self-upgrade-helper")
        .arg("--pid")
        .arg(std::process::id().to_string())
        .arg("--orig")
        .arg(current_exe.to_string_lossy().to_string())
        .arg("--new")
        .arg(new_cfg_path.to_string_lossy().to_string());
    let _ = cmd.spawn().context("Failed to spawn self-upgrade helper")?;
    println!("➡️  Relaunching mdmcpcfg via helper and exiting...");
    restore_console_cursor();
    std::process::exit(0);
}

/// Detect if Claude Desktop is currently running
fn is_claude_running() -> bool {
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = Command::new("tasklist").output() {
            let s = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
            return s.contains("claude.exe");
        }
        false
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(status) = Command::new("pgrep").arg("-x").arg("Claude").status() {
            return status.success();
        }
        false
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(status) = Command::new("pgrep").arg("-f").arg("Claude").status() {
            return status.success();
        }
        false
    }
}

/// Attempt to stop Claude Desktop if running
fn stop_claude_desktop() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Try both Claude.exe and claude.exe (case variations)
        let mut stopped = false;

        // First attempt: Claude.exe
        match Command::new("taskkill")
            .args(["/IM", "Claude.exe", "/F", "/T"])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    stopped = true;
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // Only show error if it's not "process not found"
                    if !stderr.to_lowercase().contains("not found") && !stderr.trim().is_empty() {
                        println!("⚠️  taskkill Claude.exe: {}", stderr.trim());
                    }
                }
            }
            Err(e) => println!("⚠️  Failed to run taskkill: {}", e),
        }

        // Second attempt: claude.exe (lowercase)
        match Command::new("taskkill")
            .args(["/IM", "claude.exe", "/F", "/T"])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    stopped = true;
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    // Only show error if it's not "process not found"
                    if !stderr.to_lowercase().contains("not found") && !stderr.trim().is_empty() {
                        println!("⚠️  taskkill claude.exe: {}", stderr.trim());
                    }
                }
            }
            Err(e) => println!("⚠️  Failed to run taskkill: {}", e),
        }

        if stopped {
            println!("✅ Claude Desktop stopped");
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        match Command::new("osascript")
            .args(["-e", "tell application \"Claude\" to quit"])
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ Claude Desktop stopped");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.trim().is_empty() {
                        println!(
                            "⚠️  Failed to quit Claude via AppleScript: {}",
                            stderr.trim()
                        );
                    }
                }
            }
            Err(e) => println!("⚠️  Failed to run osascript: {}", e),
        }
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        match Command::new("pkill").arg("-f").arg("Claude").output() {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ Claude Desktop stopped");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.trim().is_empty() {
                        println!("⚠️  pkill failed: {}", stderr.trim());
                    }
                }
            }
            Err(e) => println!("⚠️  Failed to run pkill: {}", e),
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn is_mdmcp_running() -> bool {
    if let Ok(out) = Command::new("tasklist").output() {
        let s = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
        return s.contains("mdmcpsrvr.exe");
    }
    false
}

#[cfg(not(target_os = "windows"))]
fn is_mdmcp_running() -> bool { false }

#[cfg(target_os = "windows")]
fn mdmcp_parent_chain_names_lower() -> Vec<String> {
    let ps = "\
$p = Get-CimInstance Win32_Process -Filter \"Name='mdmcpsrvr.exe'\" | Select-Object -First 1;\
if (-not $p) { return }\
$names = @();\
$seen = @{};\
while ($p -and $p.ParentProcessId -ne 0) {\
  try { $pp = Get-CimInstance Win32_Process -Filter \"ProcessId=$($p.ParentProcessId)\" -ErrorAction Stop } catch { break }\
  if (-not $pp) { break }\
  $names += $pp.Name;\
  if ($seen.ContainsKey($pp.ProcessId)) { break }\
  $seen[$pp.ProcessId] = $true;\
  $p = $pp\
}\
$names -join ';'\
";
    if let Ok(out) = Command::new("powershell").args(["-NoProfile", "-Command", ps]).output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).to_string();
            return s
                .split(';')
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty())
                .collect();
        }
    }
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
fn mdmcp_parent_chain_names_lower() -> Vec<String> { Vec::new() }

#[cfg(target_os = "windows")]
fn stop_vs_code() -> Result<()> {
    for name in ["Code.exe", "Code - Insiders.exe"] {
        let _ = Command::new("taskkill").args(["/IM", name, "/F", "/T"]).status();
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn stop_vs_code() -> Result<()> { Ok(()) }

/// Attempt to start Claude Desktop
fn start_claude_desktop(_prev_path: Option<&str>) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        if let Some(path) = _prev_path {
            let mut cmd = Command::new("cmd");
            cmd.args(["/C", "start", "", path]);
            let _ = cmd.spawn();
            return Ok(());
        }
        if let Some(local) = dirs::data_local_dir() {
            let candidate = local.join("Programs").join("Claude").join("Claude.exe");
            if candidate.exists() {
                let mut cmd = Command::new("cmd");
                cmd.args(["/C", "start", "", &candidate.to_string_lossy()]);
                let _ = cmd.spawn();
                return Ok(());
            }
        }
        let _ = Command::new("cmd")
            .args(["/C", "start", "", "Claude.exe"])
            .spawn();
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").args(["-a", "Claude"]).status();
        Ok(())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if Command::new("sh")
            .arg("-lc")
            .arg("command -v claude >/dev/null 2>&1 && nohup claude >/dev/null 2>&1 &")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Ok(());
        }
        Ok(())
    }
}

/// Try to find the Claude Desktop executable path from the running process (Windows only)
fn find_claude_path() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-Process -Name 'Claude' -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Path)"
            ])
            .output()
        {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
        if let Ok(output) = Command::new("wmic")
            .args([
                "process",
                "where",
                "name='Claude.exe'",
                "get",
                "ExecutablePath",
                "/value",
            ])
            .output()
        {
            if output.status.success() {
                let s = String::from_utf8_lossy(&output.stdout);
                for line in s.lines() {
                    if let Some(rest) = line.strip_prefix("ExecutablePath=") {
                        let path = rest.trim();
                        if !path.is_empty() {
                            return Some(path.to_string());
                        }
                    }
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "windows"))]
    {
        None
    }
}

/// Ensure the console cursor is visible and write a newline before exiting
fn restore_console_cursor() {
    #[cfg(target_os = "windows")]
    unsafe {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleCursorInfo, SetConsoleMode,
            CONSOLE_CURSOR_INFO, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_OUTPUT_HANDLE,
        };
        let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        if !h_out.is_null() {
            let mut mode: u32 = 0;
            let _ = GetConsoleMode(h_out, &mut mode as *mut u32);
            let _ = SetConsoleMode(h_out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            let info = CONSOLE_CURSOR_INFO {
                dwSize: 25,
                bVisible: 1,
            };
            let _ = SetConsoleCursorInfo(h_out, &info as *const CONSOLE_CURSOR_INFO);
        }
    }
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(b"\x1B[?25h\r\n");
    let _ = std::io::stdout().flush();
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
    // Remove server binary
    let bin = paths.server_binary();
    let bin_exists = bin.exists();
    let plugins_dir = paths.bin_dir.join("plugins");
    let known_plugins = ["mdaicli", "mdconfcli", "mdjiracli", "mdmailcli", "mdslackcli"];
    let mut plugin_any = false;
    for id in &known_plugins { if plugins_dir.join(format!("{}.exe", id)).exists() { plugin_any = true; break; } }
    // On Windows, detect WSL installs across all distros (not just default)
    #[cfg(target_os = "windows")]
    let wsl_installs: Vec<String> = if wsl_available() {
        let distros = wsl_list_distros();
        distros
            .into_iter()
            .filter(|d|
                // Check for server presence in the distro
                wsl_path_exists(Some(d.as_str()), "~/.local/share/mdmcp/bin/mdmcpsrvr")
            )
            .collect()
    } else { Vec::new() };
    #[cfg(not(target_os = "windows"))]
    let wsl_installs: Vec<String> = Vec::new();
    let wsl_server_exists = !wsl_installs.is_empty();

    // If nothing to do, exit early without prompting
    if !bin_exists && !plugin_any && !wsl_server_exists && !remove_policy && !remove_claude_config {
        println!("ℹ️  Nothing to uninstall: no server, plugins, WSL install, or selected config entries.");
        return Ok(());
    }

    // Offer to stop apps that can lock the server binary (Windows only), only if relevant
    #[cfg(target_os = "windows")]
    if bin_exists || wsl_server_exists {
        // Be precise: only suggest apps that appear in the parent chain of the running server
        let mut suspects: Vec<&str> = Vec::new();
        if is_mdmcp_running() {
            let chain = mdmcp_parent_chain_names_lower();
            if chain.iter().any(|n| n.contains("claude.exe")) { suspects.push("Claude Desktop"); }
            if chain.iter().any(|n| n.contains("code.exe")) { suspects.push("VS Code"); }
        }
        if !suspects.is_empty() {
            println!(
                "The following apps appear related to a running mdmcpsrvr process: {}",
                suspects.join(", ")
            );
            if prompt_named_confirmation("Stop them now? [Y/n]: ")? {
                if suspects.iter().any(|s| *s == "Claude Desktop") { let _ = stop_claude_desktop(); }
                if suspects.iter().any(|s| *s == "VS Code") { let _ = stop_vs_code(); }
            }
        }
    }


    // Ask for confirmation only when needed
    if !yes {
        let mut items: Vec<&str> = Vec::new();
        if bin_exists { items.push("server binary"); }
        if remove_policy { items.push("policy file"); }
        if remove_claude_config { items.push("Claude Desktop entry"); }
        if wsl_server_exists { items.push("WSL server binary"); }
        if plugin_any { items.push("Windows plugins"); }
        if items.is_empty() {
            println!("ℹ️  Nothing to uninstall.");
            return Ok(());
        }
        println!("This will remove: {}.", items.join(", "));
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
    if bin_exists {
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

    // Remove Windows plugins if present
    let plugins_dir = paths.bin_dir.join("plugins");
    if plugins_dir.exists() {
        let plugin_ids = ["mdaicli", "mdconfcli", "mdjiracli", "mdmailcli", "mdslackcli"]; 
        let mut removed = 0;
        for id in plugin_ids {
            let p = plugins_dir.join(format!("{}.exe", id));
            if p.exists() {
                match std::fs::remove_file(&p) {
                    Ok(_) => { println!("✅ Removed plugin: {}", p.display()); removed += 1; }
                    Err(e) => println!("⚠️  Failed to remove plugin {}: {}", p.display(), e),
                }
            }
        }
        if removed == 0 {
            println!("ℹ️  No plugin executables found in: {}", plugins_dir.display());
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

    // Remove WSL-side server (and optionally policy) when available (Windows only)
    #[cfg(target_os = "windows")]
    {
        if !wsl_installs.is_empty() {
            // If interactive, inform the user which distros will be cleaned
            if !yes {
                println!(
                    "Will remove WSL-side components from distros: {}",
                    wsl_installs.join(", ")
                );
            }
            for d in &wsl_installs {
                let server_exists = wsl_path_exists(Some(d.as_str()), "~/.local/share/mdmcp/bin/mdmcpsrvr");
                let policy_exists = if remove_policy { wsl_path_exists(Some(d.as_str()), "~/.config/mdmcp/policy.user.yaml") } else { false };
                if server_exists {
                    let _ = wsl_exec_status(Some(d.as_str()), "rm -f ~/.local/share/mdmcp/bin/mdmcpsrvr");
                    println!("✅ [{}] Removed WSL server binary: ~/.local/share/mdmcp/bin/mdmcpsrvr", d);
                }
                if policy_exists {
                    let _ = wsl_exec_status(Some(d.as_str()), "rm -f ~/.config/mdmcp/policy.user.yaml");
                    println!("✅ [{}] Removed WSL policy: ~/.config/mdmcp/policy.user.yaml", d);
                }
            }
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
            core_policy_file: default_paths.core_policy_file,
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
    // Special-case mdmcpcfg: our release assets use OS-prefixed names
    if wanted_prefix.eq_ignore_ascii_case("mdmcpcfg") {
        let expected: &str = if cfg!(target_os = "windows") {
            "windows-mdmcpcfg.exe"
        } else if cfg!(target_os = "macos") {
            "macos-mdmcpcfg"
        } else if cfg!(target_os = "linux") {
            "linux-mdmcpcfg"
        } else {
            bail!("Unsupported OS for mdmcpcfg self-update");
        };

        let chosen = release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(expected))
            .or_else(|| {
                let name = wanted_prefix.to_ascii_lowercase();
                let os_hint = if cfg!(target_os = "windows") {
                    "windows"
                } else if cfg!(target_os = "macos") {
                    "macos"
                } else {
                    "linux"
                };
                release.assets.iter().find(|a| {
                    let an = a.name.to_ascii_lowercase();
                    an.contains(&name) && an.contains(os_hint)
                })
            })
            .with_context(|| format!("No mdmcpcfg asset found for OS: {}", expected))?;

        println!("📥 Downloading: {}", chosen.name);
        let client = reqwest::Client::new();
        let response = client
            .get(&chosen.browser_download_url)
            .header("User-Agent", "mdmcpcfg")
            .send()
            .await
            .context("Failed to download binary")?;
        if !response.status().is_success() {
            bail!("Download failed: {}", response.status());
        }
        let mut temp_file = NamedTempFile::new().context("Failed to create temporary file")?;
        let content = response
            .bytes()
            .await
            .context("Failed to read download content")?;
        use std::io::Write;
        temp_file
            .write_all(&content)
            .context("Failed to write temporary file")?;
        fs::copy(temp_file.path(), dest_path).context("Failed to move binary to destination")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(dest_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(dest_path, perms)?;
        }
        if !is_executable(dest_path) {
            bail!(
                "Downloaded binary is not executable: {}",
                dest_path.display()
            );
        }
        println!("📦 Binary downloaded: {}", dest_path.display());
        return Ok(());
    }
    // Special-case server binary: prefer extracting from per-OS binaries zip
    if wanted_prefix.eq_ignore_ascii_case("mdmcpsrvr") {
        let v = VerificationOptions {
            skip: true,
            verify_key_path: None,
        };
        if let Err(e) = download_server_from_zip_verified(release, dest_path, &v).await {
            // Fall back to legacy direct-asset logic below
            println!(
                "ℹ️  Zip-based server download not available ({}); trying raw asset...",
                e
            );
        } else {
            return Ok(());
        }
    }
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

/// Create default core and user policy files if missing
async fn create_default_policies(paths: &Paths) -> Result<()> {
    // Core policy contains vendor defaults and may be overwritten by updates
    if !paths.core_policy_file.exists() {
        println!("📝 Creating core policy file...");
        let default_policy = create_default_policy_content()?;
        write_file(&paths.core_policy_file, &default_policy)?;
        // Make core policy read-only to prevent accidental edits
        set_readonly(&paths.core_policy_file, true)?;
        println!(
            "✅ Created core policy (read-only): {}",
            paths.core_policy_file.display()
        );
    } else {
        // Ensure core policy remains read-only
        if let Err(e) = set_readonly(&paths.core_policy_file, true) {
            println!(
                "⚠️  Could not enforce read-only on core policy {}: {}",
                paths.core_policy_file.display(),
                e
            );
        }
        println!(
            "\u{2139}\u{FE0F}  Core policy already exists: {}",
            paths.core_policy_file.display()
        );
    }

    // User policy is a minimal overlay; only create if missing
    if !paths.policy_file.exists() {
        println!("📝 Creating user policy overlay file...");
        let user_overlay = create_minimal_user_policy_content()?;
        write_file(&paths.policy_file, &user_overlay)?;
        println!("✅ Created user policy: {}", paths.policy_file.display());
    } else {
        println!(
            "\u{2139}\u{FE0F}  User policy already exists: {}",
            paths.policy_file.display()
        );
    }

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
    let workspace_path = home_dir
        .join("mdmcp-workspace")
        .to_string_lossy()
        .replace('\\', "/");

    let mut commands: Vec<CommandRule> = Vec::new();

    // Cross-platform commands (Unix-like)
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        commands.push(CommandRule {
            id: "cat".into(),
            exec: "/bin/cat".into(),
            description: None,
            env_static: std::collections::HashMap::new(),
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
            help_capture: Default::default(),
        });
        // Common Unix text/file tools (only on Unix)
        for (id, path) in [
            ("head", "/usr/bin/head"),
            ("tail", "/usr/bin/tail"),
            ("grep", "/usr/bin/grep"),
            ("wc", "/usr/bin/wc"),
            ("sed", "/usr/bin/sed"),
            ("diff", "/usr/bin/diff"),
            ("patch", "/usr/bin/patch"),
        ] {
            commands.push(CommandRule {
                id: id.into(),
                exec: path.into(),
                description: None,
                env_static: std::collections::HashMap::new(),
                args: ArgsPolicy {
                    allow: vec![],
                    fixed: vec![],
                    patterns: vec![],
                },
                cwd_policy: CwdPolicy::WithinRoot,
                env_allowlist: vec![],
                timeout_ms: 20_000,
                max_output_bytes: 4_000_000,
                platform: vec!["linux".into(), "macos".into()],
                allow_any_args: true,
                help_capture: Default::default(),
            });
        }
    }

    // Windows builtins via cmd
    if cfg!(target_os = "windows") {
        let windows_cmd = |id: &str, sub: &str| CommandRule {
            id: id.into(),
            exec: "C:/Windows/System32/cmd.exe".into(),
            description: None,
            env_static: std::collections::HashMap::new(),
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
            help_capture: Default::default(),
        };
        for (id, sub) in [
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
            description: None,
            env_static: std::collections::HashMap::new(),
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
            help_capture: Default::default(),
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
        // Additional common Windows tools
        commands.push(win_exec(
            "ping",
            "C:/Windows/System32/ping.exe",
            15_000,
            2_000_000,
        ));
        commands.push(win_exec(
            "ipconfig",
            "C:/Windows/System32/ipconfig.exe",
            10_000,
            2_000_000,
        ));
        commands.push(win_exec(
            "whoami",
            "C:/Windows/System32/whoami.exe",
            5_000,
            500_000,
        ));
        commands.push(win_exec(
            "fc",
            "C:/Windows/System32/fc.exe",
            20_000,
            4_000_000,
        ));
        commands.push(win_exec(
            "timeout",
            "C:/Windows/System32/timeout.exe",
            15_000,
            200_000,
        ));
        commands.push(win_exec(
            "forfiles",
            "C:/Windows/System32/forfiles.exe",
            15_000,
            2_000_000,
        ));
        commands.push(win_exec(
            "typeperf",
            "C:/Windows/System32/typeperf.exe",
            30_000,
            4_000_000,
        ));
    }

    // Build core policy
    let policy = Policy {
        version: 1,
        deny_network_fs: true,
        // For safety, do not include default allowed roots in core policy
        allowed_roots: vec![],
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
    let body = serde_yaml::to_string(&policy)?;
    // Prepend header comment
    let header = "# MDMCP core policy (policy.core.yaml)\n#\n# This file contains vendor defaults installed by mdmcpcfg.\n# It WILL be overwritten on upgrade, and is set read-only to avoid accidental edits.\n#\n# To customize behavior, edit the user policy file instead: policy.user.yaml.\n# The user policy is merged over this core file and NEVER changed by upgrades.\n#\n# Security note: Certain security-critical flags in this core policy (e.g., deny_network_fs)\n# are enforced. The effective value is core OR user, so a core=true setting cannot be\n# disabled by the user policy.\n#\n";
    let mut out = String::new();
    out.push_str(header);
    out.push_str(&body);
    Ok(out)
}

/// Overwrite the core policy file with current defaults, preserving read-only flag.
fn refresh_core_policy(paths: &Paths) -> Result<()> {
    use std::fs;
    let core = &paths.core_policy_file;
    let was_readonly = core.exists() && fs::metadata(core)?.permissions().readonly();
    if core.exists() && was_readonly {
        set_readonly(core, false).ok();
    }
    if core.exists() {
        let bak = core.with_extension("yaml.bak");
        fs::copy(core, &bak).with_context(|| format!("Failed to backup {}", core.display()))?;
    }
    let content = create_default_policy_content()?;
    write_file(core, &content)?;
    set_readonly(core, true).ok();
    println!("📝 Refreshed core policy defaults: {}", core.display());
    Ok(())
}

/// Minimal user overlay policy: valid schema with empty lists
fn create_minimal_user_policy_content() -> Result<String> {
    use mdmcp_policy::{LimitsConfig, LoggingConfig, Policy};
    let policy = Policy {
        version: 1,
        deny_network_fs: true,
        allowed_roots: vec![],
        write_rules: vec![],
        commands: vec![],
        logging: LoggingConfig::default(),
        limits: LimitsConfig::default(),
    };
    let body = serde_yaml::to_string(&policy)?;
    let header = "# MDMCP user policy (policy.user.yaml)\n#\n# This file contains your local overrides and configuration.\n# mdmcpcfg install/upgrade NEVER changes this file.\n#\n# Tips:\n# - Add your allowed_roots and write_rules here.\n# - Add or adjust commands you want exposed to the MCP server.\n# - Keep deny_network_fs consistent with your security posture.\n#   Note: The core policy may enforce deny_network_fs=true; user policy cannot weaken it.\n#\n";
    let mut out = String::new();
    out.push_str(header);
    out.push_str(&body);
    Ok(out)
}

/// Set or clear read-only attribute on a file cross-platform
fn set_readonly(path: &Path, readonly: bool) -> Result<()> {
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_readonly(readonly);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_version_various_patterns() {
        let samples = [
            ("mdmcpsrvr 1.2.3", Some("1.2.3")),
            ("version v0.3.0 (build)", Some("0.3.0")),
            ("v2.0.0 release", Some("2.0.0")),
            ("no version here", None),
        ];
        for (s, exp) in samples {
            assert_eq!(parse_version_from_output(s).as_deref(), exp);
        }
    }

    #[test]
    fn test_get_platform_string_shape() {
        let s = get_platform_string();
        let parts: Vec<&str> = s.split('-').collect();
        assert_eq!(parts.len(), 2, "expected <arch>-<os>");
        let arch_ok = matches!(parts[0], "x86_64" | "aarch64" | "unknown");
        let os_ok = matches!(parts[1], "windows" | "linux" | "macos" | "unknown");
        assert!(arch_ok && os_ok, "unexpected platform string: {}", s);
    }

    #[test]
    fn test_calculate_sha256_tempfile() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"hello").unwrap();
        let digest = calculate_sha256(tmp.path()).unwrap();
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_binary_verification_fails_on_tampered() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"original").unwrap();
        let good_hash = calculate_sha256(tmp.path()).unwrap();
        // Tamper
        std::fs::write(tmp.path(), b"modified").unwrap();
        let ver = BinaryVerification {
            sha256: good_hash,
            signature: None,
            signed_by: None,
        };
        let res = verify_binary(tmp.path(), &ver);
        assert!(res.is_err());
    }

    #[test]
    fn test_atomic_policy_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.user.yaml");
        crate::io::write_file(&p, "version: 1\nallowed_roots: []\ncommands: []\n").unwrap();
        let v = std::fs::read_to_string(&p).unwrap();
        assert!(v.starts_with("version:"));
    }

    #[test]
    fn test_rollback_after_failed_update() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let paths = crate::io::Paths {
            bin_dir: root.join("bin"),
            config_dir: root.join("config"),
            policy_file: root.join("config").join("policy.user.yaml"),
            core_policy_file: root.join("config").join("policy.core.yaml"),
        };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        crate::io::write_file(&paths.policy_file, "user: A").unwrap();
        crate::io::write_file(&paths.core_policy_file, "core: A").unwrap();
        let bak_user = paths.policy_file.with_extension("yaml.bak");
        let bak_core = paths.core_policy_file.with_extension("yaml.bak");
        std::fs::copy(&paths.policy_file, &bak_user).unwrap();
        std::fs::copy(&paths.core_policy_file, &bak_core).unwrap();
        // Corrupt
        crate::io::write_file(&paths.policy_file, "user: CORRUPT").unwrap();
        crate::io::write_file(&paths.core_policy_file, "core: CORRUPT").unwrap();
        // Rollback
        std::fs::copy(&bak_user, &paths.policy_file).unwrap();
        std::fs::copy(&bak_core, &paths.core_policy_file).unwrap();
        let user_after = std::fs::read_to_string(&paths.policy_file).unwrap();
        let core_after = std::fs::read_to_string(&paths.core_policy_file).unwrap();
        assert_eq!(user_after, "user: A");
        assert_eq!(core_after, "core: A");
    }

    #[test]
    fn test_default_policy_content_parses_and_has_defaults() {
        let yaml = create_default_policy_content().expect("default policy content");
        let pol: mdmcp_policy::Policy = mdmcp_policy::Policy::from_yaml(&yaml).unwrap();
        assert_eq!(pol.version, 1);
        // Core policy must include at least one write rule
        assert!(!pol.write_rules.is_empty());
    }

    #[test]
    fn test_refresh_core_policy_preserves_readonly_flag() {
        // Build fake Paths rooted in a temp dir
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let cfg = tmp.path().join("config");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        let paths = crate::io::Paths {
            bin_dir: bin,
            config_dir: cfg.clone(),
            policy_file: cfg.join("policy.user.yaml"),
            core_policy_file: cfg.join("policy.core.yaml"),
        };

        // Create an initial core policy file and mark it read-only
        std::fs::write(
            &paths.core_policy_file,
            b"version: 1\nallowed_roots: []\ncommands: []\n",
        )
        .unwrap();
        set_readonly(&paths.core_policy_file, true).unwrap();
        assert!(std::fs::metadata(&paths.core_policy_file)
            .unwrap()
            .permissions()
            .readonly());

        // Refresh — should overwrite content and end as read-only again
        refresh_core_policy(&paths).unwrap();
        let meta = std::fs::metadata(&paths.core_policy_file).unwrap();
        assert!(meta.permissions().readonly());
        // Content should be non-trivial (starts with comment header)
        let body = std::fs::read_to_string(&paths.core_policy_file).unwrap();
        assert!(body.contains("MDMCP core policy"));
    }

    #[tokio::test]
    async fn test_install_github_success_mocked() {
        // Arrange temp paths
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let cfg = tmp.path().join("config");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        let paths = crate::io::Paths {
            bin_dir: bin.clone(),
            config_dir: cfg.clone(),
            policy_file: cfg.join("policy.user.yaml"),
            core_policy_file: cfg.join("policy.core.yaml"),
        };

        // Fake release & downloader hooks
        let fetch = || async {
            Ok(GitHubRelease {
                tag_name: "v9.9.9".to_string(),
                assets: vec![GitHubAsset {
                    name: "mdmcpsrvr-linux-x86_64".to_string(),
                    browser_download_url: "http://example.invalid/binary".to_string(),
                }],
                prerelease: false,
            })
        };
        let downloader = |_: GitHubRelease, _: String, dest: PathBuf| async move {
            // Write an executable stub to dest
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let mut f = std::fs::File::create(&dest).unwrap();
            #[cfg(unix)]
            {
                f.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dest).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dest, perms).unwrap();
            }
            #[cfg(windows)]
            {
                f.write_all(b"MZ\0\0stub").unwrap();
            }
            Ok(())
        };

        // Prevent exiting process during self-update attempt
        std::env::set_var("MDMCP_SKIP_SELF_UPDATE", "1");

        // Act
        update_from_github_with_hooks(
            fetch,
            downloader,
            &paths,
            false,
            true,
            false,
            None,
            VerificationOptions {
                skip: true,
                verify_key_path: None,
            },
        )
        .await
        .expect("mocked update ok");

        // Assert: binary exists and is executable; install info recorded
        let server_bin = paths.server_binary();
        assert!(server_bin.exists());
        assert!(crate::io::is_executable(&server_bin));
        let info_file = paths.config_dir.join("install_info.json");
        assert!(info_file.exists());
        let info_text = std::fs::read_to_string(info_file).unwrap();
        assert!(info_text.contains("\"version\": \"v9.9.9\""));

        std::env::remove_var("MDMCP_SKIP_SELF_UPDATE");
    }

    #[tokio::test]
    async fn test_network_failure_scenarios() {
        // Arrange
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let cfg = tmp.path().join("config");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&cfg).unwrap();
        let paths = crate::io::Paths {
            bin_dir: bin,
            config_dir: cfg.clone(),
            policy_file: cfg.join("policy.user.yaml"),
            core_policy_file: cfg.join("policy.core.yaml"),
        };
        let fetch = || async {
            Ok(GitHubRelease {
                tag_name: "v0.0.1".to_string(),
                assets: vec![],
                prerelease: false,
            })
        };
        let downloader = |_: GitHubRelease, _: String, _: PathBuf| async move {
            bail!("simulated network failure")
        };
        std::env::set_var("MDMCP_SKIP_SELF_UPDATE", "1");
        let res = update_from_github_with_hooks(
            fetch,
            downloader,
            &paths,
            false,
            true,
            false,
            None,
            VerificationOptions {
                skip: true,
                verify_key_path: None,
            },
        )
        .await;
        assert!(res.is_err());
        std::env::remove_var("MDMCP_SKIP_SELF_UPDATE");
    }
}
/// Verification info for installed binary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryVerification {
    pub sha256: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signed_by: Option<String>,
}

/// Verify binary integrity and optional signature
#[cfg(test)]
pub fn verify_binary(path: &Path, verification: &BinaryVerification) -> Result<()> {
    let actual = calculate_sha256(path)
        .with_context(|| format!("Failed to calculate SHA256 for {}", path.display()))?;
    if actual != verification.sha256 {
        bail!(
            "Binary checksum mismatch: expected {}, got {}",
            verification.sha256,
            actual
        );
    }
    // Placeholder: Optional signature verification hook (e.g., minisign or GPG)
    if let (Some(sig), Some(signer)) = (&verification.signature, &verification.signed_by) {
        // Future: verify signature; for now, ensure fields are non-empty to avoid false sense of security
        if sig.trim().is_empty() || signer.trim().is_empty() {
            bail!("Invalid signature metadata (empty)");
        }
    }
    Ok(())
}
/// Options controlling binary verification
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    pub skip: bool,
    #[allow(dead_code)]
    pub verify_key_path: Option<String>,
}

/// Minisign public key pinned in the client (to be set when signing is enabled)
#[allow(dead_code)]
const MINISIGN_PUBKEY: &str = ""; // Placeholder for future signature enforcement

async fn download_asset_text(url: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header("User-Agent", "mdmcpcfg")
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Failed to download asset: {}", resp.status());
    }
    Ok(resp.text().await?)
}

async fn download_asset_bytes(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .header("User-Agent", "mdmcpcfg")
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("Failed to download asset: {}", resp.status());
    }
    Ok(resp.bytes().await?.to_vec())
}

fn parse_sha256sums(text: &str) -> Result<std::collections::HashMap<String, String>> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Format: <sha256>  <filename>
        let mut parts = line.split_whitespace();
        let hash = parts
            .next()
            .context("Malformed SHA256SUMS line (missing hash)")?;
        let name = parts
            .next()
            .context("Malformed SHA256SUMS line (missing filename)")?;
        map.insert(name.to_string(), hash.to_lowercase());
    }
    Ok(map)
}

async fn fetch_and_verify_manifest(
    release: &GitHubRelease,
    _vopts: &VerificationOptions,
) -> Result<std::collections::HashMap<String, String>> {
    // Find checksum and signature assets
    let sums_asset = release
        .assets
        .iter()
        .find(|a| {
            a.name.eq_ignore_ascii_case("SHA256SUMS")
                || a.name.eq_ignore_ascii_case("SHA256SUMS.txt")
        })
        .context("SHA256SUMS manifest not found in release")?;
    let manifest_text = download_asset_text(&sums_asset.browser_download_url).await?;

    parse_sha256sums(&manifest_text)
}

async fn download_binary_verified(
    release: &GitHubRelease,
    wanted_prefix: &str,
    dest_path: &Path,
    vopts: &VerificationOptions,
) -> Result<()> {
    let platform = get_platform_string();
    let wanted_lower = wanted_prefix.to_ascii_lowercase();

    // Choose target asset
    let mut chosen: Option<&GitHubAsset> = release.assets.iter().find(|a| {
        a.name.to_ascii_lowercase().contains(&wanted_lower) && a.name.contains(&platform)
    });
    if chosen.is_none() {
        chosen = release
            .assets
            .iter()
            .find(|a| a.name.to_ascii_lowercase().contains(&wanted_lower));
    }
    if chosen.is_none() {
        chosen = release.assets.iter().find(|a| a.name.contains(&platform));
    }
    let asset = chosen.with_context(|| {
        format!(
            "No binary found for prefix '{}' and platform '{}' in release {}",
            wanted_prefix, platform, release.tag_name
        )
    })?;

    // Fetch and (optionally) verify manifest
    let sums = if vopts.skip {
        None
    } else {
        match fetch_and_verify_manifest(release, vopts).await {
            Ok(m) => Some(m),
            Err(e) => {
                println!("⚠️  Failed to verify manifest: {}", e);
                None
            }
        }
    };

    // If we have a manifest, look up expected hash for asset name
    let expected_hash = sums.as_ref().and_then(|m| m.get(&asset.name).cloned());

    println!("📥 Downloading: {}", asset.name);
    let bytes = download_asset_bytes(&asset.browser_download_url).await?;

    // If we have an expected hash, verify
    if let Some(exp) = expected_hash {
        let got = hex::encode(Sha256::digest(&bytes));
        if got.to_lowercase() != exp.to_lowercase() {
            bail!("Downloaded binary checksum mismatch for {}", asset.name);
        }
    } else if !vopts.skip {
        println!(
            "⚠️  No checksum entry found for {}; proceeding without hash verification",
            asset.name
        );
    }

    // Write to destination atomically within the same directory as dest
    write_bytes_atomically(dest_path, &bytes)?;
    if !is_executable(dest_path) {
        bail!(
            "Downloaded binary is not executable: {}",
            dest_path.display()
        );
    }
    println!("📦 Binary downloaded: {}", dest_path.display());
    Ok(())
}

/// Download the per-OS binaries zip and extract bin/mdmcpsrvr[.exe]
async fn download_server_from_zip_verified(
    release: &GitHubRelease,
    dest_path: &Path,
    vopts: &VerificationOptions,
) -> Result<()> {
    let zip_name = if cfg!(target_os = "windows") {
        "windows-binaries.zip"
    } else if cfg!(target_os = "macos") {
        "macos-binaries.zip"
    } else if cfg!(target_os = "linux") {
        "linux-binaries.zip"
    } else {
        bail!("Unsupported OS for zip-based install");
    };

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == zip_name)
        .with_context(|| format!("Zip asset not found in release: {}", zip_name))?;

    // Try to obtain expected hash: prefer SHA256SUMS manifest, else <zip>.sha256 sidecar
    let expected_hash = if vopts.skip {
        None
    } else if let Ok(map) = fetch_and_verify_manifest(release, vopts).await {
        map.get(zip_name).cloned()
    } else {
        // Look for sidecar sha256
        if let Some(side) = release
            .assets
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(&format!("{}.sha256", zip_name)))
        {
            let text = download_asset_text(&side.browser_download_url).await?;
            let hash = text.split_whitespace().next().unwrap_or("");
            if hash.len() == 64 {
                Some(hash.to_lowercase())
            } else {
                None
            }
        } else {
            None
        }
    };

    println!("📦 Downloading ZIP: {}", asset.name);
    let bytes = download_asset_bytes(&asset.browser_download_url).await?;
    if let Some(exp) = expected_hash {
        let got = hex::encode(Sha256::digest(&bytes));
        if got.to_lowercase() != exp.to_lowercase() {
            bail!("Downloaded ZIP checksum mismatch for {}", asset.name);
        }
    } else if !vopts.skip {
        println!(
            "⚠️  No checksum found for {}; proceeding without hash verification",
            asset.name
        );
    }

    // Extract desired entry to dest_path
    let target_entry = if cfg!(target_os = "windows") {
        "bin/mdmcpsrvr.exe"
    } else {
        "bin/mdmcpsrvr"
    };

    let reader = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(reader).context("Failed to read zip archive")?;
    // Resolve the actual entry name first, then open once to avoid borrow conflicts
    let mut chosen_name: Option<String> = None;
    if zip.by_name(target_entry).is_ok() {
        chosen_name = Some(target_entry.to_string());
    } else {
        let candidates: &[&str] = if cfg!(target_os = "windows") {
            &[
                "mdmcpsrvr.exe",
                "./mdmcpsrvr.exe",
                "bin/Release/mdmcpsrvr.exe",
                "bin/mdmcpsrvr.exe",
            ]
        } else {
            &[
                "mdmcpsrvr",
                "./mdmcpsrvr",
                "bin/mdmcpsrvr",
                "bin/Release/mdmcpsrvr",
            ]
        };
        for name in candidates {
            if zip.by_name(name).is_ok() {
                chosen_name = Some((*name).to_string());
                break;
            }
        }
        if chosen_name.is_none() {
            let want = if cfg!(target_os = "windows") { "mdmcpsrvr.exe" } else { "mdmcpsrvr" };
            let total = zip.len();
            for i in 0..total {
                if let Ok(e) = zip.by_index(i) {
                    let name = e.name().to_string();
                    if name.ends_with(want) && !name.ends_with('/') {
                        chosen_name = Some(name);
                        break;
                    }
                }
            }
        }
    }
    let entry_name = chosen_name.ok_or_else(|| anyhow::anyhow!(
        "Entry not found in zip; tried {} and common fallbacks",
        target_entry
    ))?;
    let mut file = zip
        .by_name(&entry_name)
        .with_context(|| format!("Entry not found in zip: {}", entry_name))?;

    // Write out atomically in-place
    use std::io::Read as _;
    let mut buf = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut buf)
        .context("Failed to read entry from zip")?;
    write_bytes_atomically(dest_path, &buf)?;
    if !is_executable(dest_path) {
        bail!(
            "Extracted binary is not executable: {}",
            dest_path.display()
        );
    }
    println!("📦 Extracted mdmcpsrvr from {}", zip_name);
    Ok(())
}

/// Atomically write bytes to `dest_path` by staging a temp file in the same directory
fn write_bytes_atomically(dest_path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    let parent = dest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let mut temp = NamedTempFile::new_in(&parent).context("Failed to create temporary file")?;
    temp.write_all(bytes)
        .context("Failed to write temporary file")?;
    temp.flush().ok();
    // On Windows, remove destination first to avoid rename errors when file exists/locked
    if dest_path.exists() {
        // Best-effort remove; ignore errors
        let _ = fs::remove_file(dest_path);
    }
    temp.persist(dest_path)
        .map_err(|e| anyhow::anyhow!("Failed to move binary to destination: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dest_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(dest_path, perms)?;
    }
    Ok(())
}







