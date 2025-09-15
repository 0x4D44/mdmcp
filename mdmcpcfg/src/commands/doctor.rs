//! # System diagnostics command
//!
//! This module implements the doctor command that checks system health,
//! configuration validity, and MCP server functionality.

use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::commands::doctor_extra::{check_wsl_side, print_summary_clean};
use crate::io::{is_executable, ClaudeDesktopConfig, Paths};

/// Run comprehensive system diagnostics
pub async fn run() -> Result<()> {
    println!("🩺 Running mdmcp system diagnostics...\\n");

    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    // Check installation
    check_installation(&mut issues, &mut warnings).await?;

    // Check policy file
    check_policy(&mut issues, &mut warnings).await?;

    // Check Claude Desktop integration
    check_claude_desktop(&mut issues, &mut warnings).await?;

    // If configured to launch via WSL, perform basic Linux-side checks (Windows only)
    #[cfg(target_os = "windows")]
    if let Err(e) = check_wsl_side(&mut warnings, &mut issues).await {
        warnings.push(format!("WSL checks skipped: {}", e));
    }

    // Check system dependencies
    check_system_dependencies(&mut issues, &mut warnings).await?;

    // Test server functionality
    test_server_functionality(&mut issues, &mut warnings).await?;

    // Print summary
    print_summary_clean(&issues, &warnings);

    if issues.is_empty() && warnings.is_empty() {
        println!("🎉 All checks passed! Your mdmcp installation is healthy.");
    } else if issues.is_empty() {
        println!(
            "⚠️  Found {} warnings, but no critical issues.",
            warnings.len()
        );
    } else {
        println!(
            "❌ Found {} critical issues that need attention.",
            issues.len()
        );
        if !warnings.is_empty() {
            println!("   Also found {} warnings.", warnings.len());
        }
    }

    Ok(())
}

/// Check if mdmcp is properly installed
async fn check_installation(issues: &mut Vec<String>, _warnings: &mut [String]) -> Result<()> {
    println!("🔍 Checking installation...");

    let paths = Paths::new()?;
    let binary_path = paths.server_binary();

    // Single-shot metadata check to reduce TOCTOU window
    match std::fs::symlink_metadata(&binary_path) {
        Err(_) => {
            issues.push(format!(
                "MCP server binary not found: {}",
                binary_path.display()
            ));
            println!("   ❌ Binary not found: {}", binary_path.display());
            return Ok(());
        }
        Ok(md) => {
            let is_file = md.file_type().is_file();
            let exec = if cfg!(target_os = "windows") {
                binary_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.eq_ignore_ascii_case("exe"))
                    .unwrap_or(false)
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    md.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    true
                }
            };
            if !is_file || !exec {
                issues.push(format!(
                    "MCP server binary is not executable: {}",
                    binary_path.display()
                ));
                println!("   ❌ Binary not executable: {}", binary_path.display());
                return Ok(());
            }
        }
    }

    println!(
        "   ✅ Binary found and executable: {}",
        binary_path.display()
    );

    // Check installation info
    if let Ok(info_path) = paths.config_dir.join("install_info.json").canonicalize() {
        if info_path.exists() {
            if let Ok(info_content) = fs::read_to_string(&info_path) {
                if let Ok(info) = serde_json::from_str::<serde_json::Value>(&info_content) {
                    if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                        println!("   ✅ Installation info found - Version: {}", version);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Check policy file validity
async fn check_policy(issues: &mut Vec<String>, warnings: &mut Vec<String>) -> Result<()> {
    println!("🔍 Checking policy configuration...");

    let paths = Paths::new()?;

    // Check if policy file exists
    if !paths.policy_file.exists() {
        issues.push(format!(
            "Policy file not found: {}",
            paths.policy_file.display()
        ));
        println!(
            "   ❌ Policy file not found: {}",
            paths.policy_file.display()
        );
        return Ok(());
    }

    println!("   ✅ Policy file exists: {}", paths.policy_file.display());

    // Try to parse policy file
    let policy_content = match fs::read_to_string(&paths.policy_file) {
        Ok(content) => content,
        Err(e) => {
            issues.push(format!("Cannot read policy file: {}", e));
            println!("   ❌ Cannot read policy file: {}", e);
            return Ok(());
        }
    };

    let policy: serde_yaml::Value = match serde_yaml::from_str(&policy_content) {
        Ok(policy) => policy,
        Err(e) => {
            issues.push(format!("Policy file has invalid YAML syntax: {}", e));
            println!("   ❌ Invalid YAML syntax: {}", e);
            return Ok(());
        }
    };

    println!("   ✅ Policy file has valid YAML syntax");

    // Basic structure validation
    let required_fields = ["version", "allowed_roots", "commands"];
    for field in &required_fields {
        if policy.get(field).is_none() {
            issues.push(format!("Policy file missing required field: {}", field));
            println!("   ❌ Missing required field: {}", field);
        }
    }

    // Check allowed roots exist
    if let Some(roots) = policy.get("allowed_roots").and_then(|r| r.as_sequence()) {
        println!("   ℹ️  Checking {} allowed roots...", roots.len());
        let mut accessible_count = 0;

        for root in roots.iter().take(5) {
            // Check first 5 to avoid spam
            if let Some(root_str) = root.as_str() {
                let expanded_root = shellexpand::tilde(root_str);
                let root_path = Path::new(expanded_root.as_ref());

                if root_path.exists() && root_path.is_dir() {
                    accessible_count += 1;
                } else {
                    warnings.push(format!("Allowed root not accessible: {}", root_str));
                    println!("   ⚠️  Root not accessible: {}", root_str);
                }
            }
        }

        if accessible_count > 0 {
            println!("   ✅ {} allowed roots are accessible", accessible_count);
        }
    }

    // Check commands
    if let Some(commands) = policy.get("commands").and_then(|c| c.as_sequence()) {
        println!("   ℹ️  Checking {} commands...", commands.len());
        let mut valid_commands = 0;

        for cmd in commands.iter().take(3) {
            // Check first 3 commands
            if let Some(cmd_id) = cmd.get("id").and_then(|i| i.as_str()) {
                if let Some(exec) = cmd.get("exec").and_then(|e| e.as_str()) {
                    let exec_path = Path::new(exec);
                    if exec_path.exists() && is_executable(exec_path) {
                        valid_commands += 1;
                        println!("     ✅ Command '{}' executable found", cmd_id);
                    } else {
                        warnings.push(format!(
                            "Command '{}' executable not found: {}",
                            cmd_id, exec
                        ));
                        println!(
                            "     ⚠️  Command '{}' executable not found: {}",
                            cmd_id, exec
                        );
                    }
                }
            }
        }

        if valid_commands > 0 {
            println!("   ✅ {} commands have valid executables", valid_commands);
        }
    }

    Ok(())
}

/// Check Claude Desktop integration
async fn check_claude_desktop(issues: &mut Vec<String>, warnings: &mut Vec<String>) -> Result<()> {
    println!("🔍 Checking Claude Desktop integration...");

    let claude_config_path = match ClaudeDesktopConfig::config_path() {
        Ok(path) => path,
        Err(e) => {
            warnings.push(format!(
                "Cannot determine Claude Desktop config path: {}",
                e
            ));
            println!("   ⚠️  Cannot determine Claude Desktop config path: {}", e);
            return Ok(());
        }
    };

    if !claude_config_path.exists() {
        warnings
            .push("Claude Desktop config file not found - MCP server not configured".to_string());
        println!(
            "   ⚠️  Claude Desktop config not found: {}",
            claude_config_path.display()
        );
        println!("      Run 'mdmcpcfg install' to configure Claude Desktop integration");
        return Ok(());
    }

    println!(
        "   ✅ Claude Desktop config exists: {}",
        claude_config_path.display()
    );

    // Check if mdmcp is configured
    match ClaudeDesktopConfig::load_or_default() {
        Ok(config) => {
            if config.mcp_servers.contains_key("mdmcp") {
                println!("   ✅ mdmcp server is configured in Claude Desktop");

                // Validate the configuration
                if let Some(server_config) = config.mcp_servers.get("mdmcp") {
                    if let Some(command) = server_config.get("command").and_then(|c| c.as_str()) {
                        let binary_path = Path::new(command);
                        if binary_path.exists() && is_executable(binary_path) {
                            println!("   ✅ Configured binary is valid: {}", command);
                        } else {
                            issues.push(format!(
                                "Configured binary not found or not executable: {}",
                                command
                            ));
                            println!("   ❌ Configured binary not valid: {}", command);
                        }
                    }
                }
            } else {
                warnings.push("mdmcp server not configured in Claude Desktop".to_string());
                println!("   ⚠️  mdmcp server not configured in Claude Desktop");
                println!("      Run 'mdmcpcfg install' to add configuration");
            }
        }
        Err(e) => {
            issues.push(format!("Cannot parse Claude Desktop config: {}", e));
            println!("   ❌ Cannot parse Claude Desktop config: {}", e);
        }
    }

    Ok(())
}

/// Check system dependencies
async fn check_system_dependencies(
    _issues: &mut [String],
    warnings: &mut Vec<String>,
) -> Result<()> {
    println!("🔍 Checking system dependencies...");

    // Check if common system tools are available
    let tools = if cfg!(target_os = "windows") {
        vec![("cmd.exe", "Windows Command Prompt")]
    } else {
        vec![
            ("ls", "List files"),
            ("cat", "Display file contents"),
            ("git", "Git version control (optional)"),
        ]
    };

    let mut found_tools = 0;
    for (tool, description) in tools {
        if which::which(tool).is_ok() {
            println!("   ✅ {} available: {}", description, tool);
            found_tools += 1;
        } else {
            warnings.push(format!("System tool not found: {} ({})", tool, description));
            println!("   ⚠️  Tool not found: {} ({})", tool, description);
        }
    }

    if found_tools > 0 {
        println!("   ✅ Found {} system tools", found_tools);
    }

    Ok(())
}

/// Test server functionality
async fn test_server_functionality(
    issues: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Result<()> {
    println!("🔍 Testing server functionality...");

    let paths = Paths::new()?;
    let binary_path = paths.server_binary();

    if !binary_path.exists() {
        println!("   ⏭️  Skipping server test - binary not found");
        return Ok(());
    }

    if !paths.policy_file.exists() {
        println!("   ⏭️  Skipping server test - policy file not found");
        return Ok(());
    }

    // Test if server can start and show help
    println!("   ℹ️  Testing if server binary runs...");

    let output = Command::new(&binary_path)
        .arg("--help")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    match output {
        Ok(result) => {
            if result.status.success() {
                println!("   ✅ Server binary responds to --help");
            } else {
                let stderr = String::from_utf8_lossy(&result.stderr);
                warnings.push(format!("Server binary --help failed: {}", stderr.trim()));
                println!("   ⚠️  Server binary --help failed: {}", stderr.trim());
            }
        }
        Err(e) => {
            issues.push(format!("Cannot execute server binary: {}", e));
            println!("   âŒ Cannot execute server binary: {}", e);
            return Ok(());
        }
    }

    // TODO: Add more sophisticated testing like:
    // - Start server in background
    // - Send a simple JSON-RPC request
    // - Verify response
    // This would require implementing the full server first

    Ok(())
}
