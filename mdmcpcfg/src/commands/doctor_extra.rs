use crate::io::ClaudeDesktopConfig;
use anyhow::{Context, Result};
use std::process::{Command, Stdio};

pub fn print_summary_clean(issues: &[String], warnings: &[String]) {
    println!("\nDiagnostic Summary:");
    println!("==================");

    if !issues.is_empty() {
        println!("\nCritical Issues ({})", issues.len());
        for (i, issue) in issues.iter().enumerate() {
            println!("   {}. {}", i + 1, issue);
        }
    }

    if !warnings.is_empty() {
        println!("\nWarnings ({})", warnings.len());
        for (i, warning) in warnings.iter().enumerate() {
            println!("   {}. {}", i + 1, warning);
        }
    }

    if !issues.is_empty() || !warnings.is_empty() {
        println!("\nRecommended Actions:");
        if issues.iter().any(|i| i.contains("Binary not found")) {
            println!("   - Run 'mdmcpcfg install' to install the MCP server binary");
        }
        if issues.iter().any(|i| i.contains("Policy file not found")) {
            println!("   - Run 'mdmcpcfg install' to create a default policy file");
        }
        if warnings.iter().any(|w| w.contains("Claude Desktop")) {
            println!("   - Run 'mdmcpcfg install' to configure Claude Desktop integration");
        }
        if warnings.iter().any(|w| w.contains("not accessible")) {
            println!("   - Review allowed roots in policy file with 'mdmcpcfg policy show'");
            println!("   - Remove inaccessible paths or create missing directories");
        }
        if warnings.iter().any(|w| w.contains("executable not found")) {
            println!("   - Install missing system tools or update command paths in policy");
        }
    }
}

#[cfg(target_os = "windows")]
fn wsl_exec_capture(distro: Option<&str>, cmd: &str) -> Result<std::process::Output> {
    let mut args: Vec<String> = Vec::new();
    if let Some(d) = distro {
        if !d.trim().is_empty() {
            args.push("-d".into());
            args.push(d.to_string());
        }
    }
    args.push("--".into());
    args.push("bash".into());
    args.push("-lc".into());
    args.push(cmd.to_string());
    let out = Command::new("wsl.exe")
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run wsl.exe")?;
    Ok(out)
}

#[cfg(target_os = "windows")]
fn parse_wsl_target(cfg: &ClaudeDesktopConfig) -> Option<(Option<String>, String, String)> {
    let entry = cfg.mcp_servers.get("mdmcp")?;
    let cmd = entry.get("command")?.as_str()?;
    if cmd != "wsl.exe" {
        return None;
    }
    let args = entry.get("args")?.as_array()?;
    let mut distro: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if let Some(s) = args[i].as_str() {
            if s == "-d" && i + 1 < args.len() {
                distro = args[i + 1].as_str().map(|s| s.to_string());
                i += 2;
                continue;
            }
            let server = s.to_string();
            // expect --config <policy> next
            let mut policy = String::new();
            for j in (i + 1)..args.len() {
                if args[j].as_str() == Some("--config") && j + 1 < args.len() {
                    policy = args[j + 1].as_str().unwrap_or("").to_string();
                    break;
                }
            }
            if !policy.is_empty() {
                return Some((distro, server, policy));
            }
            return None;
        }
        i += 1;
    }
    None
}

#[cfg(target_os = "windows")]
#[allow(clippy::ptr_arg)]
pub async fn check_wsl_side(_warnings: &mut Vec<String>, issues: &mut Vec<String>) -> Result<()> {
    let cfg = ClaudeDesktopConfig::load_or_default()?;
    if let Some((distro, server, policy)) = parse_wsl_target(&cfg) {
        println!(
            "Checking WSL target (distro: {})...",
            distro.as_deref().unwrap_or("default")
        );
        // test -x server
        let cmd = format!("test -x '{}'", server.replace('\'', "'\\''"));
        let out = wsl_exec_capture(distro.as_deref(), &cmd)?;
        if out.status.success() {
            println!("   OK: Linux server exists and is executable: {}", server);
        } else {
            issues.push(format!(
                "Linux server missing or not executable: {}",
                server
            ));
            println!(
                "   ERROR: Linux server missing or not executable: {}",
                server
            );
        }
        // test -f policy
        let cmdp = format!("test -f '{}'", policy.replace('\'', "'\\''"));
        let outp = wsl_exec_capture(distro.as_deref(), &cmdp)?;
        if outp.status.success() {
            println!("   OK: Linux policy file exists: {}", policy);
        } else {
            issues.push(format!("Linux policy file not found: {}", policy));
            println!("   ERROR: Linux policy file not found: {}", policy);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
#[allow(clippy::ptr_arg)]
pub async fn check_wsl_side(_warnings: &mut Vec<String>, _issues: &mut Vec<String>) -> Result<()> {
    Ok(())
}
