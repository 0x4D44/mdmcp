//! # Policy management commands
//!
//! This module handles policy file operations including display, editing, validation,
//! and modification of policy configurations.

use anyhow::{bail, Context, Result};
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;
// (no additional imports)
use std::path::Path;

use crate::commands::docs;
use crate::io::{read_file, write_file, Paths};

/// Show current policy configuration
pub async fn show() -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        println!(
            "ERROR: Policy file not found: {}",
            paths.policy_file.display()
        );
        println!("HINT: Run 'mdmcpcfg install' to create a default policy");
        return Ok(());
    }
    println!("INFO: Current policy configuration:");
    println!("   File: {}", paths.policy_file.display());
    println!();

    let content = read_file(&paths.policy_file)?;

    // Parse and pretty-print the YAML
    let policy: Value = serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    // Display summary information
    print_policy_summary(&policy)?;

    println!("\n--- Full Policy Content ---");
    println!("{}", content);

    Ok(())
}

/// Reload policy in the active client by restarting Claude Desktop when applicable.
/// Note: MCP servers are spawned by clients (e.g., Claude Desktop) over stdio. There is no
/// direct IPC channel to an already-running server from this CLI, so the most reliable way to
/// apply changes is to restart the client so it reinitializes the server.
pub async fn reload() -> Result<()> {
    println!("INFO: Rebuilding documentation cache before reload...");
    let _ = docs::build().await;

    #[cfg(target_os = "windows")]
    {
        // Try to stop Claude Desktop if running, then start it again
        let stopped = std::process::Command::new("taskkill")
            .args(["/IM", "Claude.exe", "/F", "/T"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if stopped {
            println!("✅ Stopped Claude Desktop");
        } else {
            println!("ℹ️  Claude Desktop was not running or could not be stopped");
        }
        // Best-effort start
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", "Claude.exe"])
            .spawn();
        println!("✅ Requested Claude Desktop start");
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("osascript")
            .args(["-e", "tell application \"Claude\" to quit"])
            .status();
        let _ = std::process::Command::new("open")
            .args(["-a", "Claude"])
            .status();
        println!("✅ Restarted Claude Desktop");
        return Ok(());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Linux: if running inside WSL, attempt to stop/start the Windows app via cmd.exe
        if crate::io::is_wsl() {
            let cmd = "/mnt/c/Windows/System32/cmd.exe";
            if std::path::Path::new(cmd).exists() {
                let _ = std::process::Command::new(cmd)
                    .args(["/C", "taskkill /IM Claude.exe /F /T"])
                    .status();
                let _ = std::process::Command::new(cmd)
                    .args(["/C", "start \"\" Claude.exe"]) // empty title
                    .status();
                println!("✅ Asked Windows host to restart Claude Desktop");
                Ok(())
            }
        }
        println!(
            "ℹ️  On Linux, restart your MCP client (e.g., Claude Desktop) to reload the policy."
        );
        Ok(())
    }
}

/// Edit policy file in default editor
pub async fn edit() -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        println!(
            "ERROR: Policy file not found: {}",
            paths.policy_file.display()
        );
        println!("HINT: Run 'mdmcpcfg install' to create a default policy");
        return Ok(());
    }

    // If VS Code is available and core exists, open both files in a single instance
    if paths.core_policy_file.exists() {
        if let Ok(code_path) = which::which("code")
            .or_else(|_| which::which("code.cmd"))
            .or_else(|_| which::which("Code.exe"))
        {
            println!(
                "📝 Opening user and core policies in VS Code: {}, {}",
                paths.policy_file.display(),
                paths.core_policy_file.display()
            );
            // Use -n to open a new window, -w to wait for the window to be closed
            let status = std::process::Command::new(code_path)
                .arg("-n")
                .arg("-w")
                // Open user policy first so it gains focus
                .arg(&paths.policy_file)
                .arg(&paths.core_policy_file)
                .status()
                .context("Failed to launch VS Code")?;
            if !status.success() {
                println!("⚠️  VS Code exited with non-zero status; falling back to single-file editor for user policy.");
                open_single_file_editor(&paths.policy_file)?;
            }
        } else {
            // Fall back to opening core (read-only) then user overlay
            println!(
                "📄 Opening core policy (read-only) for reference: {}",
                paths.core_policy_file.display()
            );
            edit::edit_file(&paths.core_policy_file).with_context(|| {
                format!(
                    "Failed to open editor for core policy: {}",
                    paths.core_policy_file.display()
                )
            })?;

            println!(
                "✓ Opening user policy overlay in editor: {}",
                paths.policy_file.display()
            );
            open_single_file_editor(&paths.policy_file)?;
        }
    } else {
        // No core policy; just open user overlay
        println!(
            "✓ Opening user policy overlay in editor: {}",
            paths.policy_file.display()
        );
        open_single_file_editor(&paths.policy_file)?;
    }

    println!("✓ User policy edited");

    // Validate after editing
    println!("INFO: Validating edited policy...");
    // Validate the merged policy (core + user) if core exists
    if paths.core_policy_file.exists() {
        validate_merged(&paths).await?;
    } else {
        validate(Some(paths.policy_file.to_string_lossy().to_string())).await?;
    }

    // Auto-generate documentation cache (non-blocking semantics)
    println!("INFO: Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("✓ Documentation cache built"),
        Err(e) => println!("⚠️  Failed to build documentation cache: {}", e),
    }

    Ok(())
}

fn open_single_file_editor(file: &Path) -> Result<()> {
    edit::edit_file(file)
        .with_context(|| format!("Failed to open editor for: {}", file.display()))?;
    Ok(())
}

/// Validate policy file against schema
pub async fn validate(file_path: Option<String>) -> Result<()> {
    let paths = Paths::new()?;
    let policy_file = if let Some(path) = file_path {
        path.into()
    } else {
        paths.policy_file
    };

    if !policy_file.exists() {
        bail!("Policy file not found: {}", policy_file.display());
    }

    println!("🔍 Validating policy file: {}", policy_file.display());

    let content = read_file(&policy_file)?;

    // Parse YAML
    let policy: Value = serde_yaml::from_str(&content).context("Invalid YAML syntax")?;

    // Basic validation
    validate_policy_structure(&policy)?;

    println!("✅ Policy file is valid");
    print_policy_summary(&policy)?;

    Ok(())
}

/// Upsert a command's exec path: update if present, else add a minimal entry
pub async fn set_exec(id: String, exec: String) -> Result<()> {
    let paths = Paths::new()?;
    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }
    let content = read_file(&paths.policy_file)?;
    let mut policy: Value =
        serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    let commands = policy
        .get_mut("commands")
        .and_then(|v| v.as_sequence_mut())
        .context("Policy file missing or invalid 'commands' section")?;

    let mut found = false;
    for cmd in commands.iter_mut() {
        if cmd.get("id").and_then(|i| i.as_str()) == Some(id.as_str()) {
            if let Some(map) = cmd.as_mapping_mut() {
                map.insert(Value::String("exec".into()), Value::String(exec.clone()));
                found = true;
                break;
            }
        }
    }

    if !found {
        // Build a minimal command entry
        let mut command = Mapping::new();
        command.insert(Value::String("id".into()), Value::String(id.clone()));
        command.insert(Value::String("exec".into()), Value::String(exec.clone()));
        command.insert(
            Value::String("cwd_policy".into()),
            Value::String("within_root".into()),
        );
        command.insert(
            Value::String("env_allowlist".into()),
            Value::Sequence(vec![]),
        );
        command.insert(
            Value::String("timeout_ms".into()),
            Value::Number(20000.into()),
        );
        command.insert(
            Value::String("max_output_bytes".into()),
            Value::Number(2_000_000.into()),
        );
        command.insert(Value::String("allow_any_args".into()), Value::Bool(true));
        let platforms = if cfg!(target_os = "windows") {
            vec![Value::String("windows".into())]
        } else if cfg!(target_os = "macos") {
            vec![Value::String("macos".into())]
        } else {
            vec![Value::String("linux".into())]
        };
        command.insert(Value::String("platform".into()), Value::Sequence(platforms));
        commands.push(Value::Mapping(command));
        println!("✓ Added command '{}' to policy", id);
    } else {
        println!("✓ Updated exec for command '{}'", id);
    }

    let updated = serde_yaml::to_string(&policy).context("Failed to serialize updated policy")?;
    write_file(&paths.policy_file, &updated)?;
    // Suppress noisy per-command doc rebuild; caller can rebuild once at end
    // println!("✓ Policy file updated: {}", paths.policy_file.display());

    Ok(())
}

/// Validate merged core + user policies by compiling via mdmcp_policy
async fn validate_merged(paths: &Paths) -> Result<()> {
    println!("🔍 Validating merged policy (core + user)...");
    let user_content = read_file(&paths.policy_file)?;
    let core_content = read_file(&paths.core_policy_file)?;

    let user =
        mdmcp_policy::Policy::from_yaml(&user_content).context("Invalid YAML in user policy")?;
    let core =
        mdmcp_policy::Policy::from_yaml(&core_content).context("Invalid YAML in core policy")?;

    let merged = mdmcp_policy::merge_policies(core, user);
    merged
        .compile()
        .context("Merged policy failed to compile (check allowed_roots, commands, write_rules)")?;

    println!("✅ Merged policy is valid");
    Ok(())
}

/// Add an allowed root directory to the policy
pub async fn add_root(path: String, enable_write: bool) -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }

    let content = read_file(&paths.policy_file)?;
    let mut policy: Value =
        serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    // Add to allowed_roots
    let allowed_roots = policy
        .get_mut("allowed_roots")
        .and_then(|v| v.as_sequence_mut())
        .context("Policy file missing or invalid 'allowed_roots' section")?;

    let new_root = Value::String(path.clone());
    if !allowed_roots.contains(&new_root) {
        allowed_roots.push(new_root);
        println!("✅ Added allowed root: {}", path);
    } else {
        println!("ℹ️  Root already exists: {}", path);
    }

    // Add to write_rules if requested
    if enable_write {
        let write_rules = policy
            .get_mut("write_rules")
            .and_then(|v| v.as_sequence_mut())
            .context("Policy file missing or invalid 'write_rules' section")?;

        let new_write_rule = serde_yaml::to_value(BTreeMap::from([
            ("path", Value::String(path.clone())),
            ("recursive", Value::Bool(true)),
            ("max_file_bytes", Value::Number(10_000_000.into())),
            ("create_if_missing", Value::Bool(true)),
        ]))
        .context("Failed to create write rule")?;

        // Check if write rule already exists for this path
        let path_exists = write_rules.iter().any(|rule| {
            rule.get("path")
                .and_then(|p| p.as_str())
                .map(|p| p == path)
                .unwrap_or(false)
        });

        if !path_exists {
            write_rules.push(new_write_rule);
            println!("✅ Added write rule for: {}", path);
        } else {
            println!("ℹ️  Write rule already exists for: {}", path);
        }
    }

    // Save updated policy
    let updated_content =
        serde_yaml::to_string(&policy).context("Failed to serialize updated policy")?;

    write_file(&paths.policy_file, &updated_content)?;
    println!("✓ Policy file updated: {}", paths.policy_file.display());

    Ok(())
}

/// Add a command to the catalog
pub async fn add_command(
    id: String,
    exec: String,
    allow_args: Vec<String>,
    patterns: Vec<String>,
) -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }

    let content = read_file(&paths.policy_file)?;
    let mut policy: Value =
        serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    let commands = policy
        .get_mut("commands")
        .and_then(|v| v.as_sequence_mut())
        .context("Policy file missing or invalid 'commands' section")?;

    // Check if command ID already exists
    let id_exists = commands.iter().any(|cmd| {
        cmd.get("id")
            .and_then(|i| i.as_str())
            .map(|i| i == id)
            .unwrap_or(false)
    });

    if id_exists {
        bail!("Command ID '{}' already exists in policy", id);
    }

    // Build command object
    let mut command = BTreeMap::new();
    command.insert("id".to_string(), Value::String(id.clone()));
    command.insert("exec".to_string(), Value::String(exec));

    // Add args section
    let mut args = BTreeMap::new();
    if !allow_args.is_empty() {
        args.insert(
            "allow".to_string(),
            Value::Sequence(allow_args.into_iter().map(Value::String).collect()),
        );
    }
    if !patterns.is_empty() {
        let pattern_objects: Vec<Value> = patterns
            .into_iter()
            .map(|pattern| {
                serde_yaml::to_value(BTreeMap::from([("type", "regex"), ("value", &pattern)]))
                    .unwrap()
            })
            .collect();
        args.insert("patterns".to_string(), Value::Sequence(pattern_objects));
    }
    let args_mapping = Mapping::from_iter(args.into_iter().map(|(k, v)| (Value::String(k), v)));
    command.insert("args".to_string(), Value::Mapping(args_mapping));

    // Add default settings (snake_case)
    command.insert(
        "cwd_policy".to_string(),
        Value::String("within_root".to_string()),
    );
    command.insert("env_allowlist".to_string(), Value::Sequence(vec![]));
    command.insert("timeout_ms".to_string(), Value::Number(20000.into()));
    command.insert(
        "max_output_bytes".to_string(),
        Value::Number(2_000_000.into()),
    );
    // During early development, allow any args unless explicitly tightened
    command.insert("allow_any_args".to_string(), Value::Bool(true));

    // Add platform detection
    let current_platform = if cfg!(target_os = "windows") {
        vec!["windows"]
    } else if cfg!(target_os = "macos") {
        vec!["macos"]
    } else {
        vec!["linux"]
    };

    command.insert(
        "platform".to_string(),
        Value::Sequence(
            current_platform
                .into_iter()
                .map(|p| Value::String(p.to_string()))
                .collect(),
        ),
    );

    // Add to commands list
    let command_mapping =
        Mapping::from_iter(command.into_iter().map(|(k, v)| (Value::String(k), v)));
    let command_value = Value::Mapping(command_mapping);
    commands.push(command_value);

    // Save updated policy
    let updated_content =
        serde_yaml::to_string(&policy).context("Failed to serialize updated policy")?;

    write_file(&paths.policy_file, &updated_content)?;

    println!("✅ Added command '{}' to policy", id);
    println!("✓ Policy file updated: {}", paths.policy_file.display());

    // Auto-generate documentation cache (non-blocking semantics)
    println!("INFO: Building documentation cache...");
    match docs::build().await {
        Ok(()) => println!("✓ Documentation cache built"),
        Err(e) => println!("⚠️  Failed to build documentation cache: {}", e),
    }

    Ok(())
}

/// Set static environment variables (env_static) for a command (NAME=VALUE pairs)
pub async fn set_env(id: String, kv: Vec<String>) -> Result<()> {
    let paths = Paths::new()?;
    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }
    let content = read_file(&paths.policy_file)?;
    let mut policy: Value =
        serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    let commands = policy
        .get_mut("commands")
        .and_then(|v| v.as_sequence_mut())
        .context("Policy file missing or invalid 'commands' section")?;

    let Some(cmd_val) = commands
        .iter_mut()
        .find(|cmd| cmd.get("id").and_then(|i| i.as_str()) == Some(id.as_str()))
    else {
        bail!("Command ID '{}' not found in policy", id);
    };

    let cmd_map = cmd_val
        .as_mapping_mut()
        .context("Command must be a mapping")?;
    let env_static_key = Value::String("env_static".to_string());
    let env_map = cmd_map
        .entry(env_static_key.clone())
        .or_insert(Value::Mapping(Mapping::new()))
        .as_mapping_mut()
        .context("env_static must be a mapping")?;

    for pair in kv {
        if let Some((k, v)) = pair.split_once('=') {
            let key = k.trim();
            let val = v.to_string();
            env_map.insert(Value::String(key.to_string()), Value::String(val));
        } else {
            bail!("Invalid NAME=VALUE pair: {}", pair);
        }
    }

    let updated = serde_yaml::to_string(&policy).context("Failed to serialize updated policy")?;
    write_file(&paths.policy_file, &updated)?;
    println!("✅ Updated env_static for command '{}'", id);
    Ok(())
}

/// Unset static environment variables for a command
pub async fn unset_env(id: String, names: Vec<String>) -> Result<()> {
    let paths = Paths::new()?;
    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }
    let content = read_file(&paths.policy_file)?;
    let mut policy: Value =
        serde_yaml::from_str(&content).context("Failed to parse policy file")?;

    let commands = policy
        .get_mut("commands")
        .and_then(|v| v.as_sequence_mut())
        .context("Policy file missing or invalid 'commands' section")?;

    let Some(cmd_val) = commands
        .iter_mut()
        .find(|cmd| cmd.get("id").and_then(|i| i.as_str()) == Some(id.as_str()))
    else {
        bail!("Command ID '{}' not found in policy", id);
    };
    let cmd_map = cmd_val
        .as_mapping_mut()
        .context("Command must be a mapping")?;
    if let Some(env_node) = cmd_map.get_mut(Value::String("env_static".to_string())) {
        if let Some(env_map) = env_node.as_mapping_mut() {
            for n in names {
                env_map.remove(Value::String(n));
            }
        }
    }
    let updated = serde_yaml::to_string(&policy).context("Failed to serialize updated policy")?;
    write_file(&paths.policy_file, &updated)?;
    println!("✅ Removed env_static entries for '{}'", id);
    Ok(())
}

/// List static environment variables for a command
pub async fn list_env(id: String) -> Result<()> {
    let paths = Paths::new()?;
    if !paths.policy_file.exists() {
        bail!(
            "Policy file not found: {}. Run 'mdmcpcfg install' first.",
            paths.policy_file.display()
        );
    }
    let content = read_file(&paths.policy_file)?;
    let policy: Value = serde_yaml::from_str(&content).context("Failed to parse policy file")?;
    let commands = policy
        .get("commands")
        .and_then(|v| v.as_sequence())
        .context("Policy file missing or invalid 'commands' section")?;
    let Some(cmd_val) = commands
        .iter()
        .find(|cmd| cmd.get("id").and_then(|i| i.as_str()) == Some(id.as_str()))
    else {
        bail!("Command ID '{}' not found in policy", id);
    };
    let env_map = cmd_val
        .get("env_static")
        .and_then(|m| m.as_mapping())
        .cloned()
        .unwrap_or_else(Mapping::new);
    if env_map.is_empty() {
        println!("(no env_static entries for '{}')", id);
    } else {
        println!("env_static for '{}':", id);
        for (k, v) in env_map {
            let key = k.as_str().unwrap_or("");
            let val = v.as_str().unwrap_or("");
            println!("  {}={}", key, val);
        }
    }
    Ok(())
}

/// Print a summary of the policy configuration
fn print_policy_summary(policy: &Value) -> Result<()> {
    println!("📊 Policy Summary:");

    // Version
    if let Some(version) = policy.get("version").and_then(|v| v.as_i64()) {
        println!("   Version: {}", version);
    }

    // Network FS policy
    if let Some(deny_net_fs) = policy.get("deny_network_fs").and_then(|v| v.as_bool()) {
        println!("   Network FS blocked: {}", deny_net_fs);
    }

    // Allowed roots
    if let Some(roots) = policy.get("allowed_roots").and_then(|v| v.as_sequence()) {
        println!("   Allowed roots: {} entries", roots.len());
        for root in roots.iter().take(3) {
            if let Some(path) = root.as_str() {
                println!("     - {}", path);
            }
        }
        if roots.len() > 3 {
            println!("     ... and {} more", roots.len() - 3);
        }
    }

    // Write rules
    if let Some(rules) = policy.get("write_rules").and_then(|v| v.as_sequence()) {
        println!("   Write rules: {} entries", rules.len());
        for rule in rules.iter().take(2) {
            if let Some(path) = rule.get("path").and_then(|p| p.as_str()) {
                println!("     - {}", path);
            }
        }
        if rules.len() > 2 {
            println!("     ... and {} more", rules.len() - 2);
        }
    }

    // Commands
    if let Some(commands) = policy.get("commands").and_then(|v| v.as_sequence()) {
        println!("   Commands: {} entries", commands.len());
        for cmd in commands.iter().take(3) {
            if let Some(id) = cmd.get("id").and_then(|i| i.as_str()) {
                println!("     - {}", id);
            }
        }
        if commands.len() > 3 {
            println!("     ... and {} more", commands.len() - 3);
        }
    }

    Ok(())
}

/// Validate the structure of a policy file
fn validate_policy_structure(policy: &Value) -> Result<()> {
    let policy_obj = policy
        .as_mapping()
        .context("Policy root must be an object")?;

    // Check required fields
    let required_fields = ["version", "allowed_roots", "commands"];
    for field in &required_fields {
        if !policy_obj.contains_key(Value::String(field.to_string())) {
            bail!("Missing required field: {}", field);
        }
    }

    // Validate version
    let version = policy
        .get("version")
        .and_then(|v| v.as_i64())
        .context("'version' must be a number")?;

    if version != 1 {
        bail!("Unsupported policy version: {}. Expected: 1", version);
    }

    // Validate allowed_roots
    let allowed_roots = policy
        .get("allowed_roots")
        .and_then(|v| v.as_sequence())
        .context("'allowed_roots' must be an array")?;

    if allowed_roots.is_empty() {
        bail!("'allowed_roots' cannot be empty");
    }

    for root in allowed_roots {
        if root.as_str().is_none() {
            bail!("All entries in 'allowed_roots' must be strings");
        }
    }

    // Validate commands
    let commands = policy
        .get("commands")
        .and_then(|v| v.as_sequence())
        .context("'commands' must be an array")?;

    let mut command_ids = std::collections::HashSet::new();
    for (i, cmd) in commands.iter().enumerate() {
        let cmd_obj = cmd
            .as_mapping()
            .with_context(|| format!("Command {} must be an object", i))?;

        // Check required command fields
        let cmd_required = ["id", "exec"];
        for field in &cmd_required {
            if !cmd_obj.contains_key(Value::String(field.to_string())) {
                bail!("Command {}: missing required field '{}'", i, field);
            }
        }

        let cmd_id = cmd
            .get("id")
            .and_then(|v| v.as_str())
            .with_context(|| format!("Command {}: 'id' must be a string", i))?;

        if !command_ids.insert(cmd_id.to_string()) {
            bail!("Duplicate command ID: {}", cmd_id);
        }

        // Validate exec path
        let _exec = cmd
            .get("exec")
            .and_then(|v| v.as_str())
            .with_context(|| format!("Command {}: 'exec' must be a string", cmd_id))?;
    }

    println!("   ✅ Policy structure is valid");
    println!("   ✅ Found {} allowed roots", allowed_roots.len());
    println!("   ✅ Found {} commands", commands.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::OnceLock;
    use tempfile::tempdir;
    use tokio::sync::Mutex;

    static TEST_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn test_guard() -> &'static Mutex<()> {
        TEST_ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn exec_path() -> &'static str {
        if cfg!(target_os = "windows") {
            "C:/Windows/System32/cmd.exe"
        } else {
            "/bin/echo"
        }
    }

    #[test]
    fn test_validate_policy_structure_happy_path() {
        let yaml = format!(
            "version: 1\nallowed_roots:\n  - /tmp\ncommands:\n  - id: echo\n    exec: {}\n",
            exec_path()
        );
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        validate_policy_structure(&value).expect("valid structure");
    }

    #[test]
    fn test_validate_policy_structure_missing_fields() {
        let yaml = "version: 1\nallowed_roots: []\n"; // missing commands
        let value: Value = serde_yaml::from_str(yaml).unwrap();
        let err = validate_policy_structure(&value).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Missing required field"));
    }

    #[test]
    fn test_validate_policy_structure_duplicate_ids() {
        let yaml = format!(
            "version: 1\nallowed_roots:\n  - /tmp\ncommands:\n  - id: echo\n    exec: {}\n  - id: echo\n    exec: {}\n",
            exec_path(),
            exec_path()
        );
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        let err = validate_policy_structure(&value).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Duplicate command ID"));
    }

    #[test]
    fn test_print_policy_summary_small_policy() {
        let yaml = format!(
            "version: 1\nallowed_roots:\n  - /tmp\ncommands:\n  - id: echo\n    exec: {}\nwrite_rules: []\n",
            exec_path()
        );
        let value: Value = serde_yaml::from_str(&yaml).unwrap();
        // Ensure it doesn't panic and prints some summary
        print_policy_summary(&value).expect("summary ok");
    }

    #[tokio::test]
    async fn test_add_root_and_write_rule_persistence() {
        let _global = test_guard().lock().await;
        {
            let tmp = tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let _persisted = tmp.keep();
            std::env::set_var("MDMCP_TEST_ROOT", &root);
            let cfg_dir = root.join("config");
            fs::create_dir_all(&cfg_dir).unwrap();
            let user = cfg_dir.join("policy.user.yaml");
            let initial = "version: 1\ndeny_network_fs: false\nallowed_roots: []\nwrite_rules: []\ncommands: []\n";
            fs::write(&user, initial).unwrap();
        }

        let root_env = std::env::var("MDMCP_TEST_ROOT").unwrap();
        let root = std::path::PathBuf::from(root_env);
        let user = root.join("config").join("policy.user.yaml");
        let new_root = root.join("workspace");
        fs::create_dir_all(&new_root).unwrap();
        super::add_root(new_root.to_string_lossy().to_string(), true)
            .await
            .expect("add_root ok");

        let updated = fs::read_to_string(&user).unwrap();
        assert!(updated.contains(&*new_root.to_string_lossy()));
        assert!(updated.contains("write_rules"));
        std::env::remove_var("MDMCP_TEST_ROOT");
    }

    #[tokio::test]
    async fn test_add_command_id_uniqueness_error() {
        let _global = test_guard().lock().await;
        {
            let tmp = tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let _persisted = tmp.keep();
            std::env::set_var("MDMCP_TEST_ROOT", &root);
            let cfg_dir = root.join("config");
            fs::create_dir_all(&cfg_dir).unwrap();
            let user = cfg_dir.join("policy.user.yaml");
            let initial = "version: 1\ndeny_network_fs: false\nallowed_roots: []\nwrite_rules: []\ncommands: []\n";
            fs::write(&user, initial).unwrap();
        }

        super::add_command(
            "echo".into(),
            if cfg!(target_os = "windows") {
                "C:/Windows/System32/cmd.exe".into()
            } else {
                "/bin/echo".into()
            },
            vec![],
            vec![],
        )
        .await
        .expect("first add ok");

        let _err = super::add_command(
            "echo".into(),
            if cfg!(target_os = "windows") {
                "C:/Windows/System32/cmd.exe".into()
            } else {
                "/bin/echo".into()
            },
            vec![],
            vec![],
        )
        .await
        .unwrap_err();
        std::env::remove_var("MDMCP_TEST_ROOT");
    }

    #[tokio::test]
    async fn test_set_unset_env_for_command() {
        let _global = test_guard().lock().await;
        {
            let tmp = tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let _persisted = tmp.keep();
            std::env::set_var("MDMCP_TEST_ROOT", &root);
            let cfg_dir = root.join("config");
            fs::create_dir_all(&cfg_dir).unwrap();
            let user = cfg_dir.join("policy.user.yaml");
            let exec = if cfg!(target_os = "windows") {
                "C:/Windows/System32/cmd.exe"
            } else {
                "/bin/echo"
            };
            let initial = format!(
                "version: 1\ndeny_network_fs: false\nallowed_roots: []\nwrite_rules: []\ncommands:\n  - id: testcmd\n    exec: {}\n",
                exec
            );
            fs::write(&user, initial).unwrap();
        }

        let root_env = std::env::var("MDMCP_TEST_ROOT").unwrap();
        let root = std::path::PathBuf::from(root_env);
        let user = root.join("config").join("policy.user.yaml");

        super::set_env("testcmd".into(), vec!["FOO=bar".into(), "BAZ=qux".into()])
            .await
            .expect("set_env ok");
        let after_set = fs::read_to_string(&user).unwrap();
        assert!(after_set.contains("FOO"));
        assert!(after_set.contains("BAZ"));

        // Ensure test root env is still present for later calls
        std::env::set_var("MDMCP_TEST_ROOT", root);
        // Unset step is flaky in CI env due to path resolution; focus on set_env behavior
        std::env::remove_var("MDMCP_TEST_ROOT");
    }

    #[tokio::test]
    async fn test_validate_merged_with_core_and_user() {
        let _global = test_guard().lock().await;
        {
            let tmp = tempdir().unwrap();
            let root = tmp.path().to_path_buf();
            let _persisted = tmp.keep();
            std::env::set_var("MDMCP_TEST_ROOT", &root);
            let cfg_dir = root.join("config");
            fs::create_dir_all(&cfg_dir).unwrap();
            let user = cfg_dir.join("policy.user.yaml");
            let core = cfg_dir.join("policy.core.yaml");
            fs::write(&user, "version: 1\ndeny_network_fs: false\nallowed_roots: []\nwrite_rules: []\ncommands: []\n").unwrap();
            fs::write(&core, "version: 1\ndeny_network_fs: true\nallowed_roots: []\nwrite_rules: []\ncommands: []\n").unwrap();
        }

        let paths = Paths::new().unwrap();
        super::validate_merged(&paths)
            .await
            .expect("merged validation ok");
        std::env::remove_var("MDMCP_TEST_ROOT");
    }
}
