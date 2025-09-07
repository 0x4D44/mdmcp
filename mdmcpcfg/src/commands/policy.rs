//! # Policy management commands
//!
//! This module handles policy file operations including display, editing, validation,
//! and modification of policy configurations.

use anyhow::{bail, Context, Result};
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;

use crate::io::{read_file, write_file, Paths};

/// Show current policy configuration
pub async fn show() -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        println!("❌ Policy file not found: {}", paths.policy_file.display());
        println!("💡 Run 'mdmcpcfg install' to create a default policy");
        return Ok(());
    }

    println!("📋 Current policy configuration:");
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

/// Edit policy file in default editor
pub async fn edit() -> Result<()> {
    let paths = Paths::new()?;

    if !paths.policy_file.exists() {
        println!("❌ Policy file not found: {}", paths.policy_file.display());
        println!("💡 Run 'mdmcpcfg install' to create a default policy");
        return Ok(());
    }

    println!(
        "✏️  Opening policy file in editor: {}",
        paths.policy_file.display()
    );

    // Use the edit crate to open in default editor
    edit::edit_file(&paths.policy_file)
        .with_context(|| format!("Failed to open editor for: {}", paths.policy_file.display()))?;

    println!("✅ Policy file edited");

    // Validate after editing
    println!("🔍 Validating edited policy...");
    validate(Some(paths.policy_file.to_string_lossy().to_string())).await?;

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
    println!("💾 Policy file updated: {}", paths.policy_file.display());

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
    println!("💾 Policy file updated: {}", paths.policy_file.display());

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
