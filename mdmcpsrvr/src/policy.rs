//! # Policy Management and Utilities
//!
//! Provides policy loading, validation, and management utilities for the MCP server.
//! This module acts as a bridge between the raw policy configuration and the
//! server's runtime policy enforcement mechanisms.

use anyhow::{Context, Result};
use mdmcp_policy::{CompiledPolicy, Policy};
use std::path::Path;
use tracing::{debug, info, warn};

/// Load and compile policy from file path
#[allow(dead_code)]
pub async fn load_policy_from_file<P: AsRef<Path>>(path: P) -> Result<CompiledPolicy> {
    let path = path.as_ref();
    info!("Loading policy from: {}", path.display());

    // Load policy from file
    let policy = tokio::task::spawn_blocking({
        let path = path.to_owned();
        move || Policy::load(path)
    })
    .await
    .context("Failed to spawn policy loading task")?
    .context("Failed to load policy file")?;

    // Compile policy
    let compiled = tokio::task::spawn_blocking(move || policy.compile())
        .await
        .context("Failed to spawn policy compilation task")?
        .context("Failed to compile policy")?;

    debug!(
        "Policy compiled successfully: {} allowed roots, {} commands, {} write rules",
        compiled.allowed_roots_canonical.len(),
        compiled.commands_by_id.len(),
        compiled.write_rules_canonical.len()
    );

    // Validate policy configuration
    validate_policy_configuration(&compiled).await?;

    Ok(compiled)
}

/// Validate policy configuration for common issues
#[allow(dead_code)]
async fn validate_policy_configuration(policy: &CompiledPolicy) -> Result<()> {
    let mut warnings = Vec::<String>::new();

    // Check for empty allowed roots
    if policy.allowed_roots_canonical.is_empty() {
        return Err(anyhow::anyhow!(
            "Policy must define at least one allowed root"
        ));
    }

    // Check for overly permissive settings
    if policy.policy.network_fs_policy == mdmcp_policy::NetworkFsPolicy::AllowAll {
        warnings.push(
            "Network filesystem access is fully enabled (allow_all) - consider security implications".to_string(),
        );
    }

    // Check for commands without platform restrictions
    let unrestricted_commands: Vec<_> = policy
        .commands_by_id
        .values()
        .filter(|cmd| cmd.rule.platform.is_empty())
        .map(|cmd| &cmd.rule.id)
        .collect();

    if !unrestricted_commands.is_empty() {
        warnings.push(format!(
            "Commands without platform restrictions: {:?}",
            unrestricted_commands
        ));
    }

    // Check for excessively high limits
    if policy.policy.limits.max_read_bytes > 100 * 1024 * 1024 {
        warnings.push("Maximum read bytes is very high (>100MB)".to_string());
    }

    if policy.policy.limits.max_cmd_concurrency > 10 {
        warnings.push("Maximum command concurrency is very high (>10)".to_string());
    }

    // Check for dangerous command patterns
    let potentially_dangerous: Vec<_> = policy
        .commands_by_id
        .keys()
        .filter(|id| is_potentially_dangerous_command(id))
        .collect();

    if !potentially_dangerous.is_empty() {
        warnings.push(format!(
            "Potentially dangerous commands enabled: {:?}",
            potentially_dangerous
        ));
    }

    // Log warnings
    for warning in warnings {
        warn!("Policy validation warning: {}", warning);
    }

    Ok(())
}

/// Check if a command ID represents a potentially dangerous command
#[allow(dead_code)]
fn is_potentially_dangerous_command(command_id: &str) -> bool {
    let dangerous_patterns = [
        "rm",
        "del",
        "rmdir", // File deletion
        "chmod",
        "chown",
        "icacls", // Permission changes
        "sudo",
        "su",
        "runas", // Privilege escalation
        "curl",
        "wget",
        "powershell", // Network/script execution
        "bash",
        "sh",
        "cmd", // Shell access
        "python",
        "node",
        "ruby", // Script interpreters
    ];

    dangerous_patterns
        .iter()
        .any(|&pattern| command_id.contains(pattern))
}

/// Get policy summary for logging/debugging
#[allow(dead_code)]
pub fn get_policy_summary(policy: &CompiledPolicy) -> PolicySummary {
    let command_count_by_platform =
        policy
            .commands_by_id
            .values()
            .fold(std::collections::HashMap::new(), |mut acc, cmd| {
                if cmd.rule.platform.is_empty() {
                    *acc.entry("any".to_string()).or_insert(0) += 1;
                } else {
                    for platform in &cmd.rule.platform {
                        *acc.entry(platform.clone()).or_insert(0) += 1;
                    }
                }
                acc
            });

    PolicySummary {
        version: policy.policy.version,
        policy_hash: policy.policy_hash.clone(),
        allowed_roots_count: policy.allowed_roots_canonical.len(),
        write_rules_count: policy.write_rules_canonical.len(),
        total_commands: policy.commands_by_id.len(),
        command_count_by_platform,
        network_fs_policy: policy.policy.network_fs_policy,
        max_read_bytes: policy.policy.limits.max_read_bytes,
        max_cmd_concurrency: policy.policy.limits.max_cmd_concurrency,
    }
}

/// Policy summary for logging and monitoring
#[derive(Debug)]
#[allow(dead_code)]
pub struct PolicySummary {
    pub version: u32,
    pub policy_hash: String,
    pub allowed_roots_count: usize,
    pub write_rules_count: usize,
    pub total_commands: usize,
    pub command_count_by_platform: std::collections::HashMap<String, usize>,
    pub network_fs_policy: mdmcp_policy::NetworkFsPolicy,
    pub max_read_bytes: u64,
    pub max_cmd_concurrency: u32,
}

impl std::fmt::Display for PolicySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Policy v{} (hash: {}): {} roots, {} write rules, {} commands, network_fs: {:?}, limits: {}MB/{}conc",
            self.version,
            &self.policy_hash[..8],
            self.allowed_roots_count,
            self.write_rules_count,
            self.total_commands,
            self.network_fs_policy,
            self.max_read_bytes / 1024 / 1024,
            self.max_cmd_concurrency
        )
    }
}

/// Check if policy allows a specific operation type
#[allow(dead_code)]
pub fn policy_allows_operation(policy: &CompiledPolicy, operation: PolicyOperation) -> bool {
    match operation {
        PolicyOperation::FileRead => !policy.allowed_roots_canonical.is_empty(),
        PolicyOperation::FileWrite => !policy.write_rules_canonical.is_empty(),
        PolicyOperation::CommandExecution => !policy.commands_by_id.is_empty(),
    }
}

/// Types of policy-controlled operations
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum PolicyOperation {
    FileRead,
    FileWrite,
    CommandExecution,
}

/// Expand path with environment variable substitution and tilde expansion
pub fn expand_policy_path(path: &str) -> Result<String> {
    let mut expanded = path.to_string();

    // Handle tilde expansion
    if expanded.starts_with('~') {
        if let Some(home) = dirs::home_dir() {
            expanded = expanded.replace('~', &home.to_string_lossy());
        }
    }

    // Handle environment variable expansion (basic ${VAR} syntax)
    while let Some(start) = expanded.find("${") {
        if let Some(end) = expanded[start..].find('}') {
            let var_name = &expanded[start + 2..start + end];
            if let Ok(var_value) = std::env::var(var_name) {
                expanded.replace_range(start..start + end + 1, &var_value);
            } else {
                warn!("Environment variable not found: {}", var_name);
                break; // Avoid infinite loop
            }
        } else {
            break; // Malformed variable syntax
        }
    }

    Ok(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdmcp_policy::{
        ArgsPolicy, CommandRule, LimitsConfig, LoggingConfig, NetworkFsPolicy, WriteRule,
    };
    use tempfile::{tempdir, NamedTempFile};

    #[tokio::test]
    async fn test_policy_loading() {
        // Create a temporary policy file
        let temp_file = NamedTempFile::new().unwrap();
        let tmp_root = tempdir().unwrap();
        let root_path = tmp_root.path().to_path_buf();
        let _persisted = tmp_root.keep();
        let out_path = root_path.join("output");
        std::fs::create_dir_all(&out_path).unwrap();
        let policy_content = format!(
            r#"version: 1
network_fs_policy: deny_all
allowed_roots:
  - '{}'
write_rules:
  - path: '{}'
    recursive: true
    max_file_bytes: 1000000
commands:
  - id: 'echo'
    exec: '/bin/echo'
    args:
      allow: ['hello']
    platform: ['linux']
"#,
            root_path.display(),
            out_path.display()
        );
        std::fs::write(temp_file.path(), policy_content).unwrap();

        // Load the policy
        let result = load_policy_from_file(temp_file.path()).await;
        assert!(result.is_ok());

        let policy = result.unwrap();
        assert_eq!(policy.policy.version, 1);
        assert_eq!(
            policy.policy.network_fs_policy,
            mdmcp_policy::NetworkFsPolicy::DenyAll
        );
        assert_eq!(
            policy.commands_by_id.len(),
            if cfg!(target_os = "linux") { 1 } else { 0 }
        );
    }

    #[test]
    fn test_dangerous_command_detection() {
        assert!(is_potentially_dangerous_command("rm"));
        assert!(is_potentially_dangerous_command("sudo"));
        assert!(is_potentially_dangerous_command("curl"));
        assert!(is_potentially_dangerous_command("powershell"));
        assert!(!is_potentially_dangerous_command("echo"));
        assert!(!is_potentially_dangerous_command("ls"));
    }

    #[test]
    fn test_policy_summary() {
        let temp_dir = tempdir().unwrap();
        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![temp_dir.path().to_string_lossy().to_string()],
            write_rules: vec![WriteRule {
                path: temp_dir.path().to_string_lossy().to_string(),
                recursive: true,
                max_file_bytes: 1000000,
                create_if_missing: true,
            }],
            commands: vec![CommandRule {
                id: "test".to_string(),
                exec: "/bin/test".to_string(),
                description: None,
                env_static: std::collections::HashMap::new(),
                args: ArgsPolicy::default(),
                cwd_policy: mdmcp_policy::CwdPolicy::WithinRoot,
                env_allowlist: vec![],
                timeout_ms: 5000,
                max_output_bytes: 1000000,
                platform: vec!["linux".to_string()],
                allow_any_args: false,
                help_capture: Default::default(),
            }],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled = policy.compile().unwrap();
        let summary = get_policy_summary(&compiled);

        assert_eq!(summary.version, 1);
        assert_eq!(summary.allowed_roots_count, 1);
        assert_eq!(summary.write_rules_count, 1);
        assert_eq!(summary.network_fs_policy, NetworkFsPolicy::DenyAll);

        let summary_str = summary.to_string();
        assert!(summary_str.contains("Policy v1"));
        assert!(summary_str.contains("network_fs: DenyAll"));
    }

    #[test]
    fn test_policy_operation_checks() {
        let temp_dir = tempdir().unwrap();
        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::AllowAll,
            allowed_roots: vec![temp_dir.path().to_string_lossy().to_string()],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled = policy.compile().unwrap();

        assert!(policy_allows_operation(
            &compiled,
            PolicyOperation::FileRead
        ));
        assert!(!policy_allows_operation(
            &compiled,
            PolicyOperation::FileWrite
        ));
        assert!(!policy_allows_operation(
            &compiled,
            PolicyOperation::CommandExecution
        ));
    }

    #[test]
    fn test_path_expansion() {
        // Test tilde expansion (if HOME is set)
        if dirs::home_dir().is_some() {
            let expanded = expand_policy_path("~/test").unwrap();
            assert!(!expanded.starts_with('~'));
            assert!(expanded.ends_with("test"));
        }

        // Test environment variable expansion
        std::env::set_var("TEST_VAR", "test_value");
        let expanded = expand_policy_path("/path/${TEST_VAR}/file").unwrap();
        assert_eq!(expanded, "/path/test_value/file");

        // Test no expansion needed
        let expanded = expand_policy_path("/absolute/path").unwrap();
        assert_eq!(expanded, "/absolute/path");
    }
}
