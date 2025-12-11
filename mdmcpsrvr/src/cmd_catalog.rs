//! # Command Catalog Management
//!
//! Handles validation and execution of approved commands according to policy rules.
//! This module manages the command catalog, validates arguments against allowlists
//! and regex patterns, and coordinates with the sandbox for secure execution.

use anyhow::Result;
use mdmcp_common::CmdRunParams;
use mdmcp_policy::{CompiledCommand, CompiledPolicy, CwdPolicy, PolicyError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::debug;

use crate::sandbox::{self, ExecutionConfig, ExecutionResult};

#[derive(Error, Debug)]
pub enum CatalogError {
    #[error("Command not found: {id}")]
    #[allow(dead_code)]
    CommandNotFound { id: String },
    #[error("Argument validation failed: {reason}")]
    ArgumentValidation { reason: String },
    #[error("Environment validation failed: {reason}")]
    EnvironmentValidation { reason: String },
    #[error("Working directory validation failed: {reason}")]
    WorkingDirectoryValidation { reason: String },
    #[error("Policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("Sandbox error: {0}")]
    Sandbox(#[from] sandbox::SandboxError),
}

/// Validated command execution request
#[derive(Debug)]
pub struct ValidatedCommand {
    pub command: CompiledCommand,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub stdin: String,
    pub timeout_ms: u64,
}

/// Command catalog manager
pub struct CommandCatalog {
    policy: CompiledPolicy,
}

impl CommandCatalog {
    /// Create new command catalog with compiled policy
    pub fn new(policy: CompiledPolicy) -> Self {
        Self { policy }
    }

    /// Validate and prepare command for execution
    pub fn validate_command(
        &self,
        params: &CmdRunParams,
    ) -> Result<ValidatedCommand, CatalogError> {
        debug!("Validating command: {}", params.command_id);

        // Get command from catalog
        let command = self.policy.get_command(&params.command_id)?;

        // Validate and filter environment
        let filtered_env = self
            .validate_environment(command, &params.env)
            .map_err(|e| CatalogError::EnvironmentValidation {
                reason: e.to_string(),
            })?;

        // Validate working directory first so we can resolve relative paths
        let validated_cwd = self
            .validate_working_directory(command, params.cwd.as_deref())
            .map_err(|e| CatalogError::WorkingDirectoryValidation {
                reason: e.to_string(),
            })?;

        // Enforce that any path-like arguments resolve within allowed roots
        self.enforce_path_scope(command, &params.args, validated_cwd.as_deref())
            .map_err(|e| CatalogError::ArgumentValidation { reason: e })?;

        // Validate arguments against allow/patterns
        self.validate_arguments(command, &params.args)
            .map_err(|e| CatalogError::ArgumentValidation {
                reason: e.to_string(),
            })?;

        // Use command timeout if not specified in request
        let timeout_ms = params.timeout_ms.unwrap_or(command.rule.timeout_ms);

        // Combine fixed args with user args for execution
        let mut final_args = command.rule.args.fixed.clone();
        final_args.extend(params.args.clone());

        Ok(ValidatedCommand {
            command: command.clone(),
            args: final_args,
            cwd: validated_cwd,
            env: filtered_env,
            stdin: params.stdin.clone(),
            timeout_ms,
        })
    }

    /// Execute validated command
    pub async fn execute_command(
        &self,
        validated: ValidatedCommand,
    ) -> Result<ExecutionResult, CatalogError> {
        debug!(
            "Executing command: {} with {} args",
            validated.command.rule.id,
            validated.args.len()
        );

        let config = ExecutionConfig {
            executable: validated.command.exec_canonical.clone(),
            args: validated.args,
            cwd: validated.cwd,
            env: validated.env,
            stdin: validated.stdin,
            timeout_ms: validated.timeout_ms,
            max_output_bytes: validated.command.rule.max_output_bytes,
        };

        let result = sandbox::execute_command(config).await?;

        debug!("Command completed with exit code: {}", result.exit_code);
        Ok(result)
    }

    /// Validate command arguments against policy
    fn validate_arguments(
        &self,
        cmd: &CompiledCommand,
        args: &[String],
    ) -> Result<(), PolicyError> {
        // Use the policy validation logic from CompiledPolicy
        self.policy.validate_args(cmd, args)
    }

    /// Validate and filter environment variables
    fn validate_environment(
        &self,
        cmd: &CompiledCommand,
        requested_env: &HashMap<String, String>,
    ) -> Result<HashMap<String, String>, CatalogError> {
        // Start with allowlisted variables (from request or process env)
        let mut filtered = sandbox::filter_environment(requested_env, &cmd.rule.env_allowlist);

        // Apply env_static from policy with precedence below request env.
        for (k, v) in cmd.rule.env_static.iter() {
            #[cfg(windows)]
            let requested_has_key = requested_env
                .iter()
                .any(|(rk, _)| rk.eq_ignore_ascii_case(k));
            #[cfg(not(windows))]
            let requested_has_key = requested_env.contains_key(k);
            if !requested_has_key {
                filtered.insert(k.clone(), v.clone());
            }
        }

        debug!(
            "Environment filtered: {} -> {} variables",
            requested_env.len(),
            filtered.len()
        );

        Ok(filtered)
    }

    /// Validate working directory according to policy
    fn validate_working_directory(
        &self,
        cmd: &CompiledCommand,
        requested_cwd: Option<&str>,
    ) -> Result<Option<PathBuf>, CatalogError> {
        let requested_path = requested_cwd.map(Path::new);

        let validated = sandbox::validate_cwd(
            requested_path,
            &cmd.rule.cwd_policy,
            &self.policy.allowed_roots_canonical,
            &cmd.exec_canonical,
        )?;

        if let Some(ref cwd) = validated {
            debug!("Working directory validated: {}", cwd.display());
        } else {
            debug!("No working directory set");
        }

        Ok(validated)
    }

    /// Enforce that path-like args (absolute or relative) stay within allowed roots
    fn enforce_path_scope(
        &self,
        cmd: &CompiledCommand,
        args: &[String],
        cwd: Option<&Path>,
    ) -> Result<(), String> {
        for arg in args {
            if is_flag_like(arg) {
                continue;
            }

            let candidate_abs: Option<PathBuf> = match as_absolute_path(arg) {
                Some(p) => Some(p),
                None => {
                    if looks_path_like(arg) {
                        if let Some(base) = cwd {
                            Some(base.join(arg))
                        } else {
                            return Err(format!(
                                "argument '{}' looks like a path but no working directory is set for command '{}'",
                                arg, cmd.rule.id
                            ));
                        }
                    } else {
                        None
                    }
                }
            };

            if let Some(p) = candidate_abs {
                let canonical = canonicalize_for_check(&p).map_err(|e| {
                    format!(
                        "failed to canonicalize path argument '{}' for command '{}': {}",
                        arg, cmd.rule.id, e
                    )
                })?;

                if !self
                    .policy
                    .allowed_roots_canonical
                    .iter()
                    .any(|root| canonical.starts_with(root))
                {
                    return Err(format!(
                        "path '{}' resolves to '{}' which is outside allowed roots",
                        arg,
                        canonical.display()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Get command information by ID
    #[allow(dead_code)]
    pub fn get_command_info(&self, command_id: &str) -> Option<&CompiledCommand> {
        self.policy.commands_by_id.get(command_id)
    }

    /// List all available commands
    #[allow(dead_code)]
    pub fn list_commands(&self) -> Vec<&str> {
        self.policy
            .commands_by_id
            .keys()
            .map(|s| s.as_str())
            .collect()
    }

    /// Get command statistics
    #[allow(dead_code)]
    pub fn get_stats(&self) -> CatalogStats {
        let mut platform_counts = HashMap::new();
        let mut cwd_policy_counts = HashMap::new();

        for cmd in self.policy.commands_by_id.values() {
            // Count by platform
            if cmd.rule.platform.is_empty() {
                *platform_counts.entry("any".to_string()).or_insert(0) += 1;
            } else {
                for platform in &cmd.rule.platform {
                    *platform_counts.entry(platform.clone()).or_insert(0) += 1;
                }
            }

            // Count by CWD policy
            let cwd_policy = match cmd.rule.cwd_policy {
                CwdPolicy::WithinRoot => "withinRoot",
                CwdPolicy::Fixed => "fixed",
                CwdPolicy::None => "none",
            };
            *cwd_policy_counts.entry(cwd_policy.to_string()).or_insert(0) += 1;
        }

        CatalogStats {
            total_commands: self.policy.commands_by_id.len(),
            platform_counts,
            cwd_policy_counts,
        }
    }
}

/// Heuristic: is this argument a flag (not a path)?
fn is_flag_like(s: &str) -> bool {
    if s.starts_with("--") || s.starts_with('-') {
        return true;
    }
    #[cfg(windows)]
    {
        if s.len() >= 2 && s.starts_with('/') && !s.starts_with("//") {
            return true;
        }
    }
    false
}

/// Return Some(absolute_path) if the string is an absolute path-like value
fn as_absolute_path(s: &str) -> Option<PathBuf> {
    let p = Path::new(s);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    #[cfg(windows)]
    {
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return Some(PathBuf::from(s));
        }
    }
    None
}

/// Heuristic for relative path-like strings (with separators or dot components)
fn looks_path_like(s: &str) -> bool {
    s.contains('/') || s.contains('\\') || s.starts_with('.')
}

/// Canonicalize for checking; if leaf is missing, canonicalize parent and rejoin
fn canonicalize_for_check(path: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(c) = dunce::canonicalize(path) {
        return Ok(c);
    }
    if let Some(parent) = path.parent() {
        let parent_canon = dunce::canonicalize(parent)?;
        if let Some(name) = path.file_name() {
            return Ok(parent_canon.join(name));
        }
    }
    anyhow::bail!("cannot canonicalize: {}", path.display())
}

/// Command catalog statistics
#[derive(Debug)]
#[allow(dead_code)]
pub struct CatalogStats {
    pub total_commands: usize,
    pub platform_counts: HashMap<String, usize>,
    pub cwd_policy_counts: HashMap<String, usize>,
}

/// Utility function to sanitize command arguments for logging
pub fn sanitize_args_for_logging(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|arg| {
            // Redact arguments that might contain sensitive data
            if arg.contains("password") || arg.contains("token") || arg.contains("key") {
                "***REDACTED***".to_string()
            } else if arg.len() > 100 {
                // Truncate very long arguments
                format!("{}...(truncated)", &arg[..100])
            } else {
                arg.clone()
            }
        })
        .collect()
}

/// Utility function to check if command is potentially dangerous
#[allow(dead_code)]
pub fn is_dangerous_command(command_id: &str, args: &[String]) -> bool {
    // Check for commands that could be used maliciously
    match command_id {
        "rm" | "del" | "rmdir" => {
            // Check for dangerous rm/del patterns
            args.iter()
                .any(|arg| arg.contains("-rf") || arg.contains("/r"))
        }
        "chmod" | "chown" | "icacls" => {
            // File permission changes could be dangerous
            true
        }
        "curl" | "wget" | "Invoke-WebRequest" => {
            // Network access could be dangerous
            args.iter().any(|arg| {
                arg.starts_with("http://")
                    || arg.starts_with("https://")
                    || arg.starts_with("ftp://")
            })
        }
        "sudo" | "su" | "runas" => {
            // Privilege escalation
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdmcp_policy::{ArgPattern, ArgsPolicy, CommandRule, LimitsConfig, LoggingConfig, Policy};
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn create_test_policy() -> CompiledPolicy {
        let temp_dir = tempdir().unwrap();
        let test_root = temp_dir.path().to_path_buf();

        let policy = Policy {
            version: 1,
            network_fs_policy: None,
            deny_network_fs: false,
            allowed_roots: vec![test_root.to_string_lossy().to_string()],
            write_rules: vec![],
            commands: vec![CommandRule {
                id: "echo".to_string(),
                exec: if cfg!(windows) {
                    "C:/Windows/System32/cmd.exe".to_string()
                } else {
                    "/bin/echo".to_string()
                },
                description: None,
                env_static: std::collections::HashMap::new(),
                args: ArgsPolicy {
                    allow: vec!["hello".to_string(), "world".to_string()],
                    fixed: vec![],
                    patterns: vec![ArgPattern {
                        pattern_type: "regex".to_string(),
                        value: r"^test\d+$".to_string(),
                    }],
                },
                cwd_policy: CwdPolicy::WithinRoot,
                env_allowlist: vec!["TEST_VAR".to_string()],
                timeout_ms: 5000,
                max_output_bytes: 1000,
                platform: vec![
                    "linux".to_string(),
                    "windows".to_string(),
                    "macos".to_string(),
                ],
                allow_any_args: false,
                help_capture: Default::default(),
            }],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        policy.compile().unwrap()
    }

    #[test]
    fn test_command_validation_success() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);

        let params = CmdRunParams {
            command_id: "echo".to_string(),
            args: vec!["hello".to_string()],
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: Some(3000),
        };

        let result = catalog.validate_command(&params);
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.command.rule.id, "echo");
        assert_eq!(validated.args, vec!["hello"]);
        assert_eq!(validated.timeout_ms, 3000);
    }

    #[test]
    fn test_command_validation_regex_pattern() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);

        let params = CmdRunParams {
            command_id: "echo".to_string(),
            args: vec!["test123".to_string()], // Should match regex pattern
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: None,
        };

        let result = catalog.validate_command(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_command_validation_failure() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);

        let params = CmdRunParams {
            command_id: "echo".to_string(),
            args: vec!["forbidden".to_string()], // Not in allow list or regex pattern
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: None,
        };

        let result = catalog.validate_command(&params);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(CatalogError::ArgumentValidation { .. })
        ));
    }

    #[test]
    fn test_unknown_command() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);

        let params = CmdRunParams {
            command_id: "unknown".to_string(),
            args: vec![],
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: None,
        };

        let result = catalog.validate_command(&params);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(CatalogError::Policy(PolicyError::CommandNotFound(_)))
        ));
    }

    #[test]
    fn test_environment_filtering() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);

        let mut env = HashMap::new();
        env.insert("TEST_VAR".to_string(), "allowed".to_string());
        env.insert("FORBIDDEN_VAR".to_string(), "not_allowed".to_string());

        let params = CmdRunParams {
            command_id: "echo".to_string(),
            args: vec!["hello".to_string()],
            cwd: None,
            stdin: String::new(),
            env,
            timeout_ms: None,
        };

        let validated = catalog.validate_command(&params).unwrap();

        // Should contain TEST_VAR and PATH (always included)
        assert!(validated.env.contains_key("TEST_VAR"));
        assert!(validated.env.contains_key("PATH"));

        // Should not contain FORBIDDEN_VAR
        assert!(!validated.env.contains_key("FORBIDDEN_VAR"));
    }

    #[test]
    fn test_sanitize_args_for_logging() {
        let args = vec![
            "normal_arg".to_string(),
            "password=secret123".to_string(),
            "x".repeat(150), // Long argument
            "safe_arg".to_string(),
        ];

        let sanitized = sanitize_args_for_logging(&args);

        assert_eq!(sanitized[0], "normal_arg");
        assert_eq!(sanitized[1], "***REDACTED***");
        assert!(sanitized[2].ends_with("...(truncated)"));
        assert_eq!(sanitized[3], "safe_arg");
    }

    #[test]
    fn test_dangerous_command_detection() {
        assert!(is_dangerous_command(
            "rm",
            &["-rf".to_string(), "/".to_string()]
        ));
        assert!(is_dangerous_command(
            "curl",
            &["https://evil.com".to_string()]
        ));
        assert!(is_dangerous_command("sudo", &["rm".to_string()]));
        assert!(!is_dangerous_command("echo", &["hello".to_string()]));
    }

    #[test]
    fn test_catalog_stats() {
        let policy = create_test_policy();
        let catalog = CommandCatalog::new(policy);
        let stats = catalog.get_stats();

        assert_eq!(stats.total_commands, 1);
        assert!(stats.cwd_policy_counts.contains_key("withinRoot"));
    }
}
