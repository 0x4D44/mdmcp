//! # mdmcp_policy
//!
//! Policy definition, validation, and enforcement for the mdmcp server.
//! This crate handles loading YAML policy files, validating their contents,
//! and providing runtime policy checks for file access and command execution.

use anyhow::{Context, Result};
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy file not found: {0}")]
    FileNotFound(String),
    #[error("Invalid YAML: {0}")]
    InvalidYaml(String),
    #[error("Invalid regex pattern in command {command}: {pattern}")]
    InvalidRegex { command: String, pattern: String },
    #[error("Duplicate command ID: {0}")]
    DuplicateCommand(String),
    #[error("Invalid path: {0}")]
    InvalidPath(String),
    #[error("Command not found: {0}")]
    CommandNotFound(String),
    #[error("Policy denied: {rule}")]
    PolicyDenied { rule: String },
}

/// Network filesystem access policy
///
/// Controls access to network filesystems and WSL UNC paths.
/// - `DenyAll`: Block all network/UNC paths (most secure, default)
/// - `AllowLocalWsl`: Allow local WSL paths (\\wsl$\, \\wsl.localhost\) but deny remote
/// - `AllowAll`: Allow all network paths (least secure)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFsPolicy {
    /// Deny all network/UNC paths (most secure, default)
    #[default]
    DenyAll,
    /// Allow local WSL paths (\\wsl$\, \\wsl.localhost\) but deny remote network shares
    AllowLocalWsl,
    /// Allow all network paths (least secure)
    AllowAll,
}

/// Root policy configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Policy {
    pub version: u32,
    /// Network filesystem access policy
    #[serde(default)]
    pub network_fs_policy: NetworkFsPolicy,
    pub allowed_roots: Vec<String>,
    #[serde(default)]
    pub write_rules: Vec<WriteRule>,
    #[serde(default)]
    pub commands: Vec<CommandRule>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Write permission rule for specific paths
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct WriteRule {
    pub path: String,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: u64,
    #[serde(default)]
    pub create_if_missing: bool,
}

/// Command execution rule
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct CommandRule {
    pub id: String,
    pub exec: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub env_static: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub args: ArgsPolicy,
    #[serde(default)]
    pub cwd_policy: CwdPolicy,
    #[serde(default)]
    pub env_allowlist: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_output_bytes")]
    pub max_output_bytes: u64,
    #[serde(default)]
    pub platform: Vec<String>,
    /// If true, skip argument validation (development-friendly default)
    #[serde(default = "default_allow_any_args")]
    pub allow_any_args: bool,
    /// Optional: configuration for capturing help text for documentation
    #[serde(default)]
    pub help_capture: HelpCaptureConfig,
}

/// Configuration controlling optional help capture for commands
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct HelpCaptureConfig {
    #[serde(default)]
    pub enabled: bool,
    /// The arguments to pass to the command to print help (e.g., ["--help"]).
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_help_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_help_max_bytes")]
    pub max_bytes: u64,
}

impl Default for HelpCaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            args: Vec::new(),
            timeout_ms: default_help_timeout_ms(),
            max_bytes: default_help_max_bytes(),
        }
    }
}

/// Argument validation policy for commands
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct ArgsPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub fixed: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<ArgPattern>,
}

/// Argument pattern for regex validation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArgPattern {
    #[serde(rename = "type")]
    pub pattern_type: String,
    pub value: String,
}

/// Working directory policy for commands
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum CwdPolicy {
    #[default]
    WithinRoot,
    Fixed,
    None,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    pub file: Option<String>,
    #[serde(default)]
    pub redact: Vec<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
            redact: vec!["env".to_string()],
        }
    }
}

/// Resource limits configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,
    #[serde(default = "default_max_cmd_concurrency")]
    pub max_cmd_concurrency: u32,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_cmd_concurrency: default_max_cmd_concurrency(),
        }
    }
}

/// Compiled policy for runtime use
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: Policy,
    pub allowed_roots_canonical: Vec<PathBuf>,
    pub write_rules_canonical: Vec<CompiledWriteRule>,
    pub commands_by_id: HashMap<String, CompiledCommand>,
    pub policy_hash: String,
}

/// Compiled write rule with canonical path
#[derive(Debug, Clone)]
pub struct CompiledWriteRule {
    pub path_canonical: PathBuf,
    pub recursive: bool,
    pub max_file_bytes: u64,
    pub create_if_missing: bool,
}

/// Compiled command with regex patterns
#[derive(Debug, Clone)]
pub struct CompiledCommand {
    pub rule: CommandRule,
    pub exec_canonical: PathBuf,
    pub arg_patterns: Vec<Regex>,
}

impl Policy {
    /// Load policy from YAML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|_| PolicyError::FileNotFound(path.display().to_string()))?;

        Self::from_yaml(&contents)
    }

    /// Parse policy from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        serde_yaml::from_str(yaml).map_err(|e| PolicyError::InvalidYaml(e.to_string()))
    }

    /// Compile policy for runtime use
    pub fn compile(self) -> Result<CompiledPolicy> {
        let mut allowed_roots_canonical = Vec::new();
        for root in &self.allowed_roots {
            let expanded = expand_path(root)?;
            let canonical = canonicalize_path(&expanded)?;
            allowed_roots_canonical.push(canonical);
        }

        let mut write_rules_canonical = Vec::new();
        for rule in &self.write_rules {
            let expanded = expand_path(&rule.path)?;
            let canonical = canonicalize_path_for_write_rule(&expanded, rule.create_if_missing)?;
            write_rules_canonical.push(CompiledWriteRule {
                path_canonical: canonical,
                recursive: rule.recursive,
                max_file_bytes: rule.max_file_bytes,
                create_if_missing: rule.create_if_missing,
            });
        }

        let mut commands_by_id = HashMap::new();
        for cmd in &self.commands {
            if commands_by_id.contains_key(&cmd.id) {
                return Err(PolicyError::DuplicateCommand(cmd.id.clone()).into());
            }

            // Check if command is supported on current platform
            if !cmd.platform.is_empty() && !is_platform_supported(&cmd.platform) {
                continue; // Skip commands not supported on this platform
            }

            let exec_path = Path::new(&cmd.exec);
            if !exec_path.is_absolute() {
                return Err(PolicyError::InvalidPath(format!(
                    "Executable must be an absolute path: {}",
                    cmd.exec
                ))
                .into());
            }
            let exec_canonical = canonicalize_path(exec_path)?;

            let mut arg_patterns = Vec::new();
            for pattern in &cmd.args.patterns {
                let regex = Regex::new(&pattern.value).map_err(|_| PolicyError::InvalidRegex {
                    command: cmd.id.clone(),
                    pattern: pattern.value.clone(),
                })?;
                arg_patterns.push(regex);
            }

            let compiled_cmd = CompiledCommand {
                rule: cmd.clone(),
                exec_canonical,
                arg_patterns,
            };
            commands_by_id.insert(cmd.id.clone(), compiled_cmd);
        }

        let policy_hash = compute_policy_hash(&self)?;

        Ok(CompiledPolicy {
            policy: self,
            allowed_roots_canonical,
            write_rules_canonical,
            commands_by_id,
            policy_hash,
        })
    }
}

/// Merge two policies into one, with `user` taking precedence over `core`.
/// Collections are combined with simple de-duplication by key where sensible.
pub fn merge_policies(core: Policy, user: Policy) -> Policy {
    // Version: keep core's version (schemas must match)
    let version = core.version;

    // network_fs_policy: user takes precedence over core defaults
    // Core policy sets secure default (DenyAll), user can relax to AllowLocalWsl or AllowAll
    let network_fs_policy = user.network_fs_policy;

    // allowed_roots: union (preserve order: core first, then user uniques)
    let mut allowed_roots = core.allowed_roots.clone();
    for r in user.allowed_roots {
        if !allowed_roots.contains(&r) {
            allowed_roots.push(r);
        }
    }

    // write_rules: de-dupe by path; user overrides rule for same path
    use std::collections::HashMap;
    let mut write_map: HashMap<String, WriteRule> = HashMap::new();
    for r in core.write_rules.into_iter() {
        write_map.insert(r.path.clone(), r);
    }
    for r in user.write_rules.into_iter() {
        write_map.insert(r.path.clone(), r); // user overwrites
    }
    let mut write_rules: Vec<WriteRule> = write_map.into_values().collect();
    write_rules.sort_by(|a, b| a.path.cmp(&b.path));

    // commands: map by id; user overrides
    let mut cmd_map: HashMap<String, CommandRule> = HashMap::new();
    for c in core.commands.into_iter() {
        cmd_map.insert(c.id.clone(), c);
    }
    for mut c in user.commands.into_iter() {
        // If user didn't set description, inherit from core
        if let Some(core_c) = cmd_map.get(&c.id) {
            if c.description.is_none() && core_c.description.is_some() {
                c.description = core_c.description.clone();
            }
            // Merge env_static with user taking precedence per key
            if !core_c.env_static.is_empty() {
                for (k, v) in core_c.env_static.iter() {
                    c.env_static.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        cmd_map.insert(c.id.clone(), c);
    }
    let mut commands: Vec<CommandRule> = cmd_map.into_values().collect();
    commands.sort_by(|a, b| a.id.cmp(&b.id));

    // logging: user overrides fields; redact list union
    let mut logging = core.logging.clone();
    // level
    logging.level = user.logging.level;
    // file: prefer user setting if provided, else keep core
    logging.file = user.logging.file.or(logging.file);
    // redact union
    for k in user.logging.redact {
        if !logging.redact.contains(&k) {
            logging.redact.push(k);
        }
    }

    // limits: prefer user overrides (simple replace)
    let limits = user.limits;

    Policy {
        version,
        network_fs_policy,
        allowed_roots,
        write_rules,
        commands,
        logging,
        limits,
    }
}

impl CompiledPolicy {
    /// Check if a path is within allowed roots
    pub fn is_path_allowed(&self, path: &Path) -> Result<bool> {
        let canonical = canonicalize_path(path)?;

        for allowed_root in &self.allowed_roots_canonical {
            if canonical.starts_with(allowed_root) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Find write rule for a path
    pub fn find_write_rule(&self, path: &Path) -> Result<Option<&CompiledWriteRule>> {
        let canonical = canonicalize_path(path)?;

        for rule in &self.write_rules_canonical {
            if rule.recursive {
                if canonical.starts_with(&rule.path_canonical) {
                    return Ok(Some(rule));
                }
            } else if canonical == rule.path_canonical {
                return Ok(Some(rule));
            }
        }

        Ok(None)
    }

    /// Get command by ID
    pub fn get_command(&self, id: &str) -> Result<&CompiledCommand, PolicyError> {
        self.commands_by_id
            .get(id)
            .ok_or_else(|| PolicyError::CommandNotFound(id.to_string()))
    }

    /// Validate command arguments
    pub fn validate_args(&self, cmd: &CompiledCommand, args: &[String]) -> Result<(), PolicyError> {
        // Allow all args if the command opts out of validation
        if cmd.rule.allow_any_args {
            return Ok(());
        }
        // Fixed args are handled during execution (prepended to user args)
        // Here we only validate the user-provided args against allow/patterns
        // Note: args parameter contains only user args, not fixed args

        // Check each argument
        for arg in args {
            let mut allowed = false;

            // 1) If the argument looks like an absolute path and is within allowed roots, allow it
            if is_absolute_path_like(arg) && is_within_allowed_roots_str(self, arg) {
                allowed = true;
            }

            // Check against allow list
            if cmd.rule.args.allow.contains(arg) {
                allowed = true;
            }

            // Check against regex patterns
            if !allowed {
                for pattern in &cmd.arg_patterns {
                    if pattern.is_match(arg) {
                        allowed = true;
                        break;
                    }
                }
            }

            if !allowed {
                return Err(PolicyError::PolicyDenied {
                    rule: format!("argNotAllowed:{}", arg),
                });
            }
        }

        Ok(())
    }
}

fn expand_path(path: &str) -> Result<PathBuf> {
    if path == "~" {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        return Ok(home);
    }
    if path.starts_with("~/") || (cfg!(windows) && path.starts_with("~\\")) {
        let home = dirs::home_dir().context("Failed to get home directory")?;
        let suffix = &path[2..];
        return Ok(home.join(suffix));
    }
    // Normalize WSL UNC paths on Windows (backslash -> forward slash for Rust compatibility)
    #[cfg(windows)]
    {
        let normalized = normalize_wsl_path(path);
        Ok(PathBuf::from(normalized))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from(path))
    }
}

/// Normalize WSL UNC paths from backslash to forward slash format.
/// Rust's std::path on Windows doesn't handle backslash WSL paths correctly -
/// Path::exists() returns false for `\\wsl.localhost\...` but true for `//wsl.localhost/...`.
#[cfg(windows)]
fn normalize_wsl_path(path: &str) -> String {
    let lower = path.to_lowercase();
    // Check for WSL UNC paths with backslashes
    if lower.starts_with("\\\\wsl$\\") || lower.starts_with("\\\\wsl.localhost\\") {
        // Convert backslashes to forward slashes for Rust compatibility
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

fn canonicalize_path(path: &Path) -> Result<PathBuf> {
    // Normalize WSL paths first (convert backslash to forward slash for Rust compatibility)
    let path = normalize_wsl_path_buf(path);
    dunce::canonicalize(&path)
        .with_context(|| format!("Failed to canonicalize path: {}", path.display()))
}

/// Normalize WSL UNC paths from backslash to forward slash format (Path version).
/// Rust's std::path on Windows doesn't handle backslash WSL paths correctly -
/// Path::exists() returns false for `\\wsl.localhost\...` but true for `//wsl.localhost/...`.
#[cfg(windows)]
fn normalize_wsl_path_buf(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    let lower = path_str.to_lowercase();
    // Check for WSL UNC paths with backslashes
    if lower.starts_with("\\\\wsl$\\") || lower.starts_with("\\\\wsl.localhost\\") {
        // Convert backslashes to forward slashes for Rust compatibility
        PathBuf::from(path_str.replace('\\', "/"))
    } else {
        path.to_path_buf()
    }
}

#[cfg(not(windows))]
fn normalize_wsl_path_buf(path: &Path) -> PathBuf {
    path.to_path_buf()
}

/// Canonicalize a path that may not yet exist (used for write rules).
/// If `create_if_missing` is true and the path doesn't exist, canonicalize the
/// nearest existing ancestor and rejoin the remaining components.
fn canonicalize_path_for_write_rule(path: &Path, create_if_missing: bool) -> Result<PathBuf> {
    // Normalize WSL paths first (convert backslash to forward slash for Rust compatibility)
    let path = normalize_wsl_path_buf(path);
    let path = path.as_path();

    if path.exists() {
        return canonicalize_path(path);
    }
    if !create_if_missing {
        // Fall back to standard behavior (will error with a clearer message)
        return canonicalize_path(path);
    }

    // Walk up to find an existing ancestor
    let mut components: Vec<PathBuf> = Vec::new();
    let mut cursor = path;
    loop {
        if cursor.exists() {
            break;
        }
        if let Some(parent) = cursor.parent() {
            if let Some(name) = cursor.file_name() {
                components.push(PathBuf::from(name));
            }
            cursor = parent;
        } else {
            // No existing ancestor; return a clearer error
            return Err(anyhow::anyhow!(
                "Failed to canonicalize path for write rule (no existing ancestor): {}",
                path.display()
            ));
        }
    }

    // Canonicalize the existing ancestor and rejoin the non-existent suffix
    let mut base = canonicalize_path(cursor)?;
    for part in components.iter().rev() {
        base.push(part);
    }
    Ok(base)
}

// Removed PATH search: executables must be absolute

fn is_platform_supported(platforms: &[String]) -> bool {
    let current_platform = if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return false;
    };

    platforms.iter().any(|p| p == current_platform)
}

fn compute_policy_hash(policy: &Policy) -> Result<String> {
    let json = serde_json::to_string(policy)?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

// Default value functions
fn default_max_file_bytes() -> u64 {
    10_000_000 // 10MB
}

fn default_timeout_ms() -> u64 {
    30_000 // 30 seconds
}

fn default_max_output_bytes() -> u64 {
    1_000_000 // 1MB
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_max_read_bytes() -> u64 {
    5_000_000 // 5MB
}

fn default_max_cmd_concurrency() -> u32 {
    2
}

fn default_help_timeout_ms() -> u64 {
    1_500
}

fn default_help_max_bytes() -> u64 {
    4_096
}

fn default_allow_any_args() -> bool {
    true
}

fn is_absolute_path_like(s: &str) -> bool {
    if cfg!(windows) {
        if s.starts_with("\\\\") {
            // UNC path
            return true;
        }
        let bytes = s.as_bytes();
        if bytes.len() >= 3
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
            && (bytes[0].is_ascii_alphabetic())
        {
            return true;
        }
        false
    } else {
        s.starts_with('/')
    }
}

fn normalize_for_windows_compare(s: &str) -> String {
    let mut out = s.replace('/', "\\").to_lowercase();
    // Remove trailing backslash except for root like "c:\\"
    if out.len() > 3 && out.ends_with('\\') {
        out.pop();
    }
    out
}

fn is_within_allowed_roots_str(policy: &CompiledPolicy, arg: &str) -> bool {
    // Try canonicalization first
    if let Ok(canon) = canonicalize_path(Path::new(arg)) {
        for allowed in &policy.allowed_roots_canonical {
            if canon.starts_with(allowed) {
                return true;
            }
        }
        return false;
    }

    // Fallback to string-based comparison (best-effort)
    if cfg!(windows) {
        let arg_norm = normalize_for_windows_compare(arg);
        for allowed in &policy.allowed_roots_canonical {
            let allowed_str = normalize_for_windows_compare(&allowed.to_string_lossy());
            if arg_norm == allowed_str {
                return true;
            }
            if arg_norm.starts_with(&allowed_str) {
                // Ensure boundary: next char must be separator
                if arg_norm.len() == allowed_str.len() {
                    return true;
                }
                let next = arg_norm.as_bytes().get(allowed_str.len());
                if matches!(next, Some(b'\\')) {
                    return true;
                }
            }
        }
        false
    } else {
        // Unix fallback
        for allowed in &policy.allowed_roots_canonical {
            let allowed_str = allowed.to_string_lossy();
            if arg == allowed_str {
                return true;
            }
            if arg.starts_with(&*allowed_str) {
                if arg.len() == allowed_str.len() {
                    return true;
                }
                if arg.as_bytes().get(allowed_str.len()) == Some(&b'/') {
                    return true;
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_policy_yaml_parsing() {
        let yaml = r#"
version: 1
network_fs_policy: deny_all
allowed_roots:
  - "~/test"
write_rules:
  - path: "~/test/output"
    recursive: true
    max_file_bytes: 1000000
commands:
  - id: "test"
    exec: "/bin/echo"
    args:
      allow: ["hello"]
    platform: ["linux", "macos"]
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.network_fs_policy, NetworkFsPolicy::DenyAll);
        assert_eq!(policy.allowed_roots.len(), 1);
        assert_eq!(policy.commands.len(), 1);
        assert_eq!(policy.commands[0].id, "test");
    }

    #[test]
    fn test_policy_yaml_parsing_ignores_unknown_fields() {
        // Old policies with deny_network_fs should parse without error (field is ignored)
        let yaml = r#"
version: 1
deny_network_fs: true
allowed_roots:
  - "~/test"
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, 1);
        // deny_network_fs is ignored, defaults to DenyAll
        assert_eq!(policy.network_fs_policy, NetworkFsPolicy::DenyAll);
    }

    #[test]
    fn test_policy_compilation() {
        let temp_dir = tempdir().unwrap();
        let test_root = temp_dir.path().to_str().unwrap();

        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![test_root.to_string()],
            write_rules: vec![WriteRule {
                path: test_root.to_string(),
                recursive: true,
                max_file_bytes: 1000000,
                create_if_missing: true,
            }],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled = policy.compile().unwrap();
        assert_eq!(compiled.allowed_roots_canonical.len(), 1);
        assert_eq!(compiled.write_rules_canonical.len(), 1);
    }

    #[test]
    fn test_path_validation() {
        let temp_dir = tempdir().unwrap();
        let test_root = temp_dir.path();

        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![test_root.to_str().unwrap().to_string()],
            write_rules: vec![],
            commands: vec![],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled = policy.compile().unwrap();

        // Create a test file within the allowed root
        let allowed_file = test_root.join("allowed.txt");
        std::fs::write(&allowed_file, "test").unwrap();
        assert!(compiled.is_path_allowed(&allowed_file).unwrap());

        // Test a file outside the allowed root (if possible)
        let temp_dir2 = tempdir().unwrap();
        let forbidden_file = temp_dir2.path().join("forbidden.txt");
        std::fs::write(&forbidden_file, "test").unwrap();
        assert!(!compiled.is_path_allowed(&forbidden_file).unwrap());
    }

    #[test]
    fn test_command_arg_validation() {
        let cmd = CompiledCommand {
            rule: CommandRule {
                id: "test".to_string(),
                exec: "/bin/echo".to_string(),
                description: None,
                env_static: std::collections::HashMap::new(),
                args: ArgsPolicy {
                    allow: vec!["hello".to_string(), "world".to_string()],
                    fixed: vec![],
                    patterns: vec![],
                },
                cwd_policy: CwdPolicy::WithinRoot,
                env_allowlist: vec![],
                timeout_ms: 30000,
                max_output_bytes: 1000000,
                platform: vec!["linux".to_string()],
                allow_any_args: false,
                help_capture: Default::default(),
            },
            exec_canonical: PathBuf::from("/bin/echo"),
            arg_patterns: vec![],
        };

        let policy = CompiledPolicy {
            policy: Policy {
                version: 1,
                network_fs_policy: NetworkFsPolicy::DenyAll,
                allowed_roots: vec![],
                write_rules: vec![],
                commands: vec![],
                logging: LoggingConfig::default(),
                limits: LimitsConfig::default(),
            },
            allowed_roots_canonical: vec![],
            write_rules_canonical: vec![],
            commands_by_id: HashMap::new(),
            policy_hash: "test".to_string(),
        };

        // Test allowed arguments
        assert!(policy.validate_args(&cmd, &["hello".to_string()]).is_ok());
        assert!(policy.validate_args(&cmd, &["world".to_string()]).is_ok());

        // Test disallowed argument
        assert!(policy
            .validate_args(&cmd, &["forbidden".to_string()])
            .is_err());
    }

    #[test]
    fn test_merge_policies() {
        let core = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec!["/core/root".to_string()],
            write_rules: vec![WriteRule {
                path: "/core/write".to_string(),
                recursive: false,
                max_file_bytes: 100,
                create_if_missing: false,
            }],
            commands: vec![CommandRule {
                id: "core-cmd".to_string(),
                exec: "/bin/core".to_string(),
                description: Some("core description".to_string()),
                env_static: HashMap::from([("KEY".to_string(), "CORE".to_string())]),
                ..CommandRule::default()
            }],
            logging: LoggingConfig {
                level: "info".to_string(),
                file: None,
                redact: vec!["password".to_string()],
            },
            limits: LimitsConfig {
                max_read_bytes: 100,
                max_cmd_concurrency: 1,
            },
        };

        let user = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::AllowLocalWsl,
            allowed_roots: vec!["/user/root".to_string(), "/core/root".to_string()],
            write_rules: vec![WriteRule {
                path: "/core/write".to_string(), // Overrides core
                recursive: true,
                max_file_bytes: 200,
                create_if_missing: true,
            }],
            commands: vec![CommandRule {
                id: "core-cmd".to_string(), // Overrides core
                exec: "/bin/user".to_string(),
                description: None, // Should inherit
                env_static: HashMap::from([("KEY".to_string(), "USER".to_string())]),
                ..CommandRule::default()
            }],
            logging: LoggingConfig {
                level: "debug".to_string(),
                file: Some("/log/file".to_string()),
                redact: vec!["token".to_string()],
            },
            limits: LimitsConfig {
                max_read_bytes: 200,
                max_cmd_concurrency: 2,
            },
        };

        let merged = merge_policies(core, user);

        assert_eq!(merged.network_fs_policy, NetworkFsPolicy::AllowLocalWsl);
        assert_eq!(merged.allowed_roots.len(), 2);
        assert!(merged.allowed_roots.contains(&"/core/root".to_string()));
        assert!(merged.allowed_roots.contains(&"/user/root".to_string()));

        assert_eq!(merged.write_rules.len(), 1);
        assert_eq!(merged.write_rules[0].max_file_bytes, 200); // User won

        assert_eq!(merged.commands.len(), 1);
        let cmd = &merged.commands[0];
        assert_eq!(cmd.exec, "/bin/user"); // User won
        assert_eq!(cmd.description, Some("core description".to_string())); // Inherited
        assert_eq!(cmd.env_static.get("KEY").unwrap(), "USER"); // User won

        assert_eq!(merged.logging.level, "debug");
        assert_eq!(merged.logging.file, Some("/log/file".to_string()));
        assert!(merged.logging.redact.contains(&"password".to_string()));
        assert!(merged.logging.redact.contains(&"token".to_string()));

        assert_eq!(merged.limits.max_read_bytes, 200);
    }

    #[test]
    fn test_compile_duplicate_command_id() {
        // We need a valid executable path for canonicalization to succeed
        let valid_exec = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![
                CommandRule {
                    id: "cmd1".to_string(),
                    exec: valid_exec.clone(),
                    ..CommandRule::default()
                },
                CommandRule {
                    id: "cmd1".to_string(),
                    exec: valid_exec.clone(),
                    ..CommandRule::default()
                },
            ],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let err = policy.compile().unwrap_err();
        assert!(matches!(
            err.downcast_ref::<PolicyError>(),
            Some(PolicyError::DuplicateCommand(_))
        ));
    }

    #[test]
    fn test_compile_invalid_regex() {
        let valid_exec = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![CommandRule {
                id: "cmd1".to_string(),
                exec: valid_exec,
                args: ArgsPolicy {
                    patterns: vec![ArgPattern {
                        pattern_type: "regex".to_string(),
                        value: "(".to_string(), // Invalid regex
                    }],
                    ..Default::default()
                },
                ..CommandRule::default()
            }],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let err = policy.compile().unwrap_err();
        assert!(matches!(
            err.downcast_ref::<PolicyError>(),
            Some(PolicyError::InvalidRegex { .. })
        ));
    }

    #[test]
    fn test_compile_platform_filtering() {
        // This test relies on knowing the current platform.
        let current_os = if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        };
        let other_os = if current_os == "windows" {
            "linux"
        } else {
            "windows"
        };
        let valid_exec = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let policy = Policy {
            version: 1,
            network_fs_policy: NetworkFsPolicy::DenyAll,
            allowed_roots: vec![],
            write_rules: vec![],
            commands: vec![
                CommandRule {
                    id: "current_os".to_string(),
                    exec: valid_exec.clone(),
                    platform: vec![current_os.to_string()],
                    ..CommandRule::default()
                },
                CommandRule {
                    id: "other_os".to_string(),
                    exec: "/bin/other".to_string(), // Path doesn't matter, shouldn't be validated because it's skipped
                    platform: vec![other_os.to_string()],
                    ..CommandRule::default()
                },
            ],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled = policy.compile().unwrap();
        assert!(compiled.commands_by_id.contains_key("current_os"));
        assert!(!compiled.commands_by_id.contains_key("other_os"));
    }

    impl Default for CommandRule {
        fn default() -> Self {
            Self {
                id: "".to_string(),
                exec: "".to_string(),
                description: None,
                env_static: HashMap::new(),
                args: ArgsPolicy::default(),
                cwd_policy: CwdPolicy::default(),
                env_allowlist: vec![],
                timeout_ms: default_timeout_ms(),
                max_output_bytes: default_max_output_bytes(),
                platform: vec![],
                allow_any_args: false,
                help_capture: HelpCaptureConfig::default(),
            }
        }
    }
}
