//! # Audit Logging System
//!
//! Provides comprehensive audit logging for all MCP server operations.
//! Logs are written in JSONL format with content hashing for security
//! and compliance monitoring. Sensitive data is redacted according to policy.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error};

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Failed to create audit log directory: {0}")]
    DirectoryCreation(String),
    #[error("Failed to write audit log: {0}")]
    WriteError(#[from] std::io::Error),
    #[error("Failed to serialize audit entry: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Audit log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    #[serde(rename = "reqId")]
    pub req_id: String,
    pub tool: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(rename = "timedOut", skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    #[serde(rename = "policyHash")]
    pub policy_hash: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// Audit operation context for tracking request details
#[derive(Debug, Clone)]
pub struct AuditContext {
    pub req_id: String,
    pub start_time: SystemTime,
    pub tool: String,
    pub policy_hash: String,
}

impl AuditContext {
    pub fn new(req_id: String, tool: String, policy_hash: String) -> Self {
        Self {
            req_id,
            start_time: SystemTime::now(),
            tool,
            policy_hash,
        }
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().unwrap_or_default().as_millis() as u64
    }
}

/// Audit logging configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuditConfig {
    pub log_file: Option<PathBuf>,
    pub redact_fields: Vec<String>,
    pub enabled: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_file: None,
            redact_fields: vec!["env".to_string()],
            enabled: true,
        }
    }
}

/// Thread-safe audit logger
pub struct Auditor {
    config: AuditConfig,
    writer: Arc<Mutex<Option<std::fs::File>>>,
}

impl Auditor {
    /// Create new auditor with configuration
    pub fn new(config: AuditConfig) -> Result<Self, AuditError> {
        let writer = if let Some(log_file) = &config.log_file {
            // Create directory if needed
            if let Some(parent) = log_file.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| AuditError::DirectoryCreation(e.to_string()))?;
            }

            // Open log file in append mode
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)?;

            Arc::new(Mutex::new(Some(file)))
        } else {
            Arc::new(Mutex::new(None))
        };

        Ok(Auditor { config, writer })
    }

    /// Log a successful operation
    pub fn log_success(&self, ctx: &AuditContext, details: SuccessDetails) {
        if !self.config.enabled {
            return;
        }

        let entry = AuditEntry {
            ts: format_timestamp(ctx.start_time),
            req_id: ctx.req_id.clone(),
            tool: ctx.tool.clone(),
            decision: "allow".to_string(),
            path: details.path,
            cwd: details.cwd,
            command: details.command,
            bytes: details.bytes,
            exit_code: details.exit_code,
            timed_out: details.timed_out,
            policy_hash: ctx.policy_hash.clone(),
            duration_ms: ctx.elapsed_ms(),
            error: None,
            content_hash: details.content_hash,
        };

        self.write_entry(&entry);
    }

    /// Log a denied operation
    pub fn log_denial(&self, ctx: &AuditContext, rule: &str, details: Option<DenialDetails>) {
        if !self.config.enabled {
            return;
        }

        let details = details.unwrap_or_default();

        let entry = AuditEntry {
            ts: format_timestamp(ctx.start_time),
            req_id: ctx.req_id.clone(),
            tool: ctx.tool.clone(),
            decision: "deny".to_string(),
            path: details.path,
            cwd: details.cwd,
            command: details.command,
            bytes: None,
            exit_code: None,
            timed_out: None,
            policy_hash: ctx.policy_hash.clone(),
            duration_ms: ctx.elapsed_ms(),
            error: Some(format!("Policy denied: {}", rule)),
            content_hash: None,
        };

        self.write_entry(&entry);
    }

    /// Log an error during operation
    pub fn log_error(&self, ctx: &AuditContext, error: &str, details: Option<ErrorDetails>) {
        if !self.config.enabled {
            return;
        }

        let details = details.unwrap_or_default();

        let entry = AuditEntry {
            ts: format_timestamp(ctx.start_time),
            req_id: ctx.req_id.clone(),
            tool: ctx.tool.clone(),
            decision: "error".to_string(),
            path: details.path,
            cwd: details.cwd,
            command: details.command,
            bytes: None,
            exit_code: details.exit_code,
            timed_out: details.timed_out,
            policy_hash: ctx.policy_hash.clone(),
            duration_ms: ctx.elapsed_ms(),
            error: Some(error.to_string()),
            content_hash: None,
        };

        self.write_entry(&entry);
    }

    /// Write audit entry to log file
    fn write_entry(&self, entry: &AuditEntry) {
        match serde_json::to_string(entry) {
            Ok(json) => {
                debug!("Audit: {}", json);

                if let Ok(mut writer_guard) = self.writer.lock() {
                    // Rotate if needed before writing
                    self.maybe_rotate(&mut writer_guard);
                    if let Some(ref mut writer) = *writer_guard {
                        if let Err(e) = writeln!(writer, "{}", json) {
                            error!("Failed to write audit log: {}", e);
                        } else if let Err(e) = writer.flush() {
                            error!("Failed to flush audit log: {}", e);
                        }
                    }
                } else {
                    error!("Failed to acquire audit log writer lock");
                }
            }
            Err(e) => {
                error!("Failed to serialize audit entry: {}", e);
            }
        }
    }

    fn maybe_rotate(&self, writer_guard: &mut Option<std::fs::File>) {
        const MAX_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
        let Some(ref log_path) = self.config.log_file else { return };
        let Some(ref mut writer) = writer_guard else { return };
        if let Ok(meta) = writer.metadata() {
            if meta.len() < MAX_BYTES { return; }
        }
        // Close current writer
        *writer_guard = None;
        // Rotate existing file to timestamped backup
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let backup = log_path.clone();
        let ext = backup
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("log");
        let stem = backup
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("audit");
        let rotated_name = format!("{}.{}.{}", stem, ts, ext);
        let rotated_path = backup.with_file_name(rotated_name);
        let _ = std::fs::rename(log_path, &rotated_path);
        // Reopen new file
        if let Ok(new_file) = OpenOptions::new().create(true).append(true).open(log_path) {
            *writer_guard = Some(new_file);
        }
    }
}

/// Details for successful operations
#[derive(Debug, Default)]
pub struct SuccessDetails {
    pub path: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub bytes: Option<u64>,
    pub exit_code: Option<i32>,
    pub timed_out: Option<bool>,
    pub content_hash: Option<String>,
}

/// Details for denied operations
#[derive(Debug, Default)]
pub struct DenialDetails {
    pub path: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
}

/// Details for error operations
#[derive(Debug, Default)]
pub struct ErrorDetails {
    pub path: Option<String>,
    pub cwd: Option<String>,
    pub command: Option<String>,
    pub exit_code: Option<i32>,
    pub timed_out: Option<bool>,
}

/// Format timestamp for audit logs
fn format_timestamp(time: SystemTime) -> String {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = duration.as_secs();
            let nanos = duration.subsec_nanos();
            // Format as RFC 3339 timestamp
            let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, nanos)
                .unwrap_or_default();
            datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
        }
        Err(_) => "1970-01-01T00:00:00.000Z".to_string(),
    }
}

/// Hash content for audit logging (replaces actual content)
#[allow(dead_code)]
pub fn hash_content(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Redact sensitive environment variables
#[allow(dead_code)]
pub fn redact_environment(
    env: &HashMap<String, String>,
    redact_fields: &[String],
) -> HashMap<String, String> {
    let mut redacted = HashMap::new();

    for (key, value) in env {
        if redact_fields.iter().any(|field| field == "env") {
            // Redact all environment variables
            redacted.insert(key.clone(), "***REDACTED***".to_string());
        } else if redact_fields.contains(key) {
            // Redact specific environment variable
            redacted.insert(key.clone(), "***REDACTED***".to_string());
        } else {
            redacted.insert(key.clone(), value.clone());
        }
    }

    redacted
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[test]
    fn test_auditor_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = AuditConfig {
            log_file: Some(temp_file.path().to_path_buf()),
            redact_fields: vec!["env".to_string()],
            enabled: true,
        };

        let auditor = Auditor::new(config).unwrap();
        // Auditor should be created successfully
        assert!(auditor.config.enabled);
    }

    #[test]
    fn test_audit_context() {
        let ctx = AuditContext::new(
            "test-123".to_string(),
            "fs.read".to_string(),
            "hash123".to_string(),
        );

        assert_eq!(ctx.req_id, "test-123");
        assert_eq!(ctx.tool, "fs.read");
        assert_eq!(ctx.policy_hash, "hash123");

        // Sleep briefly to test elapsed time
        std::thread::sleep(Duration::from_millis(10));
        assert!(ctx.elapsed_ms() >= 10);
    }

    #[test]
    fn test_audit_logging() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = AuditConfig {
            log_file: Some(temp_file.path().to_path_buf()),
            redact_fields: vec![],
            enabled: true,
        };

        let auditor = Auditor::new(config).unwrap();
        let ctx = AuditContext::new(
            "test-456".to_string(),
            "fs.write".to_string(),
            "hash456".to_string(),
        );

        let details = SuccessDetails {
            path: Some("/test/file.txt".to_string()),
            bytes: Some(42),
            content_hash: Some("abcd1234".to_string()),
            ..Default::default()
        };

        auditor.log_success(&ctx, details);

        // Verify log was written
        let log_content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(log_content.contains("test-456"));
        assert!(log_content.contains("fs.write"));
        assert!(log_content.contains("allow"));
        assert!(log_content.contains("/test/file.txt"));
    }

    #[test]
    fn test_timestamp_formatting() {
        let now = SystemTime::now();
        let formatted = format_timestamp(now);

        // Should be a valid RFC 3339 timestamp
        assert!(formatted.contains("T"));
        assert!(formatted.ends_with("Z"));
        assert!(formatted.len() >= 20); // Minimum length for timestamp
    }

    #[test]
    fn test_content_hashing() {
        let data = b"test content";
        let hash = hash_content(data);

        // Should be a valid hex string
        assert_eq!(hash.len(), 64); // SHA256 hex length
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_environment_redaction() {
        let mut env = HashMap::new();
        env.insert("PUBLIC_VAR".to_string(), "public_value".to_string());
        env.insert("SECRET_VAR".to_string(), "secret_value".to_string());
        env.insert("API_KEY".to_string(), "key123".to_string());

        let redact_fields = vec!["SECRET_VAR".to_string(), "API_KEY".to_string()];
        let redacted = redact_environment(&env, &redact_fields);

        assert_eq!(redacted.get("PUBLIC_VAR").unwrap(), "public_value");
        assert_eq!(redacted.get("SECRET_VAR").unwrap(), "***REDACTED***");
        assert_eq!(redacted.get("API_KEY").unwrap(), "***REDACTED***");
    }

    #[test]
    fn test_full_env_redaction() {
        let mut env = HashMap::new();
        env.insert("VAR1".to_string(), "value1".to_string());
        env.insert("VAR2".to_string(), "value2".to_string());

        let redact_fields = vec!["env".to_string()];
        let redacted = redact_environment(&env, &redact_fields);

        // All environment variables should be redacted
        for (_, value) in redacted {
            assert_eq!(value, "***REDACTED***");
        }
    }
}
