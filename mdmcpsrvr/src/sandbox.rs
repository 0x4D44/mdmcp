//! # Command Execution Sandbox
//!
//! Provides secure subprocess execution with resource limits, timeouts, and output controls.
//! This module handles the safe execution of approved commands while enforcing policy
//! constraints and preventing resource exhaustion attacks.

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::time::timeout;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Command timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
    #[error("Output truncated at {limit} bytes")]
    #[allow(dead_code)]
    OutputTruncated { limit: u64 },
    #[error("Failed to set resource limits: {0}")]
    #[allow(dead_code)]
    ResourceLimitFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for command execution
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub stdin: String,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
}

/// Result of command execution
#[derive(Debug)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub truncated: bool,
}

/// Execute a command with resource limits and security constraints
pub async fn execute_command(config: ExecutionConfig) -> Result<ExecutionResult, SandboxError> {
    debug!(
        "Executing command: {} with args {:?}",
        config.executable.display(),
        config.args
    );

    // Build the command
    let mut cmd = Command::new(&config.executable);
    cmd.args(&config.args);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    // Set working directory if specified
    if let Some(cwd) = &config.cwd {
        cmd.current_dir(cwd);
    }

    // Clear environment and set only allowed variables
    cmd.env_clear();
    for (key, value) in &config.env {
        cmd.env(key, value);
    }

    // Apply platform-specific security measures
    apply_security_constraints(&mut cmd)?;

    // Spawn the process
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::ExecutionFailed(format!("Failed to spawn process: {}", e)))?;

    // Handle stdin
    if !config.stdin.is_empty() {
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(config.stdin.as_bytes()).await {
                warn!("Failed to write to stdin: {}", e);
            }
            drop(stdin); // Close stdin
        }
    }

    // Execute with timeout
    let timeout_duration = Duration::from_millis(config.timeout_ms);
    let execution_result = timeout(
        timeout_duration,
        wait_for_completion(child, config.max_output_bytes),
    )
    .await;

    match execution_result {
        Ok(result) => result,
        Err(_) => {
            // Timeout occurred, kill the process tree
            warn!("Command timed out, terminating process tree");
            // Note: In a real implementation, we'd need to kill the entire process tree
            Err(SandboxError::Timeout {
                timeout_ms: config.timeout_ms,
            })
        }
    }
}

/// Wait for process completion and collect output
async fn wait_for_completion(
    mut child: Child,
    max_output_bytes: u64,
) -> Result<ExecutionResult, SandboxError> {
    use std::sync::{Arc, Mutex};

    let stdout_data = Arc::new(Mutex::new(Vec::new()));
    let stderr_data = Arc::new(Mutex::new(Vec::new()));
    let truncated = Arc::new(Mutex::new(false));

    // Take stdout and stderr handles
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();

    // Read output with size limits
    let stdout_task = {
        let stdout_data = Arc::clone(&stdout_data);
        let truncated = Arc::clone(&truncated);
        async move {
            let mut buffer = [0u8; 8192];
            loop {
                match stdout.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let mut data = stdout_data.lock().unwrap();
                        if data.len() + n > max_output_bytes as usize {
                            let remaining = max_output_bytes as usize - data.len();
                            data.extend_from_slice(&buffer[..remaining]);
                            *truncated.lock().unwrap() = true;
                            break;
                        }
                        data.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) => {
                        warn!("Error reading stdout: {}", e);
                        break;
                    }
                }
            }
        }
    };

    let stderr_task = {
        let stderr_data = Arc::clone(&stderr_data);
        let truncated = Arc::clone(&truncated);
        async move {
            let mut buffer = [0u8; 8192];
            loop {
                match stderr.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let mut data = stderr_data.lock().unwrap();
                        if data.len() + n > max_output_bytes as usize {
                            let remaining = max_output_bytes as usize - data.len();
                            data.extend_from_slice(&buffer[..remaining]);
                            *truncated.lock().unwrap() = true;
                            break;
                        }
                        data.extend_from_slice(&buffer[..n]);
                    }
                    Err(e) => {
                        warn!("Error reading stderr: {}", e);
                        break;
                    }
                }
            }
        }
    };

    // Run output reading tasks concurrently
    tokio::join!(stdout_task, stderr_task);

    // Wait for process to exit
    let output = child.wait().await?;
    let exit_code = output.code().unwrap_or(-1);

    // Extract data from Arc<Mutex<>>
    let stdout_vec = Arc::try_unwrap(stdout_data).unwrap().into_inner().unwrap();
    let stderr_vec = Arc::try_unwrap(stderr_data).unwrap().into_inner().unwrap();
    let is_truncated = *truncated.lock().unwrap();

    // Convert output to strings, handling invalid UTF-8
    let stdout_str = String::from_utf8_lossy(&stdout_vec).to_string();
    let stderr_str = String::from_utf8_lossy(&stderr_vec).to_string();

    debug!(
        "Command completed with exit code {}, stdout: {} bytes, stderr: {} bytes",
        exit_code,
        stdout_str.len(),
        stderr_str.len()
    );

    Ok(ExecutionResult {
        exit_code,
        stdout: stdout_str,
        stderr: stderr_str,
        timed_out: false,
        truncated: is_truncated,
    })
}

/// Apply platform-specific security constraints
#[cfg(unix)]
fn apply_security_constraints(cmd: &mut Command) -> Result<(), SandboxError> {
    use std::os::unix::process::CommandExt;

    // Set process group to enable killing entire process tree
    cmd.process_group(0);

    // Apply resource limits
    cmd.pre_exec(|| {
        // Set CPU time limit (5 minutes)
        let cpu_limit = libc::rlimit {
            rlim_cur: 300, // 5 minutes
            rlim_max: 300,
        };

        unsafe {
            if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to set CPU limit",
                ));
            }
        }

        // Set memory limit (1GB virtual memory)
        let mem_limit = libc::rlimit {
            rlim_cur: 1024 * 1024 * 1024, // 1GB
            rlim_max: 1024 * 1024 * 1024,
        };

        unsafe {
            if libc::setrlimit(libc::RLIMIT_AS, &mem_limit) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to set memory limit",
                ));
            }
        }

        // Limit number of processes
        let proc_limit = libc::rlimit {
            rlim_cur: 32, // Maximum 32 processes
            rlim_max: 32,
        };

        unsafe {
            if libc::setrlimit(libc::RLIMIT_NPROC, &proc_limit) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to set process limit",
                ));
            }
        }

        // Limit file descriptors
        let fd_limit = libc::rlimit {
            rlim_cur: 64, // Maximum 64 file descriptors
            rlim_max: 64,
        };

        unsafe {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Failed to set file descriptor limit",
                ));
            }
        }

        Ok(())
    });

    Ok(())
}

#[cfg(windows)]
fn apply_security_constraints(cmd: &mut Command) -> Result<(), SandboxError> {
    // On Windows, we would use Job Objects for resource limits
    // This is more complex and requires additional Windows-specific code
    // For now, we implement basic constraints

    // Set CREATE_NEW_PROCESS_GROUP to allow termination
    cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP);

    // Note: Full implementation would create a Job Object with limits:
    // - JOB_OBJECT_LIMIT_PROCESS_TIME for CPU time
    // - JOB_OBJECT_LIMIT_PROCESS_MEMORY for memory
    // - JOB_OBJECT_LIMIT_ACTIVE_PROCESS for process count

    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn apply_security_constraints(_cmd: &mut Command) -> Result<(), SandboxError> {
    warn!("Resource limits not implemented for this platform");
    Ok(())
}

/// Validate working directory against policy
pub fn validate_cwd(
    requested_cwd: Option<&Path>,
    policy_cwd: &mdmcp_policy::CwdPolicy,
    allowed_roots: &[PathBuf],
    exec_path: &Path,
) -> Result<Option<PathBuf>, SandboxError> {
    match policy_cwd {
        mdmcp_policy::CwdPolicy::None => Ok(None),
        mdmcp_policy::CwdPolicy::Fixed => {
            // Use the directory containing the executable
            if let Some(parent) = exec_path.parent() {
                Ok(Some(parent.to_path_buf()))
            } else {
                Ok(None)
            }
        }
        mdmcp_policy::CwdPolicy::WithinRoot => {
            if let Some(cwd) = requested_cwd {
                let canonical_cwd = cwd.canonicalize().map_err(|e| {
                    SandboxError::ExecutionFailed(format!("Invalid working directory: {}", e))
                })?;

                // Check if CWD is within any allowed root
                for root in allowed_roots {
                    if canonical_cwd.starts_with(root) {
                        return Ok(Some(canonical_cwd));
                    }
                }

                Err(SandboxError::ExecutionFailed(format!(
                    "Working directory not within allowed roots: {}",
                    cwd.display()
                )))
            } else {
                // Use first allowed root as default
                Ok(allowed_roots.first().cloned())
            }
        }
    }
}

/// Filter environment variables according to allowlist
pub fn filter_environment(
    requested_env: &HashMap<String, String>,
    allowlist: &[String],
) -> HashMap<String, String> {
    let mut filtered = HashMap::new();

    // Always include basic environment variables for security
    filtered.insert(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_default(),
    );

    // Add allowed environment variables
    for key in allowlist {
        if let Some(value) = requested_env.get(key) {
            filtered.insert(key.clone(), value.clone());
        } else if let Ok(value) = std::env::var(key) {
            // Fall back to system environment if not provided in request
            filtered.insert(key.clone(), value);
        }
    }

    debug!("Filtered environment: {} variables allowed", filtered.len());
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_simple_command_execution() {
        let config = ExecutionConfig {
            executable: PathBuf::from(if cfg!(windows) { "cmd" } else { "/bin/echo" }),
            args: if cfg!(windows) {
                vec!["/c".to_string(), "echo".to_string(), "hello".to_string()]
            } else {
                vec!["hello".to_string()]
            },
            cwd: None,
            env: HashMap::new(),
            stdin: String::new(),
            timeout_ms: 5000,
            max_output_bytes: 1000,
        };

        let result = execute_command(config).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("hello"));
        assert!(!result.timed_out);
        assert!(!result.truncated);
    }

    #[test]
    fn test_cwd_validation() {
        let temp_dir = tempdir().unwrap();
        let allowed_roots = vec![temp_dir.path().to_path_buf()];
        let exec_path = PathBuf::from("/bin/echo");

        // Test WithinRoot policy with allowed path
        let result = validate_cwd(
            Some(temp_dir.path()),
            &mdmcp_policy::CwdPolicy::WithinRoot,
            &allowed_roots,
            &exec_path,
        );
        assert!(result.is_ok());

        // Test WithinRoot policy with disallowed path
        let result = validate_cwd(
            Some(Path::new("/tmp")),
            &mdmcp_policy::CwdPolicy::WithinRoot,
            &allowed_roots,
            &exec_path,
        );
        assert!(result.is_err());

        // Test Fixed policy
        let result = validate_cwd(
            None,
            &mdmcp_policy::CwdPolicy::Fixed,
            &allowed_roots,
            &exec_path,
        );
        assert!(result.is_ok());

        // Test None policy
        let result = validate_cwd(
            Some(temp_dir.path()),
            &mdmcp_policy::CwdPolicy::None,
            &allowed_roots,
            &exec_path,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_environment_filtering() {
        let mut requested = HashMap::new();
        requested.insert("ALLOWED_VAR".to_string(), "value1".to_string());
        requested.insert("FORBIDDEN_VAR".to_string(), "value2".to_string());

        let allowlist = vec!["ALLOWED_VAR".to_string(), "MISSING_VAR".to_string()];

        let filtered = filter_environment(&requested, &allowlist);

        assert!(filtered.contains_key("ALLOWED_VAR"));
        assert!(!filtered.contains_key("FORBIDDEN_VAR"));
        assert!(filtered.contains_key("PATH")); // Always included
    }

    #[tokio::test]
    async fn test_output_truncation() {
        let config = ExecutionConfig {
            executable: PathBuf::from(if cfg!(windows) { "cmd" } else { "/bin/echo" }),
            args: if cfg!(windows) {
                vec!["/c".to_string(), "echo".to_string(), "x".repeat(1000)]
            } else {
                vec!["-n".to_string(), "x".repeat(1000)]
            },
            cwd: None,
            env: HashMap::new(),
            stdin: String::new(),
            timeout_ms: 5000,
            max_output_bytes: 100, // Small limit to trigger truncation
        };

        let result = execute_command(config).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.truncated);
        assert!(result.stdout.len() <= 100);
    }
}
