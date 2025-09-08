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

#[cfg(windows)]
fn expand_windows_placeholders(input: &str) -> String {
    // Expand %VAR% tokens using the current process environment.
    // This is a best-effort expansion; unknown vars are left as-is.
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Find closing %
            if let Some(j) = bytes[i + 1..].iter().position(|&b| b == b'%') {
                let end = i + 1 + j;
                let name = &input[i + 1..end];
                if !name.is_empty() {
                    // Environment variables on Windows are case-insensitive
                    let val = std::env::vars()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .map(|(_, v)| v);
                    if let Some(v) = val {
                        out.push_str(&v);
                        i = end + 1;
                        continue;
                    }
                }
                // No expansion found; keep literal
                out.push('%');
                out.push_str(name);
                out.push('%');
                i = end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

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

    // Prepare environment: start from filtered env, then optionally bootstrap MSVC if needed
    #[cfg(windows)]
    let mut final_env = config.env.clone();
    #[cfg(not(windows))]
    let final_env = config.env.clone();

    #[cfg(windows)]
    {
        if is_rust_tool(&config.executable) {
            if let Err(e) = try_bootstrap_msvc_env(&mut final_env) {
                warn!("MSVC env bootstrap failed: {}", e);
            }
        }
    }

    // Clear environment and set only allowed/bootstrapped variables
    cmd.env_clear();
    for (key, value) in &final_env {
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

#[cfg(windows)]
fn is_rust_tool(exe: &Path) -> bool {
    let name = exe
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(name.as_str(), "cargo" | "rustc" | "rustdoc")
}

#[cfg(windows)]
fn try_bootstrap_msvc_env(
    env: &mut HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command as StdCommand;

    // Locate vswhere
    let pf86 =
        std::env::var("ProgramFiles(x86)").or_else(|_| std::env::var("PROGRAMFILES(X86)"))?;
    let vswhere_path = Path::new(&pf86)
        .join("Microsoft Visual Studio")
        .join("Installer")
        .join("vswhere.exe");
    if !vswhere_path.exists() {
        // If vswhere is not present, silently return Ok; rustc may still discover via registry/paths
        return Ok(());
    }

    let output = StdCommand::new(vswhere_path)
        .arg("-latest")
        .arg("-products")
        .arg("*")
        .arg("-requires")
        .arg("Microsoft.VisualStudio.Component.VC.Tools.x86.x64")
        .arg("-format")
        .arg("json")
        .output()?;
    if !output.status.success() {
        return Ok(());
    }
    let json = String::from_utf8_lossy(&output.stdout);
    let val: serde_json::Value = serde_json::from_str(&json).unwrap_or(serde_json::Value::Null);
    let install_path = val
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|o| o.get("installationPath"))
        .and_then(|s| s.as_str());
    let Some(install_path) = install_path else {
        return Ok(());
    };

    // Build vcvars64.bat path
    let vcvars = Path::new(install_path)
        .join("VC")
        .join("Auxiliary")
        .join("Build")
        .join("vcvars64.bat");
    if !vcvars.exists() {
        return Ok(());
    }

    // Run "cmd /d /s /c call <vcvars64.bat> && set" to capture the environment after vcvars
    let mut bootstrap = StdCommand::new("cmd");
    bootstrap.arg("/d").arg("/s").arg("/c");
    let cmdline = format!("call \"{}\" && set", vcvars.display());
    bootstrap.arg(cmdline);

    // Seed with our current env so vcvars augments it
    bootstrap.env_clear();
    for (k, v) in env.iter() {
        bootstrap.env(k, v);
    }

    let out = bootstrap.output()?;
    if !out.status.success() {
        return Ok(());
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    for line in listing.lines() {
        if let Some((k, v)) = line.split_once('=') {
            if !k.is_empty() {
                env.insert(k.to_string(), v.to_string());
            }
        }
    }
    Ok(())
}

/// Apply platform-specific security constraints
#[cfg(unix)]
fn apply_security_constraints(cmd: &mut Command) -> Result<(), SandboxError> {
    // Apply resource limits
    unsafe {
        cmd.pre_exec(|| {
            // Set CPU time limit (5 minutes)
            let cpu_limit = libc::rlimit {
                rlim_cur: 300, // 5 minutes
                rlim_max: 300,
            };

            if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                return Err(std::io::Error::other("Failed to set CPU limit"));
            }

            // Set memory limit (1GB virtual memory)
            let mem_limit = libc::rlimit {
                rlim_cur: 1024 * 1024 * 1024, // 1GB
                rlim_max: 1024 * 1024 * 1024,
            };

            if libc::setrlimit(libc::RLIMIT_AS, &mem_limit) != 0 {
                return Err(std::io::Error::other("Failed to set memory limit"));
            }

            // Limit number of processes
            let proc_limit = libc::rlimit {
                rlim_cur: 32, // Maximum 32 processes
                rlim_max: 32,
            };

            if libc::setrlimit(libc::RLIMIT_NPROC, &proc_limit) != 0 {
                return Err(std::io::Error::other("Failed to set process limit"));
            }

            // Limit file descriptors
            let fd_limit = libc::rlimit {
                rlim_cur: 64, // Maximum 64 file descriptors
                rlim_max: 64,
            };

            if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
                return Err(std::io::Error::other("Failed to set file descriptor limit"));
            }

            Ok(())
        });
    }

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
                let canonical_cwd = dunce::canonicalize(cwd).map_err(|e| {
                    SandboxError::ExecutionFailed(format!("Invalid working directory: {}", e))
                })?;

                // Normalize allowed roots for robust comparison on Windows (strip \\?\ prefix)
                for root in allowed_roots {
                    let root_norm = dunce::canonicalize(root).unwrap_or_else(|_| root.clone());
                    if canonical_cwd.starts_with(&root_norm) {
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

    // Always include essential environment variables
    filtered.insert(
        "PATH".to_string(),
        std::env::var("PATH").unwrap_or_default(),
    );

    // Preserve a minimal baseline needed by common toolchains
    #[cfg(windows)]
    {
        // Preserve common Windows discovery variables used by VS/rustc and the shell
        for key in [
            "SYSTEMROOT",
            "WINDIR",
            "SYSTEMDRIVE",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
            "APPDATA",
            "LOCALAPPDATA",
            "PROGRAMDATA",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PROGRAMW6432",
            "COMMONPROGRAMFILES",
            "COMMONPROGRAMFILES(X86)",
            "USERPROFILE",
            "HOME",
            // Rust/cargo specific homes
            "CARGO_HOME",
            "RUSTUP_HOME",
            // Helpful CPU/arch hints some tools read
            "NUMBER_OF_PROCESSORS",
            "PROCESSOR_ARCHITECTURE",
        ] {
            if let Ok(val) = std::env::var(key) {
                filtered.insert(key.to_string(), val);
            }
        }

        // Sanitize PATH to avoid GNU coreutils link.exe shadowing MSVC's linker
        if let Ok(path_val) = std::env::var("PATH") {
            let parts: Vec<String> = path_val.split(';').map(|s| s.to_string()).collect();
            let mut others = Vec::with_capacity(parts.len());
            let mut git_usr = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for p in parts.into_iter() {
                let key = p.to_ascii_lowercase();
                if !seen.insert(key.clone()) {
                    continue; // dedupe
                }
                if key.contains("\\git\\usr\\bin") || key.contains("/git/usr/bin") {
                    git_usr.push(p);
                } else {
                    others.push(p);
                }
            }
            others.extend(git_usr);
            filtered.insert("PATH".to_string(), others.join(";"));
        }
    }
    #[cfg(unix)]
    {
        for key in [
            "HOME",
            "USER",
            "SHELL",
            "TMPDIR",
            "CARGO_HOME",
            "RUSTUP_HOME",
        ] {
            if let Ok(val) = std::env::var(key) {
                filtered.insert(key.to_string(), val);
            }
        }
    }

    // Add allowed environment variables
    for key in allowlist {
        // Prefer requested env if provided, but expand Windows-style placeholders.
        let mut chosen: Option<String> = None;
        if let Some(req_val) = requested_env.get(key) {
            #[cfg(windows)]
            {
                let expanded = expand_windows_placeholders(req_val);
                if expanded != *req_val {
                    chosen = Some(expanded);
                } else if req_val == &format!("%{}%", key) {
                    // Request provided a self-referential placeholder; prefer system value if available
                    if let Ok(sys_val) = std::env::var(key) {
                        chosen = Some(sys_val);
                    } else {
                        chosen = Some(req_val.clone());
                    }
                } else {
                    chosen = Some(req_val.clone());
                }
            }
            #[cfg(not(windows))]
            {
                chosen = Some(req_val.clone());
            }
        }

        if chosen.is_none() {
            if let Ok(sys_val) = std::env::var(key) {
                chosen = Some(sys_val);
            }
        }

        if let Some(v) = chosen {
            filtered.insert(key.clone(), v);
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
