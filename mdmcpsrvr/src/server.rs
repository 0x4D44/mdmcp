//! # MCP Server Implementation
//!
//! Core MCP server implementation that handles JSON-RPC requests and coordinates
//! all server components including policy enforcement, file system operations,
//! command execution, and audit logging. This module serves as the main
//! orchestrator for all MCP protocol interactions.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use mdmcp_common::{
    CmdRunParams, CmdRunResult, FsReadParams, FsReadResult, FsWriteParams, FsWriteResult,
    HandshakeParams, InitializeParams, InitializeResult, McpErrorCode, RpcId, RpcRequest, RpcResponse,
    ServerCapabilities, ServerInfo,
};
use mdmcp_policy::CompiledPolicy;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::audit::{
    AuditConfig, AuditContext, Auditor, DenialDetails, ErrorDetails, SuccessDetails,
};
use crate::cmd_catalog::{CatalogError, CommandCatalog};
use crate::fs_safety::{FsError, GuardedFileReader, GuardedFileWriter};
use crate::rpc::{
    self, create_error_response, create_notification, create_success_response, send_notification,
    send_response, validate_method,
};

/// Main MCP server instance
pub struct Server {
    policy: Arc<CompiledPolicy>,
    auditor: Auditor,
    command_catalog: CommandCatalog,
}

impl Server {
    /// Create new server instance with compiled policy
    pub async fn new(policy: Arc<CompiledPolicy>) -> Result<Self> {
        info!("Initializing MCP server");

        // Create audit configuration from policy
        let audit_config = AuditConfig {
            log_file: policy.policy.logging.file.as_ref().map(|f| {
                crate::policy::expand_policy_path(f)
                    .unwrap_or_else(|_| f.clone())
                    .into()
            }),
            redact_fields: policy.policy.logging.redact.clone(),
            enabled: true,
        };

        // Initialize auditor
        let auditor = Auditor::new(audit_config).context("Failed to initialize audit logger")?;

        // Create command catalog
        let command_catalog = CommandCatalog::new(Arc::as_ref(&policy).clone());

        info!(
            "Server initialized with policy hash: {}",
            &policy.policy_hash[..16]
        );

        Ok(Server {
            policy,
            auditor,
            command_catalog,
        })
    }

    /// Send MCP handshake notification
    pub async fn send_handshake(&self) -> Result<()> {
        let mut capabilities = HashMap::new();
        capabilities.insert("fs.read".to_string(), serde_json::json!(true));
        capabilities.insert("fs.write".to_string(), serde_json::json!(true));
        capabilities.insert(
            "cmd.run".to_string(),
            serde_json::json!({"streaming": false}),
        );

        let params = HandshakeParams {
            name: "mdmcpsrvr".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            capabilities,
            policy_hash: self.policy.policy_hash.clone(),
        };

        let notification =
            create_notification("mcp.handshake".to_string(), serde_json::to_value(params)?);

        send_notification(&notification)
            .await
            .context("Failed to send handshake notification")
    }

    /// Handle a JSON-RPC request line
    pub async fn handle_request_line(&self, line: &str) -> Result<()> {
        match rpc::parse_request(line) {
            Ok(request) => {
                self.handle_request(request).await;
            }
            Err(e) => {
                error!("Failed to parse request: {}", e);
                // Send error response with null ID since we couldn't parse the request
                let response = create_error_response(
                    RpcId::Null,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid JSON-RPC request: {}", e)),
                    None,
                );
                if let Err(send_err) = send_response(&response).await {
                    error!("Failed to send error response: {}", send_err);
                }
            }
        }
        Ok(())
    }

    /// Handle initialize request
    async fn handle_initialize(&self, ctx: &AuditContext, id: RpcId, params: Value) -> RpcResponse {
        let init_params: InitializeParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor
                    .log_error(ctx, &format!("Invalid initialize parameters: {}", e), None);
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!(
            "initialize: client={} version={} protocol={}",
            init_params.client_info.name,
            init_params.client_info.version,
            init_params.protocol_version
        );

        // Validate protocol version
        if init_params.protocol_version != "2024-11-05" {
            let error_msg = format!("Unsupported protocol version: {}", init_params.protocol_version);
            self.auditor.log_error(ctx, &error_msg, None);
            return create_error_response(
                id,
                McpErrorCode::InvalidArgs,
                Some(error_msg),
                None,
            );
        }

        // Create server capabilities - this server doesn't support resources, tools, or prompts
        // It only supports file system and command execution via the custom protocol
        let capabilities = ServerCapabilities {
            logging: None,
            prompts: None,
            resources: None,
            tools: None,
        };

        let result = InitializeResult {
            protocol_version: "2024-11-05".to_string(),
            capabilities,
            server_info: ServerInfo {
                name: "mdmcpsrvr".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        self.auditor.log_success(ctx, SuccessDetails::default());

        create_success_response(id, serde_json::to_value(result).unwrap())
    }

    /// Handle a parsed JSON-RPC request
    async fn handle_request(&self, request: RpcRequest) {
        let req_id = format!("req_{}", generate_request_id(&request.id));
        debug!("Handling request: {} method={}", req_id, request.method);

        // Validate method
        if let Err(error_code) = validate_method(&request.method) {
            let response = create_error_response(
                request.id,
                error_code,
                Some(format!("Unsupported method: {}", request.method)),
                None,
            );
            if let Err(e) = send_response(&response).await {
                error!("Failed to send method validation error: {}", e);
            }
            return;
        }

        // Create audit context
        let audit_ctx = AuditContext::new(
            req_id,
            request.method.clone(),
            self.policy.policy_hash.clone(),
        );

        // Dispatch to appropriate handler
        let response = match request.method.as_str() {
            "initialize" => {
                self.handle_initialize(&audit_ctx, request.id, request.params)
                    .await
            }
            "fs.read" => {
                self.handle_fs_read(&audit_ctx, request.id, request.params)
                    .await
            }
            "fs.write" => {
                self.handle_fs_write(&audit_ctx, request.id, request.params)
                    .await
            }
            "cmd.run" => {
                self.handle_cmd_run(&audit_ctx, request.id, request.params)
                    .await
            }
            _ => {
                // This should not happen due to validate_method above
                create_error_response(
                    request.id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Method not implemented: {}", request.method)),
                    None,
                )
            }
        };

        // Send response
        if let Err(e) = send_response(&response).await {
            error!("Failed to send response: {}", e);
        }
    }

    /// Handle fs.read request
    async fn handle_fs_read(&self, ctx: &AuditContext, id: RpcId, params: Value) -> RpcResponse {
        let read_params: FsReadParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor
                    .log_error(ctx, &format!("Invalid fs.read parameters: {}", e), None);
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!(
            "fs.read: path={}, offset={}, length={}",
            read_params.path, read_params.offset, read_params.length
        );

        // Validate encoding
        if read_params.encoding != "utf8" && read_params.encoding != "base64" {
            let error_msg = format!("Unsupported encoding: {}", read_params.encoding);
            self.auditor.log_error(
                ctx,
                &error_msg,
                Some(ErrorDetails {
                    path: Some(read_params.path.clone()),
                    ..Default::default()
                }),
            );
            return create_error_response(id, McpErrorCode::InvalidArgs, Some(error_msg), None);
        }

        // Open file with policy checks
        let mut reader = match GuardedFileReader::open(&read_params.path, &self.policy) {
            Ok(reader) => reader,
            Err(FsError::PathNotAllowed { path }) => {
                self.auditor.log_denial(
                    ctx,
                    "pathNotAllowed",
                    Some(DenialDetails {
                        path: Some(path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Path not allowed: {}", path)),
                    Some(serde_json::json!({"rule": "pathNotAllowed"})),
                );
            }
            Err(FsError::NetworkFsDenied { path }) => {
                self.auditor.log_denial(
                    ctx,
                    "networkFsDenied",
                    Some(DenialDetails {
                        path: Some(path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Network filesystem denied: {}", path)),
                    Some(serde_json::json!({"rule": "networkFsDenied"})),
                );
            }
            Err(FsError::SpecialFile { path }) => {
                self.auditor.log_denial(
                    ctx,
                    "specialFile",
                    Some(DenialDetails {
                        path: Some(path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Special file not allowed: {}", path)),
                    Some(serde_json::json!({"rule": "specialFile"})),
                );
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("File access error: {}", e),
                    Some(ErrorDetails {
                        path: Some(read_params.path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::IoError,
                    Some(format!("File access error: {}", e)),
                    None,
                );
            }
        };

        // Read file content
        match reader.read_with_limits(read_params.offset, read_params.length) {
            Ok((data, hash)) => {
                let (encoded_data, bytes_read) = match read_params.encoding.as_str() {
                    "utf8" => match String::from_utf8(data.clone()) {
                        Ok(utf8_data) => (utf8_data, data.len() as u64),
                        Err(_) => {
                            self.auditor.log_error(
                                ctx,
                                "Invalid UTF-8 data",
                                Some(ErrorDetails {
                                    path: Some(read_params.path.clone()),
                                    ..Default::default()
                                }),
                            );
                            return create_error_response(
                                id,
                                McpErrorCode::IoError,
                                Some("File contains invalid UTF-8 data".to_string()),
                                None,
                            );
                        }
                    },
                    "base64" => (BASE64.encode(&data), data.len() as u64),
                    _ => unreachable!(), // Already validated above
                };

                let result = FsReadResult {
                    data: encoded_data,
                    bytes_read,
                    sha256: hash.clone(),
                };

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        path: Some(read_params.path.clone()),
                        bytes: Some(bytes_read),
                        content_hash: Some(hash),
                        ..Default::default()
                    },
                );

                create_success_response(id, serde_json::to_value(result).unwrap())
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Read error: {}", e),
                    Some(ErrorDetails {
                        path: Some(read_params.path.clone()),
                        ..Default::default()
                    }),
                );
                create_error_response(
                    id,
                    McpErrorCode::IoError,
                    Some(format!("Read error: {}", e)),
                    None,
                )
            }
        }
    }

    /// Handle fs.write request
    async fn handle_fs_write(&self, ctx: &AuditContext, id: RpcId, params: Value) -> RpcResponse {
        let write_params: FsWriteParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor
                    .log_error(ctx, &format!("Invalid fs.write parameters: {}", e), None);
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!(
            "fs.write: path={}, create={}, overwrite={}",
            write_params.path, write_params.create, write_params.overwrite
        );

        // Decode data based on encoding
        let data = match write_params.encoding.as_str() {
            "utf8" => write_params.data.into_bytes(),
            "base64" => match BASE64.decode(&write_params.data) {
                Ok(decoded) => decoded,
                Err(e) => {
                    let error_msg = format!("Invalid base64 data: {}", e);
                    self.auditor.log_error(
                        ctx,
                        &error_msg,
                        Some(ErrorDetails {
                            path: Some(write_params.path.clone()),
                            ..Default::default()
                        }),
                    );
                    return create_error_response(
                        id,
                        McpErrorCode::InvalidArgs,
                        Some(error_msg),
                        None,
                    );
                }
            },
            _ => {
                let error_msg = format!("Unsupported encoding: {}", write_params.encoding);
                self.auditor.log_error(
                    ctx,
                    &error_msg,
                    Some(ErrorDetails {
                        path: Some(write_params.path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(id, McpErrorCode::InvalidArgs, Some(error_msg), None);
            }
        };

        // Create file writer with policy checks
        let writer = match GuardedFileWriter::create(
            &write_params.path,
            &self.policy,
            write_params.create,
            write_params.overwrite,
        ) {
            Ok(writer) => writer,
            Err(FsError::PathNotAllowed { path }) => {
                self.auditor.log_denial(
                    ctx,
                    "pathNotAllowed",
                    Some(DenialDetails {
                        path: Some(path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Path not allowed: {}", path)),
                    Some(serde_json::json!({"rule": "pathNotAllowed"})),
                );
            }
            Err(FsError::WriteNotPermitted { path }) => {
                self.auditor.log_denial(
                    ctx,
                    "writeNotPermitted",
                    Some(DenialDetails {
                        path: Some(path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Write not permitted: {}", path)),
                    Some(serde_json::json!({"rule": "writeNotPermitted"})),
                );
            }
            Err(FsError::FileTooLarge { size, limit }) => {
                self.auditor.log_denial(
                    ctx,
                    "fileTooLarge",
                    Some(DenialDetails {
                        path: Some(write_params.path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!(
                        "File too large: {} bytes exceeds limit {}",
                        size, limit
                    )),
                    Some(serde_json::json!({"rule": "fileTooLarge"})),
                );
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Write setup error: {}", e),
                    Some(ErrorDetails {
                        path: Some(write_params.path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::IoError,
                    Some(format!("Write setup error: {}", e)),
                    None,
                );
            }
        };

        // Write data atomically
        match writer.write_atomic(&data) {
            Ok((bytes_written, hash)) => {
                let result = FsWriteResult {
                    bytes_written,
                    sha256: hash.clone(),
                };

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        path: Some(write_params.path.clone()),
                        bytes: Some(bytes_written),
                        content_hash: Some(hash),
                        ..Default::default()
                    },
                );

                create_success_response(id, serde_json::to_value(result).unwrap())
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Write error: {}", e),
                    Some(ErrorDetails {
                        path: Some(write_params.path.clone()),
                        ..Default::default()
                    }),
                );
                create_error_response(
                    id,
                    McpErrorCode::IoError,
                    Some(format!("Write error: {}", e)),
                    None,
                )
            }
        }
    }

    /// Handle cmd.run request
    async fn handle_cmd_run(&self, ctx: &AuditContext, id: RpcId, params: Value) -> RpcResponse {
        let run_params: CmdRunParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor
                    .log_error(ctx, &format!("Invalid cmd.run parameters: {}", e), None);
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!(
            "cmd.run: command={}, args={:?}",
            run_params.command_id,
            crate::cmd_catalog::sanitize_args_for_logging(&run_params.args)
        );

        // Validate command
        let validated_cmd = match self.command_catalog.validate_command(&run_params) {
            Ok(cmd) => cmd,
            Err(CatalogError::Policy(mdmcp_policy::PolicyError::CommandNotFound(cmd_id))) => {
                self.auditor.log_denial(
                    ctx,
                    "commandNotFound",
                    Some(DenialDetails {
                        command: Some(cmd_id.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Command not found: {}", cmd_id)),
                    Some(serde_json::json!({"rule": "commandNotFound"})),
                );
            }
            Err(CatalogError::Policy(mdmcp_policy::PolicyError::PolicyDenied { rule })) => {
                self.auditor.log_denial(
                    ctx,
                    &rule,
                    Some(DenialDetails {
                        command: Some(run_params.command_id.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(format!("Policy denied: {}", rule)),
                    Some(serde_json::json!({"rule": rule})),
                );
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Command validation error: {}", e),
                    Some(ErrorDetails {
                        command: Some(run_params.command_id.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Command validation error: {}", e)),
                    None,
                );
            }
        };

        // Execute command
        match self.command_catalog.execute_command(validated_cmd).await {
            Ok(execution_result) => {
                let result = CmdRunResult {
                    exit_code: execution_result.exit_code,
                    stdout: execution_result.stdout,
                    stderr: execution_result.stderr,
                    timed_out: execution_result.timed_out,
                    truncated: execution_result.truncated,
                };

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        command: Some(run_params.command_id.clone()),
                        exit_code: Some(execution_result.exit_code),
                        timed_out: Some(execution_result.timed_out),
                        ..Default::default()
                    },
                );

                create_success_response(id, serde_json::to_value(result).unwrap())
            }
            Err(CatalogError::Sandbox(crate::sandbox::SandboxError::Timeout { timeout_ms })) => {
                self.auditor.log_error(
                    ctx,
                    "Command timeout",
                    Some(ErrorDetails {
                        command: Some(run_params.command_id.clone()),
                        timed_out: Some(true),
                        ..Default::default()
                    }),
                );
                create_error_response(
                    id,
                    McpErrorCode::Timeout,
                    Some(format!("Command timed out after {}ms", timeout_ms)),
                    None,
                )
            }
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Command execution error: {}", e),
                    Some(ErrorDetails {
                        command: Some(run_params.command_id.clone()),
                        ..Default::default()
                    }),
                );
                create_error_response(
                    id,
                    McpErrorCode::Internal,
                    Some(format!("Command execution error: {}", e)),
                    None,
                )
            }
        }
    }
}

/// Generate a unique request ID for audit logging
fn generate_request_id(rpc_id: &RpcId) -> String {
    match rpc_id {
        RpcId::String(s) => s.clone(),
        RpcId::Number(n) => n.to_string(),
        RpcId::Null => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdmcp_policy::{ArgsPolicy, CommandRule, LimitsConfig, LoggingConfig, Policy, WriteRule};
    use std::collections::HashMap;
    use tempfile::{tempdir, NamedTempFile};

    async fn create_test_server() -> Server {
        let temp_dir = tempdir().unwrap();
        let test_root = temp_dir.path().to_path_buf();

        let policy = Policy {
            version: 1,
            deny_network_fs: false,
            allowed_roots: vec![test_root.to_string_lossy().to_string()],
            write_rules: vec![WriteRule {
                path: test_root.to_string_lossy().to_string(),
                recursive: true,
                max_file_bytes: 1000,
                create_if_missing: true,
            }],
            commands: vec![CommandRule {
                id: "echo".to_string(),
                exec: if cfg!(windows) {
                    "cmd".to_string()
                } else {
                    "/bin/echo".to_string()
                },
                args: ArgsPolicy {
                    allow: vec!["test".to_string()],
                    fixed: vec![],
                    patterns: vec![],
                },
                cwd_policy: mdmcp_policy::CwdPolicy::WithinRoot,
                env_allowlist: vec![],
                timeout_ms: 5000,
                max_output_bytes: 1000,
                platform: vec![
                    "linux".to_string(),
                    "windows".to_string(),
                    "macos".to_string(),
                ],
            }],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };

        let compiled_policy = Arc::new(policy.compile().unwrap());
        Server::new(compiled_policy).await.unwrap()
    }

    #[tokio::test]
    async fn test_fs_read_success() {
        let server = create_test_server().await;

        // Create a test file
        let temp_file = NamedTempFile::new_in(&server.policy.allowed_roots_canonical[0]).unwrap();
        std::fs::write(temp_file.path(), "test content").unwrap();

        let params = FsReadParams {
            path: temp_file.path().to_string_lossy().to_string(),
            offset: 0,
            length: 1000,
            encoding: "utf8".to_string(),
        };

        let audit_ctx = AuditContext::new(
            "test".to_string(),
            "fs.read".to_string(),
            "hash".to_string(),
        );
        let response = server
            .handle_fs_read(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::to_value(params).unwrap(),
            )
            .await;

        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_fs_read_path_denied() {
        let server = create_test_server().await;

        // Try to read a file outside allowed roots
        let params = FsReadParams {
            path: "/forbidden/path".to_string(),
            offset: 0,
            length: 1000,
            encoding: "utf8".to_string(),
        };

        let audit_ctx = AuditContext::new(
            "test".to_string(),
            "fs.read".to_string(),
            "hash".to_string(),
        );
        let response = server
            .handle_fs_read(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::to_value(params).unwrap(),
            )
            .await;

        assert!(response.result.is_none());
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, McpErrorCode::PolicyDeny as i32);
    }

    #[tokio::test]
    async fn test_fs_write_success() {
        let server = create_test_server().await;
        let test_file = server.policy.allowed_roots_canonical[0].join("test_write.txt");

        let params = FsWriteParams {
            path: test_file.to_string_lossy().to_string(),
            data: "test data".to_string(),
            encoding: "utf8".to_string(),
            create: true,
            overwrite: true,
        };

        let audit_ctx = AuditContext::new(
            "test".to_string(),
            "fs.write".to_string(),
            "hash".to_string(),
        );
        let response = server
            .handle_fs_write(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::to_value(params).unwrap(),
            )
            .await;

        assert!(response.result.is_some());
        assert!(response.error.is_none());
        assert_eq!(std::fs::read_to_string(&test_file).unwrap(), "test data");
    }

    #[tokio::test]
    async fn test_cmd_run_success() {
        let server = create_test_server().await;

        let mut params = CmdRunParams {
            command_id: "echo".to_string(),
            args: if cfg!(windows) {
                vec!["/c".to_string(), "echo".to_string(), "test".to_string()]
            } else {
                vec!["test".to_string()]
            },
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: None,
        };

        // Adjust for Windows command structure
        if cfg!(windows) {
            params.args = vec!["/c".to_string(), "echo".to_string(), "test".to_string()];
        }

        let audit_ctx = AuditContext::new(
            "test".to_string(),
            "cmd.run".to_string(),
            "hash".to_string(),
        );
        let response = server
            .handle_cmd_run(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::to_value(params).unwrap(),
            )
            .await;

        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_generate_request_id() {
        assert_eq!(
            generate_request_id(&RpcId::String("test".to_string())),
            "test"
        );
        assert_eq!(generate_request_id(&RpcId::Number(42)), "42");
        assert_eq!(generate_request_id(&RpcId::Null), "null");
    }
}
