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
    InitializeParams, InitializeResult, McpErrorCode, PromptArgument, PromptContent, PromptInfo,
    PromptMessage, PromptsGetParams, PromptsGetResult, PromptsListParams, PromptsListResult,
    ResourceContent, ResourceInfo, ResourcesListParams, ResourcesListResult, ResourcesReadParams,
    ResourcesReadResult, RpcId, RpcRequest, RpcResponse, ServerCapabilities, ServerInfo,
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
    self, create_error_response, create_success_response, send_response, validate_method,
    RpcMessage,
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

    /// Handle a JSON-RPC message line (request or notification)
    pub async fn handle_request_line(&self, line: &str) -> Result<()> {
        info!("📨 Incoming request: {}", line);

        match rpc::parse_message(line) {
            Ok(RpcMessage::Request(request)) => {
                info!(
                    "🔍 Parsed request: method='{}', id={:?}",
                    request.method, request.id
                );
                self.handle_request(request).await;
                debug!("Request handling completed");
            }
            Ok(RpcMessage::Notification { method, params }) => {
                info!(
                    "🔔 Parsed notification: method='{}', params={}",
                    method,
                    serde_json::to_string(&params).unwrap_or_else(|_| "invalid".to_string())
                );
                self.handle_notification(method, params).await;
                debug!("Notification handling completed");
            }
            Err(e) => {
                error!("Failed to parse message: {}", e);
                eprintln!("Server error: Failed to parse message: {}", e);
                // Send error response with null ID since we couldn't parse the message
                let response = create_error_response(
                    RpcId::Null,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid JSON-RPC message: {}", e)),
                    None,
                );
                if let Err(send_err) = send_response(&response).await {
                    error!("Failed to send error response: {}", send_err);
                    eprintln!("Server error: Failed to send error response: {}", send_err);
                }
            }
        }
        Ok(())
    }

    /// Handle a notification (no response needed)
    async fn handle_notification(&self, method: String, _params: Value) {
        debug!("Handling notification: method={}", method);
        match method.as_str() {
            "initialized" => {
                info!("🤝 Received initialized notification - handshake complete");
                // The client has confirmed initialization is complete
                // Server is now ready for normal operation
            }
            _ => {
                debug!("Unknown notification method: {}", method);
            }
        }
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

        // Validate protocol version - accept both current and newer versions
        if init_params.protocol_version != "2024-11-05"
            && init_params.protocol_version != "2025-06-18"
        {
            let error_msg = format!(
                "Unsupported protocol version: {}",
                init_params.protocol_version
            );
            self.auditor.log_error(ctx, &error_msg, None);
            return create_error_response(id, McpErrorCode::InvalidArgs, Some(error_msg), None);
        }

        // Create server capabilities - declare tools for fs.read, fs.write, cmd.run
        let mut tools_caps = HashMap::new();
        tools_caps.insert("listChanged".to_string(), serde_json::Value::Bool(true));

        // Declare prompts capability
        let mut prompts_caps = HashMap::new();
        prompts_caps.insert("listChanged".to_string(), serde_json::Value::Bool(true));

        // Declare resources capability
        let mut resources_caps = HashMap::new();
        resources_caps.insert("listChanged".to_string(), serde_json::Value::Bool(true));

        // Create capabilities object with full MCP support
        let capabilities = ServerCapabilities {
            logging: None,
            prompts: Some(prompts_caps),
            resources: Some(resources_caps),
            tools: Some(tools_caps),
        };

        // Use the client's protocol version in the response
        let response_protocol_version = if init_params.protocol_version == "2025-06-18" {
            "2025-06-18"
        } else {
            "2024-11-05"
        };

        let result = InitializeResult {
            protocol_version: response_protocol_version.to_string(),
            capabilities,
            server_info: ServerInfo {
                name: "mdmcpsrvr".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        };

        self.auditor.log_success(ctx, SuccessDetails::default());

        create_success_response(id, serde_json::to_value(result).unwrap())
    }

    /// Handle tools/list request
    async fn handle_tools_list(
        &self,
        ctx: &AuditContext,
        id: RpcId,
        _params: Value,
    ) -> RpcResponse {
        debug!("tools/list request");

        let tools = serde_json::json!({
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read file contents from the filesystem",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to read"
                            },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "default": "utf8",
                                "description": "File encoding"
                            }
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write data to a file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Path to the file to write"
                            },
                            "data": {
                                "type": "string",
                                "description": "Data to write to the file"
                            },
                            "encoding": {
                                "type": "string",
                                "enum": ["utf8", "base64"],
                                "default": "utf8",
                                "description": "Data encoding"
                            },
                            "create": {
                                "type": "boolean",
                                "default": true,
                                "description": "Create file if it doesn't exist"
                            },
                            "overwrite": {
                                "type": "boolean",
                                "default": true,
                                "description": "Overwrite file if it exists"
                            }
                        },
                        "required": ["path", "data"]
                    }
                },
                {
                    "name": "run_command",
                    "description": "Execute a command from the policy-defined catalog",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command_id": {
                                "type": "string",
                                "description": "ID of the command to run from the catalog"
                            },
                            "args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Command arguments"
                            },
                            "stdin": {
                                "type": "string",
                                "default": "",
                                "description": "Data to send to command stdin"
                            }
                        },
                        "required": ["command_id"]
                    }
                },
                {
                    "name": "list_accessible_directories",
                    "description": "List all directories that are accessible for file operations based on the current policy",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                },
                {
                    "name": "list_available_commands",
                    "description": "List all commands that can be executed through run_command, with their IDs, descriptions, and allowed arguments",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                }
            ]
        });

        self.auditor.log_success(ctx, SuccessDetails::default());
        create_success_response(id, tools)
    }

    /// Handle tools/call request
    async fn handle_tools_call(&self, ctx: &AuditContext, id: RpcId, params: Value) -> RpcResponse {
        let call_params: serde_json::Value = params;

        let tool_name = match call_params.get("name").and_then(|n| n.as_str()) {
            Some(name) => name,
            None => {
                self.auditor
                    .log_error(ctx, "Missing tool name in tools/call", None);
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some("Missing tool name".to_string()),
                    None,
                );
            }
        };

        let tool_args = call_params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        debug!("tools/call: tool={}, args={:?}", tool_name, tool_args);

        // Dispatch to the appropriate tool implementation
        match tool_name {
            "read_file" => {
                // Convert tool args to fs.read format
                let fs_params = serde_json::json!({
                    "path": tool_args.get("path"),
                    "encoding": tool_args.get("encoding").unwrap_or(&serde_json::json!("utf8")),
                    "offset": 0,
                    "length": 1_000_000 // Max length
                });
                self.handle_fs_read(ctx, id, fs_params).await
            }
            "write_file" => {
                // Convert tool args to fs.write format
                let fs_params = serde_json::json!({
                    "path": tool_args.get("path"),
                    "data": tool_args.get("data"),
                    "encoding": tool_args.get("encoding").unwrap_or(&serde_json::json!("utf8")),
                    "create": tool_args.get("create").unwrap_or(&serde_json::json!(true)),
                    "overwrite": tool_args.get("overwrite").unwrap_or(&serde_json::json!(true))
                });
                self.handle_fs_write(ctx, id, fs_params).await
            }
            "run_command" => {
                // Convert tool args to cmd.run format
                let cmd_params = serde_json::json!({
                    "commandId": tool_args.get("command_id"),
                    "args": tool_args.get("args").unwrap_or(&serde_json::json!([])),
                    "stdin": tool_args.get("stdin").unwrap_or(&serde_json::json!("")),
                    "cwd": null,
                    "env": {},
                    "timeoutMs": null
                });

                // Execute via cmd.run handler, then adapt result to MCP tool content blocks
                let cmd_response = self.handle_cmd_run(ctx, id.clone(), cmd_params).await;

                if let Some(err) = &cmd_response.error {
                    return create_error_response(
                        id,
                        McpErrorCode::Internal,
                        Some(err.message.clone()),
                        cmd_response.error.as_ref().and_then(|e| e.data.clone()),
                    );
                }

                let raw = match cmd_response.result {
                    Some(v) => v,
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some("cmd.run returned no result".to_string()),
                            None,
                        )
                    }
                };

                let parsed: Result<mdmcp_common::CmdRunResult, _> = serde_json::from_value(raw);
                let cmd_out = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some(format!("Failed to parse cmd.run result: {}", e)),
                            None,
                        )
                    }
                };

                // Build MCP tool content blocks. Prefer stdout; include stderr if present.
                let mut content_blocks: Vec<serde_json::Value> = Vec::new();

                if !cmd_out.stdout.is_empty() {
                    content_blocks.push(serde_json::json!({
                        "type": "text",
                        "text": cmd_out.stdout,
                    }));
                }
                if !cmd_out.stderr.is_empty() {
                    content_blocks.push(serde_json::json!({
                        "type": "text",
                        "text": format!("[stderr]\n{}", cmd_out.stderr),
                    }));
                }
                if content_blocks.is_empty() {
                    content_blocks.push(serde_json::json!({
                        "type": "text",
                        "text": "(command produced no output)",
                    }));
                }

                // Add a trailing status note if helpful
                if cmd_out.timed_out || cmd_out.truncated || cmd_out.exit_code != 0 {
                    let mut notes: Vec<String> = Vec::new();
                    if cmd_out.timed_out {
                        notes.push("timed out".to_string());
                    }
                    if cmd_out.truncated {
                        notes.push("output truncated".to_string());
                    }
                    if cmd_out.exit_code != 0 {
                        notes.push(format!("exit code {}", cmd_out.exit_code));
                    }
                    if !notes.is_empty() {
                        content_blocks.push(serde_json::json!({
                            "type": "text",
                            "text": format!("[note] {}", notes.join(", ")),
                        }));
                    }
                }

                let result = serde_json::json!({
                    "content": content_blocks,
                    "isError": false
                });

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        ..Default::default()
                    },
                );
                create_success_response(id, result)
            }
            "list_accessible_directories" => {
                debug!("Listing accessible directories from policy");

                let directories: Vec<_> = self
                    .policy
                    .allowed_roots_canonical
                    .iter()
                    .map(|path| path.to_string_lossy().to_string())
                    .collect();

                // Create human-readable text content
                let text_content = if directories.is_empty() {
                    "No accessible directories configured.".to_string()
                } else {
                    let mut content =
                        format!("Accessible directories ({} total):\n", directories.len());
                    for (i, dir) in directories.iter().enumerate() {
                        content.push_str(&format!("{}. {}\n", i + 1, dir));
                    }
                    content
                };

                // Return proper MCP tools/call response format
                let result = serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": text_content
                        }
                    ],
                    "isError": false
                });

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        ..Default::default()
                    },
                );

                create_success_response(id, result)
            }
            "list_available_commands" => {
                debug!("Listing available commands from policy");

                // Create human-readable text content
                let text_content = if self.policy.commands_by_id.is_empty() {
                    "No commands available in policy.".to_string()
                } else {
                    let mut content = format!(
                        "Available commands ({} total):\n\n",
                        self.policy.commands_by_id.len()
                    );
                    for (i, (cmd_id, cmd_rule)) in self.policy.commands_by_id.iter().enumerate() {
                        content.push_str(&format!("{}. **{}**\n", i + 1, cmd_id));
                        content.push_str(&format!("   - Executable: {}\n", cmd_rule.rule.exec));
                        content
                            .push_str(&format!("   - Timeout: {}ms\n", cmd_rule.rule.timeout_ms));
                        content.push_str(&format!(
                            "   - Max output: {} bytes\n",
                            cmd_rule.rule.max_output_bytes
                        ));
                        if !cmd_rule.rule.args.allow.is_empty() {
                            content.push_str(&format!(
                                "   - Allowed args: {:?}\n",
                                cmd_rule.rule.args.allow
                            ));
                        }
                        if !cmd_rule.rule.args.fixed.is_empty() {
                            content.push_str(&format!(
                                "   - Fixed args: {:?}\n",
                                cmd_rule.rule.args.fixed
                            ));
                        }
                        content
                            .push_str(&format!("   - Platforms: {:?}\n\n", cmd_rule.rule.platform));
                    }
                    content
                };

                // Return proper MCP tools/call response format
                let result = serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": text_content
                        }
                    ],
                    "isError": false
                });

                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        ..Default::default()
                    },
                );

                create_success_response(id, result)
            }
            _ => {
                self.auditor
                    .log_error(ctx, &format!("Unknown tool: {}", tool_name), None);
                create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Unknown tool: {}", tool_name)),
                    None,
                )
            }
        }
    }

    /// Handle prompts/list request
    async fn handle_prompts_list(
        &self,
        ctx: &AuditContext,
        id: RpcId,
        params: Value,
    ) -> RpcResponse {
        let _list_params: PromptsListParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Invalid prompts/list parameters: {}", e),
                    None,
                );
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!("Handling prompts/list request");

        // Define available prompts that help users interact with this server
        let prompts = vec![
            PromptInfo {
                name: "file_operation".to_string(),
                title: "File Operation Helper".to_string(),
                description: Some(
                    "Generate prompts for file read/write operations within allowed directories"
                        .to_string(),
                ),
                arguments: vec![
                    PromptArgument {
                        name: "operation".to_string(),
                        description: Some("The operation type: 'read' or 'write'".to_string()),
                        required: true,
                    },
                    PromptArgument {
                        name: "path".to_string(),
                        description: Some("The file path to operate on".to_string()),
                        required: true,
                    },
                ],
            },
            PromptInfo {
                name: "command_execution".to_string(),
                title: "Command Execution Helper".to_string(),
                description: Some(
                    "Generate prompts for running commands from the allowed catalog".to_string(),
                ),
                arguments: vec![PromptArgument {
                    name: "command_id".to_string(),
                    description: Some("The command ID from the available commands".to_string()),
                    required: true,
                }],
            },
            PromptInfo {
                name: "server_status".to_string(),
                title: "Server Status Query".to_string(),
                description: Some(
                    "Generate prompts for checking server status and capabilities".to_string(),
                ),
                arguments: vec![],
            },
        ];

        let result = PromptsListResult {
            prompts,
            next_cursor: None, // No pagination for now
        };

        self.auditor.log_success(
            ctx,
            SuccessDetails {
                ..Default::default()
            },
        );

        create_success_response(id, serde_json::to_value(result).unwrap())
    }

    /// Handle prompts/get request
    async fn handle_prompts_get(
        &self,
        ctx: &AuditContext,
        id: RpcId,
        params: Value,
    ) -> RpcResponse {
        let get_params: PromptsGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Invalid prompts/get parameters: {}", e),
                    None,
                );
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!("Handling prompts/get request for: {}", get_params.name);

        let messages = match get_params.name.as_str() {
            "file_operation" => {
                let operation = get_params
                    .arguments
                    .get("operation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("read");
                let path = get_params
                    .arguments
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/path/to/file");

                vec![PromptMessage {
                    role: "user".to_string(),
                    content: PromptContent::Text {
                        text: format!(
                            "I need to {} the file at '{}'. Can you help me use the appropriate MCP tool to {} this file safely within the server's policy constraints?",
                            operation, path, operation
                        ),
                    },
                }]
            }
            "command_execution" => {
                let command_id = get_params
                    .arguments
                    .get("command_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("echo");

                vec![PromptMessage {
                    role: "user".to_string(),
                    content: PromptContent::Text {
                        text: format!(
                            "I want to execute the '{}' command. Can you show me how to use the run_command tool with the proper arguments according to the server's command catalog?",
                            command_id
                        ),
                    },
                }]
            }
            "server_status" => {
                vec![PromptMessage {
                    role: "user".to_string(),
                    content: PromptContent::Text {
                        text: "Can you help me understand what this MCP server can do? Please show me what directories I can access, what commands are available, and how to use the various tools provided.".to_string(),
                    },
                }]
            }
            _ => {
                let error_msg = format!("Unknown prompt: {}", get_params.name);
                self.auditor.log_error(ctx, &error_msg, None);
                return create_error_response(id, McpErrorCode::InvalidArgs, Some(error_msg), None);
            }
        };

        let result = PromptsGetResult { messages };

        self.auditor.log_success(
            ctx,
            SuccessDetails {
                ..Default::default()
            },
        );

        create_success_response(id, serde_json::to_value(result).unwrap())
    }

    /// Handle resources/list request
    async fn handle_resources_list(
        &self,
        ctx: &AuditContext,
        id: RpcId,
        params: Value,
    ) -> RpcResponse {
        let _list_params: ResourcesListParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Invalid resources/list parameters: {}", e),
                    None,
                );
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!("Handling resources/list request");

        // Define available resources that expose server information
        let resources = vec![
            ResourceInfo {
                uri: "mdmcp://server/config".to_string(),
                name: "Server Configuration".to_string(),
                description: Some("Current server policy configuration and settings".to_string()),
                mime_type: Some("application/json".to_string()),
            },
            ResourceInfo {
                uri: "mdmcp://server/capabilities".to_string(),
                name: "Server Capabilities".to_string(),
                description: Some(
                    "Detailed information about server capabilities and features".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
            ResourceInfo {
                uri: "mdmcp://server/status".to_string(),
                name: "Server Status".to_string(),
                description: Some(
                    "Current server runtime status and health information".to_string(),
                ),
                mime_type: Some("application/json".to_string()),
            },
        ];

        let result = ResourcesListResult {
            resources,
            next_cursor: None, // No pagination for now
        };

        self.auditor.log_success(
            ctx,
            SuccessDetails {
                ..Default::default()
            },
        );

        create_success_response(id, serde_json::to_value(result).unwrap())
    }

    /// Handle resources/read request
    async fn handle_resources_read(
        &self,
        ctx: &AuditContext,
        id: RpcId,
        params: Value,
    ) -> RpcResponse {
        let read_params: ResourcesReadParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => {
                self.auditor.log_error(
                    ctx,
                    &format!("Invalid resources/read parameters: {}", e),
                    None,
                );
                return create_error_response(
                    id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };

        debug!("Handling resources/read request for: {}", read_params.uri);

        let contents = match read_params.uri.as_str() {
            "mdmcp://server/config" => {
                let config_info = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "policy_hash": &self.policy.policy_hash[..16],
                    "allowed_roots": self.policy.allowed_roots_canonical.len(),
                    "available_commands": self.policy.commands_by_id.len(),
                    "capabilities": ["tools", "prompts", "resources"]
                });

                vec![ResourceContent::Text {
                    text: serde_json::to_string_pretty(&config_info).unwrap(),
                    mime_type: Some("application/json".to_string()),
                }]
            }
            "mdmcp://server/capabilities" => {
                let capabilities_info = serde_json::json!({
                    "tools": {
                        "read_file": "Read files within allowed directories",
                        "write_file": "Write files within allowed directories with policy constraints",
                        "run_command": "Execute pre-approved commands from the catalog",
                        "list_accessible_directories": "List all directories accessible for file operations",
                        "list_available_commands": "List all commands available for execution"
                    },
                    "prompts": {
                        "file_operation": "Helper for file read/write operations",
                        "command_execution": "Helper for command execution",
                        "server_status": "Helper for server status queries"
                    },
                    "resources": {
                        "mdmcp://server/config": "Server configuration information",
                        "mdmcp://server/capabilities": "Detailed capability information",
                        "mdmcp://server/status": "Runtime status information"
                    }
                });

                vec![ResourceContent::Text {
                    text: serde_json::to_string_pretty(&capabilities_info).unwrap(),
                    mime_type: Some("application/json".to_string()),
                }]
            }
            "mdmcp://server/status" => {
                let status_info = serde_json::json!({
                    "server": "mdmcpsrvr",
                    "version": env!("CARGO_PKG_VERSION"),
                    "protocol_version": "2024-11-05",
                    "status": "running",
                    "policy": {
                        "hash": &self.policy.policy_hash[..16],
                        "roots_count": self.policy.allowed_roots_canonical.len(),
                        "commands_count": self.policy.commands_by_id.len()
                    }
                });

                vec![ResourceContent::Text {
                    text: serde_json::to_string_pretty(&status_info).unwrap(),
                    mime_type: Some("application/json".to_string()),
                }]
            }
            _ => {
                let error_msg = format!("Unknown resource URI: {}", read_params.uri);
                self.auditor.log_error(ctx, &error_msg, None);
                return create_error_response(id, McpErrorCode::InvalidArgs, Some(error_msg), None);
            }
        };

        let result = ResourcesReadResult { contents };

        self.auditor.log_success(
            ctx,
            SuccessDetails {
                ..Default::default()
            },
        );

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
            "tools/list" => {
                self.handle_tools_list(&audit_ctx, request.id, request.params)
                    .await
            }
            "tools/call" => {
                self.handle_tools_call(&audit_ctx, request.id, request.params)
                    .await
            }
            "prompts/list" => {
                self.handle_prompts_list(&audit_ctx, request.id, request.params)
                    .await
            }
            "prompts/get" => {
                self.handle_prompts_get(&audit_ctx, request.id, request.params)
                    .await
            }
            "resources/list" => {
                self.handle_resources_list(&audit_ctx, request.id, request.params)
                    .await
            }
            "resources/read" => {
                self.handle_resources_read(&audit_ctx, request.id, request.params)
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

        // Log response summary before sending
        if response.error.is_some() {
            info!("⚠️  Processing '{}' -> ERROR", request.method);
        } else {
            info!("✨ Processing '{}' -> SUCCESS", request.method);
        }

        // Send response
        if let Err(e) = send_response(&response).await {
            error!("Failed to send response: {}", e);
            eprintln!("Server error: Failed to send response: {}", e);
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
                    Some(format!("Network filesystem access blocked: {}. This policy blocks access to network-mounted filesystems (UNC paths, mapped network drives) for security reasons. To allow network filesystem access, set 'deny_network_fs: false' in your policy configuration.", path)),
                    Some(serde_json::json!({"rule": "networkFsDenied", "path": path})),
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
                let error_msg = if path.contains("(directory)") {
                    format!("Cannot read directory as file: {}. Use the 'run_command' tool with 'dir' command to list directory contents instead.", path)
                } else {
                    format!(
                        "Cannot read special file: {}. Only regular files can be read.",
                        path
                    )
                };
                return create_error_response(
                    id,
                    McpErrorCode::PolicyDeny,
                    Some(error_msg),
                    Some(serde_json::json!({"rule": "specialFile", "path": path})),
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
        // Prevent automatic deletion so paths remain valid during tests
        let test_root = temp_dir.path().to_path_buf();
        let _persisted = temp_dir.keep();

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
                    "C:/Windows/System32/cmd.exe".to_string()
                } else {
                    "/bin/echo".to_string()
                },
                args: ArgsPolicy {
                    allow: vec!["test".to_string()],
                    fixed: if cfg!(windows) {
                        vec!["/c".to_string(), "echo".to_string()]
                    } else {
                        vec![]
                    },
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
                allow_any_args: false,
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

        let params = CmdRunParams {
            command_id: "echo".to_string(),
            args: vec!["test".to_string()],
            cwd: None,
            stdin: String::new(),
            env: HashMap::new(),
            timeout_ms: None,
        };

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
