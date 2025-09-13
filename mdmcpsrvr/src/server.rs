//! # MCP Server Implementation
//!
//! Core MCP server implementation that handles JSON-RPC requests and coordinates
//! all server components including policy enforcement, file system operations,
//! command execution, and audit logging. This module serves as the main
//! orchestrator for all MCP protocol interactions.
use crate::audit::{
    AuditConfig, AuditContext, Auditor, DenialDetails, ErrorDetails, SuccessDetails,
};
use crate::cmd_catalog::{CatalogError, CommandCatalog};
use crate::fs_safety::{FsError, GuardedFileReader, GuardedFileWriter};
use crate::rpc::{
    self, create_error_response, create_success_response, send_response, validate_method,
    RpcMessage,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{Datelike, Timelike};
use mdmcp_common::{
    CmdRunParams, CmdRunResult, FsReadMetadata, FsReadParams, FsReadResult, FsWriteParams,
    FsWriteResult, InitializeParams, InitializeResult, McpErrorCode, PromptArgument, PromptContent,
    PromptInfo, PromptMessage, PromptsGetParams, PromptsGetResult, PromptsListParams,
    PromptsListResult, ResourceContent, ResourceInfo, ResourcesListParams, ResourcesListResult,
    ResourcesReadParams, ResourcesReadResult, RpcId, RpcRequest, RpcResponse, ServerCapabilities,
    ServerInfo,
};
use mdmcp_policy::{CompiledPolicy, Policy};
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info};

static ANSI_RE_FAST: Lazy<regex::Regex> = Lazy::new(|| {
    // Explicit ESC byte avoids portability issues in patches
    regex::Regex::new(r"\x1B\[[0-?]*[ -/]*[@-~]").expect("valid ANSI regex")
});

fn strip_ansi_fast(input: &str) -> String {
    ANSI_RE_FAST.replace_all(input, "").to_string()
}

#[allow(dead_code)]
fn strip_ansi(input: &str) -> String {
    let re = regex::Regex::new(r"\[[0-?]*[ -/]*[@-~]").unwrap();
    re.replace_all(input, "").to_string()
}

#[cfg(target_os = "linux")]
fn is_wsl_runtime() -> bool {
    if std::env::var("WSL_INTEROP").is_ok() || std::env::var("WSL_DISTRO_NAME").is_ok() {
        return true;
    }
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let l = release.to_ascii_lowercase();
        return l.contains("microsoft") || l.contains("wsl");
    }
    false
}

#[cfg(not(target_os = "linux"))]
fn is_wsl_runtime() -> bool {
    false
}

fn platform_string() -> String {
    if cfg!(target_os = "windows") {
        "Windows".to_string()
    } else if cfg!(target_os = "macos") {
        "macOS".to_string()
    } else if cfg!(target_os = "linux") {
        if is_wsl_runtime() {
            "Linux (WSL)".to_string()
        } else {
            "Linux".to_string()
        }
    } else {
        "Unknown".to_string()
    }
}

fn validate_file_path(path: &str) -> Result<(), String> {
    if path.starts_with("mdmcp://") {
        return Err(format!(
            "'{}' is a resource URI, not a file path. Use resources/read instead",
            path
        ));
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return Err("HTTP URLs are not valid file paths".to_string());
    }
    Ok(())
}

fn get_resource_suggestion(uri: &str) -> Option<String> {
    if uri.starts_with("mdmcp://") {
        Some(format!("Try: resources/read with uri: '{}'", uri))
    } else {
        None
    }
}
fn truncate_str(s: &str, max: usize) -> String {
    // Truncate on UTF-8 character boundary to avoid invalid slices.
    let mut it = s.chars();
    let mut out = String::with_capacity(std::cmp::min(s.len(), max));
    for i in 0..max {
        match it.next() {
            Some(c) => out.push(c),
            None => break,
        }
        if i + 1 == max {
            if it.next().is_some() {
                out.push('…');
            }
            break;
        }
    }
    out
}

fn is_path_absolute_like(p: &str) -> bool {
    use std::path::Path;
    let path = Path::new(p);
    if path.is_absolute() {
        return true;
    }
    #[cfg(windows)]
    {
        let b = p.as_bytes();
        if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
            return true;
        }
        if p.starts_with("\\\\") {
            // UNC paths
            return true;
        }
    }
    false
}

/// Main MCP server instance
pub struct Server {
    policy: RwLock<Arc<CompiledPolicy>>, // hot-swappable policy
    auditor: Auditor,
    command_catalog: RwLock<CommandCatalog>, // rebuilt on policy reload
    config_path: PathBuf,
    default_cwd: RwLock<Option<PathBuf>>,
    next_command_cwd: RwLock<Option<PathBuf>>,
}
impl Server {
    /// Build a minimal structured error context for error.data.context
    /// This keeps payloads small and stable while giving clients a typed hint,
    /// a short user-facing message, retryability, and optional suggestions.
    fn minimal_error_context(
        &self,
        error_type: &str,
        user_message: &str,
        retryable: bool,
        suggestions: &[&str],
    ) -> serde_json::Value {
        let mut suggs: Vec<String> = Vec::new();
        for s in suggestions.iter().take(3) {
            suggs.push(truncate_str(s, 256));
        }
        serde_json::json!({
            "schemaVersion": 1,
            "type": error_type,
            "userMessage": truncate_str(user_message, 256),
            "suggestions": suggs,
            "retryable": retryable
        })
    }
    /// Build standardized error.data payload with common fields plus extras
    fn build_error_data(
        &self,
        method: &str,
        id: &RpcId,
        reason: &str,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        // Capture current policy hash and server version
        let policy_hash = { self.policy.read().unwrap().policy_hash.clone() };
        let mut base = serde_json::json!({
            "method": method,
            "reason": reason,
            "requestId": generate_request_id(id),
            "serverVersion": env!("CARGO_PKG_VERSION"),
            "policyHash": policy_hash,
        });
        if let serde_json::Value::Object(extra_obj) = extra {
            if let serde_json::Value::Object(ref mut base_obj) = base {
                for (k, v) in extra_obj {
                    base_obj.insert(k, v);
                }
            }
        }
        // Ensure a nested structured context exists under data.context
        if let serde_json::Value::Object(ref mut base_obj) = base {
            let mut has_context = false;
            if let Some(ctx) = base_obj.get("context") {
                if ctx.is_object() {
                    has_context = true;
                }
            }
            if !has_context {
                let ctx = serde_json::json!({
                    "schemaVersion": 1,
                    "type": "internal_error",
                    "userMessage": truncate_str(reason, 256),
                    "suggestions": [],
                    "retryable": false
                });
                base_obj.insert("context".to_string(), ctx);
            }
        }
        base
    }
    /// Create new server instance with compiled policy
    pub async fn new(policy: Arc<CompiledPolicy>, config_path: PathBuf) -> Result<Self> {
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
            policy: RwLock::new(policy),
            auditor,
            command_catalog: RwLock::new(command_catalog),
            config_path,
            default_cwd: RwLock::new(None),
            next_command_cwd: RwLock::new(None),
        })
    }
    /// Handle a JSON-RPC message line (request or notification)
    pub async fn handle_request_line(&self, line: &str) -> Result<()> {
        info!("Incoming request: {}", line);
        match rpc::parse_message(line) {
            Ok(RpcMessage::Request(request)) => {
                info!(
                    "Parsed request: method='{}', id={:?}",
                    request.method, request.id
                );
                self.handle_request(request).await;
                debug!("Request handling completed");
            }
            Ok(RpcMessage::Notification { method, params }) => {
                info!(
                    "Parsed notification: method='{}', params={}",
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
                let data = self.build_error_data(
                    "unknown",
                    &RpcId::Null,
                    "invalidJson",
                    serde_json::json!({}),
                );
                let response = create_error_response(
                    RpcId::Null,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid JSON-RPC message: {}", e)),
                    Some(data),
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
                info!("Received initialized notification - handshake complete");
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
                let data = self.build_error_data(
                    "initialize",
                    &id,
                    "invalidParameters",
                    serde_json::json!({}),
                );
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(data),
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
            let data = self.build_error_data(
                "initialize",
                &id,
                "unsupportedProtocolVersion",
                serde_json::json!({
                    "protocolVersion": init_params.protocol_version
                }),
            );
            return create_error_response(
                id,
                McpErrorCode::InvalidArgs,
                Some(error_msg.clone()),
                Some(data),
            );
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
        // Build dynamic, example-first description for run_command from policy
        let run_cmd_desc: String = {
            let policy = { self.policy.read().unwrap().clone() };
            let mut cmds: Vec<_> = policy.commands_by_id.values().collect();
            cmds.sort_by(|a, b| a.rule.id.cmp(&b.rule.id));
            let mut parts: Vec<String> = Vec::new();
            for c in cmds.iter().take(6) {
                let id = &c.rule.id;
                if let Some(desc) = &c.rule.description {
                    let d = desc.trim();
                    if !d.is_empty() {
                        let short = if d.len() > 40 {
                            format!("{}…", &d[..40])
                        } else {
                            d.to_string()
                        };
                        parts.push(format!("{}: {}", id, short));
                        continue;
                    }
                }
                parts.push(id.clone());
            }
            let listed = if parts.is_empty() {
                "no configured commands".to_string()
            } else {
                parts.join(", ")
            };
            format!(
                "Commands providing functions such as {}. Use run_command with 'commandId'. For full details, use resources/read on 'mdmcp://commands/catalog' (not file tools).",
                listed
            )
        };
        // Build dynamic command_id enum and oneOf entries (cap to 50 to keep payload small)
        let (cmd_id_enum, cmd_id_oneof) = {
            let policy = { self.policy.read().unwrap().clone() };
            let mut cmds: Vec<_> = policy.commands_by_id.values().collect();
            cmds.sort_by(|a, b| a.rule.id.cmp(&b.rule.id));
            let mut ids = Vec::new();
            let mut oneofs: Vec<serde_json::Value> = Vec::new();
            for c in cmds.into_iter().take(50) {
                ids.push(c.rule.id.clone());
                let desc = c.rule.description.clone().unwrap_or_default();
                oneofs.push(serde_json::json!({
                    "const": c.rule.id,
                    "description": if desc.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(desc) }
                }));
            }
            (ids, oneofs)
        };

        let platform = platform_string();
        let tools = serde_json::json!({
            "tools": [
                {
                    "name": "get_datetime",
                    "description": "Get current system date, time, and timezone",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {"type": "string", "enum": ["iso8601", "unix", "human"], "default": "iso8601"}
                        },
                        "additionalProperties": false
                    }
                },
                {
                    "name": "get_working_directory",
                    "description": "Get current working directory",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
                },
                {
                    "name": "set_working_directory",
                    "description": "Change working directory for subsequent run_command calls and for relative file tool paths",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "scope": {"type": "string", "enum": ["session", "next_command"], "default": "session"}
                        },
                        "required": ["path"],
                        "additionalProperties": false
                    }
                },
                {
                    "name": "platform_hints",
                    "description": format!("Running on {}. Note: Claude Desktop only has access to directories allowed by server policy. Use 'list_accessible_directories' to see them.", platform),
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
                },
                {
                    "name": "read_bytes",
                    "description": "Read bytes from a file (simple): {path, offset?, length?, encoding?}. Note: Only files within allowed roots are accessible; use 'list_accessible_directories' to view them.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "offset": {"type": ["integer","null"], "description": "Byte offset"},
                            "length": {"type": ["integer","null"], "description": "Byte length"},
                            "encoding": {"type": "string", "enum": ["utf8","base64"], "default": "utf8"}
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "read_lines",
                    "description": "Read lines from a file (simple): {path, line_offset?, line_count?, encoding?}. Note: Only files within allowed roots are accessible; use 'list_accessible_directories' to view them.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "line_offset": {"type": ["integer","null"], "description": "Line start (0-index)"},
                            "line_count": {"type": ["integer","null"], "description": "Number of lines"},
                            "encoding": {"type": "string", "enum": ["utf8","base64"], "default": "utf8"}
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write to a file (simple): {path, data, append?, create?, overwrite?, encoding?}. Note: Only files within allowed roots are accessible; use 'list_accessible_directories' to view them.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "data": {"type": "string"},
                            "append": {"type": ["boolean","null"], "default": false},
                            "create": {"type": ["boolean","null"], "default": true},
                            "overwrite": {"type": ["boolean","null"], "default": true},
                            "encoding": {"type": "string", "enum": ["utf8","base64"], "default": "utf8"}
                        },
                        "required": ["path","data"]
                    }
                },
                {
                    "name": "stat_path",
                    "description": "Get file/directory info: {path}. Note: Only files within allowed roots are accessible; use 'list_accessible_directories' to view them.",
                    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
                },
                {
                    "name": "list_directory",
                    "description": "List directory entries: {path}. Note: Only directories within allowed roots are accessible; use 'list_accessible_directories' to view them.",
                    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
                },


                {
                    "name": "run_command",
                    "description": run_cmd_desc,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command_id": {
                                "type": "string",
                                "description": "ID of the command to run from the catalog (see enum below); full catalog at mdmcp://commands/catalog",
                                "enum": cmd_id_enum,
                                "oneOf": cmd_id_oneof
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
                    "name": "reload_policy",
                    "description": "Reload the server policy from disk without restarting",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
                },
                {
                    "name": "server_info",
                    "description": "Show server version, build time, current policy summary, and policy format details",
                    "inputSchema": {"type": "object", "properties": {"format": {"type": "string", "enum": ["text", "json"], "default": "text"}}, "additionalProperties": false}
                },
                {
                    "name": "environment_defaults",
                    "description": "Show the default environment variable names the server passes to child processes",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
                },
                {
                    "name": "Documentation",
                    "description": "Usage guide for mdmcpcfg and mdmcpsrvr: install/update, manage policy (add/remove roots and commands)",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
                },
                {
                    "name": "list_resources",
                    "description": "List available MCP resources (use resources/read to access)",
                    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
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
                let data = self.build_error_data(
                    "tools/call",
                    &id,
                    "invalidParameters",
                    serde_json::json!({}),
                );
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some("Missing tool name".to_string()),
                    Some(data),
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
            "get_datetime" => {
                #[allow(clippy::unwrap_used)]
                fn fmt_offset(secs: i32) -> String {
                    let sign = if secs >= 0 { '+' } else { '-' };
                    let abs = secs.abs();
                    let h = abs / 3600;
                    let m = (abs % 3600) / 60;
                    format!("{}{:02}:{:02}", sign, h, m)
                }

                let now = chrono::Local::now();
                let iso = now.to_rfc3339();
                let unix = now.timestamp();
                let offset = fmt_offset(now.offset().local_minus_utc());
                let tz = iana_time_zone::get_timezone().unwrap_or_else(|_| "Local".to_string());
                let weekday = now.format("%A").to_string();
                let components = serde_json::json!({
                    "year": now.year(),
                    "month": now.month(),
                    "day": now.day(),
                    "hour": now.hour(),
                    "minute": now.minute(),
                    "second": now.second(),
                    "weekday": weekday
                });
                // Optional format: iso8601 | unix | human
                let format = tool_args
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("json");
                let result = match format {
                    "iso8601" => serde_json::json!({
                        "content": [{"type": "text", "text": iso}],
                        "isError": false
                    }),
                    "unix" => serde_json::json!({
                        "content": [{"type": "text", "text": unix.to_string()}],
                        "isError": false
                    }),
                    "human" => {
                        let human = format!(
                            "{} {:04}-{:02}-{:02} {:02}:{:02}:{:02} (UTC{}) — {}",
                            weekday,
                            now.year(),
                            now.month(),
                            now.day(),
                            now.hour(),
                            now.minute(),
                            now.second(),
                            offset,
                            tz
                        );
                        serde_json::json!({
                            "content": [{"type": "text", "text": human}],
                            "isError": false
                        })
                    }
                    _ => {
                        // Default: JSON payload for structured clients
                        let payload = serde_json::json!({
                            "datetime": iso,
                            "timezone": tz,
                            "offset": offset,
                            "unix": unix,
                            "components": components
                        });
                        serde_json::json!({
                            "content": [{"type": "text", "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())}],
                            "isError": false
                        })
                    }
                };
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "platform_hints" => {
                // Return a brief set of platform hints and capabilities
                let plat = platform_string();
                let is_wsl = if plat.contains("WSL") { " (WSL)" } else { "" };
                let mut msg = format!(
                    "Running on {}{}.\n- File tools operate within allowed roots only.\n- Use 'list_accessible_directories' to discover accessible paths.\n- Use 'run_command' with a catalog 'command_id' to execute approved tools.",
                    plat, is_wsl
                );
                // Append a quick summary of root count and some examples
                let pol = { self.policy.read().unwrap().clone() };
                let total = pol.allowed_roots_canonical.len();
                if total > 0 {
                    use std::fmt::Write as _;
                    let mut preview = String::new();
                    for r in pol.allowed_roots_canonical.iter().take(3) {
                        let _ = writeln!(&mut preview, "  - {}", r.display());
                    }
                    if total > 3 {
                        let _ = writeln!(&mut preview, "  - ... and {} more", total - 3);
                    }
                    msg.push_str(&format!("\nAllowed roots ({} total):\n{}", total, preview));
                }
                let result = serde_json::json!({
                    "content": [{"type": "text", "text": msg}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "get_working_directory" => {
                let cwd = std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "".to_string());
                let payload = serde_json::json!({"cwd": cwd});
                let result = serde_json::json!({
                    "content": [{"type": "text", "text": payload.to_string()}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "set_working_directory" => {
                let path = tool_args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if let Err(mut msg) = validate_file_path(path) {
                    if let Some(s) = get_resource_suggestion(path) {
                        msg.push_str(&format!("\n{}", s));
                    }
                    return create_error_response(id, McpErrorCode::InvalidArgs, Some(msg), None);
                }
                let candidate = match dunce::canonicalize(path) {
                    Ok(p) => p,
                    Err(e) => {
                        return create_error_response(
                            id,
                            McpErrorCode::InvalidArgs,
                            Some(format!("Invalid path: {}", e)),
                            None,
                        )
                    }
                };
                if !candidate.is_dir() {
                    return create_error_response(
                        id,
                        McpErrorCode::InvalidArgs,
                        Some("Path is not a directory".to_string()),
                        None,
                    );
                }
                let allowed = {
                    let pol = self.policy.read().unwrap();
                    pol.is_path_allowed(&candidate).unwrap_or(false)
                };
                if !allowed {
                    return create_error_response(
                        id,
                        McpErrorCode::PolicyDeny,
                        Some("Working directory not within allowed roots".to_string()),
                        None,
                    );
                }
                let scope = tool_args
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .unwrap_or("session");
                match scope {
                    "next_command" => {
                        let mut lock = self.next_command_cwd.write().unwrap();
                        *lock = Some(candidate.clone());
                    }
                    _ => {
                        let mut lock = self.default_cwd.write().unwrap();
                        *lock = Some(candidate.clone());
                    }
                }
                let payload = serde_json::json!({
                    "cwd": candidate.to_string_lossy(),
                    "scope": scope
                });
                let result = serde_json::json!({
                    "content": [{"type": "text", "text": payload.to_string()}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "read_bytes" => {
                if let Some(p) = tool_args.get("path").and_then(|v| v.as_str()) {
                    if let Err(mut msg) = validate_file_path(p) {
                        if let Some(s) = get_resource_suggestion(p) {
                            msg.push_str(&format!("\n{}", s));
                        }
                        return create_error_response(
                            id.clone(),
                            McpErrorCode::InvalidArgs,
                            Some(msg),
                            Some(self.build_error_data(
                                "tools/call",
                                &id,
                                "invalidPath",
                                serde_json::json!({}),
                            )),
                        );
                    }
                }
                let resolved_path = tool_args.get("path").and_then(|v| v.as_str()).map(|s| {
                    if is_path_absolute_like(s) {
                        s.to_string()
                    } else {
                        let dc = self.default_cwd.read().unwrap();
                        if let Some(base) = &*dc {
                            base.join(s).to_string_lossy().to_string()
                        } else {
                            s.to_string()
                        }
                    }
                });
                let fs_params = serde_json::json!({
                    "path": resolved_path,
                    "encoding": tool_args.get("encoding").cloned().unwrap_or(serde_json::json!("utf8")),
                    "offset": tool_args.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                    "length": tool_args.get("length").cloned().unwrap_or(serde_json::Value::Null),
                    "mode": serde_json::Value::Null,
                    "line_offset": serde_json::Value::Null,
                    "line_count": serde_json::Value::Null,
                    "include_stats": serde_json::Value::Null
                });
                let resp = self.handle_fs_read(ctx, id.clone(), fs_params).await;
                if let Some(err) = &resp.error {
                    return create_error_response(
                        id,
                        McpErrorCode::Internal,
                        Some(err.message.clone()),
                        resp.error.as_ref().and_then(|e| e.data.clone()),
                    );
                }
                let raw = match resp.result {
                    Some(v) => v,
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some("fs.read returned no result".to_string()),
                            None,
                        )
                    }
                };
                let parsed: Result<mdmcp_common::FsReadResult, _> = serde_json::from_value(raw);
                let read_out = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some(format!("Failed to parse fs.read result: {}", e)),
                            None,
                        )
                    }
                };
                let result = serde_json::json!({
                    "content": [{"type":"text","text": read_out.content}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "read_lines" => {
                if let Some(p) = tool_args.get("path").and_then(|v| v.as_str()) {
                    if let Err(mut msg) = validate_file_path(p) {
                        if let Some(s) = get_resource_suggestion(p) {
                            msg.push_str(&format!("\n{}", s));
                        }
                        return create_error_response(
                            id.clone(),
                            McpErrorCode::InvalidArgs,
                            Some(msg),
                            Some(self.build_error_data(
                                "tools/call",
                                &id,
                                "invalidPath",
                                serde_json::json!({}),
                            )),
                        );
                    }
                }
                let resolved_path = tool_args.get("path").and_then(|v| v.as_str()).map(|s| {
                    if is_path_absolute_like(s) {
                        s.to_string()
                    } else {
                        let dc = self.default_cwd.read().unwrap();
                        if let Some(base) = &*dc {
                            base.join(s).to_string_lossy().to_string()
                        } else {
                            s.to_string()
                        }
                    }
                });
                let fs_params = serde_json::json!({
                    "path": resolved_path,
                    "encoding": tool_args.get("encoding").cloned().unwrap_or(serde_json::json!("utf8")),
                    "line_offset": tool_args.get("line_offset").cloned().unwrap_or(serde_json::Value::Null),
                    "line_count": tool_args.get("line_count").cloned().unwrap_or(serde_json::Value::Null),
                    "mode": "lines",
                    "offset": serde_json::Value::Null,
                    "length": serde_json::Value::Null,
                    "include_stats": serde_json::Value::Null
                });
                let resp = self.handle_fs_read(ctx, id.clone(), fs_params).await;
                if let Some(err) = &resp.error {
                    return create_error_response(
                        id,
                        McpErrorCode::Internal,
                        Some(err.message.clone()),
                        resp.error.as_ref().and_then(|e| e.data.clone()),
                    );
                }
                let raw = match resp.result {
                    Some(v) => v,
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some("fs.read returned no result".to_string()),
                            None,
                        )
                    }
                };
                let parsed: Result<mdmcp_common::FsReadResult, _> = serde_json::from_value(raw);
                let read_out = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some(format!("Failed to parse fs.read result: {}", e)),
                            None,
                        )
                    }
                };
                let result = serde_json::json!({
                    "content": [{"type":"text","text": read_out.content}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }

            "write_file" => {
                if let Some(p) = tool_args.get("path").and_then(|v| v.as_str()) {
                    if let Err(mut msg) = validate_file_path(p) {
                        if let Some(s) = get_resource_suggestion(p) {
                            msg.push_str(&format!("\n{}", s));
                        }
                        return create_error_response(
                            id.clone(),
                            McpErrorCode::InvalidArgs,
                            Some(msg),
                            Some(self.build_error_data(
                                "tools/call",
                                &id,
                                "invalidPath",
                                serde_json::json!({}),
                            )),
                        );
                    }
                }
                // Simple writer: supports append/create/overwrite booleans
                let append = tool_args
                    .get("append")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let create = tool_args
                    .get("create")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let overwrite = tool_args
                    .get("overwrite")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let mode = if append {
                    serde_json::json!("append")
                } else {
                    serde_json::Value::Null
                };
                let resolved_path = tool_args.get("path").and_then(|v| v.as_str()).map(|s| {
                    if is_path_absolute_like(s) {
                        s.to_string()
                    } else {
                        let dc = self.default_cwd.read().unwrap();
                        if let Some(base) = &*dc {
                            base.join(s).to_string_lossy().to_string()
                        } else {
                            s.to_string()
                        }
                    }
                });
                let fs_params = serde_json::json!({
                    "path": resolved_path,
                    "data": tool_args.get("data"),
                    "encoding": tool_args.get("encoding").cloned().unwrap_or(serde_json::json!("utf8")),
                    "create": create,
                    "atomic": true,
                    "mode": mode,
                    "overwrite": overwrite
                });
                if !overwrite {
                    if let Some(p) = tool_args.get("path").and_then(|v| v.as_str()) {
                        if std::path::Path::new(p).exists() && !append {
                            return create_error_response(
                                id,
                                McpErrorCode::InvalidArgs,
                                Some("File exists and overwrite=false".to_string()),
                                None,
                            );
                        }
                    }
                }
                let resp = self.handle_fs_write(ctx, id.clone(), fs_params).await;
                if let Some(err) = &resp.error {
                    return create_error_response(
                        id,
                        McpErrorCode::Internal,
                        Some(err.message.clone()),
                        resp.error.as_ref().and_then(|e| e.data.clone()),
                    );
                }
                let raw = match resp.result {
                    Some(v) => v,
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some("fs.write returned no result".to_string()),
                            None,
                        )
                    }
                };
                let parsed: Result<mdmcp_common::FsWriteResult, _> = serde_json::from_value(raw);
                let write_out = match parsed {
                    Ok(v) => v,
                    Err(e) => {
                        return create_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some(format!("Failed to parse fs.write result: {}", e)),
                            None,
                        )
                    }
                };
                let result = serde_json::json!({
                    "content": [{"type":"text","text": format!("Write OK. bytesWritten={} newSize={} created={}", write_out.bytes_written, write_out.file_size, write_out.created)}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "stat_path" => {
                let path = match tool_args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p.to_string(),
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::InvalidArgs,
                            Some("Missing path".to_string()),
                            None,
                        )
                    }
                };
                if let Err(mut msg) = validate_file_path(&path) {
                    if let Some(s) = get_resource_suggestion(&path) {
                        msg.push_str(&format!("\n{}", s));
                    }
                    return create_error_response(
                        id.clone(),
                        McpErrorCode::InvalidArgs,
                        Some(msg),
                        Some(self.build_error_data(
                            "tools/call",
                            &id,
                            "invalidPath",
                            serde_json::json!({}),
                        )),
                    );
                }
                let effective_path = if is_path_absolute_like(&path) {
                    path.clone()
                } else {
                    let dc = self.default_cwd.read().unwrap();
                    if let Some(base) = &*dc {
                        base.join(&path).to_string_lossy().to_string()
                    } else {
                        path.clone()
                    }
                };
                let policy = { self.policy.read().unwrap().clone() };
                match crate::fs_safety::canonicalize_path(std::path::Path::new(&effective_path)) {
                    Ok(canon) => {
                        if !policy
                            .allowed_roots_canonical
                            .iter()
                            .any(|r| canon.starts_with(r))
                        {
                            return create_error_response(
                                id,
                                McpErrorCode::PolicyDeny,
                                Some(format!("Path not allowed: {}", canon.display())),
                                None,
                            );
                        }
                        if policy.policy.deny_network_fs {
                            if let Ok(true) = crate::fs_safety::is_network_fs(&canon) {
                                return create_error_response(
                                    id,
                                    McpErrorCode::PolicyDeny,
                                    Some("Network filesystem denied".to_string()),
                                    None,
                                );
                            }
                        }
                        match std::fs::metadata(&canon) {
                            Ok(m) => {
                                let is_file = m.is_file();
                                let is_dir = m.is_dir();
                                let size = m.len();
                                let mtime = m
                                    .modified()
                                    .ok()
                                    .and_then(|t| t.elapsed().ok())
                                    .map(|e| format!("{}s ago", e.as_secs()));
                                let json = serde_json::json!({"path": canon.display().to_string(), "isFile": is_file, "isDir": is_dir, "size": size, "modified": mtime});
                                let result = serde_json::json!({"content":[{"type":"text","text": json.to_string()}], "isError": false});
                                self.auditor.log_success(ctx, SuccessDetails::default());
                                create_success_response(id, result)
                            }
                            Err(e) => create_error_response(
                                id,
                                McpErrorCode::IoError,
                                Some(format!("Stat error: {}", e)),
                                None,
                            ),
                        }
                    }
                    Err(_) => create_error_response(
                        id,
                        McpErrorCode::InvalidArgs,
                        Some("Invalid path".to_string()),
                        None,
                    ),
                }
            }
            "list_directory" => {
                let path = match tool_args.get("path").and_then(|v| v.as_str()) {
                    Some(p) => p.to_string(),
                    None => {
                        return create_error_response(
                            id,
                            McpErrorCode::InvalidArgs,
                            Some("Missing path".to_string()),
                            None,
                        )
                    }
                };
                if let Err(mut msg) = validate_file_path(&path) {
                    if let Some(s) = get_resource_suggestion(&path) {
                        msg.push_str(&format!("\n{}", s));
                    }
                    return create_error_response(
                        id.clone(),
                        McpErrorCode::InvalidArgs,
                        Some(msg),
                        Some(self.build_error_data(
                            "tools/call",
                            &id,
                            "invalidPath",
                            serde_json::json!({}),
                        )),
                    );
                }
                let effective_path = if is_path_absolute_like(&path) {
                    path.clone()
                } else {
                    let dc = self.default_cwd.read().unwrap();
                    if let Some(base) = &*dc {
                        base.join(&path).to_string_lossy().to_string()
                    } else {
                        path.clone()
                    }
                };
                let policy = { self.policy.read().unwrap().clone() };
                match crate::fs_safety::canonicalize_path(std::path::Path::new(&effective_path)) {
                    Ok(canon) => {
                        if !policy
                            .allowed_roots_canonical
                            .iter()
                            .any(|r| canon.starts_with(r))
                        {
                            return create_error_response(
                                id,
                                McpErrorCode::PolicyDeny,
                                Some(format!("Path not allowed: {}", canon.display())),
                                None,
                            );
                        }
                        if policy.policy.deny_network_fs {
                            if let Ok(true) = crate::fs_safety::is_network_fs(&canon) {
                                return create_error_response(
                                    id,
                                    McpErrorCode::PolicyDeny,
                                    Some("Network filesystem denied".to_string()),
                                    None,
                                );
                            }
                        }
                        match std::fs::read_dir(&canon) {
                            Ok(iter) => {
                                let mut entries = Vec::new();
                                for e in iter.flatten() {
                                    let file_type = e.file_type().ok();
                                    let is_dir =
                                        file_type.as_ref().map(|t| t.is_dir()).unwrap_or(false);
                                    let is_file =
                                        file_type.as_ref().map(|t| t.is_file()).unwrap_or(false);
                                    entries.push(serde_json::json!({"name": e.file_name().to_string_lossy(), "isDir": is_dir, "isFile": is_file}));
                                }
                                let json = serde_json::json!({"path": canon.display().to_string(), "entries": entries});
                                let result = serde_json::json!({"content":[{"type":"text","text": json.to_string()}], "isError": false});
                                self.auditor.log_success(ctx, SuccessDetails::default());
                                create_success_response(id, result)
                            }
                            Err(e) => create_error_response(
                                id,
                                McpErrorCode::IoError,
                                Some(format!("list error: {}", e)),
                                None,
                            ),
                        }
                    }
                    Err(_) => create_error_response(
                        id,
                        McpErrorCode::InvalidArgs,
                        Some("Invalid path".to_string()),
                        None,
                    ),
                }
            }

            "run_command" => {
                // Convert tool args to cmd.run format
                // Choose working directory from next_command or session default if present
                let chosen_cwd: Option<String> = {
                    let mut next = self.next_command_cwd.write().unwrap();
                    if let Some(p) = next.take() {
                        Some(p.to_string_lossy().to_string())
                    } else {
                        drop(next);
                        let sess = self.default_cwd.read().unwrap();
                        sess.as_ref().map(|p| p.to_string_lossy().to_string())
                    }
                };
                let mut cmd_params = serde_json::json!({
                    "commandId": tool_args.get("command_id"),
                    "args": tool_args.get("args").unwrap_or(&serde_json::json!([])),
                    "stdin": tool_args.get("stdin").unwrap_or(&serde_json::json!("")),
                    "cwd": null,
                    "env": {},
                    "timeoutMs": null
                });
                if let Some(cwd_s) = chosen_cwd {
                    if let Some(map) = cmd_params.as_object_mut() {
                        map.insert("cwd".to_string(), serde_json::json!(cwd_s));
                    }
                }
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
                    .read()
                    .unwrap()
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

            "reload_policy" => match self.reload_policy().await {
                Ok(new_policy) => {
                    let msg = format!(
                        "Policy reloaded successfully. Hash: {}â€¦ | roots: {} | commands: {}",
                        &new_policy.policy_hash[..16],
                        new_policy.allowed_roots_canonical.len(),
                        new_policy.commands_by_id.len()
                    );
                    let result = serde_json::json!({
                        "content": [{"type": "text", "text": msg}],
                        "isError": false
                    });
                    tracing::info!("Policy reloaded. Docs may be stale; run 'mdmcpcfg docs --build' to refresh.");
                    self.auditor.log_success(ctx, SuccessDetails::default());
                    create_success_response(id, result)
                }
                Err(e) => {
                    self.auditor
                        .log_error(ctx, &format!("Policy reload failed: {}", e), None);
                    create_error_response(
                        id,
                        McpErrorCode::Internal,
                        Some(format!("Policy reload failed: {}", e)),
                        None,
                    )
                }
            },
            "server_info" => {
                let policy = { self.policy.read().unwrap().clone() };
                let version = env!("CARGO_PKG_VERSION");
                let build_str = if let Some(epoch_str) = option_env!("BUILD_EPOCH") {
                    if let Ok(secs) = epoch_str.parse::<i64>() {
                        if let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0) {
                            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                        } else {
                            "unknown".to_string()
                        }
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                };
                // Detailed policy format description (concise but informative)
                let policy_format = r#"Policy v1 (YAML) fields:
- version: number (required)
- deny_network_fs: bool
- allowed_roots: [string path, ...] (required)
- write_rules: [{ path, recursive, max_file_bytes, create_if_missing }]
- commands: [{
    id, exec (absolute path),
    args: { allow: [string], fixed: [string], patterns: [{type: "regex", value: "..."}] },
    cwd_policy: one of [within_root, fixed, none],
    env_allowlist: [VAR,...], timeout_ms, max_output_bytes,
    platform: ["windows"|"linux"|"macos"], allow_any_args: bool
  }]
- logging: { file: string?, redact: [string] }
- limits: { max_read_bytes, max_cmd_concurrency }

Notes:
- mdmcpcfg installs a read-only core policy with deny_network_fs=true by default.
- The effective deny_network_fs is core OR user; user policy cannot disable a core=true.
"#;
                let summary = format!(
                    "mdmcpsrvr v{}\nBuild: {}\nPolicy hash: {}\nAllowed roots: {}\nCommands: {}\n\nPolicy format:\n{}",
                    version,
                    build_str,
                    &policy.policy_hash[..16],
                    policy.allowed_roots_canonical.len(),
                    policy.commands_by_id.len(),
                    policy_format
                );
                // Support optional format: { format: "json" | "text" }
                let format = tool_args
                    .get("format")
                    .and_then(|v| v.as_str())
                    .unwrap_or("text");
                let result = if format.eq_ignore_ascii_case("json") {
                    let json_obj = serde_json::json!({
                        "server": {
                            "name": "mdmcpsrvr",
                            "version": version,
                            "build": build_str,
                            "protocolVersion": "2024-11-05"
                        },
                        "policy": {
                            "hash": &policy.policy_hash[..16],
                            "rootsCount": policy.allowed_roots_canonical.len(),
                            "commandsCount": policy.commands_by_id.len()
                        },
                        "guidance": {
                            "resourceAccess": [
                                "Use resources/read for mdmcp:// URIs",
                                "Use file tools (read_lines, read_bytes, write_file) for filesystem paths",
                                "Run resources/list to see all available resources"
                            ]
                        }
                    });
                    serde_json::json!({
                        "content": [{"type":"text","text": serde_json::to_string_pretty(&json_obj).unwrap()}],
                        "isError": false
                    })
                } else {
                    let guidance = "\nResource Access:\n- Use resources/read for mdmcp:// URIs\n- Use file tools (read_lines, read_bytes, write_file) for filesystem paths\n- Available resources: run resources/list\n";
                    serde_json::json!({
                        "content": [{"type":"text","text": format!("{}{}", summary, guidance)}],
                        "isError": false
                    })
                };
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "environment_defaults" => {
                // Describe baseline env keys included by the sandbox (names only, actual values are taken from the process env/request env)
                #[cfg(windows)]
                let keys: &[&str] = &[
                    "PATH",
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
                    "CARGO_HOME",
                    "RUSTUP_HOME",
                    "NUMBER_OF_PROCESSORS",
                    "PROCESSOR_ARCHITECTURE",
                ];
                #[cfg(unix)]
                let keys: &[&str] = &[
                    "PATH",
                    "HOME",
                    "USER",
                    "SHELL",
                    "TMPDIR",
                    "CARGO_HOME",
                    "RUSTUP_HOME",
                ];

                let mut text = String::new();
                text.push_str(
                    "Default environment variable names included by the sandbox (names only):\n\n",
                );
                for k in keys {
                    text.push_str("  - ");
                    text.push_str(k);
                    text.push('\n');
                }
                text.push_str("\nNotes:\n");
                text.push_str("- Only names listed above (plus any allowlisted names) are passed to child processes.\n");
                text.push_str("- Values are taken from the mdmcpsrvr process environment or the cmd.run request env; nothing is fabricated.\n");
                text.push_str(
                    "- On Windows, PATH is sanitized to avoid GNU link.exe shadowing MSVC.\n",
                );

                let result = serde_json::json!({
                    "content": [{"type":"text","text": text}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "Documentation" | "documentation" => {
                let policy = { self.policy.read().unwrap().clone() };
                let version = env!("CARGO_PKG_VERSION");
                let build_str = if let Some(epoch_str) = option_env!("BUILD_EPOCH") {
                    if let Ok(secs) = epoch_str.parse::<i64>() {
                        if let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0) {
                            dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                        } else {
                            "unknown".to_string()
                        }
                    } else {
                        "unknown".to_string()
                    }
                } else {
                    "unknown".to_string()
                };
                let doc = format!(
                    r#"mdmcp Documentation

Server: mdmcpsrvr v{} (build {})
Policy hash: {}… | roots: {} | commands: {}

mdmcpcfg – Policy and Install CLI
- Show policy: `mdmcpcfg policy show`
- Edit policy: `mdmcpcfg policy edit` (opens your editor)
- Validate policy: `mdmcpcfg policy validate`
- Add allowed root: `mdmcpcfg policy add-root "<path>" --write`
  • Adds to `allowed_roots` and (with --write) creates a write rule.
- Add command: `mdmcpcfg policy add-command <id> --exec "<absolute_exec_path>"`
  • Optional: `--allow <arg>` (repeatable), `--pattern <regex>` (repeatable).
  • Defaults: `cwd_policy: within_root`, `allow_any_args: true`, sane timeouts.
  • Recommendation: add a short `description` to each custom command so clients can explain its purpose.
  • Environment variables: list any required names in `env_allowlist`. Values come from the cmd.run request `env` or the server process environment. With split policy, set/override these in `policy.user.yaml`.
- Set static env for a command (policy-owned values): `mdmcpcfg policy set-env <id> NAME=VALUE [NAME=VALUE ...]`
- Remove static env entries: `mdmcpcfg policy unset-env <id> NAME [NAME ...]`
- List static env entries: `mdmcpcfg policy list-env <id>`
- Remove a rule or command: use `mdmcpcfg policy edit`, delete the YAML entry, then `mdmcpcfg policy validate`.

Installing and Updating mdmcpsrvr
- Install latest release and configure Claude Desktop: `mdmcpcfg install`
  • Optionally `--dest <dir>` to choose binary directory.
  • `--local --local-path <path>` to install a locally built binary.
- Update to latest: `mdmcpcfg update` (flags: `--channel stable|beta`, `--force`)
  • Rollback is not yet implemented (`--rollback` will report unimplemented).
- Uninstall: no dedicated command. To remove manually:
  1) Stop clients using the server (e.g., close Claude Desktop).
  2) Delete the server binary from the mdmcp bin dir.
  3) Remove policy/config directory if desired.
  4) Remove the mdmcp entry from Claude Desktop config (see below).

Claude Desktop Integration
- `mdmcpcfg install` adds an entry to Claude Desktop’s config pointing at mdmcpsrvr with `--config <policy> --stdio`.
- Config paths (typical):
  • Windows: `%APPDATA%/Claude/claude_desktop_config.json`
  • macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
  • Linux: `~/.config/Claude/claude_desktop_config.json`

Using the MCP Tools
- File I/O: `read_file`, `write_file` operate within allowed roots. Relative paths resolve against the session working directory if set.
- Commands: `run_command` executes catalog entries from the policy.
- Discoverability:
  • `list_accessible_directories` — shows allowed roots.
  • Use `mdmcp://commands/catalog` for a live command list (with help snippets when enabled).
  • On Windows, the default policy includes common system tools. Examples:
    - `where` (C:/Windows/System32/where.exe)
    - `findstr` (C:/Windows/System32/findstr.exe)
    - `tree` (C:/Windows/System32/tree.com)
    - `tasklist` (C:/Windows/System32/tasklist.exe)
    - `taskkill` (C:/Windows/System32/taskkill.exe)
    - `systeminfo` (C:/Windows/System32/systeminfo.exe)
    - `netstat` (C:/Windows/System32/netstat.exe)
    - `ping` (C:/Windows/System32/ping.exe)
    - `ipconfig` (C:/Windows/System32/ipconfig.exe)
    - `whoami` (C:/Windows/System32/whoami.exe)
    - `fc` (C:/Windows/System32/fc.exe)
    - `timeout` (C:/Windows/System32/timeout.exe)
    - `forfiles` (C:/Windows/System32/forfiles.exe)
    - `typeperf` (C:/Windows/System32/typeperf.exe)
  Use `run_command` with `commandId` set to one of the above and supply args as needed.
- Management:
  • `server_info` — version, build, policy summary, policy format.
  • `reload_policy` — reloads the policy file without restart.

Policy Authoring Tips
- Start from defaults (`mdmcpcfg install` creates a sensible policy).
- Keep `deny_network_fs: true` unless you explicitly need network mounts.
- Restrict `allowed_roots` to the folders you actually use.
- Prefer fixed/allow args for commands; use regex patterns carefully.
- Never put secrets into logs.

Examples
- Add a dev workspace and allow writes:
  `mdmcpcfg policy add-root "<your_dev_dir>" --write`
- Add Cargo (Windows):
  `mdmcpcfg policy add-command cargo --exec C:/Users/<you>/.cargo/bin/cargo.exe`
- Add Git (Windows):
  `mdmcpcfg policy add-command git --exec C:/Program Files/Git/bin/git.exe`
- Build a project from Claude:
  Use `cmd.run` with `commandId: "cargo"`, `args: ["build"]`, and set `cwd` to your project folder.

Notes
- The server runs commands directly (no implicit shell). Use `cmd.exe /c` or `/bin/sh -c` in a policy command if you need shell features.
- On Windows/MSVC, the server bootstraps VS variables automatically (vcvars) for cargo/rustc so linking works like your normal shell.
"#,
                    version,
                    build_str,
                    &policy.policy_hash[..16],
                    policy.allowed_roots_canonical.len(),
                    policy.commands_by_id.len(),
                );
                let result = serde_json::json!({
                    "content": [{"type": "text", "text": doc}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            "list_resources" => {
                let resources = vec![
                    ("mdmcp://doc/tools", "Tools & Commands Overview (Markdown)"),
                    ("mdmcp://commands/catalog", "Command Catalog (JSON)"),
                    ("mdmcp://server/capabilities", "Server Capabilities (JSON)"),
                ];
                let mut text =
                    String::from("Available resources (use resources/read to access):\n\n");
                for (uri, desc) in resources {
                    text.push_str(&format!("- {} — {}\n", uri, desc));
                }
                let result = serde_json::json!({
                    "content": [{"type":"text","text": text}],
                    "isError": false
                });
                self.auditor.log_success(ctx, SuccessDetails::default());
                create_success_response(id, result)
            }
            _ => {
                self.auditor
                    .log_error(ctx, &format!("Unknown tool: {}", tool_name), None);
                let data = self.build_error_data(
                    "tools/call",
                    &id,
                    "unknownTool",
                    serde_json::json!({
                        "tool": tool_name
                    }),
                );
                create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Unknown tool: {}", tool_name)),
                    Some(data),
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
                let data = self.build_error_data(
                    "prompts/list",
                    &id,
                    "invalidParameters",
                    serde_json::json!({}),
                );
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(data),
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(self.build_error_data(
                        "prompts/get",
                        &id,
                        "invalidParameters",
                        serde_json::json!({}),
                    )),
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
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(error_msg),
                    Some(self.build_error_data(
                        "prompts/get",
                        &id,
                        "unknownPrompt",
                        serde_json::json!({
                            "name": get_params.name
                        }),
                    )),
                );
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
                let data = self.build_error_data(
                    "resources/list",
                    &id,
                    "invalidParameters",
                    serde_json::json!({}),
                );
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(data),
                );
            }
        };
        debug!("Handling resources/list request");
        // Define available resources that expose server information
        let resources = vec![
            ResourceInfo {
                uri: "mdmcp://doc/tools".to_string(),
                name: "Tools & Commands Overview".to_string(),
                description: Some(
                    "One-stop Markdown doc of MCP tools and command catalog".to_string(),
                ),
                mime_type: Some("text/markdown".to_string()),
            },
            ResourceInfo {
                uri: "mdmcp://commands/catalog".to_string(),
                name: "Command Catalog".to_string(),
                description: Some(
                    "JSON catalog - access via resources/read, not file tools".to_string(),
                ),
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(self.build_error_data(
                        "resources/read",
                        &id,
                        "invalidParameters",
                        serde_json::json!({}),
                    )),
                );
            }
        };
        debug!("Handling resources/read request for: {}", read_params.uri);
        let contents = match read_params.uri.as_str() {
            "mdmcp://doc/tools" => {
                // Serve doc cache file if present
                if let Some(dir) = self.config_path.parent() {
                    let path = dir.join("doc.cache.md");
                    match std::fs::read_to_string(&path) {
                        Ok(text) => vec![ResourceContent::Text { text, mime_type: Some("text/markdown".to_string()) }],
                        Err(_) => vec![ResourceContent::Text { text: "Documentation cache not found. Run `mdmcpcfg docs --build` to generate it.".into(), mime_type: Some("text/markdown".to_string()) }],
                    }
                } else {
                    vec![ResourceContent::Text { text: "Documentation cache not found. Run `mdmcpcfg docs --build` to generate it.".into(), mime_type: Some("text/markdown".to_string()) }]
                }
            }
            "mdmcp://commands/catalog" => {
                // Build a JSON array of command metadata with optional help snippets
                let policy = { self.policy.read().unwrap().clone() };
                let mut items: Vec<serde_json::Value> = Vec::new();

                // Create a temp catalog for validation/execution
                let catalog = CommandCatalog::new(Arc::as_ref(&policy).clone());

                for (id, compiled) in policy.commands_by_id.iter() {
                    let rule = &compiled.rule;
                    let mut obj = serde_json::json!({
                        "id": id,
                        "description": rule.description.clone().unwrap_or_default(),
                        "exec": rule.exec,
                        "platform": rule.platform,
                        "allow_any_args": rule.allow_any_args,
                        "args": {
                            "fixed": rule.args.fixed,
                            "allow": rule.args.allow,
                            "patterns": rule.args.patterns.iter().map(|p| &p.value).collect::<Vec<_>>()
                        }
                    });

                    // Optional help capture
                    if rule.help_capture.enabled && !rule.help_capture.args.is_empty() {
                        let params = mdmcp_common::CmdRunParams {
                            command_id: id.clone(),
                            args: rule.help_capture.args.clone(),
                            cwd: None,
                            stdin: String::new(),
                            env: std::collections::HashMap::new(),
                            timeout_ms: Some(rule.help_capture.timeout_ms),
                        };
                        if let Ok(validated) = catalog.validate_command(&params) {
                            if let Ok(exec) = catalog.execute_command(validated).await {
                                let mut out = if !exec.stdout.is_empty() {
                                    exec.stdout
                                } else {
                                    exec.stderr
                                };
                                let mut truncated = false;
                                if out.len() as u64 > rule.help_capture.max_bytes {
                                    out = out
                                        .chars()
                                        .take(rule.help_capture.max_bytes as usize)
                                        .collect();
                                    truncated = true;
                                }
                                let cleaned = strip_ansi_fast(&out);
                                let snippet = if truncated {
                                    format!("{}\n(truncated)", cleaned)
                                } else {
                                    cleaned
                                };
                                if let Some(map) = obj.as_object_mut() {
                                    map.insert(
                                        "help_snippet".to_string(),
                                        serde_json::json!(snippet),
                                    );
                                }
                            }
                        }
                    }

                    items.push(obj);
                }

                let json = serde_json::to_string_pretty(&items).unwrap_or("[]".to_string());
                vec![ResourceContent::Text {
                    text: json,
                    mime_type: Some("application/json".to_string()),
                }]
            }

            "mdmcp://server/capabilities" => {
                let capabilities_info = serde_json::json!({
                    "tools": {
                        "read_file": "Read files within allowed directories",
                        "write_file": "Write files within allowed directories with policy constraints",
                        "run_command": "Execute pre-approved commands from the catalog",
                        "list_accessible_directories": "List all directories accessible for file operations"
                    },
                    "prompts": {
                        "file_operation": "Helper for file read/write operations",
                        "command_execution": "Helper for command execution",
                        "server_status": "Helper for server status queries"
                    },
                    "resources": {
                        "mdmcp://server/capabilities": "Detailed capability information"
                    }
                });
                vec![ResourceContent::Text {
                    text: serde_json::to_string_pretty(&capabilities_info).unwrap(),
                    mime_type: Some("application/json".to_string()),
                }]
            }
            _ => {
                let error_msg = format!("Unknown resource URI: {}", read_params.uri);
                self.auditor.log_error(ctx, &error_msg, None);
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(error_msg),
                    Some(self.build_error_data(
                        "resources/read",
                        &id,
                        "unknownResource",
                        serde_json::json!({
                            "uri": read_params.uri
                        }),
                    )),
                );
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
            let data = self.build_error_data(
                &request.method,
                &request.id,
                "unsupportedMethod",
                serde_json::json!({
                    "method": request.method
                }),
            );
            let response = create_error_response(
                request.id,
                error_code,
                Some(format!("Unsupported method: {}", request.method)),
                Some(data),
            );
            if let Err(e) = send_response(&response).await {
                error!("Failed to send method validation error: {}", e);
            }
            return;
        }
        // Create audit context
        let policy_hash = { self.policy.read().unwrap().policy_hash.clone() };
        let audit_ctx = AuditContext::new(req_id, request.method.clone(), policy_hash);
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
                let data = self.build_error_data(
                    &request.method,
                    &request.id,
                    "methodNotImplemented",
                    serde_json::json!({
                        "method": request.method
                    }),
                );
                create_error_response(
                    request.id,
                    McpErrorCode::InvalidArgs,
                    Some(format!("Method not implemented: {}", request.method)),
                    Some(data),
                )
            }
        };
        // Log response summary before sending
        if response.error.is_some() {
            info!("âš ï¸  Processing '{}' -> ERROR", request.method);
        } else {
            info!("âœ¨ Processing '{}' -> SUCCESS", request.method);
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };
        debug!("fs.read: path={}", read_params.path);
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
            return create_error_response(
                id.clone(),
                McpErrorCode::InvalidArgs,
                Some(error_msg.clone()),
                Some(self.build_error_data(
                    "fs.read",
                    &id,
                    "invalidEncoding",
                    serde_json::json!({
                        "encoding": read_params.encoding,
                        "detail": "Unsupported encoding"
                    }),
                )),
            );
        }
        // Open file with policy checks
        let policy = { self.policy.read().unwrap().clone() };
        let mut reader = match GuardedFileReader::open(&read_params.path, &policy) {
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
                // Build legacy data then overlay minimal typed context
                let mut data = self.build_error_data(
                    "fs.read",
                    &id,
                    "policyDenied",
                    serde_json::json!({
                        "rule": "pathNotAllowed",
                        "path": path,
                        "detail": "Path outside allowed roots"
                    }),
                );
                if let serde_json::Value::Object(ref mut obj) = data {
                    obj.insert(
                        "context".to_string(),
                        self.minimal_error_context(
                            "path_not_allowed",
                            "The path is not within allowed directories",
                            false,
                            &["Use a path within allowed roots"],
                        ),
                    );
                }
                return create_error_response(
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Path not allowed: {}", path)),
                    Some(data),
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
                let mut data = self.build_error_data(
                    "fs.read",
                    &id,
                    "policyDenied",
                    serde_json::json!({
                        "rule": "networkFsDenied",
                        "path": path,
                        "detail": "Network filesystem denied by policy"
                    }),
                );
                if let serde_json::Value::Object(ref mut obj) = data {
                    obj.insert(
                        "context".to_string(),
                        self.minimal_error_context(
                            "network_fs_denied",
                            "Network filesystem access is blocked by policy",
                            false,
                            &["Set deny_network_fs: false in policy if needed"],
                        ),
                    );
                }
                return create_error_response(
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Network filesystem access blocked: {}. This policy blocks access to network-mounted filesystems (UNC paths, mapped network drives) for security reasons. To allow network filesystem access, set 'deny_network_fs: false' in your policy configuration.", path)),
                    Some(data),
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
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(error_msg.clone()),
                    Some(self.build_error_data(
                        "fs.read",
                        &id,
                        "policyDenied",
                        serde_json::json!({
                            "rule": "specialFile",
                            "path": path,
                            "detail": error_msg
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::IoError,
                    Some(format!("File access error: {}", e)),
                    Some(self.build_error_data(
                        "fs.read",
                        &id,
                        "ioError",
                        serde_json::json!({
                            "path": read_params.path,
                            "detail": "File access error"
                        }),
                    )),
                );
            }
        };

        // Enhanced read: lines precedence over bytes
        let use_lines = read_params.line_offset.is_some()
            || read_params.line_count.is_some()
            || matches!(read_params.mode.as_deref(), Some("lines"));

        let file_size = reader.file_len().unwrap_or(0);

        if use_lines {
            // Read all and slice lines
            match reader.read_with_limits(0, file_size) {
                Ok((buf, _)) => {
                    let text = String::from_utf8_lossy(&buf);
                    let lines: Vec<&str> = text.lines().collect();
                    let total_lines = lines.len() as u64;
                    let start = read_params.line_offset.unwrap_or(0);
                    let count = read_params
                        .line_count
                        .unwrap_or(total_lines.saturating_sub(start));
                    let start_idx = std::cmp::min(start, total_lines);
                    let end_idx = std::cmp::min(start_idx + count, total_lines);
                    let slice = lines[start_idx as usize..end_idx as usize].join("\n");
                    let content = match read_params.encoding.as_str() {
                        "utf8" => slice,
                        "base64" => BASE64.encode(slice.as_bytes()),
                        _ => unreachable!(),
                    };
                    let include_stats = read_params.include_stats.unwrap_or(false);
                    let mut meta = FsReadMetadata {
                        file_size,
                        byte_start: 0,
                        byte_count: content.len() as u64,
                        line_start: Some(start_idx),
                        line_count: Some(end_idx - start_idx),
                        total_lines: if include_stats {
                            Some(total_lines)
                        } else {
                            None
                        },
                        truncated: false,
                        actual_offset: None,
                        ..Default::default()
                    };
                    if include_stats && read_params.encoding == "utf8" {
                        meta.word_count = Some(content.split_whitespace().count() as u64);
                        meta.char_count = Some(content.chars().count() as u64);
                        meta.char_count_no_whitespace =
                            Some(content.chars().filter(|c| !c.is_whitespace()).count() as u64);
                    }
                    let result = FsReadResult {
                        content,
                        metadata: meta,
                    };
                    self.auditor.log_success(ctx, SuccessDetails::default());
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
                        id.clone(),
                        McpErrorCode::IoError,
                        Some(format!("Read error: {}", e)),
                        Some(self.build_error_data(
                            "fs.read",
                            &id,
                            "ioError",
                            serde_json::json!({
                                "path": read_params.path,
                                "detail": "Read error"
                            }),
                        )),
                    )
                }
            }
        } else {
            // Byte mode with head/tail support
            let mut offset = read_params.offset.unwrap_or(0);
            let mut length = read_params
                .length
                .unwrap_or_else(|| policy.policy.limits.max_read_bytes);
            if let Some(mode) = read_params
                .mode
                .as_deref()
                .map(|s| s.to_ascii_lowercase())
                .as_deref()
            {
                match mode {
                    "head" => {
                        offset = 0;
                        if read_params.length.is_none() {
                            const DEFAULT_HEAD: u64 = 8 * 1024;
                            length = std::cmp::min(DEFAULT_HEAD, file_size);
                        }
                    }
                    "tail" => {
                        // default tail length if none provided
                        if read_params.length.is_none() {
                            const DEFAULT_TAIL: u64 = 8 * 1024;
                            length = std::cmp::min(DEFAULT_TAIL, file_size);
                        }
                        if length > file_size {
                            length = file_size;
                        }
                        offset = file_size.saturating_sub(length);
                    }
                    _ => {}
                }
            }
            // Adjust UTF-8 boundary for utf8 encoding
            let mut actual_offset = None;
            if read_params.encoding == "utf8" && offset > 0 {
                let back = std::cmp::min(4, offset as usize);
                let adj_start = offset - back as u64;
                if let Ok((probe, _)) = reader.read_with_limits(adj_start, back as u64) {
                    for i in (0..=probe.len()).rev() {
                        if std::str::from_utf8(&probe[i..]).is_ok() {
                            actual_offset = Some(adj_start + i as u64);
                            break;
                        }
                    }
                }
                if let Some(a) = actual_offset {
                    offset = a;
                }
            }
            match reader.read_with_limits(offset, length) {
                Ok((buffer, _)) => {
                    let truncated = (offset + buffer.len() as u64) < (offset + length)
                        && (offset + length) < file_size;
                    let content = match read_params.encoding.as_str() {
                        "utf8" => String::from_utf8_lossy(&buffer).to_string(),
                        "base64" => BASE64.encode(&buffer),
                        _ => unreachable!(),
                    };
                    let mut meta = FsReadMetadata {
                        file_size,
                        byte_start: offset,
                        byte_count: buffer.len() as u64,
                        line_start: None,
                        line_count: None,
                        total_lines: None,
                        truncated,
                        actual_offset,
                        ..Default::default()
                    };
                    let include_stats = read_params.include_stats.unwrap_or(false);
                    if include_stats && read_params.encoding == "utf8" {
                        meta.word_count = Some(content.split_whitespace().count() as u64);
                        meta.char_count = Some(content.chars().count() as u64);
                        meta.char_count_no_whitespace =
                            Some(content.chars().filter(|c| !c.is_whitespace()).count() as u64);
                    }
                    let result = FsReadResult {
                        content,
                        metadata: meta,
                    };
                    self.auditor.log_success(ctx, SuccessDetails::default());
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
                        id.clone(),
                        McpErrorCode::IoError,
                        Some(format!("Read error: {}", e)),
                        Some(self.build_error_data(
                            "fs.read",
                            &id,
                            "ioError",
                            serde_json::json!({
                                "path": read_params.path,
                                "detail": "Read error"
                            }),
                        )),
                    )
                }
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    None,
                );
            }
        };
        debug!("fs.write: path={}", write_params.path);
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
                        id.clone(),
                        McpErrorCode::InvalidArgs,
                        Some(error_msg.clone()),
                        Some(self.build_error_data(
                            "fs.write",
                            &id,
                            "invalidBase64",
                            serde_json::json!({
                                "path": write_params.path,
                                "detail": "Invalid base64 content"
                            }),
                        )),
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
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(error_msg.clone()),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "invalidEncoding",
                        serde_json::json!({
                            "encoding": write_params.encoding,
                            "detail": "Unsupported encoding"
                        }),
                    )),
                );
            }
        };
        // Create file writer with policy checks
        let policy = { self.policy.read().unwrap().clone() };
        // Determine overwrite permission:
        // - default to true
        // - if append mode is requested, allow overwrite (modifies existing file)
        // - otherwise honor explicit overwrite=false
        let requested_mode = write_params
            .mode
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "overwrite".to_string());
        let mut allow_overwrite = write_params.overwrite.unwrap_or(true);
        if requested_mode == "append" {
            allow_overwrite = true;
        }
        let writer = match GuardedFileWriter::create(
            &write_params.path,
            &policy,
            write_params.create,
            allow_overwrite,
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
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Path not allowed: {}", path)),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "policyDenied",
                        serde_json::json!({
                            "rule": "pathNotAllowed",
                            "path": path,
                            "detail": "Path outside allowed roots"
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Write not permitted: {}", path)),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "policyDenied",
                        serde_json::json!({
                            "rule": "writeNotPermitted",
                            "path": path,
                            "detail": "Write not permitted by policy"
                        }),
                    )),
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
                let mut data = self.build_error_data(
                    "fs.write",
                    &id,
                    "fileTooLarge",
                    serde_json::json!({
                        "rule": "fileTooLarge",
                        "path": write_params.path,
                        "sizeBytes": size,
                        "limitBytes": limit,
                        "detail": "File exceeds maximum size"
                    }),
                );
                if let serde_json::Value::Object(ref mut obj) = data {
                    obj.insert(
                        "context".to_string(),
                        self.minimal_error_context(
                            "file_too_large",
                            "File exceeds maximum allowed size",
                            false,
                            &["Reduce file size or adjust policy max_file_bytes"],
                        ),
                    );
                }
                return create_error_response(
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!(
                        "File too large: {} bytes exceeds limit {}",
                        size, limit
                    )),
                    Some(data),
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
                    id.clone(),
                    McpErrorCode::IoError,
                    Some(format!("Write setup error: {}", e)),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "ioError",
                        serde_json::json!({
                            "path": write_params.path,
                            "detail": "Write setup error"
                        }),
                    )),
                );
            }
        };
        // Build final content based on mode
        let existed_before = std::fs::metadata(&write_params.path).is_ok();
        let existing = std::fs::read(&write_params.path).unwrap_or_else(|_| Vec::new());
        let mode = write_params
            .mode
            .as_deref()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| "overwrite".to_string());
        let final_bytes = match mode.as_str() {
            "overwrite" => data.clone(),
            "append" => {
                let mut v = existing.clone();
                v.extend_from_slice(&data);
                v
            }
            "insert" => {
                let off = write_params.offset.unwrap_or(existing.len() as u64) as usize;
                let mut v = Vec::with_capacity(existing.len() + data.len());
                let split = std::cmp::min(off, existing.len());
                v.extend_from_slice(&existing[..split]);
                v.extend_from_slice(&data);
                v.extend_from_slice(&existing[split..]);
                v
            }
            "patch" => {
                // Not implemented: return error
                let msg = "patch mode not supported".to_string();
                self.auditor.log_error(
                    ctx,
                    &msg,
                    Some(ErrorDetails {
                        path: Some(write_params.path.clone()),
                        ..Default::default()
                    }),
                );
                return create_error_response(
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(msg),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "unsupportedMode",
                        serde_json::json!({"mode": mode}),
                    )),
                );
            }
            _ => data.clone(),
        };

        // Write data atomically regardless of requested atomic flag for safety
        match writer.write_atomic(&final_bytes) {
            Ok((bytes_written, _hash)) => {
                let file_size = std::fs::metadata(&write_params.path)
                    .map(|m| m.len())
                    .unwrap_or(bytes_written);
                let created = !existed_before;
                let result = FsWriteResult {
                    bytes_written,
                    file_size,
                    created,
                };
                self.auditor.log_success(
                    ctx,
                    SuccessDetails {
                        path: Some(write_params.path.clone()),
                        bytes: Some(bytes_written),
                        content_hash: None,
                        ..Default::default()
                    },
                );
                create_success_response(id, serde_json::to_value(result).unwrap())
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
                let mut data = self.build_error_data(
                    "fs.write",
                    &id,
                    "fileTooLarge",
                    serde_json::json!({
                        "rule": "fileTooLarge",
                        "path": write_params.path,
                        "sizeBytes": size,
                        "limitBytes": limit,
                        "detail": "File exceeds maximum size"
                    }),
                );
                if let serde_json::Value::Object(ref mut obj) = data {
                    obj.insert(
                        "context".to_string(),
                        self.minimal_error_context(
                            "file_too_large",
                            "File exceeds maximum allowed size",
                            false,
                            &["Reduce file size or adjust policy max_file_bytes"],
                        ),
                    );
                }
                return create_error_response(
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!(
                        "File too large: {} bytes exceeds limit {}",
                        size, limit
                    )),
                    Some(data),
                );
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
                    id.clone(),
                    McpErrorCode::IoError,
                    Some(format!("Write error: {}", e)),
                    Some(self.build_error_data(
                        "fs.write",
                        &id,
                        "ioError",
                        serde_json::json!({
                            "path": write_params.path,
                            "detail": "Write error"
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Invalid parameters: {}", e)),
                    Some(serde_json::json!({
                        "reason": "invalidParameters"
                    })),
                );
            }
        };
        debug!(
            "cmd.run: command={}, args={:?}",
            run_params.command_id,
            crate::cmd_catalog::sanitize_args_for_logging(&run_params.args)
        );
        // Validate command
        let validation_res = {
            let catalog = self.command_catalog.read().unwrap();
            catalog.validate_command(&run_params)
        };
        let validated_cmd = match validation_res {
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
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Command not found: {}", cmd_id)),
                    Some(self.build_error_data(
                        "cmd.run",
                        &id,
                        "policyDenied",
                        serde_json::json!({
                            "rule": "commandNotFound",
                            "commandId": cmd_id,
                            "timedOut": false,
                            "truncated": false
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::PolicyDeny,
                    Some(format!("Policy denied: {}", rule)),
                    Some(self.build_error_data(
                        "cmd.run",
                        &id,
                        "policyDenied",
                        serde_json::json!({
                            "rule": rule,
                            "commandId": run_params.command_id,
                            "timedOut": false,
                            "truncated": false
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::InvalidArgs,
                    Some(format!("Command validation error: {}", e)),
                    Some(self.build_error_data(
                        "cmd.run",
                        &id,
                        "validationFailed",
                        serde_json::json!({
                            "commandId": run_params.command_id,
                            "timedOut": false,
                            "truncated": false
                        }),
                    )),
                );
            }
        };
        // Execute command
        // Execute without holding the catalog lock across await
        let policy_for_exec = { self.policy.read().unwrap().clone() };
        let temp_catalog = CommandCatalog::new(Arc::as_ref(&policy_for_exec).clone());
        match temp_catalog.execute_command(validated_cmd).await {
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
                    id.clone(),
                    McpErrorCode::Timeout,
                    Some(format!("Command timed out after {}ms", timeout_ms)),
                    Some(self.build_error_data(
                        "cmd.run",
                        &id,
                        "timeout",
                        serde_json::json!({
                            "commandId": run_params.command_id,
                            "timeoutMs": timeout_ms,
                            "timedOut": true,
                            "truncated": false
                        }),
                    )),
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
                    id.clone(),
                    McpErrorCode::Internal,
                    Some(format!("Command execution error: {}", e)),
                    Some(self.build_error_data(
                        "cmd.run",
                        &id,
                        "executionError",
                        serde_json::json!({
                            "commandId": run_params.command_id,
                            "timedOut": false,
                            "truncated": false
                        }),
                    )),
                )
            }
        }
    }
}
impl Server {
    /// Reload the policy from the configured path, rebuilding catalogs.
    async fn reload_policy(&self) -> Result<Arc<CompiledPolicy>> {
        let path = self.config_path.clone();
        // Merge core + user same as startup
        let new_policy = tokio::task::spawn_blocking(move || -> anyhow::Result<CompiledPolicy> {
            let user = Policy::load(&path)?;
            // Look for sibling policy.core.yaml
            let core_path = path
                .parent()
                .map(|d| d.join("policy.core.yaml"))
                .filter(|p| p.exists());
            let merged = if let Some(cp) = core_path {
                let core = Policy::load(&cp)?;
                mdmcp_policy::merge_policies(core, user)
            } else {
                user
            };
            merged.compile()
        })
        .await
        .context("Failed to reload policy")??;
        let new_policy_arc = Arc::new(new_policy);
        // Swap policy and rebuild command catalog
        {
            let mut policy_lock = self.policy.write().unwrap();
            *policy_lock = new_policy_arc.clone();
        }
        {
            let mut catalog_lock = self.command_catalog.write().unwrap();
            *catalog_lock = CommandCatalog::new(Arc::as_ref(&new_policy_arc).clone());
        }
        Ok(new_policy_arc)
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
                description: None,
                env_static: std::collections::HashMap::new(),
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
                help_capture: Default::default(),
            }],
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        };
        let compiled_policy = Arc::new(policy.compile().unwrap());
        Server::new(
            compiled_policy,
            std::env::current_dir()
                .unwrap()
                .join("tests/test_policy.yaml"),
        )
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn test_fs_read_success() {
        let server = create_test_server().await;
        // Create a test file
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        let temp_file = NamedTempFile::new_in(&root0).unwrap();
        std::fs::write(temp_file.path(), "test content").unwrap();
        let params = FsReadParams {
            path: temp_file.path().to_string_lossy().to_string(),
            encoding: "utf8".to_string(),
            offset: Some(0),
            length: Some(1000),
            line_offset: None,
            line_count: None,
            mode: None,
            include_stats: None,
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
            encoding: "utf8".to_string(),
            offset: Some(0),
            length: Some(1000),
            line_offset: None,
            line_count: None,
            mode: None,
            include_stats: None,
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
        // Validate minimal context is present and typed
        let data = error.data.unwrap();
        let ctx = &data["context"];
        assert_eq!(ctx["schemaVersion"].as_i64().unwrap(), 1);
        assert_eq!(ctx["type"].as_str().unwrap(), "path_not_allowed");
        assert_eq!(ctx["retryable"].as_bool().unwrap(), false);
        assert!(ctx["suggestions"].is_array());
    }
    #[tokio::test]
    async fn test_fs_write_success() {
        let server = create_test_server().await;
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        let test_file = root0.join("test_write.txt");
        let params = FsWriteParams {
            path: test_file.to_string_lossy().to_string(),
            data: "test data".to_string(),
            encoding: "utf8".to_string(),
            offset: None,
            mode: Some("overwrite".to_string()),
            create: true,
            atomic: true,
            overwrite: None,
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
    #[tokio::test]
    async fn test_tools_list_includes_get_datetime() {
        let server = create_test_server().await;
        let audit_ctx = AuditContext::new("test".into(), "tools/list".into(), "hash".into());
        let resp = server
            .handle_tools_list(&audit_ctx, RpcId::Number(1), serde_json::json!({}))
            .await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        let tools = result.get("tools").and_then(|t| t.as_array()).unwrap();
        let has = tools
            .iter()
            .any(|t| t.get("name").and_then(|n| n.as_str()) == Some("get_datetime"));
        assert!(has);
    }
    #[tokio::test]
    async fn test_get_datetime_tool_shape() {
        let server = create_test_server().await;
        let audit_ctx = AuditContext::new("test".into(), "tools/call".into(), "hash".into());
        let params = serde_json::json!({
            "name": "get_datetime",
            "arguments": {}
        });
        let resp = server
            .handle_tools_call(&audit_ctx, RpcId::Number(1), params)
            .await;
        assert!(resp.error.is_none());
        let binding = resp.result.unwrap();
        let txt = binding["content"][0]["text"].as_str().unwrap();
        let v: serde_json::Value = serde_json::from_str(txt).unwrap();
        assert!(v.get("datetime").and_then(|x| x.as_str()).is_some());
        assert!(v.get("offset").and_then(|x| x.as_str()).is_some());
        assert!(v.get("unix").and_then(|x| x.as_i64()).is_some());
        let comps = v.get("components").and_then(|c| c.as_object()).unwrap();
        assert!(comps.get("year").unwrap().as_i64().unwrap() >= 1970);
    }

    #[tokio::test]
    async fn test_get_datetime_format_variants() {
        let server = create_test_server().await;
        let audit_ctx = AuditContext::new("test".into(), "tools/call".into(), "hash".into());

        // iso8601
        let iso = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::json!({"name":"get_datetime","arguments":{"format":"iso8601"}}),
            )
            .await
            .result
            .unwrap();
        let iso_txt = iso["content"][0]["text"].as_str().unwrap();
        assert!(iso_txt.contains("T") && iso_txt.contains("+") || iso_txt.contains("Z"));

        // unix
        let unix = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(2),
                serde_json::json!({"name":"get_datetime","arguments":{"format":"unix"}}),
            )
            .await
            .result
            .unwrap();
        let unix_txt = unix["content"][0]["text"].as_str().unwrap();
        assert!(unix_txt.parse::<i64>().is_ok());

        // human
        let human = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(3),
                serde_json::json!({"name":"get_datetime","arguments":{"format":"human"}}),
            )
            .await
            .result
            .unwrap();
        let human_txt = human["content"][0]["text"].as_str().unwrap();
        assert!(human_txt.contains("UTC") || human_txt.contains("GMT"));
    }
    #[tokio::test]
    async fn test_working_directory_tools_and_next_command() {
        let server = create_test_server().await;

        // get_working_directory returns a JSON with cwd
        let audit_ctx = AuditContext::new("test".into(), "tools/call".into(), "hash".into());
        let resp = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::json!({"name":"get_working_directory","arguments":{}}),
            )
            .await;
        assert!(resp.error.is_none());

        // Set next_command working directory to allowed root
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        let set_resp = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(2),
                serde_json::json!({
                    "name":"set_working_directory",
                    "arguments": {"path": root0.to_string_lossy(), "scope": "next_command"}
                }),
            )
            .await;
        assert!(set_resp.error.is_none());
        {
            let nc = server.next_command_cwd.read().unwrap();
            assert!(nc.is_some());
        }
        // Run echo; this should consume next_command_cwd
        let call = serde_json::json!({
            "name": "run_command",
            "arguments": {"command_id": "echo", "args": ["ok"]}
        });
        let _rr = server
            .handle_tools_call(&audit_ctx, RpcId::Number(3), call)
            .await;
        {
            let nc = server.next_command_cwd.read().unwrap();
            assert!(nc.is_none());
        }
    }

    #[tokio::test]
    async fn test_session_cwd_applies_to_file_tools() {
        let server = create_test_server().await;
        // Use allowed root as working directory
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        // Create a file inside the root
        let rel_name = "rel_file.txt";
        let abs_path = root0.join(rel_name);
        std::fs::write(&abs_path, b"hello cwd").unwrap();

        // Set session working directory
        let audit_ctx = AuditContext::new("test".into(), "tools/call".into(), "hash".into());
        let _set_resp = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(1),
                serde_json::json!({
                    "name": "set_working_directory",
                    "arguments": {"path": root0.to_string_lossy(), "scope": "session"}
                }),
            )
            .await;

        // Read the file using a relative path
        let read_resp = server
            .handle_tools_call(
                &audit_ctx,
                RpcId::Number(2),
                serde_json::json!({
                    "name": "read_bytes",
                    "arguments": {"path": rel_name, "encoding": "utf8"}
                }),
            )
            .await;
        assert!(read_resp.error.is_none());
        let content_text = read_resp.result.unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(content_text, "hello cwd");
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

    #[tokio::test]
    async fn reload_policy_success_rebuilds_catalog() {
        let server = create_test_server().await;
        // Build a minimal valid policy YAML pointing to the same allowed root
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        let yaml = format!(
            "version: 1\ndeny_network_fs: false\nallowed_roots:\n  - {}\nwrite_rules: []\ncommands: []\n",
            root0.to_string_lossy()
        );
        // Sanity-check compile independently
        let parsed = mdmcp_policy::Policy::from_yaml(&yaml).unwrap();
        let _compiled = parsed.compile().unwrap();
        std::fs::write(&server.config_path, yaml).unwrap();
        let res = server.reload_policy().await;
        assert!(res.is_ok());
        // Catalog should rebuild without error when fetching read lock
        let _guard = server.command_catalog.read().unwrap();
    }

    #[tokio::test]
    async fn test_minimal_error_context_helper() {
        let server = create_test_server().await;
        // Long strings to trigger truncation logic
        let long_msg = "x".repeat(400);
        let long_sugg = "y".repeat(400);
        let ctx = server.minimal_error_context(
            "sample_type",
            &long_msg,
            true,
            &["s1", &long_sugg, "s3", "s4", "s5"],
        );
        assert_eq!(ctx["schemaVersion"].as_i64().unwrap(), 1);
        assert_eq!(ctx["type"].as_str().unwrap(), "sample_type");
        assert_eq!(ctx["retryable"].as_bool().unwrap(), true);
        // userMessage truncated to <= 259 bytes (256 + UTF-8 ellipsis)
        let um = ctx["userMessage"].as_str().unwrap();
        assert!(um.len() <= 259);
        // suggestions capped to 3 and each truncated
        let suggs = ctx["suggestions"].as_array().unwrap();
        assert_eq!(suggs.len(), 3);
        assert!(suggs[1].as_str().unwrap().len() <= 259);
    }

    #[tokio::test]
    async fn test_fs_write_file_too_large_context() {
        let server = create_test_server().await;
        let root0 = { server.policy.read().unwrap().allowed_roots_canonical[0].clone() };
        let test_file = root0.join("too_large.txt");
        // Build data larger than the 1000-byte limit used in tests
        let big = "a".repeat(2000);
        let params = FsWriteParams {
            path: test_file.to_string_lossy().to_string(),
            data: big,
            encoding: "utf8".to_string(),
            offset: None,
            mode: Some("overwrite".to_string()),
            create: true,
            atomic: true,
            overwrite: None,
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
        assert!(response.result.is_none());
        let err = response.error.unwrap();
        // We may get PolicyDeny (from our mapping) or IoError depending on platform specifics,
        // but for FileTooLarge mapping we expect PolicyDeny path.
        assert_eq!(err.code, McpErrorCode::PolicyDeny as i32);
        let data = err.data.unwrap();
        let ctxv = &data["context"];
        assert_eq!(ctxv["type"].as_str().unwrap(), "file_too_large");
        assert!(ctxv["suggestions"].is_array());
    }
}
