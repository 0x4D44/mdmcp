//! # mdmcp_common
//!
//! Common types and utilities for the mdmcp project, including JSON-RPC message types
//! and MCP protocol definitions. This crate provides the foundational data structures
//! used by both the server and client components.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JSON-RPC 2.0 request message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: RpcId,
    pub method: String,
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: RpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

/// JSON-RPC 2.0 notification message (no id field)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
}

/// JSON-RPC ID can be string, number, or null
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RpcId {
    String(String),
    Number(i64),
    Null,
}

/// JSON-RPC error object
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP error codes as defined in the specification
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum McpErrorCode {
    PolicyDeny = -32001,
    InvalidArgs = -32602,
    Timeout = -32002,
    OutputTruncated = -32003,
    IoError = -32004,
    Internal = -32603,
}

impl McpErrorCode {
    pub fn message(&self) -> &'static str {
        match self {
            McpErrorCode::PolicyDeny => "Policy denied the operation",
            McpErrorCode::InvalidArgs => "Invalid method parameter(s)",
            McpErrorCode::Timeout => "Operation timed out",
            McpErrorCode::OutputTruncated => "Output was truncated due to size limits",
            McpErrorCode::IoError => "I/O error occurred",
            McpErrorCode::Internal => "Internal server error",
        }
    }
}

impl From<McpErrorCode> for i32 {
    fn from(code: McpErrorCode) -> Self {
        code as i32
    }
}

/// Parameters for fs.read method (enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadParams {
    pub path: String,
    #[serde(default = "default_encoding")]
    pub encoding: String, // utf8|base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u64>,
    #[serde(rename = "line_offset", skip_serializing_if = "Option::is_none")]
    pub line_offset: Option<u64>,
    #[serde(rename = "line_count", skip_serializing_if = "Option::is_none")]
    pub line_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>, // full|partial|tail|head|lines
    #[serde(rename = "include_stats", skip_serializing_if = "Option::is_none")]
    pub include_stats: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FsReadMetadata {
    #[serde(rename = "file_size")]
    pub file_size: u64,
    #[serde(rename = "byte_start")]
    pub byte_start: u64,
    #[serde(rename = "byte_count")]
    pub byte_count: u64,
    #[serde(rename = "line_start", skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u64>,
    #[serde(rename = "line_count", skip_serializing_if = "Option::is_none")]
    pub line_count: Option<u64>,
    #[serde(rename = "total_lines", skip_serializing_if = "Option::is_none")]
    pub total_lines: Option<u64>,
    #[serde(rename = "word_count", skip_serializing_if = "Option::is_none")]
    pub word_count: Option<u64>,
    #[serde(rename = "char_count", skip_serializing_if = "Option::is_none")]
    pub char_count: Option<u64>,
    #[serde(
        rename = "char_count_no_whitespace",
        skip_serializing_if = "Option::is_none"
    )]
    pub char_count_no_whitespace: Option<u64>,
    pub truncated: bool,
    #[serde(rename = "actual_offset", skip_serializing_if = "Option::is_none")]
    pub actual_offset: Option<u64>,
}

/// Result of fs.read method (enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadResult {
    pub content: String,
    pub metadata: FsReadMetadata,
}

/// Parameters for fs.write method (enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub path: String,
    pub data: String,
    #[serde(default = "default_encoding")]
    pub encoding: String, // utf8|base64
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>, // overwrite|insert|append|patch
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub atomic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<bool>,
}

/// Result of fs.write method (enhanced)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteResult {
    #[serde(rename = "bytes_written")]
    pub bytes_written: u64,
    #[serde(rename = "file_size")]
    pub file_size: u64,
    pub created: bool,
}

/// Parameters for cmd.run method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdRunParams {
    #[serde(rename = "commandId")]
    pub command_id: String,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default)]
    pub stdin: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(rename = "timeoutMs", skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// Result of cmd.run method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdRunResult {
    #[serde(rename = "exitCode")]
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "timedOut")]
    pub timed_out: bool,
    pub truncated: bool,
}

/// MCP handshake notification parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeParams {
    pub name: String,
    pub version: String,
    pub capabilities: HashMap<String, serde_json::Value>,
    #[serde(rename = "policyHash")]
    pub policy_hash: String,
}

/// Parameters for initialize method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

/// Client capabilities in initialize request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<RootsCapability>,
    #[serde(default)]
    pub sampling: Option<HashMap<String, serde_json::Value>>,
}

/// Root listing capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// Client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

/// Result of initialize method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

/// Server capabilities in initialize response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<HashMap<String, serde_json::Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<HashMap<String, serde_json::Value>>,
}

/// Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// default_read_length removed (length now optional)

fn default_encoding() -> String {
    "utf8".to_string()
}

/// Parameters for prompts/list method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Result of prompts/list method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsListResult {
    pub prompts: Vec<PromptInfo>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Information about a prompt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInfo {
    pub name: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
}

/// Prompt argument definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Parameters for prompts/get method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsGetParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub arguments: HashMap<String, serde_json::Value>,
}

/// Result of prompts/get method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptsGetResult {
    pub messages: Vec<PromptMessage>,
}

/// A message in a prompt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptMessage {
    pub role: String, // "user", "assistant", "system"
    pub content: PromptContent,
}

/// Content of a prompt message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum PromptContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image {
        #[serde(rename = "imageUrl")]
        image_url: String,
    },
}

/// Parameters for resources/list method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// Result of resources/list method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesListResult {
    pub resources: Vec<ResourceInfo>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Information about a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// Parameters for resources/read method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadParams {
    pub uri: String,
}

/// Result of resources/read method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesReadResult {
    pub contents: Vec<ResourceContent>,
}

/// Content of a resource
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResourceContent {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
        mime_type: Option<String>,
    },
    #[serde(rename = "blob")]
    Blob {
        blob: String, // base64 encoded
        #[serde(skip_serializing_if = "Option::is_none", rename = "mimeType")]
        mime_type: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request_serialization() {
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: RpcId::Number(1),
            method: "fs.read".to_string(),
            params: serde_json::json!({"path": "/test"}),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_fs_read_params_defaults() {
        let json = r#"{"path": "/test"}"#;
        let params: FsReadParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.offset, None);
        assert_eq!(params.length, None);
        assert_eq!(params.encoding, "utf8");
    }

    #[test]
    fn test_mcp_error_codes() {
        assert_eq!(McpErrorCode::PolicyDeny as i32, -32001);
        assert_eq!(McpErrorCode::InvalidArgs as i32, -32602);
        assert_eq!(McpErrorCode::Timeout as i32, -32002);
    }

    #[test]
    fn test_rpc_id_variants() {
        let string_id = RpcId::String("test".to_string());
        let number_id = RpcId::Number(42);
        let null_id = RpcId::Null;

        let json_string = serde_json::to_string(&string_id).unwrap();
        let json_number = serde_json::to_string(&number_id).unwrap();
        let json_null = serde_json::to_string(&null_id).unwrap();

        assert_eq!(json_string, r#""test""#);
        assert_eq!(json_number, "42");
        assert_eq!(json_null, "null");
    }
}
