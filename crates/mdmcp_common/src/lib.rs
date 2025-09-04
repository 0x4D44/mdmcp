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

/// Parameters for fs.read method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadParams {
    pub path: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_read_length")]
    pub length: u64,
    #[serde(default = "default_encoding")]
    pub encoding: String,
}

/// Result of fs.read method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadResult {
    pub data: String,
    #[serde(rename = "bytesRead")]
    pub bytes_read: u64,
    pub sha256: String,
}

/// Parameters for fs.write method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteParams {
    pub path: String,
    pub data: String,
    #[serde(default = "default_encoding")]
    pub encoding: String,
    #[serde(default)]
    pub create: bool,
    #[serde(default)]
    pub overwrite: bool,
}

/// Result of fs.write method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteResult {
    #[serde(rename = "bytesWritten")]
    pub bytes_written: u64,
    pub sha256: String,
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
    #[serde(default)]
    pub logging: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub prompts: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub resources: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub tools: Option<HashMap<String, serde_json::Value>>,
}

/// Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

fn default_read_length() -> u64 {
    1_048_576 // 1MB default
}

fn default_encoding() -> String {
    "utf8".to_string()
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
        assert_eq!(params.offset, 0);
        assert_eq!(params.length, 1_048_576);
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
