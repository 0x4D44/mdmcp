//! # JSON-RPC 2.0 Transport Layer
//!
//! Handles JSON-RPC 2.0 message parsing, validation, and serialization over stdio.
//! This module implements the transport layer for the MCP protocol, processing
//! newline-delimited JSON messages and ensuring proper RPC format compliance.

use anyhow::{Context, Result};
use mdmcp_common::{McpErrorCode, RpcError, RpcId, RpcRequest, RpcResponse};
use serde_json::Value;
use tokio::io::{self, AsyncWriteExt};
use tracing::{debug, warn};

/// Represents either a request or notification
#[derive(Debug)]
pub enum RpcMessage {
    Request(RpcRequest),
    Notification { method: String, params: Value },
}

/// Parse a JSON-RPC message (request or notification) from a line of input
pub fn parse_message(line: &str) -> Result<RpcMessage> {
    let value: Value = serde_json::from_str(line).context("Invalid JSON")?;

    // Validate required fields
    let value_clone = value.clone();
    let obj = value_clone
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Message must be a JSON object"))?;

    let jsonrpc = obj
        .get("jsonrpc")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'jsonrpc' field"))?;

    if jsonrpc != "2.0" {
        return Err(anyhow::anyhow!("Invalid jsonrpc version: {}", jsonrpc));
    }

    let method = obj
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'method' field"))?;

    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    // Check if this is a request (has id) or notification (no id)
    if obj.contains_key("id") {
        let request: RpcRequest =
            serde_json::from_value(value).context("Failed to deserialize RPC request")?;
        debug!("Parsed RPC request: method={}, id={:?}", method, request.id);
        Ok(RpcMessage::Request(request))
    } else {
        debug!("Parsed RPC notification: method={}", method);
        Ok(RpcMessage::Notification {
            method: method.to_string(),
            params,
        })
    }
}

/// Parse a JSON-RPC request from a line of input (legacy function for compatibility)
#[cfg(test)]
pub fn parse_request(line: &str) -> Result<RpcRequest> {
    match parse_message(line)? {
        RpcMessage::Request(req) => Ok(req),
        RpcMessage::Notification { method, .. } => {
            Err(anyhow::anyhow!("Expected request but got notification: {}", method))
        }
    }
}

/// Send a JSON-RPC response to stdout
pub async fn send_response(response: &RpcResponse) -> Result<()> {
    let json = serde_json::to_string(response).context("Failed to serialize response")?;
    
    // Log the response being sent (with emoji for visibility in logs)
    if response.error.is_some() {
        tracing::info!("❌ Sending error response (id={:?}): {}", response.id, json);
    } else {
        tracing::info!("✅ Sending success response (id={:?}): {}", response.id, json);
    }

    send_json_line(&json).await
}

/// Send a line of JSON to stdout with newline
async fn send_json_line(json: &str) -> Result<()> {
    debug!("Preparing to send JSON: {}", json);
    let mut stdout = io::stdout();
    
    debug!("Writing JSON to stdout...");
    stdout
        .write_all(json.as_bytes())
        .await
        .context("Failed to write to stdout")?;
    
    debug!("Writing newline to stdout...");
    stdout
        .write_all(b"\n")
        .await
        .context("Failed to write newline to stdout")?;
    
    debug!("Flushing stdout...");
    stdout.flush().await.context("Failed to flush stdout")?;

    debug!("Successfully sent JSON: {}", json);
    Ok(())
}

/// Create a success response
pub fn create_success_response(id: RpcId, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

/// Create an error response
pub fn create_error_response(
    id: RpcId,
    code: McpErrorCode,
    message: Option<String>,
    data: Option<Value>,
) -> RpcResponse {
    let error_message = message.unwrap_or_else(|| code.message().to_string());

    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(RpcError {
            code: code.into(),
            message: error_message,
            data,
        }),
    }
}

/// Validate method name against MCP specification
pub fn validate_method(method: &str) -> Result<(), McpErrorCode> {
    match method {
        "initialize" | "tools/list" | "tools/call" 
        | "prompts/list" | "prompts/get"
        | "resources/list" | "resources/read" => Ok(()),
        _ => {
            warn!("Unsupported method: {}", method);
            Err(McpErrorCode::InvalidArgs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mdmcp_common::RpcId;

    #[test]
    fn test_parse_valid_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"fs.read","params":{"path":"/test"}}"#;
        let request = parse_request(json).unwrap();

        assert_eq!(request.jsonrpc, "2.0");
        assert_eq!(request.method, "fs.read");
        match request.id {
            RpcId::Number(n) => assert_eq!(n, 1),
            _ => panic!("Expected number ID"),
        }
    }

    #[test]
    fn test_parse_invalid_jsonrpc_version() {
        let json = r#"{"jsonrpc":"1.0","id":1,"method":"fs.read","params":{}}"#;
        assert!(parse_request(json).is_err());
    }

    #[test]
    fn test_parse_missing_id() {
        let json = r#"{"jsonrpc":"2.0","method":"fs.read","params":{}}"#;
        assert!(parse_request(json).is_err());
    }

    #[test]
    fn test_parse_missing_method() {
        let json = r#"{"jsonrpc":"2.0","id":1,"params":{}}"#;
        assert!(parse_request(json).is_err());
    }

    #[test]
    fn test_validate_method() {
        assert!(validate_method("initialize").is_ok());
        assert!(validate_method("tools/list").is_ok());
        assert!(validate_method("tools/call").is_ok());
        assert!(validate_method("invalid.method").is_err());
    }

    #[test]
    fn test_create_success_response() {
        let response =
            create_success_response(RpcId::Number(1), serde_json::json!({"result": "success"}));

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, RpcId::Number(1));
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_create_error_response() {
        let response = create_error_response(
            RpcId::Number(1),
            McpErrorCode::PolicyDeny,
            None,
            Some(serde_json::json!({"rule": "test"})),
        );

        assert_eq!(response.jsonrpc, "2.0");
        assert_eq!(response.id, RpcId::Number(1));
        assert!(response.result.is_none());

        let error = response.error.unwrap();
        assert_eq!(error.code, McpErrorCode::PolicyDeny as i32);
        assert_eq!(error.message, "Policy denied the operation");
    }
}
