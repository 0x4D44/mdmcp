# MDMCP Enhanced Error Handling - Detailed Design

## 1. Overview

### 1.1 Purpose
This design document describes a comprehensive enhancement to the error handling system in mdmcp to provide rich, contextual error information to MCP clients while maintaining backward compatibility.

### 1.2 Goals
- Provide structured, actionable error information to clients
- Preserve error context throughout the error propagation chain
- Maintain backward compatibility with existing clients
- Improve debuggability and reduce support burden
- Enable clients to implement intelligent error recovery

### 1.3 Non-Goals
- Changing existing error codes or basic error structure
- Breaking changes to the RPC protocol
- Exposing sensitive internal implementation details
- Implementing client-side error handling logic

## 2. Architecture

### 2.1 Component Overview

```
┌─────────────────┐
│   MCP Client    │
└────────┬────────┘
         │ JSON-RPC Error Response
         ▼
┌─────────────────┐
│  RPC Layer      │◄──── Enhanced Error Response Builder
│  (rpc.rs)       │
└────────┬────────┘
         │
┌────────▼────────┐
│  Server Core    │◄──── Error Context Enrichment
│  (server.rs)    │
└────────┬────────┘
         │
┌────────▼────────┐      ┌──────────────┐
│ Domain Modules  │◄─────│ Error Context│
│ - fs_safety     │      │   Registry   │
│ - cmd_catalog   │      └──────────────┘
│ - policy        │
└─────────────────┘
```

### 2.2 Error Flow

1. **Error Origin**: Domain module generates typed error
2. **Context Capture**: Error context is extracted and structured
3. **Enrichment**: Additional context added (suggestions, allowed values)
4. **Conversion**: Typed error converted to RPC error with data field
5. **Response**: Client receives rich error information

## 3. Data Structures

### 3.1 Core Error Context Types

```rust
// crates/mdmcp_common/src/error_context.rs

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Root error context that will be serialized to the data field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Machine-readable error type identifier
    #[serde(rename = "type")]
    pub error_type: ErrorType,
    
    /// Detailed error-specific information
    pub details: ErrorDetails,
    
    /// Human-readable message for end users
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    
    /// Suggestions for fixing or avoiding the error
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggestions: Vec<String>,
    
    /// Additional context for debugging (only in verbose mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
}

/// Enumeration of all error types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    // Policy violations
    PathNotAllowed,
    CommandNotAllowed,
    EnvironmentNotAllowed,
    NetworkFsDenied,
    WriteNotPermitted,
    
    // Validation failures
    InvalidPath,
    InvalidArgument,
    InvalidEnvironment,
    MissingRequired,
    
    // Resource limits
    FileTooLarge,
    OutputTooLarge,
    Timeout,
    ConcurrencyLimit,
    
    // Execution errors
    CommandFailed,
    IoError,
    PermissionDenied,
    NotFound,
    
    // System errors
    InternalError,
    ConfigurationError,
}

/// Detailed error information variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorDetails {
    PolicyViolation(PolicyViolationDetails),
    ValidationFailure(ValidationFailureDetails),
    ResourceLimit(ResourceLimitDetails),
    ExecutionError(ExecutionErrorDetails),
    SystemError(SystemErrorDetails),
}

/// Details for policy violation errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolationDetails {
    /// What was requested
    pub requested: String,
    
    /// What policy rule was violated
    pub rule: String,
    
    /// Allowed values/patterns (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<String>>,
    
    /// Policy file location and line number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_location: Option<String>,
}

/// Details for validation failure errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFailureDetails {
    /// Field or parameter that failed validation
    pub field: String,
    
    /// The invalid value provided
    pub value: String,
    
    /// Why the validation failed
    pub reason: String,
    
    /// Expected format or pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_format: Option<String>,
    
    /// Valid examples
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub examples: Vec<String>,
}

/// Details for resource limit errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitDetails {
    /// Type of resource (file_size, memory, time, etc.)
    pub resource: String,
    
    /// The configured limit
    pub limit: u64,
    
    /// The actual/requested value
    pub actual: u64,
    
    /// Unit of measurement
    pub unit: String,
    
    /// Where this limit is configured
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
}

/// Details for execution errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionErrorDetails {
    /// Phase where error occurred
    pub phase: ExecutionPhase,
    
    /// Command or operation that failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    
    /// Exit code if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    
    /// Stderr output if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    
    /// System error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_error: Option<String>,
}

/// Execution phases
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Validation,
    Preparation,
    Execution,
    OutputProcessing,
    Cleanup,
}

/// Details for system errors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemErrorDetails {
    /// Component where error occurred
    pub component: String,
    
    /// Internal error message
    pub message: String,
    
    /// Error code if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Debug information (only included in verbose mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInfo {
    /// Full error chain
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub error_chain: Vec<String>,
    
    /// Stack trace if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace: Option<String>,
    
    /// Request context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    
    /// Timestamp
    pub timestamp: String,
    
    /// Server version
    pub server_version: String,
}
```

### 3.2 Error Context Builder

```rust
// mdmcpsrvr/src/error_context.rs

use mdmcp_common::error_context::*;
use std::error::Error;

/// Builder for constructing error contexts
pub struct ErrorContextBuilder {
    error_type: ErrorType,
    details: Option<ErrorDetails>,
    user_message: Option<String>,
    suggestions: Vec<String>,
    debug_info: Option<DebugInfo>,
}

impl ErrorContextBuilder {
    /// Create a new builder with an error type
    pub fn new(error_type: ErrorType) -> Self {
        Self {
            error_type,
            details: None,
            user_message: None,
            suggestions: Vec::new(),
            debug_info: None,
        }
    }
    
    /// Set error details
    pub fn with_details(mut self, details: ErrorDetails) -> Self {
        self.details = Some(details);
        self
    }
    
    /// Add a user-friendly message
    pub fn with_user_message(mut self, message: impl Into<String>) -> Self {
        self.user_message = Some(message.into());
        self
    }
    
    /// Add a suggestion
    pub fn add_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }
    
    /// Add multiple suggestions
    pub fn with_suggestions(mut self, suggestions: Vec<String>) -> Self {
        self.suggestions.extend(suggestions);
        self
    }
    
    /// Add debug information (if verbose mode enabled)
    pub fn with_debug_info(mut self, config: &ServerConfig, error: &dyn Error) -> Self {
        if config.verbose_errors {
            self.debug_info = Some(build_debug_info(error));
        }
        self
    }
    
    /// Build the final ErrorContext
    pub fn build(self) -> ErrorContext {
        ErrorContext {
            error_type: self.error_type,
            details: self.details.unwrap_or_else(|| {
                ErrorDetails::SystemError(SystemErrorDetails {
                    component: "unknown".to_string(),
                    message: "No details available".to_string(),
                    code: None,
                })
            }),
            user_message: self.user_message,
            suggestions: self.suggestions,
            debug_info: self.debug_info,
        }
    }
}

/// Build debug information from an error
fn build_debug_info(error: &dyn Error) -> DebugInfo {
    let mut error_chain = Vec::new();
    let mut current = error.source();
    
    while let Some(err) = current {
        error_chain.push(err.to_string());
        current = err.source();
    }
    
    DebugInfo {
        error_chain,
        backtrace: std::backtrace::Backtrace::capture().to_string().into(),
        request_id: None, // Set by caller if available
        timestamp: chrono::Utc::now().to_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}
```

### 3.3 Error Conversion Traits

```rust
// mdmcpsrvr/src/error_conversion.rs

use mdmcp_common::error_context::*;
use mdmcp_common::{McpErrorCode, RpcResponse};
use crate::fs_safety::FsError;
use crate::cmd_catalog::CatalogError;
use mdmcp_policy::PolicyError;

/// Trait for converting domain errors to error contexts
pub trait ToErrorContext {
    /// Convert to error context with appropriate details
    fn to_error_context(&self) -> ErrorContext;
    
    /// Get the appropriate MCP error code
    fn to_mcp_code(&self) -> McpErrorCode;
}

impl ToErrorContext for FsError {
    fn to_error_context(&self) -> ErrorContext {
        match self {
            FsError::PathNotAllowed { path } => {
                ErrorContextBuilder::new(ErrorType::PathNotAllowed)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: path.clone(),
                        rule: "allowed_roots".to_string(),
                        allowed: Some(get_allowed_roots()), // Helper function
                        policy_location: None,
                    }))
                    .with_user_message(format!(
                        "The path '{}' is not within the allowed directories",
                        path
                    ))
                    .add_suggestion("Use a path within one of the allowed root directories")
                    .add_suggestion("Check your policy configuration for allowed paths")
                    .build()
            }
            
            FsError::NetworkFsDenied { path } => {
                ErrorContextBuilder::new(ErrorType::NetworkFsDenied)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: path.clone(),
                        rule: "deny_network_fs".to_string(),
                        allowed: None,
                        policy_location: Some("policy.yaml:deny_network_fs".to_string()),
                    }))
                    .with_user_message("Network filesystem access is not allowed")
                    .add_suggestion("Copy the file to a local filesystem first")
                    .add_suggestion("Or update the policy to allow network filesystem access")
                    .build()
            }
            
            FsError::FileTooLarge { size, limit } => {
                ErrorContextBuilder::new(ErrorType::FileTooLarge)
                    .with_details(ErrorDetails::ResourceLimit(ResourceLimitDetails {
                        resource: "file_size".to_string(),
                        limit: *limit,
                        actual: *size,
                        unit: "bytes".to_string(),
                        config_source: Some("policy.yaml:limits.max_read_bytes".to_string()),
                    }))
                    .with_user_message(format!(
                        "File is too large ({} MB) to read. Maximum allowed size is {} MB",
                        size / 1_048_576,
                        limit / 1_048_576
                    ))
                    .add_suggestion("Read the file in chunks using offset and length parameters")
                    .add_suggestion("Or increase the max_read_bytes limit in the policy")
                    .build()
            }
            
            FsError::WriteNotPermitted { path } => {
                ErrorContextBuilder::new(ErrorType::WriteNotPermitted)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: path.clone(),
                        rule: "write_rules".to_string(),
                        allowed: Some(get_allowed_write_patterns()), // Helper function
                        policy_location: Some("policy.yaml:write_rules".to_string()),
                    }))
                    .with_user_message(format!("Writing to '{}' is not permitted", path))
                    .add_suggestion("Check if the path matches any write rule patterns")
                    .add_suggestion("Update the policy to allow writing to this location")
                    .build()
            }
            
            // ... other variants
        }
    }
    
    fn to_mcp_code(&self) -> McpErrorCode {
        match self {
            FsError::PathNotAllowed { .. } |
            FsError::NetworkFsDenied { .. } |
            FsError::WriteNotPermitted { .. } => McpErrorCode::PolicyDeny,
            FsError::FileTooLarge { .. } => McpErrorCode::InvalidArgs,
            FsError::Io(_) => McpErrorCode::IoError,
            _ => McpErrorCode::Internal,
        }
    }
}

impl ToErrorContext for CatalogError {
    fn to_error_context(&self) -> ErrorContext {
        match self {
            CatalogError::CommandNotFound { id } => {
                ErrorContextBuilder::new(ErrorType::CommandNotAllowed)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: id.clone(),
                        rule: "commands".to_string(),
                        allowed: Some(get_allowed_commands()), // Helper function
                        policy_location: Some("policy.yaml:commands".to_string()),
                    }))
                    .with_user_message(format!("Command '{}' is not allowed", id))
                    .add_suggestion("Use one of the allowed commands")
                    .add_suggestion("Or add this command to the policy")
                    .build()
            }
            
            CatalogError::ArgumentValidation { reason } => {
                ErrorContextBuilder::new(ErrorType::InvalidArgument)
                    .with_details(ErrorDetails::ValidationFailure(ValidationFailureDetails {
                        field: "args".to_string(),
                        value: reason.clone(), // This should be enhanced to include actual arg
                        reason: reason.clone(),
                        expected_format: None,
                        examples: vec![],
                    }))
                    .with_user_message("Command arguments failed validation")
                    .add_suggestion("Check the argument format and allowed values")
                    .build()
            }
            
            CatalogError::EnvironmentValidation { reason } => {
                ErrorContextBuilder::new(ErrorType::InvalidEnvironment)
                    .with_details(ErrorDetails::ValidationFailure(ValidationFailureDetails {
                        field: "env".to_string(),
                        value: String::new(), // Should include the problematic env var
                        reason: reason.clone(),
                        expected_format: Some("KEY=value".to_string()),
                        examples: vec!["PATH=/usr/bin".to_string()],
                    }))
                    .with_user_message("Environment variables failed validation")
                    .add_suggestion("Only use allowed environment variables")
                    .add_suggestion("Check the env_policy in your command configuration")
                    .build()
            }
            
            // ... other variants
        }
    }
    
    fn to_mcp_code(&self) -> McpErrorCode {
        match self {
            CatalogError::CommandNotFound { .. } => McpErrorCode::PolicyDeny,
            CatalogError::ArgumentValidation { .. } |
            CatalogError::EnvironmentValidation { .. } |
            CatalogError::WorkingDirectoryValidation { .. } => McpErrorCode::InvalidArgs,
            CatalogError::Policy(_) => McpErrorCode::PolicyDeny,
            CatalogError::Sandbox(_) => McpErrorCode::Internal,
        }
    }
}
```

## 4. Implementation

### 4.1 Enhanced RPC Error Response Builder

```rust
// mdmcpsrvr/src/rpc.rs

use mdmcp_common::error_context::ErrorContext;
use serde_json::Value;

/// Create an enhanced error response with context
pub fn create_contextual_error_response(
    id: RpcId,
    code: McpErrorCode,
    message: Option<String>,
    context: Option<ErrorContext>,
) -> RpcResponse {
    let error_message = message.unwrap_or_else(|| code.message().to_string());
    
    let data = context.map(|ctx| serde_json::to_value(ctx).unwrap_or(Value::Null));
    
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

/// Helper to create error response from any error implementing ToErrorContext
pub fn create_error_from_context<E: ToErrorContext>(
    id: RpcId,
    error: &E,
    config: &ServerConfig,
) -> RpcResponse {
    let mut context = error.to_error_context();
    
    // Add debug info if verbose mode is enabled
    if config.verbose_errors {
        if let Some(ref mut debug_info) = context.debug_info {
            debug_info.request_id = get_current_request_id(); // Thread-local or context
        }
    }
    
    create_contextual_error_response(
        id,
        error.to_mcp_code(),
        Some(error.to_string()),
        Some(context),
    )
}
```

### 4.2 Server Integration

```rust
// mdmcpsrvr/src/server.rs

impl McpServer {
    async fn handle_fs_read(
        &self,
        ctx: &str,
        id: RpcId,
        params: FsReadParams,
    ) -> RpcResponse {
        // Validate path against policy
        match self.validate_read_path(&params.path).await {
            Ok(canonical_path) => {
                // Proceed with read
                match GuardedFileReader::open(&canonical_path, self.policy.limits.max_read_bytes) {
                    Ok(reader) => {
                        // ... perform read
                    }
                    Err(fs_error) => {
                        // Create contextual error response
                        create_error_from_context(id, &fs_error, &self.config)
                    }
                }
            }
            Err(validation_error) => {
                // Create contextual error response
                create_error_from_context(id, &validation_error, &self.config)
            }
        }
    }
    
    async fn handle_cmd_run(
        &self,
        ctx: &str,
        id: RpcId,
        params: CmdRunParams,
    ) -> RpcResponse {
        let catalog = CommandCatalog::new(self.policy.clone());
        
        match catalog.validate_command(&params) {
            Ok(validated) => {
                match catalog.execute_command(validated).await {
                    Ok(result) => {
                        // Success response
                        create_success_response(id, serde_json::to_value(result).unwrap())
                    }
                    Err(exec_error) => {
                        // Enhanced error with execution details
                        let context = ErrorContextBuilder::new(ErrorType::CommandFailed)
                            .with_details(ErrorDetails::ExecutionError(ExecutionErrorDetails {
                                phase: ExecutionPhase::Execution,
                                operation: Some(params.command_id.clone()),
                                exit_code: exec_error.exit_code(),
                                stderr: exec_error.stderr(),
                                system_error: Some(exec_error.to_string()),
                            }))
                            .with_user_message(format!(
                                "Command '{}' failed to execute",
                                params.command_id
                            ))
                            .add_suggestion("Check the command output for details")
                            .with_debug_info(&self.config, &exec_error)
                            .build();
                        
                        create_contextual_error_response(
                            id,
                            McpErrorCode::Internal,
                            Some(exec_error.to_string()),
                            Some(context),
                        )
                    }
                }
            }
            Err(validation_error) => {
                create_error_from_context(id, &validation_error, &self.config)
            }
        }
    }
}
```

### 4.3 Configuration

```rust
// mdmcpsrvr/src/config.rs

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Enable verbose error reporting (includes debug info)
    #[serde(default)]
    pub verbose_errors: bool,
    
    /// Include suggestions in error responses
    #[serde(default = "default_true")]
    pub include_suggestions: bool,
    
    /// Maximum number of suggestions to include
    #[serde(default = "default_max_suggestions")]
    pub max_suggestions: usize,
    
    /// Include examples in validation errors
    #[serde(default)]
    pub include_examples: bool,
    
    /// Redact sensitive information from errors
    #[serde(default = "default_true")]
    pub redact_sensitive: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            verbose_errors: false,
            include_suggestions: true,
            max_suggestions: 3,
            include_examples: false,
            redact_sensitive: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_suggestions() -> usize {
    3
}
```

## 5. Examples

### 5.1 Policy Denial Error

**Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "fs.read",
        "arguments": {
            "path": "/etc/passwd"
        }
    }
}
```

**Enhanced Error Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32001,
        "message": "Path is outside allowed roots",
        "data": {
            "type": "path_not_allowed",
            "details": {
                "requested": "/etc/passwd",
                "rule": "allowed_roots",
                "allowed": ["/home/user", "/tmp", "/var/app"],
                "policy_location": "policy.yaml:allowed_roots"
            },
            "user_message": "The path '/etc/passwd' is not within the allowed directories",
            "suggestions": [
                "Use a path within one of the allowed root directories",
                "Check your policy configuration for allowed paths"
            ]
        }
    }
}
```

### 5.2 Validation Error

**Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
        "name": "cmd.run",
        "arguments": {
            "commandId": "git",
            "args": ["rm", "-rf", "/"]
        }
    }
}
```

**Enhanced Error Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "error": {
        "code": -32602,
        "message": "Command arguments failed validation",
        "data": {
            "type": "invalid_argument",
            "details": {
                "field": "args[1]",
                "value": "-rf",
                "reason": "Argument matches blocked pattern",
                "expected_format": "Arguments not matching blocked patterns: -rf, --force",
                "examples": ["-n", "--dry-run"]
            },
            "user_message": "The argument '-rf' is not allowed for security reasons",
            "suggestions": [
                "Remove the -rf flag",
                "Use safer alternatives like -i for interactive mode"
            ]
        }
    }
}
```

### 5.3 Resource Limit Error

**Request:**
```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
        "name": "fs.read",
        "arguments": {
            "path": "/var/log/large-file.log"
        }
    }
}
```

**Enhanced Error Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "error": {
        "code": -32602,
        "message": "File too large: 104857600 bytes exceeds limit",
        "data": {
            "type": "file_too_large",
            "details": {
                "resource": "file_size",
                "limit": 10485760,
                "actual": 104857600,
                "unit": "bytes",
                "config_source": "policy.yaml:limits.max_read_bytes"
            },
            "user_message": "File is too large (100 MB) to read. Maximum allowed size is 10 MB",
            "suggestions": [
                "Read the file in chunks using offset and length parameters",
                "Use the 'tail' or 'head' mode to read only part of the file",
                "Or increase the max_read_bytes limit in the policy"
            ]
        }
    }
}
```

### 5.4 Execution Error with Debug Info

**Request (with verbose_errors enabled):**
```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
        "name": "cmd.run",
        "arguments": {
            "commandId": "python",
            "args": ["script.py"],
            "timeoutMs": 5000
        }
    }
}
```

**Enhanced Error Response:**
```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "error": {
        "code": -32002,
        "message": "Command execution timed out",
        "data": {
            "type": "timeout",
            "details": {
                "resource": "execution_time",
                "limit": 5000,
                "actual": 5000,
                "unit": "milliseconds",
                "config_source": "request:timeoutMs"
            },
            "user_message": "The command 'python script.py' took too long to execute",
            "suggestions": [
                "Increase the timeout value if the operation needs more time",
                "Check if the script is stuck in an infinite loop",
                "Consider optimizing the script for better performance"
            ],
            "debug_info": {
                "error_chain": [
                    "Process killed due to timeout",
                    "Signal SIGTERM sent to process 12345"
                ],
                "request_id": "req_abc123",
                "timestamp": "2024-01-15T10:30:45Z",
                "server_version": "0.3.6"
            }
        }
    }
}
```

## 6. Migration Strategy

### 6.1 Phase 1: Foundation (Week 1-2)
1. Implement error context data structures in `mdmcp_common`
2. Add `ToErrorContext` trait and implementations
3. Create `ErrorContextBuilder`
4. Add configuration options

### 6.2 Phase 2: Integration (Week 3-4)
1. Update RPC layer with enhanced error response builder
2. Integrate with existing error paths in `server.rs`
3. Convert domain errors to use new system
4. Add helper functions for common patterns

### 6.3 Phase 3: Enrichment (Week 5-6)
1. Add suggestion generation logic
2. Implement debug info collection
3. Add sensitive data redaction
4. Create error context registry

### 6.4 Phase 4: Testing & Documentation (Week 7-8)
1. Unit tests for all error conversions
2. Integration tests for error responses
3. Update API documentation
4. Create migration guide for clients

## 7. Testing Strategy

### 7.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fs_error_to_context() {
        let error = FsError::FileTooLarge {
            size: 100_000_000,
            limit: 10_000_000,
        };
        
        let context = error.to_error_context();
        
        assert_eq!(context.error_type, ErrorType::FileTooLarge);
        match context.details {
            ErrorDetails::ResourceLimit(details) => {
                assert_eq!(details.limit, 10_000_000);
                assert_eq!(details.actual, 100_000_000);
            }
            _ => panic!("Wrong error details type"),
        }
        assert!(!context.suggestions.is_empty());
    }
    
    #[test]
    fn test_error_response_serialization() {
        let context = ErrorContextBuilder::new(ErrorType::PathNotAllowed)
            .with_user_message("Test message")
            .add_suggestion("Test suggestion")
            .build();
        
        let response = create_contextual_error_response(
            RpcId::Number(1),
            McpErrorCode::PolicyDeny,
            None,
            Some(context),
        );
        
        let json = serde_json::to_value(&response).unwrap();
        
        assert!(json["error"]["data"].is_object());
        assert_eq!(json["error"]["data"]["type"], "path_not_allowed");
        assert!(json["error"]["data"]["suggestions"].is_array());
    }
}
```

### 7.2 Integration Tests

```rust
#[tokio::test]
async fn test_enhanced_error_in_fs_read() {
    let server = create_test_server();
    
    let response = server.handle_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fs.read",
            "arguments": {
                "path": "/forbidden/path"
            }
        }
    })).await;
    
    let error = &response["error"];
    assert_eq!(error["code"], -32001);
    assert!(error["data"].is_object());
    assert_eq!(error["data"]["type"], "path_not_allowed");
    assert!(error["data"]["suggestions"].as_array().unwrap().len() > 0);
}
```

## 8. Backward Compatibility

### 8.1 Compatibility Guarantees
- All existing error codes remain unchanged
- Basic error structure (code, message) unchanged
- Clients ignoring the `data` field continue to work
- Error messages remain compatible

### 8.2 Client Migration Path

```javascript
// Old client code (continues to work)
if (response.error) {
    console.error(`Error ${response.error.code}: ${response.error.message}`);
}

// Enhanced client code
if (response.error) {
    if (response.error.data) {
        // Use rich error information
        const context = response.error.data;
        console.error(`Error: ${context.user_message || response.error.message}`);
        if (context.suggestions) {
            console.log("Suggestions:");
            context.suggestions.forEach(s => console.log(`  - ${s}`));
        }
    } else {
        // Fall back to basic error
        console.error(`Error ${response.error.code}: ${response.error.message}`);
    }
}
```

## 9. Performance Considerations

### 9.1 Impact Analysis
- Error path performance is not critical (errors should be rare)
- Context building adds minimal overhead (~1-2ms)
- Debug info collection only in verbose mode
- Suggestion generation can be cached

### 9.2 Optimizations
- Lazy evaluation of expensive context fields
- Cache frequently used suggestions
- Pre-compile error templates
- Use thread-local storage for request context

## 10. Security Considerations

### 10.1 Information Disclosure
- Never expose internal file paths in production
- Redact sensitive information from error messages
- Limit debug info to authorized users
- Sanitize user input in error messages

### 10.2 Implementation

```rust
fn redact_sensitive_info(mut context: ErrorContext, config: &ServerConfig) -> ErrorContext {
    if !config.redact_sensitive {
        return context;
    }
    
    // Redact internal paths
    if let ErrorDetails::PolicyViolation(ref mut details) = context.details {
        details.policy_location = details.policy_location.map(|_| "<redacted>".to_string());
    }
    
    // Remove debug info in production
    if !config.verbose_errors {
        context.debug_info = None;
    }
    
    context
}
```

## 11. Monitoring & Observability

### 11.1 Metrics
- Error rate by type
- Most common error contexts
- Suggestion effectiveness (if clients report back)
- Error resolution time

### 11.2 Logging

```rust
impl McpServer {
    fn log_error_context(&self, context: &ErrorContext) {
        info!(
            error_type = ?context.error_type,
            has_suggestions = !context.suggestions.is_empty(),
            "Error response generated"
        );
        
        // Detailed logging for debugging
        debug!(
            error_context = ?context,
            "Full error context"
        );
    }
}
```

## 12. Future Enhancements

### 12.1 Short Term (v1.1)
- Localization support for user messages
- Error context caching
- Suggestion ranking based on likelihood

### 12.2 Medium Term (v2.0)
- Machine learning for suggestion generation
- Error pattern detection
- Automatic error recovery hints

### 12.3 Long Term (v3.0)
- Interactive error resolution
- Client-side error recovery automation
- Policy recommendation engine

## 13. Conclusion

This enhanced error handling system will significantly improve the developer experience when working with mdmcp by providing:

1. **Clear, actionable error messages** that explain what went wrong and how to fix it
2. **Structured error data** that clients can programmatically interpret
3. **Debugging support** through optional verbose error information
4. **Backward compatibility** ensuring existing clients continue to work
5. **Security-conscious design** that doesn't leak sensitive information

The implementation is designed to be incremental, testable, and maintainable while providing immediate value to users.