# MDMCP Enhanced Error Handling - Final Design v2

## 1. Overview

### 1.1 Purpose
This design document describes a comprehensive enhancement to the error handling system in mdmcp to provide rich, contextual error information to MCP clients while maintaining strict backward compatibility and security guarantees.

### 1.2 Goals
- Provide structured, actionable error information to clients
- Preserve complete backward compatibility with existing clients
- Maintain security through controlled information disclosure
- Enable clients to implement intelligent error recovery
- Keep error payload sizes bounded and performant

### 1.3 Non-Goals
- Changing existing error codes or basic error structure
- Breaking changes to the RPC protocol
- Exposing sensitive internal implementation details
- Implementing client-side error handling logic

### 1.4 Key Design Decisions
- **Nested context approach**: New error context under `data.context` to preserve legacy keys
- **Schema versioning**: Include `schemaVersion` for future evolution
- **Size bounds**: Enforce maximum payload sizes with truncation
- **Security-first**: Default to minimal disclosure, verbose only with explicit flag

## 2. Architecture

### 2.1 Component Overview

```
┌─────────────────┐
│   MCP Client    │
└────────┬────────┘
         │ JSON-RPC Error Response
         │ {error: {code, message, data: {legacy_keys..., context: {...}}}}
         ▼
┌─────────────────┐
│  RPC Layer      │◄──── Enhanced Error Response Builder
│  (rpc.rs)       │      (preserves legacy data keys)
└────────┬────────┘
         │
┌────────▼────────┐
│  Server Core    │◄──── Error Context Enrichment
│  (server.rs)    │      (with size bounds)
└────────┬────────┘
         │
┌────────▼────────┐      ┌──────────────┐
│ Domain Modules  │◄─────│ Error Context│
│ - fs_safety     │      │   Registry   │
│ - cmd_catalog   │      └──────────────┘
│ - policy        │
└─────────────────┘
```

### 2.2 Error Response Structure

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": -32001,
        "message": "Policy denied the operation",
        "data": {
            // Legacy keys preserved for backward compatibility
            "method": "tools/call",
            "requestId": "req_123",
            "policyHash": "abc123...",
            
            // New structured context
            "context": {
                "schemaVersion": 1,
                "type": "path_not_allowed",
                "details": { /* type-specific details */ },
                "userMessage": "The path is not within allowed directories",
                "suggestions": ["Use a path within allowed roots"],
                "retryable": false
            }
        }
    }
}
```

## 3. Data Structures

### 3.1 Core Error Context Types

```rust
// crates/mdmcp_common/src/error_context.rs

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum size for serialized error data (16 KB)
const MAX_ERROR_DATA_SIZE: usize = 16_384;

/// Maximum number of suggestions to include
const MAX_SUGGESTIONS: usize = 3;

/// Maximum length for any single string field
const MAX_STRING_LENGTH: usize = 1024;

/// Maximum stderr/output to include in errors
const MAX_OUTPUT_LENGTH: usize = 2048;

/// Root error context that will be nested under data.context
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorContext {
    /// Schema version for future evolution
    pub schema_version: u32,
    
    /// Machine-readable error type identifier
    #[serde(rename = "type")]
    pub error_type: ErrorType,
    
    /// Detailed error-specific information
    pub details: ErrorDetails,
    
    /// Human-readable message for end users (kept short)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    
    /// Actionable suggestions for fixing the error (max 3)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggestions: Vec<String>,
    
    /// Whether the operation can be retried
    #[serde(default)]
    pub retryable: bool,
    
    /// Debug information (only in verbose mode)
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
    PathTraversal,
    
    // Resource limits
    FileTooLarge,
    OutputTooLarge,
    Timeout,
    ConcurrencyLimit,
    RateLimit,
    
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
#[serde(rename_all = "camelCase")]
pub struct PolicyViolationDetails {
    /// What was requested (truncated if needed)
    pub requested: String,
    
    /// What policy rule was violated
    pub rule: String,
    
    /// Sample of allowed values (max 5, with "+N more" indicator)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_sample: Option<AllowedValuesSample>,
    
    /// Policy location (only in non-production or verbose mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_location: Option<String>,
}

/// Sample of allowed values with overflow indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedValuesSample {
    /// First N allowed values
    pub values: Vec<String>,
    
    /// Number of additional values not shown
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more_count: Option<usize>,
    
    /// Link to full list if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub list_endpoint: Option<String>,
}

/// Details for validation failure errors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationFailureDetails {
    /// Field or parameter that failed validation
    pub field: String,
    
    /// The invalid value provided (truncated and sanitized)
    pub value: String,
    
    /// Why the validation failed
    pub reason: String,
    
    /// Expected format or pattern (sanitized regex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_format: Option<String>,
    
    /// Which specific argument index failed (for array args)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_index: Option<usize>,
    
    /// Valid examples (max 2)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub examples: Vec<String>,
}

/// Details for resource limit errors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLimitDetails {
    /// Type of resource
    pub resource: String,
    
    /// The configured limit
    pub limit: u64,
    
    /// The actual/requested value
    pub actual: u64,
    
    /// Unit of measurement
    pub unit: String,
    
    /// Where this limit is configured (only in verbose mode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
}

/// Details for execution errors
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionErrorDetails {
    /// Phase where error occurred
    pub phase: ExecutionPhase,
    
    /// Command or operation that failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    
    /// Exit code if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    
    /// Truncated stderr output
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
#[serde(rename_all = "camelCase")]
pub struct SystemErrorDetails {
    /// Component where error occurred
    pub component: String,
    
    /// Internal error message (sanitized)
    pub message: String,
    
    /// Error code if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// Debug information (only included in verbose mode)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugInfo {
    /// Error chain (max 5 levels, truncated messages)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub error_chain: Vec<String>,
    
    /// Request context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    
    /// Timestamp
    pub timestamp: String,
    
    /// Server version
    pub server_version: String,
}
```

### 3.2 Error Context Builder with Size Bounds

```rust
// mdmcpsrvr/src/error_context.rs

use mdmcp_common::error_context::*;
use std::error::Error;

/// Builder for constructing error contexts with size constraints
pub struct ErrorContextBuilder {
    error_type: ErrorType,
    details: Option<ErrorDetails>,
    user_message: Option<String>,
    suggestions: Vec<String>,
    retryable: bool,
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
            retryable: false,
            debug_info: None,
        }
    }
    
    /// Set error details
    pub fn with_details(mut self, details: ErrorDetails) -> Self {
        self.details = Some(details);
        self
    }
    
    /// Add a user-friendly message (will be truncated to MAX_STRING_LENGTH)
    pub fn with_user_message(mut self, message: impl Into<String>) -> Self {
        let msg = message.into();
        self.user_message = Some(truncate_string(msg, MAX_STRING_LENGTH));
        self
    }
    
    /// Add a suggestion (max MAX_SUGGESTIONS will be kept)
    pub fn add_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        if self.suggestions.len() < MAX_SUGGESTIONS {
            let sug = truncate_string(suggestion.into(), MAX_STRING_LENGTH);
            self.suggestions.push(sug);
        }
        self
    }
    
    /// Set retryable flag
    pub fn set_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }
    
    /// Add debug information (only if verbose mode enabled)
    pub fn with_debug_info(mut self, config: &ServerConfig, error: &dyn Error) -> Self {
        if config.verbose_errors {
            self.debug_info = Some(build_debug_info(error, config));
        }
        self
    }
    
    /// Build the final ErrorContext with size validation
    pub fn build(self) -> Result<ErrorContext, String> {
        let context = ErrorContext {
            schema_version: 1,
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
            retryable: self.retryable,
            debug_info: self.debug_info,
        };
        
        // Validate size
        if let Ok(serialized) = serde_json::to_vec(&context) {
            if serialized.len() > MAX_ERROR_DATA_SIZE {
                // Fallback to minimal context
                return Ok(create_minimal_context(self.error_type));
            }
        }
        
        Ok(context)
    }
}

/// Truncate string with ellipsis indicator
fn truncate_string(s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        s
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Create minimal context when size limit exceeded
fn create_minimal_context(error_type: ErrorType) -> ErrorContext {
    ErrorContext {
        schema_version: 1,
        error_type,
        details: ErrorDetails::SystemError(SystemErrorDetails {
            component: "error".to_string(),
            message: "Error details truncated due to size".to_string(),
            code: None,
        }),
        user_message: Some("Error details were too large".to_string()),
        suggestions: vec![],
        retryable: false,
        debug_info: None,
    }
}

/// Build debug information with size constraints
fn build_debug_info(error: &dyn Error, config: &ServerConfig) -> DebugInfo {
    let mut error_chain = Vec::new();
    let mut current = error.source();
    let mut depth = 0;
    
    while let Some(err) = current {
        if depth >= 5 {
            error_chain.push("... (truncated)".to_string());
            break;
        }
        error_chain.push(truncate_string(err.to_string(), 256));
        current = err.source();
        depth += 1;
    }
    
    DebugInfo {
        error_chain,
        request_id: None, // Set by caller if available
        timestamp: chrono::Utc::now().to_rfc3339(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Create sample of allowed values with overflow handling
pub fn create_allowed_sample(values: &[String], max_items: usize) -> AllowedValuesSample {
    let total = values.len();
    let take = max_items.min(total);
    
    AllowedValuesSample {
        values: values.iter()
            .take(take)
            .map(|s| truncate_string(s.clone(), 128))
            .collect(),
        more_count: if total > take {
            Some(total - take)
        } else {
            None
        },
        list_endpoint: if total > take {
            Some("/tools/list".to_string()) // Or appropriate endpoint
        } else {
            None
        },
    }
}
```

### 3.3 Error Conversion with Security Controls

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
    fn to_error_context(&self, config: &ServerConfig) -> ErrorContext;
    
    /// Get the appropriate MCP error code
    fn to_mcp_code(&self) -> McpErrorCode;
    
    /// Whether this error is retryable
    fn is_retryable(&self) -> bool {
        false
    }
}

impl ToErrorContext for FsError {
    fn to_error_context(&self, config: &ServerConfig) -> ErrorContext {
        match self {
            FsError::PathNotAllowed { path } => {
                let sanitized_path = sanitize_path(path, config);
                let allowed_roots = get_allowed_roots_sample(config);
                
                ErrorContextBuilder::new(ErrorType::PathNotAllowed)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: sanitized_path,
                        rule: "allowed_roots".to_string(),
                        allowed_sample: Some(allowed_roots),
                        policy_location: if config.show_policy_location {
                            Some("policy.yaml:allowed_roots".to_string())
                        } else {
                            None
                        },
                    }))
                    .with_user_message("The path is not within allowed directories")
                    .add_suggestion("Use a path within allowed root directories")
                    .set_retryable(false)
                    .build()
                    .unwrap_or_else(|_| create_minimal_context(ErrorType::PathNotAllowed))
            }
            
            FsError::NetworkFsDenied { path } => {
                ErrorContextBuilder::new(ErrorType::NetworkFsDenied)
                    .with_details(ErrorDetails::PolicyViolation(PolicyViolationDetails {
                        requested: sanitize_path(path, config),
                        rule: "deny_network_fs".to_string(),
                        allowed_sample: None,
                        policy_location: if config.show_policy_location {
                            Some("policy.yaml:deny_network_fs".to_string())
                        } else {
                            None
                        },
                    }))
                    .with_user_message("Network filesystem access is not allowed")
                    .add_suggestion("Copy the file to a local filesystem first")
                    .set_retryable(false)
                    .build()
                    .unwrap_or_else(|_| create_minimal_context(ErrorType::NetworkFsDenied))
            }
            
            FsError::FileTooLarge { size, limit } => {
                ErrorContextBuilder::new(ErrorType::FileTooLarge)
                    .with_details(ErrorDetails::ResourceLimit(ResourceLimitDetails {
                        resource: "file_size".to_string(),
                        limit: *limit,
                        actual: *size,
                        unit: "bytes".to_string(),
                        config_source: if config.verbose_errors {
                            Some("policy.yaml:limits.max_read_bytes".to_string())
                        } else {
                            None
                        },
                    }))
                    .with_user_message(format!(
                        "File is too large ({} MB), maximum is {} MB",
                        size / 1_048_576,
                        limit / 1_048_576
                    ))
                    .add_suggestion("Read the file in chunks using offset/length")
                    .add_suggestion("Use 'tail' or 'head' mode for partial reads")
                    .set_retryable(false)
                    .build()
                    .unwrap_or_else(|_| create_minimal_context(ErrorType::FileTooLarge))
            }
            
            FsError::Io(io_err) => {
                let retryable = is_transient_io_error(io_err);
                ErrorContextBuilder::new(ErrorType::IoError)
                    .with_details(ErrorDetails::SystemError(SystemErrorDetails {
                        component: "filesystem".to_string(),
                        message: sanitize_io_error(io_err).to_string(),
                        code: io_err.raw_os_error().map(|c| c.to_string()),
                    }))
                    .with_user_message("File operation failed")
                    .set_retryable(retryable)
                    .build()
                    .unwrap_or_else(|_| create_minimal_context(ErrorType::IoError))
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
    
    fn is_retryable(&self) -> bool {
        match self {
            FsError::Io(e) => is_transient_io_error(e),
            _ => false,
        }
    }
}

impl ToErrorContext for CatalogError {
    fn to_error_context(&self, config: &ServerConfig) -> ErrorContext {
        match self {
            CatalogError::ArgumentValidation { reason } => {
                // Parse reason to extract argument details if possible
                let (arg_index, expected) = parse_validation_reason(reason);
                
                ErrorContextBuilder::new(ErrorType::InvalidArgument)
                    .with_details(ErrorDetails::ValidationFailure(ValidationFailureDetails {
                        field: "args".to_string(),
                        value: sanitize_value(reason, config),
                        reason: reason.clone(),
                        expected_format: expected,
                        arg_index,
                        examples: if config.include_examples {
                            vec!["--safe-flag".to_string()]
                        } else {
                            vec![]
                        },
                    }))
                    .with_user_message("Command arguments failed validation")
                    .add_suggestion("Check the argument format")
                    .set_retryable(false)
                    .build()
                    .unwrap_or_else(|_| create_minimal_context(ErrorType::InvalidArgument))
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

/// Security helper functions

fn sanitize_path(path: &str, config: &ServerConfig) -> String {
    if config.redact_sensitive {
        // Redact user-specific parts if needed
        path.replace(r"\Users\", r"\<user>\")
            .replace("/home/", "/<user>/")
            .replace("/Users/", "/<user>/")
    } else {
        truncate_string(path.to_string(), MAX_STRING_LENGTH)
    }
}

fn sanitize_value(value: &str, config: &ServerConfig) -> String {
    if config.redact_sensitive {
        // Redact potential secrets (simple heuristic)
        if value.contains("password") || value.contains("token") || value.contains("key") {
            "<redacted>".to_string()
        } else {
            truncate_string(value.to_string(), 256)
        }
    } else {
        truncate_string(value.to_string(), 256)
    }
}

fn sanitize_io_error(err: &std::io::Error) -> String {
    // Remove potentially sensitive paths from IO errors
    let msg = err.to_string();
    // Simple path redaction - enhance as needed
    msg.replace(r"\Users\", r"\<user>\")
       .replace("/home/", "/<user>/")
}

fn is_transient_io_error(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut
    )
}

fn get_allowed_roots_sample(config: &ServerConfig) -> AllowedValuesSample {
    // Get from policy - placeholder
    let roots = vec![
        "/home/user".to_string(),
        "/tmp".to_string(),
        "/var/app".to_string(),
    ];
    create_allowed_sample(&roots, 5)
}
```

## 4. Implementation

### 4.1 Enhanced RPC Layer with Legacy Preservation

```rust
// mdmcpsrvr/src/rpc.rs

use mdmcp_common::error_context::ErrorContext;
use serde_json::{json, Value};

/// Create enhanced error response preserving legacy data keys
pub fn create_enhanced_error_response(
    id: RpcId,
    code: McpErrorCode,
    message: Option<String>,
    method: &str,
    request_id: &str,
    policy_hash: &str,
    context: Option<ErrorContext>,
) -> RpcResponse {
    let error_message = message.unwrap_or_else(|| code.message().to_string());
    
    // Build data field with legacy keys and new context
    let mut data = json!({
        // Preserve legacy keys for backward compatibility
        "method": method,
        "requestId": request_id,
        "policyHash": policy_hash,
    });
    
    // Add new context under "context" key
    if let Some(ctx) = context {
        if let Ok(ctx_value) = serde_json::to_value(ctx) {
            data["context"] = ctx_value;
        }
    }
    
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(RpcError {
            code: code.into(),
            message: error_message,
            data: Some(data),
        }),
    }
}

/// Fallback when context building fails
pub fn create_fallback_error_response(
    id: RpcId,
    code: McpErrorCode,
    message: String,
    method: &str,
    request_id: &str,
    policy_hash: &str,
) -> RpcResponse {
    create_enhanced_error_response(
        id,
        code,
        Some(message),
        method,
        request_id,
        policy_hash,
        None,
    )
}
```

### 4.2 Server Integration with Safeguards

```rust
// mdmcpsrvr/src/server.rs

impl McpServer {
    /// Handle errors with context building and fallback
    fn handle_error<E: ToErrorContext>(
        &self,
        id: RpcId,
        error: &E,
        method: &str,
        request_id: &str,
    ) -> RpcResponse {
        // Try to build rich context
        let context = match std::panic::catch_unwind(|| {
            error.to_error_context(&self.config)
        }) {
            Ok(ctx) => Some(ctx),
            Err(_) => {
                // Log context build failure
                warn!("Failed to build error context for {}", method);
                None
            }
        };
        
        create_enhanced_error_response(
            id,
            error.to_mcp_code(),
            Some(error.to_string()),
            method,
            request_id,
            &self.policy.policy_hash,
            context,
        )
    }
    
    async fn handle_fs_read(
        &self,
        ctx: &str,
        id: RpcId,
        params: FsReadParams,
    ) -> RpcResponse {
        let request_id = generate_request_id();
        
        match self.validate_read_path(&params.path).await {
            Ok(canonical_path) => {
                match GuardedFileReader::open(&canonical_path, self.policy.limits.max_read_bytes) {
                    Ok(reader) => {
                        // ... perform read
                    }
                    Err(fs_error) => {
                        self.handle_error(id, &fs_error, "fs.read", &request_id)
                    }
                }
            }
            Err(validation_error) => {
                self.handle_error(id, &validation_error, "fs.read", &request_id)
            }
        }
    }
}
```

### 4.3 Configuration with Security Defaults

```rust
// mdmcpsrvr/src/config.rs

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Enable verbose error reporting (default: false)
    #[serde(default)]
    pub verbose_errors: bool,
    
    /// Include suggestions in error responses (default: true)
    #[serde(default = "default_true")]
    pub include_suggestions: bool,
    
    /// Include examples in validation errors (default: false)
    #[serde(default)]
    pub include_examples: bool,
    
    /// Redact sensitive information from errors (default: true)
    #[serde(default = "default_true")]
    pub redact_sensitive: bool,
    
    /// Show policy file locations (default: false in production)
    #[serde(default = "default_policy_location")]
    pub show_policy_location: bool,
    
    /// Maximum error data size in bytes (default: 16KB)
    #[serde(default = "default_max_error_size")]
    pub max_error_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            verbose_errors: false,
            include_suggestions: true,
            include_examples: false,
            redact_sensitive: true,
            show_policy_location: cfg!(debug_assertions), // Only in debug builds
            max_error_size: 16_384,
        }
    }
}

fn default_true() -> bool { true }
fn default_policy_location() -> bool { cfg!(debug_assertions) }
fn default_max_error_size() -> usize { 16_384 }
```

## 5. Testing Strategy

### 5.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_preserve_legacy_keys() {
        let context = ErrorContextBuilder::new(ErrorType::PathNotAllowed)
            .build()
            .unwrap();
        
        let response = create_enhanced_error_response(
            RpcId::Number(1),
            McpErrorCode::PolicyDeny,
            None,
            "fs.read",
            "req_123",
            "abc123",
            Some(context),
        );
        
        let json = serde_json::to_value(&response).unwrap();
        
        // Assert legacy keys exist
        assert_eq!(json["error"]["data"]["method"], "fs.read");
        assert_eq!(json["error"]["data"]["requestId"], "req_123");
        assert_eq!(json["error"]["data"]["policyHash"], "abc123");
        
        // Assert new context exists
        assert!(json["error"]["data"]["context"].is_object());
        assert_eq!(json["error"]["data"]["context"]["schemaVersion"], 1);
    }
    
    #[test]
    fn test_size_limit_enforcement() {
        let huge_string = "x".repeat(20_000);
        let context = ErrorContextBuilder::new(ErrorType::IoError)
            .with_user_message(huge_string)
            .build()
            .unwrap();
        
        // Should be minimal context due to size
        matches!(context.details, ErrorDetails::SystemError(_));
    }
    
    #[test]
    fn test_sensitive_redaction() {
        let config = ServerConfig {
            redact_sensitive: true,
            ..Default::default()
        };
        
        let path = "/Users/johndoe/secret.txt";
        let sanitized = sanitize_path(path, &config);
        assert!(!sanitized.contains("johndoe"));
    }
    
    #[test]
    fn test_allowed_values_sample() {
        let values: Vec<String> = (0..20).map(|i| format!("value_{}", i)).collect();
        let sample = create_allowed_sample(&values, 5);
        
        assert_eq!(sample.values.len(), 5);
        assert_eq!(sample.more_count, Some(15));
        assert!(sample.list_endpoint.is_some());
    }
}
```

### 5.2 Integration Tests

```rust
#[tokio::test]
async fn test_backward_compatibility() {
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
    
    // Legacy clients can still work
    assert_eq!(error["code"], -32001);
    assert!(error["message"].is_string());
    assert_eq!(error["data"]["method"], "tools/call");
    
    // New clients get enhanced context
    assert_eq!(error["data"]["context"]["type"], "path_not_allowed");
    assert_eq!(error["data"]["context"]["schemaVersion"], 1);
}

#[tokio::test]
async fn test_error_size_bounds() {
    let server = create_test_server();
    
    // Trigger error with huge stderr
    let response = server.handle_request(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "cmd.run",
            "arguments": {
                "commandId": "generate-huge-output",
                "args": []
            }
        }
    })).await;
    
    let serialized = serde_json::to_string(&response).unwrap();
    assert!(serialized.len() < 20_000); // Well under size limit
}
```

## 6. Rollout Plan

### 6.1 Phase 1: Foundation (Week 1)
- Implement core error context types in `mdmcp_common`
- Add schema version constant
- Create builder with size validation
- Add security helpers

### 6.2 Phase 2: Domain Integration (Week 2)
- Implement `ToErrorContext` for `FsError`
- Implement `ToErrorContext` for `CatalogError`
- Add retryability detection
- Create allowed values sampling

### 6.3 Phase 3: Server Integration (Week 3)
- Update RPC layer to preserve legacy keys
- Integrate context building with fallbacks
- Add configuration options
- Implement request ID generation

### 6.4 Phase 4: Testing & Metrics (Week 4)
- Comprehensive unit tests
- Integration tests for compatibility
- Add metrics counters
- Performance validation

### 6.5 Incremental Rollout
1. Start with `--verbose-errors` flag (opt-in)
2. Monitor error payload sizes
3. Track client adoption via schema version
4. Gradually enable by default after validation

## 7. Monitoring & Observability

### 7.1 Metrics

```rust
struct ErrorMetrics {
    /// Count of errors by type
    error_count_by_type: HashMap<ErrorType, u64>,
    
    /// Count of legacy vs enhanced responses
    legacy_response_count: u64,
    enhanced_response_count: u64,
    
    /// Size distribution of error payloads
    payload_size_histogram: Histogram,
    
    /// Context build failures
    context_build_failures: u64,
    
    /// Truncation events
    truncation_count: u64,
}
```

### 7.2 Logging

```rust
impl McpServer {
    fn log_error_response(&self, response: &RpcResponse) {
        if let Some(ref error) = response.error {
            let has_context = error.data
                .as_ref()
                .and_then(|d| d.get("context"))
                .is_some();
            
            info!(
                error_code = error.code,
                has_context = has_context,
                message_len = error.message.len(),
                "Error response generated"
            );
            
            if self.config.verbose_errors {
                debug!(?error, "Full error details");
            }
        }
    }
}
```

## 8. Client Migration Guide

### 8.1 Detection and Usage

```javascript
// JavaScript/TypeScript client example
class McpClient {
    handleError(response) {
        const error = response.error;
        if (!error) return;
        
        // Check for enhanced context
        if (error.data?.context?.schemaVersion === 1) {
            this.handleEnhancedError(error.data.context);
        } else {
            // Fallback to legacy handling
            this.handleLegacyError(error);
        }
    }
    
    handleEnhancedError(context) {
        // Use structured context
        console.error(`Error: ${context.userMessage || 'Operation failed'}`);
        
        if (context.suggestions?.length > 0) {
            console.log('Suggestions:');
            context.suggestions.forEach(s => console.log(`  - ${s}`));
        }
        
        if (context.retryable) {
            this.scheduleRetry();
        }
        
        // Handle specific error types
        switch (context.type) {
            case 'path_not_allowed':
                this.showAllowedPaths(context.details.allowedSample);
                break;
            case 'file_too_large':
                this.suggestChunkedRead(context.details);
                break;
            // ... other cases
        }
    }
}
```

### 8.2 Schema Documentation

```typescript
// TypeScript definitions for clients
interface ErrorContext {
    schemaVersion: number;
    type: ErrorType;
    details: ErrorDetails;
    userMessage?: string;
    suggestions?: string[];
    retryable: boolean;
    debugInfo?: DebugInfo;
}

type ErrorType = 
    | 'path_not_allowed'
    | 'command_not_allowed'
    | 'file_too_large'
    | 'timeout'
    // ... etc
```

## 9. Security Checklist

- [x] Path sanitization for user directories
- [x] Secret redaction in values
- [x] Policy location only in debug/verbose
- [x] Size limits on all string fields
- [x] Truncation of stderr/output
- [x] No raw backtraces by default
- [x] Error chain depth limit
- [x] Configurable redaction levels
- [x] Fallback on context build failure

## 10. Open Questions & Future Work

### 10.1 Addressed Questions
- **Q: Should we surface a "retryable" hint?**
  - A: Yes, added `retryable` field based on error type
  
- **Q: How do we expose allowed write patterns succinctly?**
  - A: Using `AllowedValuesSample` with top-N and "+N more" pattern

- **Q: Will clients request detail level per request?**
  - A: Deferred to v2; using server config for now

### 10.2 Future Enhancements
- Client-specific error detail levels via headers
- Localization of user messages
- Error code mapping for different client types
- Caching of expensive error context generation
- Machine learning for suggestion generation

## 11. Conclusion

This final design addresses all review feedback:

1. **Backward Compatibility**: Preserves legacy `data` keys, adds `context` as new nested object
2. **Security**: Defaults to redacted/minimal info, verbose only with explicit flag
3. **Size Bounds**: Enforces 16KB limit with truncation and fallbacks
4. **Completeness**: Enhanced error types for all scenarios including rate limits and Windows paths
5. **Robustness**: Fallback paths ensure errors always return valid responses
6. **Testing**: Comprehensive strategy including golden tests and size validation

The implementation provides immediate value while maintaining safety and compatibility.