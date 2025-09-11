# MDMCP Error Handling Analysis

## Executive Summary

After reviewing the error handling in mdmcp, I've identified several opportunities to provide more informative error messages to clients. While the current implementation has good basic error structure, many errors lack contextual information that would help clients understand and recover from failures.

## Current State

### Error Structure
- **RPC Error Format**: Uses standard JSON-RPC 2.0 error structure with `code`, `message`, and optional `data` field
- **Error Codes**: Six well-defined MCP error codes:
  - `PolicyDeny` (-32001): Policy violations
  - `InvalidArgs` (-32602): Invalid method parameters
  - `Timeout` (-32002): Operation timeouts
  - `OutputTruncated` (-32003): Output size limits exceeded
  - `IoError` (-32004): I/O errors
  - `Internal` (-32603): Internal server errors

### Current Issues

1. **Minimal Context in Errors**: Most errors only include a basic message without utilizing the `data` field for additional context
2. **Lost Error Details**: When converting from internal errors to RPC errors, detailed information is often discarded
3. **Generic Error Messages**: Many errors use the default message from the error code enum
4. **Inconsistent Error Reporting**: Some paths provide detailed messages while others don't

## Key Findings

### 1. Underutilized `data` Field
The RPC error structure includes an optional `data` field that could provide structured error details, but it's rarely used:

```rust
// Current usage - data field is usually None
create_error_response(
    id,
    McpErrorCode::PolicyDeny,
    Some("Path is outside allowed roots".to_string()),
    None,  // <-- data field unused
)
```

### 2. Lost Policy Violation Context
Policy denials don't indicate which specific rule was violated or what would be allowed:

```rust
// Current: Generic policy denial
if !canon.starts_with(root) {
    return create_error_response(
        id,
        McpErrorCode::PolicyDeny,
        Some("Path is outside allowed roots".to_string()),
        None,
    );
}
```

### 3. Command Execution Error Details
Command validation errors lose important details about what specifically failed:

```rust
// CatalogError has detailed variants but they're flattened to strings
ArgumentValidation { reason: String }
EnvironmentValidation { reason: String }
WorkingDirectoryValidation { reason: String }
```

### 4. File System Error Context
File system errors have good internal structure but don't expose helpful details to clients:

```rust
pub enum FsError {
    PathNotAllowed { path: String },
    NetworkFsDenied { path: String },
    FileTooLarge { size: u64, limit: u64 },
    // etc.
}
```

## Recommendations

### 1. Enhance Error Response Structure

Create structured error data for common failure scenarios:

```rust
// Enhanced error response with contextual data
create_error_response(
    id,
    McpErrorCode::PolicyDeny,
    Some("Path is outside allowed roots".to_string()),
    Some(json!({
        "type": "path_not_allowed",
        "requested_path": "/etc/passwd",
        "allowed_roots": ["/home/user", "/tmp"],
        "suggestion": "Use a path within the allowed roots"
    })),
)
```

### 2. Implement Error Context Types

Define structured error data types for each error category:

```rust
#[derive(Serialize)]
#[serde(tag = "type")]
enum ErrorData {
    PolicyViolation {
        rule_type: String,  // "path", "command", "environment"
        requested_value: String,
        allowed_values: Option<Vec<String>>,
        suggestion: Option<String>,
    },
    ValidationFailure {
        field: String,
        value: String,
        reason: String,
        expected_format: Option<String>,
    },
    ResourceLimit {
        resource: String,  // "file_size", "output", "timeout"
        limit: u64,
        actual: u64,
        unit: String,
    },
    CommandError {
        command_id: String,
        phase: String,  // "validation", "execution", "output"
        details: String,
    },
}
```

### 3. Preserve Error Chain Information

When converting internal errors to RPC errors, preserve the error chain:

```rust
fn convert_fs_error(err: FsError) -> (McpErrorCode, String, Option<Value>) {
    match err {
        FsError::FileTooLarge { size, limit } => (
            McpErrorCode::InvalidArgs,
            format!("File too large: {} bytes exceeds limit", size),
            Some(json!({
                "type": "file_too_large",
                "file_size": size,
                "limit": limit,
                "unit": "bytes"
            }))
        ),
        FsError::NetworkFsDenied { path } => (
            McpErrorCode::PolicyDeny,
            "Network filesystem access denied".to_string(),
            Some(json!({
                "type": "network_fs_denied",
                "path": path,
                "suggestion": "Copy files to a local filesystem first"
            }))
        ),
        // ... other variants
    }
}
```

### 4. Add Debug Mode for Detailed Errors

Include a server configuration option for verbose error reporting during development:

```rust
pub struct ServerConfig {
    pub verbose_errors: bool,  // Include full error chains and stack traces
}

fn create_error_with_context(
    config: &ServerConfig,
    id: RpcId,
    code: McpErrorCode,
    err: &dyn std::error::Error,
) -> RpcResponse {
    let mut data = json!({
        "type": error_type_from_code(code),
    });
    
    if config.verbose_errors {
        data["chain"] = json!(error_chain_to_vec(err));
        data["backtrace"] = json!(err.backtrace().to_string());
    }
    
    create_error_response(id, code, Some(err.to_string()), Some(data))
}
```

### 5. Improve Specific Error Scenarios

#### Policy Denials
```rust
// Instead of:
"Policy denied the operation"

// Provide:
{
    "message": "Command execution denied by policy",
    "data": {
        "type": "command_not_allowed",
        "command_id": "dangerous-cmd",
        "reason": "Command not in allowed list",
        "allowed_commands": ["safe-cmd1", "safe-cmd2"]
    }
}
```

#### Validation Failures
```rust
// Instead of:
"Invalid method parameter(s)"

// Provide:
{
    "message": "Invalid path parameter",
    "data": {
        "type": "validation_failure",
        "field": "path",
        "value": "../../../etc/passwd",
        "reason": "Path traversal detected",
        "expected_format": "Absolute path within allowed roots"
    }
}
```

#### Resource Limits
```rust
// Instead of:
"Operation timed out"

// Provide:
{
    "message": "Command execution timed out",
    "data": {
        "type": "timeout",
        "timeout_ms": 5000,
        "command": "slow-command",
        "suggestion": "Consider increasing timeout or optimizing the command"
    }
}
```

### 6. Client-Friendly Error Messages

Add a `client_message` field for user-facing error text:

```rust
#[derive(Serialize)]
struct EnhancedErrorData {
    #[serde(rename = "type")]
    error_type: String,
    details: Value,
    client_message: String,  // User-friendly explanation
    recovery_suggestions: Vec<String>,  // How to fix/avoid the error
}
```

## Implementation Priority

1. **High Priority**:
   - Add structured data to policy denial errors
   - Include allowed values/ranges in validation errors
   - Preserve file system error details

2. **Medium Priority**:
   - Implement error context types
   - Add recovery suggestions
   - Include command validation details

3. **Low Priority**:
   - Debug mode with full error chains
   - Backtrace information
   - Performance metrics in timeout errors

## Benefits

1. **Improved Debugging**: Clients can understand exactly what went wrong
2. **Better UX**: Applications can provide meaningful error messages to users
3. **Easier Recovery**: Suggestions help clients correct their requests
4. **Reduced Support**: Detailed errors reduce need for server-side log investigation
5. **API Documentation**: Structured errors serve as implicit API documentation

## Backward Compatibility

All proposed changes are backward compatible:
- The `data` field is already optional in the RPC spec
- Existing clients ignoring the `data` field will continue to work
- Error codes and basic messages remain unchanged

## Testing Requirements

1. Unit tests for error conversion functions
2. Integration tests verifying error data structure
3. Client compatibility tests
4. Documentation of all error data schemas

## Conclusion

By enhancing error responses with structured contextual data, mdmcp can significantly improve the developer experience for MCP clients. The proposed changes maintain backward compatibility while providing rich error information that helps clients understand, debug, and recover from failures.