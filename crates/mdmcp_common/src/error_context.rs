use serde::{Deserialize, Serialize};

/// Maximum size for serialized error data (16 KB)
pub const MAX_ERROR_DATA_SIZE: usize = 16_384;
/// Maximum number of suggestions to include
pub const MAX_SUGGESTIONS: usize = 3;
/// Maximum length for any single string field
pub const MAX_STRING_LENGTH: usize = 1024;
/// Maximum stderr/output to include in errors
pub const MAX_OUTPUT_LENGTH: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorContext {
    pub schema_version: u32,
    #[serde(rename = "type")]
    pub error_type: ErrorType,
    pub details: ErrorDetails,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_message: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suggestions: Vec<String>,
    #[serde(default)]
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_info: Option<DebugInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorType {
    PathNotAllowed,
    CommandNotAllowed,
    EnvironmentNotAllowed,
    NetworkFsDenied,
    WriteNotPermitted,
    InvalidPath,
    InvalidArgument,
    InvalidEnvironment,
    MissingRequired,
    PathTraversal,
    FileTooLarge,
    OutputTooLarge,
    Timeout,
    ConcurrencyLimit,
    RateLimit,
    CommandFailed,
    IoError,
    PermissionDenied,
    NotFound,
    InternalError,
    ConfigurationError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ErrorDetails {
    PolicyViolation(PolicyViolationDetails),
    ValidationFailure(ValidationFailureDetails),
    ResourceLimit(ResourceLimitDetails),
    ExecutionError(ExecutionErrorDetails),
    SystemError(SystemErrorDetails),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedValuesSample {
    pub values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub more_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyViolationDetails {
    pub requested: String,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_sample: Option<AllowedValuesSample>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFailureDetails {
    pub field: String,
    pub value: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_format: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimitDetails {
    pub resource: String,
    pub limit: u64,
    pub actual: u64,
    pub unit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionErrorDetails {
    pub phase: ExecutionPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPhase {
    Validation,
    Preparation,
    Execution,
    OutputProcessing,
    Cleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemErrorDetails {
    pub component: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugInfo {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub error_chain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backtrace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub timestamp: String,
    pub server_version: String,
}

