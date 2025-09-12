use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug, Clone)]
#[command(name = "mdaicli")]
#[command(about = "Unified AI CLI with MCP integration", long_about = None)]
pub struct Cli {
    /// Provider (openai|anthropic|openrouter)
    #[arg(short = 'p', long = "provider")]
    pub provider: Option<String>,

    /// Account alias
    #[arg(long)]
    pub account: Option<String>,

    /// Profile name
    #[arg(long)]
    pub profile: Option<String>,

    /// Config file path
    #[arg(long)]
    pub config: Option<String>,

    /// Dry run (print request JSON without executing)
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Bypass cache for this request
    #[arg(long, default_value_t = false)]
    pub no_cache: bool,

    /// Redact sensitive info in logs (no-op placeholder)
    #[arg(long, default_value_t = true)]
    pub redact: bool,

    /// Verbose output
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Send a query to an AI model
    Query(Query),
    /// Store API credentials
    Store(Store),
    /// List providers/models/credentials/cache
    List(List),
    /// Remove credential or cache
    Remove(Remove),
    /// Show usage statistics
    Usage(Usage),
    /// Manage configuration
    #[command(subcommand)]
    Config(ConfigCmd),
    /// OpenAI-specific operations (assistant, vector-store, etc.)
    Openai(OpenaiCmd),
}

#[derive(Args, Debug, Clone)]
pub struct Query {
    #[arg(short = 'm', long = "model")]
    pub model: Option<String>,
    #[arg(long)]
    pub system: Option<String>,
    #[arg(long = "user")]
    pub user: Option<String>,
    /// JSON or YAML conversation file
    #[arg(long = "messages-file")]
    pub messages_file: Option<String>,
    /// Additional context files (may repeat)
    #[arg(long = "input-file")]
    pub input_files: Vec<String>,
    /// How to include input files (system|user)
    #[arg(long = "input-role", default_value = "user")]
    pub input_role: String,
    /// Sampling temperature
    #[arg(short = 't', long = "temperature")]
    pub temperature: Option<f32>,
    /// Nucleus sampling
    #[arg(long = "top-p")]
    pub top_p: Option<f32>,
    /// Max tokens
    #[arg(long = "max-tokens")]
    pub max_tokens: Option<u32>,
    /// Stream response
    #[arg(long, default_value_t = false)]
    pub stream: bool,
    /// Output format (json|text|markdown)
    #[arg(short = 'f', long = "format", default_value = "json")]
    pub format: String,
    /// Request timeout (seconds)
    #[arg(short = 'T', long = "timeout")]
    pub timeout: Option<u64>,
    /// JSON/YAML file with tool definitions
    #[arg(long = "tools-file")]
    pub tools_file: Option<String>,
    /// Write response to file
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct Store {
    #[arg(short = 'p', long = "provider")]
    pub provider: String,
    #[arg(long = "account")]
    pub account: Option<String>,
    #[arg(long = "base-url")]
    pub base_url: Option<String>,
    #[arg(long = "org-id")]
    pub org_id: Option<String>,
    /// Error if stdin is not available (non-interactive)
    #[arg(long = "no-interactive", default_value_t = false)]
    pub no_interactive: bool,
}

#[derive(Args, Debug, Clone)]
pub struct List {
    #[command(subcommand)]
    pub which: ListType,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ListType {
    /// List available providers
    Providers,
    /// List models for a provider
    Models {
        #[arg(short = 'p', long = "provider")]
        provider: Option<String>,
        #[arg(long = "refresh", default_value_t = false)]
        refresh: bool,
    },
    /// List stored credentials (no keys)
    Credentials {
        #[arg(short = 'v', long = "verbose", default_value_t = false)]
        verbose: bool,
    },
    /// List cached responses
    Cache {
        #[arg(short = 'p', long = "provider")]
        provider: Option<String>,
        #[arg(short = 'v', long = "verbose", default_value_t = false)]
        verbose: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub struct Remove {
    #[command(subcommand)]
    pub which: RemoveType,
}

#[derive(Subcommand, Debug, Clone)]
pub enum RemoveType {
    /// Remove stored API key
    Credential {
        #[arg(short = 'p', long = "provider")]
        provider: String,
        #[arg(long = "account")]
        account: Option<String>,
        #[arg(long = "all", default_value_t = false)]
        all: bool,
    },
    /// Clear cache entries
    Cache {
        #[arg(short = 'p', long = "provider")]
        provider: Option<String>,
        #[arg(long = "older-than")]
        older_than_days: Option<u64>,
        #[arg(long = "all", default_value_t = false)]
        all: bool,
        #[arg(long = "confirm", default_value_t = false)]
        confirm: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub struct Usage {
    #[arg(short = 'p', long = "provider")]
    pub provider: Option<String>,
    #[arg(long = "account")]
    pub account: Option<String>,
    #[arg(long = "days", default_value_t = 30)]
    pub days: u32,
    #[arg(short = 'f', long = "format")]
    pub format: Option<String>,
    #[arg(long = "refresh", default_value_t = false)]
    pub refresh: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCmd {
    Get { key: String },
    Set { key: String, value: String },
    List,
    Validate,
    Reset,
}

#[derive(Args, Debug, Clone)]
pub struct OpenaiCmd {
    #[command(subcommand)]
    pub which: OpenaiWhich,
}

#[derive(Subcommand, Debug, Clone)]
pub enum OpenaiWhich {
    Assistant {
        #[command(subcommand)]
        sub: AssistantSub,
    },
    VectorStore {
        #[command(subcommand)]
        sub: VectorStoreSub,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AssistantSub {
    List,
}

#[derive(Subcommand, Debug, Clone)]
pub enum VectorStoreSub {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long = "files")]
        files: Vec<String>,
        #[arg(long = "expires-days")]
        expires_days: Option<u32>,
    },
    Upload {
        #[arg(long = "store-id")]
        store_id: String,
        #[arg(long = "files")]
        files: Vec<String>,
    },
    Delete {
        #[arg(long = "store-id")]
        store_id: String,
    },
}
