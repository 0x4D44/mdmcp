# mdaicli Interface Specification v2.0

## Overview
`mdaicli` is a command-line interface tool providing unified access to multiple AI providers (OpenAI, Anthropic, OpenRouter) with secure credential management and integration with MDMCP server via the `run_command` tool.

## Design Principles
1. **Security First**: No API keys in command arguments; platform-native credential storage
2. **Provider Agnostic**: Consistent interface across providers for common operations
3. **MCP Compatible**: Output format and file access respect MDMCP policies
4. **Platform Native**: OS-specific secure credential storage and conventions
5. **Auditable**: Complete request/response logging for security monitoring

## Command Structure

```
mdaicli <command> [options]
```

### Global Options
- `-p, --provider <name>`: Provider (openai|anthropic|openrouter)
- `--account <alias>`: Account alias for multi-account support
- `--profile <name>`: Configuration profile to use
- `--config <path>`: Custom config file location
- `--dry-run`: Print request JSON without executing
- `--no-cache`: Bypass cache for this request
- `--redact`: Redact sensitive data in logs [default: true]
- `-v, --verbose`: Verbose output
- `-h, --help`: Show help

## Commands

### 1. `query` - Send a query to an AI model
```bash
mdaicli query [OPTIONS]

Required (one of):
  --user <text>            User message/prompt
  --messages-file <path>   JSON/YAML file with conversation

Options:
  -p, --provider <name>    Provider name [env: MDAICLI_PROVIDER]
  -m, --model <name>       Model identifier [env: MDAICLI_MODEL]
  --system <text>          System prompt/instructions
  --input-file <path>...   Additional context files (can repeat)
  --input-role <role>      How to include input files (system|user) [default: user]
  --max-tokens <n>         Maximum tokens to generate
  -t, --temperature <n>    Sampling temperature (0.0-2.0)
  --top-p <n>             Nucleus sampling parameter
  --stream                Stream the response
  -f, --format <type>     Output format (json|text|markdown) [default: json]
  -T, --timeout <sec>     Request timeout [default: 120] [env: MDAICLI_TIMEOUT]
  --tools-file <path>     JSON/YAML file with tool definitions
  -o, --output <path>     Write response to file

Examples:
  mdaicli query -p openai -m gpt-4 --user "Explain quantum computing"
  mdaicli query --messages-file chat.json --stream -f text
  mdaicli query --input-file main.rs --input-role system --user "Review this code"
  echo "What is 2+2?" | mdaicli query -p anthropic -m claude-3-opus-20240229
```

### 2. `store` - Store API credentials
```bash
mdaicli store [OPTIONS]

Options:
  -p, --provider <name>    Provider name [required]
  --account <alias>        Account alias [default: default]
  --base-url <url>        Custom base URL
  --org-id <id>          Organization ID (OpenAI)
  --no-interactive        Error if stdin is not available

Security Note: API key is read from stdin or interactive prompt only.
Never pass API keys as command arguments.

Examples:
  mdaicli store -p openai --account personal
  echo $API_KEY | mdaicli store -p anthropic --no-interactive
  mdaicli store -p openrouter --base-url https://proxy.corp.com
```

### 3. `list` - List providers, models, or credentials
```bash
mdaicli list <type> [OPTIONS]

Types:
  providers              List available providers
  models                List models for a provider
  credentials           List stored credentials (no keys shown)
  cache                 List cached responses

Options:
  -p, --provider <name>  Filter by provider (for models)
  --account <alias>      Filter by account
  --refresh             Force refresh (bypass cache)
  -v, --verbose         Detailed information

Examples:
  mdaicli list providers
  mdaicli list models -p openai --refresh
  mdaicli list credentials --verbose
  mdaicli list cache --provider anthropic
```

### 4. `remove` - Remove stored credentials or cache
```bash
mdaicli remove <type> [OPTIONS]

Types:
  credential            Remove stored API key
  cache                Clear cache entries

Options:
  -p, --provider <name>  Provider [required for credential]
  --account <alias>      Account alias
  --all                 Remove all entries
  --older-than <days>   Remove cache older than N days
  --confirm             Skip confirmation

Examples:
  mdaicli remove credential -p openai --account work
  mdaicli remove cache --all --confirm
  mdaicli remove cache --older-than 7
```

### 5. `usage` - Show usage statistics
```bash
mdaicli usage [OPTIONS]

Options:
  -p, --provider <name>  Filter by provider
  --account <alias>      Filter by account
  --days <n>            Days to show [default: 30]
  -f, --format <type>   Output format (table|json|csv)
  --refresh             Query provider APIs (vs local logs)

Examples:
  mdaicli usage --days 7
  mdaicli usage -p openai --format csv --refresh
```

### 6. `config` - Manage configuration
```bash
mdaicli config <subcommand> [OPTIONS]

Subcommands:
  get <key>            Get configuration value
  set <key> <value>    Set configuration value
  list                 List all configuration
  validate            Validate configuration
  reset               Reset to defaults

Examples:
  mdaicli config set default.provider openai
  mdaicli config set cache.max_size_mb 500
  mdaicli config get limits.openai.requests_per_minute
  mdaicli config validate
```

### 7. Provider-Specific Commands

#### OpenAI-specific operations
```bash
mdaicli openai <subcommand> [OPTIONS]

Subcommands:
  assistant           Manage assistants
  vector-store       Manage vector stores
  file               Manage files
  fine-tune          Manage fine-tuned models

Examples:
  mdaicli openai assistant create --name "Helper" --model gpt-4
  mdaicli openai vector-store create --name "Docs" --files "*.md"
  mdaicli openai assistant run --id asst_xxx --user "Help me"
```

## Configuration

### Precedence Order
1. Command-line flags
2. Environment variables
3. Configuration file
4. Built-in defaults

### Environment Variables
```bash
MDAICLI_PROVIDER=openai
MDAICLI_MODEL=gpt-4
MDAICLI_FORMAT=json
MDAICLI_TIMEOUT=120
MDAICLI_CACHE_DIR=/custom/cache
MDAICLI_CONFIG=/custom/config.toml
MDAICLI_ALLOWED_ROOTS=/workspace,/tmp  # MCP integration
MDAICLI_NO_CACHE=1
MDAICLI_PROFILE=production
HTTP_PROXY=http://proxy:8080
HTTPS_PROXY=http://proxy:8080
NO_PROXY=localhost,127.0.0.1
```

### Configuration File

Location:
- Windows: `%APPDATA%\mdaicli\config.toml`
- macOS: `~/Library/Application Support/mdaicli/config.toml`
- Linux: `~/.config/mdaicli/config.toml`

```toml
[default]
provider = "openai"
format = "json"

[default.models]
openai = "gpt-4"
anthropic = "claude-3-opus-20240229"
openrouter = "auto"

[profiles.production]
provider = "openai"
model = "gpt-4-turbo"
temperature = 0.3
max_tokens = 2000

[cache]
enabled = true
ttl_seconds = 3600
max_size_mb = 500
directory = "~/.cache/mdaicli"

[limits.openai]
requests_per_minute = 60
tokens_per_minute = 90000

[limits.anthropic]
requests_per_minute = 50
tokens_per_minute = 100000

[logging]
level = "info"
directory = "~/.local/share/mdaicli/logs"  # %LOCALAPPDATA%\mdaicli\logs on Windows
max_files = 10
max_size_mb = 50
redact_sensitive = true
```

## Output Formats

### JSON Format (MCP Compatible)
```json
{
  "success": true,
  "request": {
    "provider": "openai",
    "model": "gpt-4",
    "messages": "[redacted]",
    "parameters": {
      "temperature": 0.7,
      "max_tokens": 1000
    }
  },
  "response": {
    "content": "AI response text",
    "role": "assistant",
    "tool_calls": []
  },
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350,
    "estimated_cost": {
      "amount": 0.0105,
      "currency": "USD",
      "price_date": "2024-01-15"
    }
  },
  "metadata": {
    "request_id": "req_xxx",
    "latency_ms": 1234,
    "cached": false,
    "cache_key": "sha256:abc123...",
    "timestamp": "2024-01-15T10:30:00Z",
    "account": "default"
  },
  "warnings": []
}
```

### Streaming JSON Format
```jsonl
{"event": "start", "request_id": "req_xxx", "model": "gpt-4"}
{"event": "delta", "content": "Hello"}
{"event": "delta", "content": " there"}
{"event": "tool_call", "tool": "get_weather", "arguments": {...}}
{"event": "end", "usage": {...}, "finish_reason": "stop"}
```

### Text/Markdown Streaming
```
[Streaming from OpenAI GPT-4...]
Hello there! How can I help you today?
[... content streams in real-time ...]

---
Tokens: 350 | Cost: $0.0105 | Latency: 1.23s
```

## Message File Formats

### JSON Format
```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are a helpful assistant"
    },
    {
      "role": "user",
      "content": "Hello"
    },
    {
      "role": "assistant",
      "content": "Hi! How can I help?"
    }
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get weather",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {"type": "string"}
          },
          "required": ["location"]
        }
      }
    }
  ]
}
```

### YAML Format
```yaml
messages:
  - role: system
    content: You are a helpful assistant
  - role: user
    content: Hello
  - role: assistant
    content: Hi! How can I help?

tools:
  - type: function
    function:
      name: get_weather
      description: Get weather
      parameters:
        type: object
        properties:
          location:
            type: string
        required: [location]
```

## Credential Storage

### Storage Locations

#### Windows
- Method: Windows Credential Manager
- Namespace: `mdaicli:<provider>:<account>`
- Encryption: DPAPI
- Multi-account: Supported via account aliases

#### macOS
- Method: Keychain Services
- Service: `mdaicli`
- Account: `<provider>:<account>`
- Encryption: Keychain encryption

#### Linux
- Primary: Secret Service (libsecret)
- Fallback: Encrypted file `~/.config/mdaicli/credentials.enc`
- Key derivation: Argon2id with:
  - Memory: 64MB
  - Iterations: 3
  - Parallelism: 4
  - Salt: Random 32 bytes stored with ciphertext
- Encryption: AES-256-GCM
- Passphrase: User-provided, no-echo prompt

### Multi-Account Support
```bash
# Store multiple accounts
mdaicli store -p openai --account personal
mdaicli store -p openai --account work

# Use specific account
mdaicli query -p openai --account work --user "Query"

# Set default account
mdaicli config set accounts.openai.default work
```

## Security

### API Key Input
- **Never** pass API keys as command arguments
- Input methods:
  - Interactive masked prompt (default)
  - Stdin pipe: `echo $KEY | mdaicli store -p openai`
  - File redirect: `mdaicli store -p openai < key.txt`

### File Access Control (MCP Integration)
When running under MDMCP:
- Honor `MDAICLI_ALLOWED_ROOTS` environment variable
- Validate all file paths against allowed roots
- Reject URI schemes (http://, file://, mdmcp://)
- Error with clear message suggesting MCP resource tools

Example enforcement:
```bash
export MDAICLI_ALLOWED_ROOTS="/workspace,/tmp"
mdaicli query --input-file /etc/passwd  # ERROR: Path not in allowed roots
```

### Logging and Redaction
- Default: Redact API keys, file contents, and sensitive patterns
- Control: `--redact` / `--no-redact`
- Patterns redacted:
  - API keys (sk-*, key-*, api_*)
  - Passwords and tokens
  - File contents over 1KB
  - Email addresses (optional)

## Cache Management

### Cache Key Composition
```
SHA256(
  provider +
  model +
  normalized_messages +
  tool_definitions +
  temperature +
  max_tokens +
  file_content_hashes
)
```

### Cache Operations
```bash
# View cache status
mdaicli list cache --verbose

# Clear all cache
mdaicli remove cache --all

# Clear old entries
mdaicli remove cache --older-than 7

# Clear specific provider
mdaicli remove cache -p openai
```

## Rate Limiting

### Algorithm
- Token bucket per provider-account pair
- Configurable via `limits.<provider>.*` config
- Automatic 429 handling with exponential backoff
- Honor `Retry-After` headers

### Configuration
```toml
[limits.openai]
requests_per_minute = 60
tokens_per_minute = 90000
max_retries = 3
backoff_base_ms = 1000
backoff_max_ms = 60000
```

## Error Handling

### Exit Codes
- `0`: Success
- `1`: General error
- `2`: Validation error (bad arguments)
- `3`: Provider API error
- `4`: Network error
- `5`: Credential error
- `6`: File access error
- `7`: Configuration error
- `8`: Rate limit error
- `9`: Cache error

### Error Response Format
```json
{
  "success": false,
  "error": {
    "type": "provider_error",
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded for OpenAI",
    "http_status": 429,
    "details": {
      "provider": "openai",
      "account": "default",
      "retry_after_ms": 60000
    },
    "remediation": "Wait 60 seconds or use a different account"
  }
}
```

## MCP Integration

### Policy Configuration
```yaml
commands:
  - id: ai
    exec: C:/mdmcp/bin/mdaicli.exe
    description: "AI model queries via mdaicli"
    args:
      # Only allow query and list operations from MCP
      pattern: '^(query|list|usage)$'
      # Further restrict subcommands
      allowed_args:
        - "--provider"
        - "--model"
        - "--user"
        - "--system"
        - "--input-file"
        - "--format"
        - "--stream"
        - "--max-tokens"
        - "--temperature"
    env_allowlist:
      - "MDAICLI_ALLOWED_ROOTS"
    env_pass:
      MDAICLI_ALLOWED_ROOTS: "${MDMCP_ALLOWED_ROOTS}"
    cwd_policy: "allowed"
    timeout: 300
    platform: ["windows", "linux", "macos"]
```

### WSL Support
- Runtime detection: Check for `/proc/sys/fs/binfmt_misc/WSLInterop`
- Path normalization:
  - Convert Windows paths to WSL: `C:\Users` → `/mnt/c/Users`
  - Access Windows Credential Manager from WSL via `/mnt/c/Windows/System32/cmdkey.exe`

### Usage from Claude
```javascript
// Simple query
await use_mcp_tool("mdmcp", "run_command", {
  command_id: "ai",
  args: [
    "query",
    "--provider", "openai",
    "--model", "gpt-4",
    "--user", "Explain this code",
    "--input-file", "/workspace/main.rs",
    "--format", "json"
  ]
});

// With streaming
await use_mcp_tool("mdmcp", "run_command", {
  command_id: "ai",
  args: [
    "query",
    "--provider", "anthropic",
    "--model", "claude-3-opus-20240229",
    "--messages-file", "/workspace/conversation.json",
    "--stream",
    "--format", "text"
  ]
});
```

## Examples

### Basic Query
```bash
# Simple question
mdaicli query -p openai -m gpt-4 --user "What is the capital of France?"

# With system prompt
mdaicli query -p anthropic -m claude-3-opus-20240229 \
  --system "You are a helpful coding assistant" \
  --user "Explain async/await in Rust"

# From file with streaming
mdaicli query -p openai -m gpt-4 \
  --input-file code.rs \
  --user "Review this code for bugs" \
  --stream -f text
```

### Multi-turn Conversation
```bash
# Create conversation file
cat > chat.json << EOF
{
  "messages": [
    {"role": "system", "content": "You are a Rust expert"},
    {"role": "user", "content": "What are lifetimes?"},
    {"role": "assistant", "content": "Lifetimes are..."},
    {"role": "user", "content": "Show me an example"}
  ]
}
EOF

# Continue conversation
mdaicli query --messages-file chat.json -p openai -m gpt-4
```

### Tool Use
```bash
# Define tools
cat > tools.json << EOF
{
  "tools": [{
    "type": "function",
    "function": {
      "name": "calculate",
      "description": "Perform calculations",
      "parameters": {
        "type": "object",
        "properties": {
          "expression": {"type": "string"}
        }
      }
    }
  }]
}
EOF

# Query with tools
mdaicli query -p openai -m gpt-4 \
  --tools-file tools.json \
  --user "What is 15% of 2,500?"
```

## Performance Considerations

1. **Connection Pooling**: Reuse HTTPS connections per provider
2. **Response Caching**: SHA256-based with configurable TTL
3. **Streaming**: Reduces time-to-first-token for long responses
4. **Parallel Requests**: Batch processing via `--batch` flag (future)
5. **Retry Logic**: Exponential backoff with jitter

## Future Extensions

1. **Embeddings**: `mdaicli embed` command
2. **Fine-tuning**: Manage fine-tuned models
3. **Templates**: Reusable prompt templates
4. **Chains**: Sequential operations with context
5. **Budgets**: Cost limits and alerts
6. **Plugins**: Provider extensions via shared libraries
7. **Batch API**: Async batch processing support