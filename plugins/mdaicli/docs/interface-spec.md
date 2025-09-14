# mdaicli Interface Specification

## Overview
`mdaicli` is a command-line interface tool that provides unified access to multiple AI providers (OpenAI, Anthropic, OpenRouter) with secure credential management and integration with the MDMCP server via the `run_command` tool.

## Design Principles
1. **Security First**: No API keys in command arguments or environment variables
2. **Provider Agnostic**: Consistent interface across all providers
3. **MCP Compatible**: Output format suitable for MDMCP auditing
4. **Platform Native**: Use OS-specific secure credential storage
5. **Extensible**: Easy to add new providers and features

## Command Structure

```
mdaicli <command> [options]
```

### Commands

#### 1. `query` - Send a query to an AI model
```bash
mdaicli query [OPTIONS]

Options:
  --provider <name>         Provider name (openai|anthropic|openrouter) [required]
  --model <name>            Model identifier [required]
  --system <text>           System prompt/instructions
  --user <text>             User message/prompt [required unless --messages-file]
  --messages-file <path>    JSON file containing full conversation
  --input-file <path>       Additional context file to include
  --max-tokens <n>          Maximum tokens to generate
  --temperature <n>         Sampling temperature (0.0-2.0)
  --top-p <n>              Nucleus sampling parameter
  --stream                  Stream the response
  --format <type>          Output format (json|text|markdown) [default: json]
  --cache                   Use cached response if available
  --timeout <seconds>       Request timeout [default: 120]
  --tools-file <path>       JSON file defining available tools
  --output <path>          Write response to file instead of stdout

Examples:
  mdaicli query --provider openai --model gpt-4 --user "Explain quantum computing"
  mdaicli query --provider anthropic --model claude-3-opus-20240229 --system "You are a code reviewer" --input-file main.rs --user "Review this code"
  mdaicli query --provider openrouter --model auto --messages-file conversation.json
```

#### 2. `store` - Store API credentials
```bash
mdaicli store [OPTIONS]

Options:
  --provider <name>         Provider name [required]
  --api-key <key>          API key (prompted if not provided)
  --base-url <url>         Custom base URL (for self-hosted/proxies)
  --org-id <id>           Organization ID (OpenAI specific)

Examples:
  mdaicli store --provider openai
  mdaicli store --provider openrouter --api-key sk-or-xxx
  mdaicli store --provider anthropic --base-url https://proxy.company.com
```

#### 3. `list` - List providers, models, or stored credentials
```bash
mdaicli list <type> [OPTIONS]

Types:
  providers               List available providers
  models                 List models for a provider
  credentials            List stored credentials (without showing keys)

Options:
  --provider <name>      Filter by provider (for models)
  --verbose             Show detailed information

Examples:
  mdaicli list providers
  mdaicli list models --provider openai
  mdaicli list credentials --verbose
```

#### 4. `remove` - Remove stored credentials
```bash
mdaicli remove [OPTIONS]

Options:
  --provider <name>      Provider to remove [required]
  --confirm             Skip confirmation prompt

Examples:
  mdaicli remove --provider openai
  mdaicli remove --provider all --confirm
```

#### 5. `usage` - Show usage statistics and costs
```bash
mdaicli usage [OPTIONS]

Options:
  --provider <name>      Filter by provider
  --days <n>            Number of days to show [default: 30]
  --format <type>       Output format (table|json|csv)

Examples:
  mdaicli usage --days 7
  mdaicli usage --provider openai --format csv
```

#### 6. `assistant` - OpenAI Assistant operations
```bash
mdaicli assistant <subcommand> [OPTIONS]

Subcommands:
  create                Create a new assistant
  list                  List assistants
  run                   Run an assistant
  delete                Delete an assistant

Options (create):
  --name <name>         Assistant name
  --instructions <text> System instructions
  --model <name>        Model to use
  --tools <list>        Tools (code_interpreter|file_search)
  --files <paths>       Files to attach

Options (run):
  --assistant-id <id>   Assistant ID [required]
  --thread-id <id>      Thread ID (creates new if not provided)
  --user <text>         User message
  --files <paths>       Additional files

Examples:
  mdaicli assistant create --name "Code Helper" --model gpt-4 --tools code_interpreter
  mdaicli assistant run --assistant-id asst_xxx --user "Debug this error"
```

#### 7. `vector-store` - OpenAI Vector Store operations
```bash
mdaicli vector-store <subcommand> [OPTIONS]

Subcommands:
  create                Create vector store
  upload                Upload files to store
  list                  List vector stores
  search                Search in vector store
  delete                Delete vector store

Options (create):
  --name <name>         Store name
  --files <paths>       Initial files to upload
  --expires-days <n>    Auto-expiry in days

Options (search):
  --store-id <id>       Vector store ID [required]
  --query <text>        Search query [required]
  --limit <n>           Maximum results [default: 10]

Examples:
  mdaicli vector-store create --name "Documentation" --files "*.md"
  mdaicli vector-store search --store-id vs_xxx --query "authentication"
```

#### 8. `config` - Manage mdaicli configuration
```bash
mdaicli config <subcommand> [OPTIONS]

Subcommands:
  get <key>             Get configuration value
  set <key> <value>     Set configuration value
  list                  List all configuration
  reset                 Reset to defaults

Configuration Keys:
  default.provider      Default provider
  default.model         Default model per provider
  cache.enabled         Enable response caching
  cache.ttl            Cache TTL in seconds
  cache.max_size       Maximum cache size in MB
  output.format        Default output format
  limits.<provider>.rpm Requests per minute limit
  limits.<provider>.tpm Tokens per minute limit

Examples:
  mdaicli config set default.provider openai
  mdaicli config set cache.enabled true
  mdaicli config get default.model.openai
```

## Output Formats

### JSON Format (MCP Compatible)
```json
{
  "success": true,
  "provider": "openai",
  "model": "gpt-4",
  "request_id": "req_xxx",
  "response": {
    "content": "AI response text",
    "role": "assistant",
    "tool_calls": []
  },
  "usage": {
    "prompt_tokens": 150,
    "completion_tokens": 200,
    "total_tokens": 350,
    "estimated_cost": 0.0105
  },
  "metadata": {
    "latency_ms": 1234,
    "cached": false,
    "timestamp": "2024-01-15T10:30:00Z",
    "provider_metadata": {}
  }
}
```

### Text Format
```
[OpenAI GPT-4]
AI response text here...

---
Tokens: 350 | Cost: $0.0105 | Latency: 1.23s
```

### Markdown Format
```markdown
## Response from OpenAI GPT-4

AI response text here...

---
*Tokens: 350 | Cost: $0.0105 | Latency: 1.23s*
```

## Message File Format
For complex conversations, use `--messages-file`:

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
    },
    {
      "role": "user",
      "content": "Tell me about Rust"
    }
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get weather for a location",
        "parameters": {
          "type": "object",
          "properties": {
            "location": {
              "type": "string"
            }
          }
        }
      }
    }
  ]
}
```

## Credential Storage

### Windows
- Storage: Windows Credential Manager
- Namespace: `mdaicli:<provider>`
- Encryption: DPAPI

### macOS
- Storage: Keychain
- Service: `mdaicli`
- Account: `<provider>`
- Encryption: Keychain Services

### Linux
- Primary: Secret Service (libsecret)
- Fallback: Encrypted file `~/.config/mdaicli/credentials.enc`
- Encryption: AES-256-GCM with key from keyring

## Configuration File

Location:
- Windows: `%APPDATA%\mdaicli\config.toml`
- macOS: `~/Library/Application Support/mdaicli/config.toml`
- Linux: `~/.config/mdaicli/config.toml`

Format:
```toml
[default]
provider = "openai"
format = "json"

[default.models]
openai = "gpt-4"
anthropic = "claude-3-opus-20240229"
openrouter = "auto"

[cache]
enabled = true
ttl = 3600
max_size_mb = 100
directory = "~/.cache/mdaicli"

[limits.openai]
requests_per_minute = 60
tokens_per_minute = 90000

[limits.anthropic]
requests_per_minute = 50
tokens_per_minute = 100000

[logging]
level = "info"
file = "~/.local/share/mdaicli/mdaicli.log"
```

## Error Handling

### Error Response Format
```json
{
  "success": false,
  "error": {
    "type": "provider_error",
    "code": "rate_limit_exceeded",
    "message": "Rate limit exceeded for OpenAI",
    "details": {
      "provider": "openai",
      "retry_after": 60
    }
  }
}
```

### Error Types
- `credential_error`: Missing or invalid credentials
- `provider_error`: Provider API error
- `network_error`: Connection issues
- `validation_error`: Invalid parameters
- `file_error`: File access issues
- `config_error`: Configuration problems

## Integration with MDMCP

### Policy Configuration
```yaml
commands:
  - id: ai
    exec: C:/mdmcp/bin/mdaicli.exe
    description: "AI model queries via mdaicli"
    args:
      pattern: '^(query|list|usage|assistant|vector-store)$'
      allow_any_args: true
    env_allowlist: []
    cwd_policy: "allowed"
    timeout: 300
    platform: ["windows", "linux", "macos"]
```

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

// Assistant interaction
await use_mcp_tool("mdmcp", "run_command", {
  command_id: "ai",
  args: [
    "assistant",
    "run",
    "--assistant-id", "asst_xxx",
    "--user", "Debug this error",
    "--files", "/workspace/error.log"
  ]
});
```

## Security Considerations

1. **No Secrets in Arguments**: API keys never passed as arguments
2. **Secure Storage**: Platform-native encrypted credential storage
3. **Audit Trail**: All operations logged for security monitoring
4. **File Access**: Respects MDMCP's `allowed_roots` when accessing files
5. **Output Sanitization**: No credentials in output
6. **Rate Limiting**: Built-in rate limit management
7. **Timeout Protection**: Configurable timeouts for all operations

## Performance Features

1. **Response Caching**: Optional caching with TTL
2. **Connection Pooling**: Reuse HTTP connections
3. **Streaming Support**: For long responses
4. **Parallel Requests**: Batch processing support
5. **Retry Logic**: Automatic retry with backoff

## Future Extensions

1. **Embedding Operations**: Support for embedding APIs
2. **Fine-Tuning Management**: Manage fine-tuned models
3. **Prompt Templates**: Reusable prompt templates
4. **Chain Operations**: Sequential API calls with context
5. **Cost Budgets**: Spending limits and alerts
6. **Multi-Account Support**: Multiple credentials per provider
7. **Proxy Support**: SOCKS/HTTP proxy configuration
8. **Offline Mode**: Work with cached responses