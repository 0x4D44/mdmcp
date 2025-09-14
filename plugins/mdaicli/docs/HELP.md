<!-- This file mirrors the in-tool --help output for mdaicli -->

# mdaicli — Unified AI CLI with MCP integration

## Overview
- Provider-agnostic interface to OpenAI, Anthropic, OpenRouter, and Ollama
- Secure credentials (OS keyring; Argon2id + AES-GCM fallback)
- MCP-aware file access (honors `MDAICLI_ALLOWED_ROOTS`)
- Streaming (JSONL or text), caching, rate limiting, audit logging

## Global Options
- `-p, --provider <name>`: Provider (openai|anthropic|openrouter|ollama)
- `--account <alias>`: Account alias (multi-account)
- `--profile <name>`: Configuration profile
- `--config <path>`: Custom config file
- `--dry-run`: Print normalized request JSON
- `--no-cache`: Bypass response cache
- `--redact`: Redact sensitive data in logs (default: on)
- `-v, --verbose`: Verbose output
- `-h, --help`: Show this full help page (all commands)

## Environment Variables
- `MDAICLI_PROVIDER`, `MDAICLI_MODEL`, `MDAICLI_FORMAT`, `MDAICLI_TIMEOUT`
- `MDAICLI_CACHE_DIR`, `MDAICLI_PROFILE`
- `MDAICLI_ALLOWED_ROOTS=/workspace,/tmp` (MCP integration)
- `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` (networking)

## Configuration File
- Windows: `%APPDATA%\mdaicli\config.toml`
- macOS: `~/Library/Application Support/mdaicli/config.toml`
- Linux: `~/.config/mdaicli/config.toml`

### Example `config.toml` (partial)
```
[default]
provider = "openai"
format = "json"

[default.models]
openai = "gpt-4"
anthropic = "claude-3-opus-20240229"
openrouter = "auto"
ollama = "llama2"

[cache]
enabled = true
ttl_seconds = 3600
max_size_mb = 500
directory = "~/.cache/mdaicli"

[limits.openai]
requests_per_minute = 60
tokens_per_minute = 90000
max_retries = 3
backoff_base_ms = 1000
backoff_max_ms = 60000
```

## Primary Commands

### 1) `query` — Send a query to a model
Usage:
```
mdaicli query [OPTIONS]
```

Options:
- `-p, --provider <name>`: Provider (env: `MDAICLI_PROVIDER`)
- `-m, --model <name>`: Model (env: `MDAICLI_MODEL`)
- `--system <text>`: System prompt/instructions
- `--user <text>`: User prompt (required unless `--messages-file`)
- `--messages-file <path>`: JSON/YAML with full conversation
- `--input-file <path>...` Additional context files
- `--input-role <role>`: `system|user` (default: `user`)
- `--max-tokens <n>`: Max completion tokens
- `-t, --temperature <n>`: Sampling temperature
- `--top-p <n>`: Nucleus sampling
- `--stream`: Stream the response
- `-f, --format <type>`: `json|text|markdown` (default: `json`)
- `-T, --timeout <sec>`: Timeout (default: 120)
- `--tools-file <path>`: JSON/YAML tool definitions
- `-o, --output <path>`: Write response to file

Examples:
- Simple:
```
mdaicli query -p openai -m gpt-4 --user "Explain quantum computing"
```
- With system + file context:
```
mdaicli query -p anthropic -m claude-3-opus-20240229 \
  --system "You are a code reviewer" \
  --input-file src/main.rs \
  --user "Review this code for bugs"
```
- Messages file + streaming JSONL:
```
mdaicli query -p openai -m gpt-4 --messages-file chat.json --stream -f json
```
- Dry-run normalized request JSON:
```
mdaicli query -p openai -m gpt-4 --user "Hi" --dry-run
```

### 2) `store` — Save API credentials (securely)
Usage:
```
mdaicli store -p <provider> [--account <alias>] [--base-url <url>] [--org-id <id>] [--no-interactive]
```
Notes:
- API keys are read via stdin or interactive masked prompt (no args)
- Multi-account supported via `--account`

Examples:
```
mdaicli store -p openai --account personal
echo $API_KEY | mdaicli store -p anthropic --no-interactive
mdaicli store -p openrouter --base-url https://proxy.example.com
```

### 3) `list` — Providers, models, credentials, cache
Usage:
```
mdaicli list providers
mdaicli list models [-p <provider>] [--refresh]
mdaicli list credentials
mdaicli list cache [--provider <name>]
```

### 4) `remove` — Credential or cache
Usage:
```
mdaicli remove credential -p <provider> [--account <alias>] [--all]
mdaicli remove cache [--provider <name>] [--older-than <days>] [--all]
```

### 5) `usage` — Usage summary
Usage:
```
mdaicli usage [-p <provider>] [--account <alias>] [--days <n>] [-f table|json|csv] [--refresh]
```

### 6) `config` — Manage configuration
Usage:
```
mdaicli config get <key>
mdaicli config set <key> <value>
mdaicli config list
mdaicli config validate
mdaicli config reset
```

### 7) `openai` — Provider-specific operations
Subcommands:
- `assistant list`
- `vector-store list`
- `vector-store create --name <name> [--files <paths>...] [--expires-days <n>]`
- `vector-store upload --store-id <id> --files <paths>...`
- `vector-store delete --store-id <id>`

Examples:
```
mdaicli openai assistant list
mdaicli openai vector-store list
mdaicli openai vector-store create --name "Docs" --files README.md "docs/*.md"
mdaicli openai vector-store upload --store-id vs_123 --files notes.md
mdaicli openai vector-store delete --store-id vs_123
```

### 8) `ollama` — Local/self-hosted provider operations
Subcommands:
- `models list`
- `models show <name>`
- `models pull <name>`
- `models delete <name>`
- `status`

Examples:
```
mdaicli ollama status
mdaicli ollama models list
mdaicli ollama models pull llama2:7b
mdaicli query -p ollama -m llama2 --user "Explain quantum computing"
```

## MCP Integration
- Respect `MDAICLI_ALLOWED_ROOTS` for any file flags; URIs (`http://`, `https://`, `file://`, `mdmcp://`) rejected for file inputs.
- Suggest using MCP resource tools for reading remote/resource URIs.

## Streaming Output
- `-f json` with `--stream`: emits JSONL events: `{ "event":"start" }`, `{ "event":"delta" }`, `{ "event":"end" }`
- `-f text/markdown` with `--stream`: prints tokens to stdout; final footer when complete

## Caching & Rate Limits
- Cache: SHA256 key over provider, model, normalized messages, tools, params, file hashes; TTL + optional size limit
- Limits: requests/minute per provider-account; retries with exponential backoff and `Retry-After` honoring (OpenAI)

## Credential Storage
- Windows: Credential Manager (`mdaicli:<provider>:<account>`)
- macOS: Keychain (service: `mdaicli`; account: `<provider>:<account>`)
- Linux: Secret Service; fallback: `~/.config/mdaicli/credentials.enc` (Argon2id + AES-256-GCM)

## Examples: End-to-End
- Ask a question (OpenAI):
```
mdaicli query -p openai -m gpt-4 --user "What is the capital of France?"
```
- Streaming (Anthropic JSONL):
```
mdaicli query -p anthropic -m claude-3-opus-20240229 --messages-file chat.json --stream -f json
```
- OpenRouter simple:
```
mdaicli query -p openrouter -m auto --user "Summarize this README"
```
- Ollama local:
```
mdaicli query -p ollama -m llama2 --user "Give me 3 shell tips"
```

## Exit Codes
- 0 success; 2 validation; 3 provider; 4 network; 5 credential; 6 file access; 7 config; 8 rate limit; 9 cache

## Tips
- Use `--dry-run` to inspect the exact normalized request
- Use `MDAICLI_ALLOWED_ROOTS` to control file access under MCP
- Set per-provider limits under `[limits.<provider>]` in config to tune retry/backoff
