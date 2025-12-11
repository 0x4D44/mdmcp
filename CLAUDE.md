# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains `mdmcp` - a minimal, policy-driven Model Context Protocol (MCP) server written in Rust, plus configuration and utility CLIs. The project provides a hardened MCP server that exposes only three capabilities (`fs.read`, `fs.write`, `cmd.run`) with strict policy-based access controls.

## Repository Structure

Cargo workspace with resolver v2:

- **`mdmcpsrvr/`**: Core MCP server (Rust binary)
- **`mdmcpcfg/`**: Configuration CLI for installing/managing the server and policies
- **`crates/`**: Shared libraries:
  - `mdmcp_policy/`: Policy types and validation
  - `mdmcp_common/`: MCP protocol types
- **`plugins/`**: Additional CLI tools:
  - `mdaicli/`: Unified AI provider CLI with MCP integration
  - `mdconfcli/`: Confluence CLI
  - `mdjiracli/`: Jira CLI
  - `mdmailcli/`: Mail CLI
  - `mdslackcli/`: Slack CLI

## Development Commands

```bash
# Build
cargo build --workspace
cargo build --release

# Run MCP server (stdio mode for testing)
cargo run -p mdmcpsrvr -- --config tests/test_policy.yaml --stdio

# Run CLIs
cargo run -p mdmcpcfg -- --help
cargo run -p mdaicli -- --help

# Test
cargo test --workspace --all-features
cargo test -p mdmcp_policy              # Single package
cargo test -p mdmcpsrvr -- e2e_stdio    # Single test

# Lint & format
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
```

## Architecture Overview

### MCP Server (`mdmcpsrvr/src/`)

| File | Purpose |
|------|---------|
| `main.rs` | Entry point, CLI args |
| `rpc.rs` | JSON-RPC 2.0 over stdio (NDJSON) |
| `server.rs` | MCP method handlers (`fs.read`, `fs.write`, `cmd.run`) |
| `policy.rs` | Policy loading, validation, runtime enforcement |
| `fs_safety.rs` | Path normalization, network FS detection |
| `cmd_catalog.rs` | Command catalog validation, argument filtering |
| `sandbox.rs` | Subprocess isolation with resource limits |
| `audit.rs` | JSONL audit logging with redaction |

### Security Model

- **Path Controls**: File ops constrained to `allowed_roots`
- **Network FS Detection**: Blocks NFS/SMB/UNC unless explicitly allowed
- **Command Catalog**: Only pre-approved commands with validated arguments
- **Resource Limits**: Per-command timeout and output size constraints
- **No Shell Access**: Direct process execution only

### Key Design Principles

1. **Minimal Attack Surface**: Only three capabilities exposed
2. **Policy-First**: Every operation requires explicit permission
3. **Platform Safety**: OS-specific filesystem and security controls (Unix rlimits, Windows Job Objects)

## Testing

E2E tests in `mdmcpsrvr/tests/`:
- `e2e_stdio.rs` - Server lifecycle over stdio
- `e2e_file_tools.rs` - fs.read/fs.write operations
- `e2e_reload_policy.rs` - Hot policy reload
- `e2e_resources_info.rs` - Resource introspection

## Platform Considerations

- **Linux/macOS**: `nix` crate for rlimits, process group management
- **Windows**: `windows-sys` for Job Objects, drive type detection
- **Network FS Detection**: Platform-specific in `fs_safety.rs`

## Policy Configuration

Policy file locations:
- Linux: `~/.config/mdmcp/policy.yaml`
- macOS: `~/Library/Preferences/mdmcp/policy.yaml`
- Windows: `%APPDATA%\mdmcp\policy.yaml`

Test policy: `tests/test_policy.yaml`
Example template: `examples/policy.example.yaml`

## Version Management

Update version in `Cargo.toml` workspace section when making changes. Current: check `[workspace.package]` version field.