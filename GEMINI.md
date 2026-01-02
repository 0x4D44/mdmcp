# mdmcp - Minimal, Policy-Driven MCP Server

## Project Overview
`mdmcp` is a security-focused Model Context Protocol (MCP) server written in Rust. It gates file system access and command execution behind a strict `policy.yaml` configuration. The project is organized as a Cargo workspace containing the server, a configuration CLI, shared libraries, and a set of plugin CLIs.

## Architecture & Structure
The repository is a Rust workspace with the following members:

### Core Components
- **`mdmcpsrvr/`**: The core MCP server binary. Handles JSON-RPC over stdio, policy enforcement, and tool execution (`fs.read`, `fs.write`, `cmd.run`).
- **`mdmcpcfg/`**: Configuration CLI. Manages server installation, updates, and policy management (adding roots, commands, etc.).
- **`crates/mdmcp_common/`**: Shared library containing MCP protocol types and error handling.
- **`crates/mdmcp_policy/`**: Shared library for policy data structures, parsing, and validation.

### Plugins (`plugins/`)
A collection of standalone CLI tools that integrate with or extend the ecosystem:
- **`mdaicli`**: Unified AI provider CLI.
- **`mdconfcli`**: Confluence integration.
- **`mdjiracli`**: Jira integration.
- **`mdmailcli`**: Mail integration.
- **`mdslackcli`**: Slack integration.

### Documentation & Config
- **`docs/`**: Detailed design documents and usage guides.
- **`examples/`**: Example configurations (e.g., `policy.example.yaml`).
- **`tests/`**: Integration and smoke tests (e.g., `test_new_methods.py`).
- **`CLAUDE.md` / `AGENTS.md`**: Context files for AI assistants.

## Building and Running

### Prerequisites
- Rust (stable)
- Python 3 (for smoke tests)

### Key Commands
**Build Workspace:**
```bash
cargo build --workspace
```

**Run Tests (All):**
```bash
cargo test --workspace --all-features
```

**Run MCP Server (Stdio Mode):**
```bash
cargo run -p mdmcpsrvr -- --config tests/test_policy.yaml --stdio
```

**Run Configuration CLI:**
```bash
cargo run -p mdmcpcfg -- --help
```

**Lint & Format:**
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -D warnings
```

**Smoke Test (Python):**
```bash
python tests/test_new_methods.py
```

## Development Conventions
- **Style:** Standard Rust 2021 edition. Enforce formatting with `cargo fmt`.
- **Linting:** Code must be `clippy` clean (no warnings).
- **Testing:**
  - Unit tests co-located with code (`mod tests`).
  - Integration tests in `tests/` directory or crate-specific `tests/` folders.
  - End-to-end testing of the server over stdio is critical.
- **Policy:** The system is "policy-first". All features requiring I/O or execution must be validated against `policy.yaml`.
- **Platform:** Be mindful of OS differences (Windows vs. Unix), especially regarding file paths, permissions, and process execution.

## Key Files for Context
- **`README.md`**: Main entry point and quick start.
- **`CLAUDE.md`**: Developer guide and architecture summary.
- **`mdmcpsrvr/src/main.rs`**: Server entry point.
- **`mdmcpsrvr/src/policy.rs`**: Policy logic implementation.
- **`mdmcpsrvr/src/server.rs`**: MCP tool implementation.
