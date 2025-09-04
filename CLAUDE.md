# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains `mdmcp` - a minimal, policy-driven Model Context Protocol (MCP) server written in Rust, plus a configuration CLI tool. The project provides a hardened MCP server that exposes only three capabilities (`fs.read`, `fs.write`, `cmd.run`) with strict policy-based access controls.

**Current Status**: Early development phase with design specification complete but implementation just beginning.

## Repository Structure

This is a Cargo workspace containing:

- **`mdmcpsrvr/`**: The core MCP server (Rust binary)
- **`mdmcpcfg/`**: Configuration CLI tool for installing/managing the server and policies
- **`crates/`**: Shared libraries (planned):
  - `mdmcp_policy/`: Policy types and validation
  - `mdmcp_common/`: MCP protocol types
- **`mdmcp_design_spec_v_1.md`**: Complete technical specification

## Development Commands

### Build Commands
- `cargo build --workspace` - Build all workspace members
- `cargo build --release` - Release build 
- `cargo run -p mdmcpsrvr -- --config policy.yaml --stdio` - Run MCP server
- `cargo run -p mdmcpcfg -- <subcommand>` - Run configuration CLI
- `cargo test --workspace` - Run all tests
- `cargo clippy -- -D warnings` - Lint with strict warnings
- `cargo fmt --check` - Check formatting

### Schema Generation (when implemented)
- `cargo run -p mdmcp_policy --example emit-schema > policy.schema.json` - Generate JSON schema

## Architecture Overview

### Core Components

**MCP Server (`mdmcpsrvr`)**:
- `main.rs` - Entry point, CLI argument handling
- `rpc.rs` - JSON-RPC 2.0 over stdio transport layer
- `server.rs` - MCP method handlers (`fs.read`, `fs.write`, `cmd.run`)
- `policy.rs` - Policy loading, validation, and runtime enforcement
- `fs_safety.rs` - Path normalization, network filesystem detection
- `cmd_catalog.rs` - Command catalog validation and argument filtering
- `sandbox.rs` - Subprocess isolation with resource limits
- `audit.rs` - JSONL audit logging with redaction

**Configuration CLI (`mdmcpcfg`)**:
- `main.rs` - CLI interface using clap
- `commands/install.rs` - Server binary installation/updates
- `commands/policy.rs` - Policy file management
- `commands/doctor.rs` - System diagnostics
- `io.rs` - File I/O utilities

### Security Model

The server enforces strict policies through:
- **Path Controls**: All file operations constrained to `allowedRoots`
- **Network FS Detection**: Blocks network filesystems unless explicitly allowed
- **Command Catalog**: Only pre-approved commands with argument validation
- **Resource Limits**: Timeout and output size constraints
- **Audit Trail**: All operations logged with content hashing

### Protocol Details

- **Transport**: JSON-RPC 2.0 over stdio (NDJSON format)
- **Methods**: `fs.read`, `fs.write`, `cmd.run`, plus `mcp.handshake` notification
- **Policy-Driven**: All operations validated against YAML configuration
- **Error Codes**: Domain-specific codes (`POLICY_DENY`, `TIMEOUT`, `OUTPUT_TRUNCATED`, etc.)

## Code Quality Standards

- **Zero Warnings**: All code must compile cleanly with no warnings
- **Clippy Compliance**: Must pass `cargo clippy -- -D warnings`
- **Formatting**: Code must be formatted with `cargo fmt`
- **Documentation**: Public APIs and complex logic must be well-documented

## Key Design Principles

1. **Minimal Attack Surface**: Only three core capabilities exposed
2. **Policy-First**: Every operation requires explicit policy permission
3. **No Shell Access**: Direct process execution only, no shell interpretation
4. **Platform Safety**: OS-specific filesystem and security controls
5. **Comprehensive Auditing**: Full operation logging for security monitoring

## Development Workflow

Following the specification's recommended implementation order:

1. **Foundation**: Workspace setup, shared crates (`mdmcp_policy`, `mdmcp_common`)
2. **Policy System**: YAML parsing, validation, schema generation
3. **MCP Server**: RPC plumbing, protocol handlers, security enforcement
4. **Configuration CLI**: Installation, policy management, diagnostics
5. **Testing**: Unit tests for security controls, E2E tests for full workflow

## Testing Strategy

**Unit Tests**:
- Path normalization and escaping prevention
- Policy validation (malformed YAML, invalid regex patterns)
- Command argument filtering
- Network filesystem detection (platform-specific)

**E2E Tests**:
- Full server lifecycle (spawn, handshake, request/response)
- Policy enforcement (allowed vs denied operations)
- Resource limits (timeouts, output truncation)
- Cross-platform compatibility

## Platform Considerations

- **Linux/macOS**: Uses `nix` crate for rlimits, process group management
- **Windows**: Uses `windows-sys` for Job Objects, drive type detection
- **Network FS Detection**: Platform-specific implementation in `fs_safety.rs`

## Configuration Files

- **`policy.yaml`**: Main configuration defining allowed operations
- **`policy.schema.json`**: Generated JSON Schema for validation
- **Platform paths**: 
  - Linux: `~/.config/mdmcp/policy.yaml`
  - macOS: `~/Library/Preferences/mdmcp/policy.yaml`
  - Windows: `%APPDATA%\mdmcp\policy.yaml`
- Remember to update the semver patch number with each change