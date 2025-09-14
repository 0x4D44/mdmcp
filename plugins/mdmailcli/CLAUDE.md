# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

mdmailcli is a minimal command-line tool for interacting with Microsoft Graph API, specifically for Outlook mail and calendar operations. It's written in Rust and uses device-code authentication flow with refresh tokens stored in the OS keyring.

## Key Commands

### Development
- Build: `cargo build` or `cargo build --release`
- Run: `cargo run -- <command>`
- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-targets --all-features -D warnings`
- Test: `cargo test`
- Run specific test: `cargo test <test_name>`

### Common Usage
- Initialize/authenticate: `cargo run -- init`
- Test authentication: `cargo run -- whoami`
- List folders: `cargo run -- folders-list`
- List messages: `cargo run -- messages-list --folder "Inbox"`
- Send mail: `cargo run -- send-mail --to user@example.com --subject "Subject" --body "Body"`

## Architecture

The entire application is in a single file `src/main.rs` with these key components:

1. **Authentication Flow**: Uses Microsoft Identity device code flow (public client) with refresh tokens stored in OS keyring under service name `outlook-graph-cli`

2. **Graph API Integration**: All Graph API calls go through `graph_base_url()` (https://graph.microsoft.com/v1.0) with bearer token authentication

3. **Command Structure**: Uses clap for CLI parsing with subcommands for mail, calendar, and search operations

4. **Token Management**: Automatic token refresh using stored refresh tokens, with 401 retry logic

5. **Search Implementation**: Supports both `$search` (full-text) and `$filter` (structured) modes with client-side sorting for search results

## Important Constraints

- All code must compile cleanly with no warnings
- `cargo fmt` and `cargo clippy` must pass without errors
- Uses `reqwest` with `rustls` (no OpenSSL dependency)
- Requires Microsoft Graph delegated permissions (Mail.Read, Mail.ReadWrite, Mail.Send, Calendars.Read, Calendars.ReadWrite, etc.)
- Device code flow requires app registration with "Allow public client flows" enabled in Azure AD