# mdjiracli (Jira CLI)

A small Rust command-line tool that stores Jira Cloud credentials securely (via the OS keychain) and makes authenticated requests to Jira’s REST API. Currently supports interactive auth setup and a simple identity check.

## Features
- Interactive credential setup (base URL, email/username, API token)
- Secure storage via `keyring` (Windows Credential Manager on Windows)
- Agile-first: boards list, board issues (with optional JQL), issue get via Agile API
- `whoami` verifies Agile API access (no PII fetched)
- View and clear stored credentials

## Requirements
- Rust (stable) with Cargo: https://rustup.rs
- Jira Cloud base URL (e.g., `https://yourorg.atlassian.net`)
- Jira API token: https://id.atlassian.com/manage-profile/security/api-tokens
- Internet access to reach Jira `/rest/api/3` endpoints

## Create an Atlassian API token
1) Visit: https://id.atlassian.com/manage-profile/security/api-tokens
2) Sign in with your Atlassian account (the email you use for Jira).
3) Click "Create API token" → add a label → Create.
4) Click "Copy" to copy the token. Store it securely.
5) Use your Atlassian email as the username and this token as the password when prompted by the CLI.

Notes:
- The token is shown only once. If you lose it, revoke and create a new one.
- You can revoke tokens anytime from the same page.

## Install
Clone and build from source:

- Debug build: `cargo build`
- Release build: `cargo build --release` (binary at `target/release/mdjiracli[.exe]`)

Optionally install to your Cargo bin dir:

- `cargo install --path .`

Note: The binary name is `mdjiracli`. The CLI help may show `jira` as the command name; you can alias it if you prefer:
- PowerShell (session): `doskey jira=mdjiracli $*`
- Bash/Zsh: `alias jira=mdjiracli`

## Setup
1) Create an API token at Atlassian (link above).
2) Run interactive init and follow prompts:
- `mdjiracli init`
- Base URL: e.g. `https://yourorg.atlassian.net`
- Email/username: your Atlassian account email
- API token: paste the token (stored securely via keychain)
3) Verify credentials:
- `mdjiracli whoami` → verifies Agile API access (prints auth status)

## Usage
- Initialize credentials: `mdjiracli init`
- Verify auth: `mdjiracli whoami`
- List boards (JSON): `mdjiracli agile-boards --limit 20`
- Board issues (JSON): `mdjiracli agile-board-issues --board 123 --limit 25 [--jql "assignee = currentUser()"] [--fields summary,status,assignee]`
- Agile issue get (JSON): `mdjiracli agile-issue-get ABC-123 [--fields summary,status]`
- Control JSON size: add `--max-len 512` and/or `--max-items 50`; pretty print with `--pretty`.
- Show stored values (token masked): `mdjiracli auth-show`
- Clear stored credentials: `mdjiracli auth-reset`

## Where credentials are stored
- Service: `jira-cli`
- Keys: `base_url`, `username`, `token`
- On Windows: Windows Credential Manager. On other OSes, `keyring` maps to the native keychain (e.g., macOS Keychain, libsecret on Linux) if available.

## Troubleshooting
- 401/403 errors: Recreate token, confirm base URL, re-run `mdjiracli init`.
- Network/Proxy: Set `HTTPS_PROXY`/`HTTP_PROXY` env vars if required by your environment.
- Stuck with bad values: Run `mdjiracli auth-reset`, then `mdjiracli init`.
- Certificate/TLS issues: Tool uses `reqwest` with Rustls; ensure your environment allows outbound HTTPS to Atlassian.

## Development
- Format: `cargo fmt --all`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Test: `cargo test`

See `AGENTS.md` for contributor guidelines.
