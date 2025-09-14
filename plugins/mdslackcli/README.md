# mdslackcli — A Tiny Slack CLI in Rust

mdslackcli is a minimal command‑line tool to inspect channels/DMs, read recent messages, and post messages to Slack. It stores your token securely using Windows Credential Manager.

## Build & Run
- Prerequisites: Rust toolchain (stable).
- Build: `cargo build --release`
- Binary: `target/release/mdslackcli`
- Run (dev): `cargo run -- <command> [flags]`

Note: The CLI self‑identifies as `slack` in help output, but the binary name is `mdslackcli`.

## Get a Slack Bot Token (xoxb-…)
1. Go to https://api.slack.com/apps → Create New App → From scratch.
2. Under “OAuth & Permissions” add Bot Token Scopes you need, e.g.:
   - Read: `channels:read`, `groups:read`, `im:read`, `mpim:read`, `channels:history`, `groups:history`, `im:history`, `mpim:history`
   - Write: `chat:write`
3. Click “Install to Workspace”. Copy the Bot User OAuth Token (starts with `xoxb-`).
4. You can later rotate/revoke the token from the same page.

## First‑time Setup
- Store and validate token: `cargo run -- init`
  - You’ll be prompted for the `xoxb-…` token. It’s saved in Windows Credential Manager under service `slackcli`.
  - Re‑prompt from scratch: `cargo run -- init --reset`
- Verify: `cargo run -- whoami`

## Common Commands
- List channels/DMs: `cargo run -- channels --types public_channel,private_channel,mpim,im --limit 100`
- Recent messages: `cargo run -- msgs --channel C01234567 --limit 25`
- Send a message: `cargo run -- send --channel C01234567 --text "Hello from Rust!"`
- Reply in thread: `cargo run -- send --channel C01234567 --text "Reply" --thread-ts 1718123456.000100`

If you installed the release binary, replace `cargo run --` with `target/release/mdslackcli`.

## Troubleshooting
- `invalid_auth` or HTTP errors: re‑run `init --reset` and re‑copy the token; ensure the bot is installed to the workspace and has required scopes.
- Network/proxy: reqwest honors standard env vars like `HTTPS_PROXY`.
- Token storage: currently uses Windows Credential Manager via the `keyring` crate.
# mdslackcli — A Tiny Slack CLI in Rust

mdslackcli is a minimal command-line tool to list channels/DMs, read recent messages, and post to Slack. It acts on your behalf using a Slack user token and stores that token in Windows Credential Manager.

## Build & Run
- Prerequisites: Rust (stable).
- Build: `cargo build --release`
- Dev run: `cargo run -- <command> [flags]`
- Release binary: `target/release/mdslackcli`

## Get a Slack User Token (xoxp-…)
1. Go to https://api.slack.com/apps → Create New App → From scratch.
2. Open “OAuth & Permissions” and add User Token Scopes:
   - Read: `channels:read`, `groups:read`, `im:read`, `mpim:read`, `channels:history`, `groups:history`, `im:history`, `mpim:history`
   - Write: `chat:write`, `conversations:write` (needed for `open` to create DMs/MPDMs)
3. Click “Install to Workspace” and complete the OAuth flow.
4. Copy the User OAuth Token (starts with `xoxp-`). You can rotate/revoke it later from the same page.

## First-time Setup
- Initialize and validate your token: `cargo run -- init`
  - You’ll be prompted for the `xoxp-…` token. It is saved in Windows Credential Manager under service `slackcli_user` (username `token`).
  - Reset and re-prompt: `cargo run -- init --reset`
- Verify identity: `cargo run -- whoami`

## Common Commands
- List channels/DMs: `cargo run -- channels --types public_channel,private_channel,mpim,im --limit 100`
- Recent messages: `cargo run -- msgs --channel C01234567 --limit 25`
- Send a message: `cargo run -- send --channel C01234567 --text "Hello from Rust!"`
- Join public channel (if needed): `cargo run -- join --channel C01234567`
- List DMs: `cargo run -- directmsgs --limit 100`
- List MPDMs: `cargo run -- directmpmsgs --limit 100`
- Find a person: `cargo run -- findperson --query alice --limit 20`
- Open DM/MPDM: `cargo run -- open --users U123,U456 [--text "Hi"]`

If using the release binary, replace `cargo run --` with `target/release/mdslackcli`.

## Troubleshooting
- `not_in_channel`: join the channel in Slack or run `join` for public channels.
- `invalid_auth`: run `init --reset` and paste the correct `xoxp-` token with the scopes above; ensure the app is installed to the workspace.
- Proxies: reqwest honors `HTTP_PROXY`/`HTTPS_PROXY` environment variables.
- Token storage: tokens are stored via the `keyring` crate in Windows Credential Manager (`slackcli_user`).
