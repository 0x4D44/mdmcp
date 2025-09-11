# Repository Guidelines

## Project Structure & Module Organization
- Workspace: `Cargo.toml` defines members `mdmcpsrvr`, `mdmcpcfg`, `crates/mdmcp_policy`, `crates/mdmcp_common`.
- Server: `mdmcpsrvr/src` (binary `mdmcpsrvr`) implements the MCP server (`main.rs`, plus `server.rs`, `rpc.rs`, `policy.rs`, `fs_safety.rs`, `sandbox.rs`, `audit.rs`).
- CLI: `mdmcpcfg/src` (binary `mdmcpcfg`) provides install/update/policy tooling with subcommands under `src/commands/`.
- Shared crates: common types and policy compiler live in `crates/mdmcp_common` and `crates/mdmcp_policy`.
- Examples & tests: `examples/policy.example.yaml`, `tests/` (for integration); ad‑hoc smoke test: `tests/test_new_methods.py`.

## Build, Test, and Development Commands
- Build all: `cargo build --workspace`
- Run server (stdio): `cargo run -p mdmcpsrvr -- --config tests/test_policy.yaml --stdio`
- Run config CLI: `cargo run -p mdmcpcfg -- --help`
- Unit tests: `cargo test --workspace --all-features`
- Smoke test (Windows): `python tests/test_new_methods.py` (uses `tests/test_policy.yaml`)
- Lint/format: `cargo fmt --all` and `cargo clippy --all-targets --all-features -D warnings`

## Coding Style & Naming Conventions
- Rust 2021; 4‑space indent; keep modules small and cohesive.
- Names: `snake_case` for files/functions, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for consts.
- Keep binaries minimal; put logic in crates (`mdmcp_*`). Run `cargo fmt` before PRs.

## Testing Guidelines
- Frameworks: Rust built‑in tests plus `tokio-test` where async is involved.
- Place unit tests next to code (`mod tests`), and broader scenarios under `tests/`.
- Name tests descriptively (e.g., `enforces_disallowed_root`, `parses_policy_regex`).
- Run `cargo test --workspace`; for end‑to‑end requests, use `python tests/test_new_methods.py`.

## Commit & Pull Request Guidelines
- Commits: imperative, concise subject; include rationale in body when needed (e.g., “server: enforce root canonicalization”).
- Prefer logical commits over large batches; reference issues (`#123`) when applicable.
- PRs: include summary, scope, testing notes, and any platform considerations (Windows/Unix). Add screenshots/log snippets for CLI UX changes.

## Security & Configuration Tips
- Policies gate all I/O and commands. Start from `examples/policy.example.yaml`; keep `deny_network_fs: true` unless explicitly needed.
- Limit `allowed_roots` and command args; avoid broad regexes. Do not log secrets.
- Logs go to stderr; adjust with `--log-level` (e.g., `debug`).
