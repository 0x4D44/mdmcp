# Repository Guidelines

This repository contains a small Rust CLI that interacts with Jira’s REST API and stores credentials in the OS credential store via the `keyring` crate.

## Project Structure & Module Organization
- Root: `Cargo.toml` (crate metadata and dependencies)
- Source: `src/main.rs` (CLI, auth flow, HTTP client)
- Tests: add unit tests alongside code in `src/` and integration tests in `tests/`.

## Build, Test, and Development Commands
- Build: `cargo build` (debug) / `cargo build --release`
- Run: `cargo run -- <command>`
  - Examples: `cargo run -- init`, `cargo run -- whoami`, `cargo run -- auth-show`, `cargo run -- auth-reset`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Format: `cargo fmt --all`
- Check: `cargo check`
- Test: `cargo test` (add tests first; see below)

## Coding Style & Naming Conventions
- Edition 2021; use stable Rust.
- Formatting: `rustfmt` with defaults (`cargo fmt --all`).
- Linting: keep `clippy` clean; treat warnings as errors.
- Naming: modules/files `snake_case`; types/traits `CamelCase`; functions/vars `snake_case`; constants `SCREAMING_SNAKE_CASE`.
- Errors: return `anyhow::Result` and add context via `anyhow::Context`.
- CLI: prefer `clap` derive APIs; keep subcommand help concise and actionable.

## Testing Guidelines
- Framework: built-in `cargo test`; for async, use `#[tokio::test]`.
- Unit tests: colocate in `mod tests { ... }` within `src/*.rs`.
- Integration tests: create files under `tests/` calling the public binary logic when feasible.
- Naming: test functions end with `_works`, `_fails`, or describe behavior (`whoami_prints_display_name`).

## Commit & Pull Request Guidelines
- Commits: use Conventional Commits (e.g., `feat: add agile board issues`, `fix(auth): mask token in output`). Keep them small and focused.
- PRs: include a clear description, linked issue (if any), rationale, and sample CLI output (before/after) for user-facing changes. Note any security or breaking changes.

## Security & Configuration Tips
- Do not log credentials or tokens. Only store via `keyring` (service: `jira-cli`, keys: `base_url`, `username`, `token`).
- Network: Jira base URL must be set (e.g., `https://acme.atlassian.net`). HTTP uses `reqwest` with `rustls-tls`.
- Local runs verify credentials using Agile API (`/rest/agile/1.0/board?maxResults=1`).

## Agent-Specific Notes
- Keep patches focused; avoid unrelated refactors.
- Follow this guide for formatting and linting before proposing changes.
