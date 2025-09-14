# Repository Guidelines

## Project Structure & Module Organization
- Source code lives in `src/` (entry in `src/main.rs`).
- Add additional binaries under `src/bin/<name>.rs` for separate CLI tools.
- Integration tests go in `tests/` (create if needed). Fixtures can live under `tests/fixtures/`.
- Build metadata is in `Cargo.toml`.

## Build, Test, and Development Commands
- Build: `cargo build` (release: `cargo build --release`).
- Run: `cargo run -- <args>` (passes args to the CLI).
- Test: `cargo test` (all: `cargo test --all`).
- Format: `cargo fmt --all` (check in CI: `cargo fmt --all -- --check`).
- Lint: `cargo clippy -- -D warnings` (treat lints as errors).

## Coding Style & Naming Conventions
- Rust 2024 edition; follow `rustfmt` defaults (4-space indent, trailing commas, sorted imports where applicable).
- Naming: `snake_case` for functions/files, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for consts.
- Keep functions small and pure where practical; prefer `Result<T, E>` over panics in library-like code.
- Error messages should be actionable and concise for CLI users.

## Testing Guidelines
- Unit tests colocated via `#[cfg(test)] mod tests { ... }` in the same file.
- Integration tests in `tests/` using public API or CLI invocation via `assert_cmd` (add when needed).
- Write tests for new features and bug fixes; cover happy paths and key edge cases.
- Prefer deterministic tests; avoid filesystem/network unless mocked or scoped to `tempdir`.

## Commit & Pull Request Guidelines
- Use imperative, descriptive commits. Conventional style encouraged: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`.
- PRs should include: summary, rationale, before/after behavior, and test notes. Link related issues.
- Keep PRs focused and small; update docs/examples when behavior changes.

## Security & Configuration Tips
- Do not commit secrets. Use environment variables for tokens and redact in logs.
- Validate and sanitize user input from CLI flags and files; prefer safe defaults.
- When adding deps, prefer well-maintained crates; enable `deny(warnings)` in CI for safety.
