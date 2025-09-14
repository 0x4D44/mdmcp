# Plugins

This directory contains optional, decoupled tools that integrate with or extend the mdmcp ecosystem. Each plugin is a standalone Cargo crate and is included in the top-level workspace.

Current plugins:
- `mdaicli` — Unified AI CLI with MCP integration.

Adding a new plugin:
- Create a new crate under `plugins/<name>`.
- Add `"plugins/<name>"` to the `[workspace].members` array in the repository `Cargo.toml`.
- Keep crates small and cohesive; follow the repo coding style and testing guidelines.

