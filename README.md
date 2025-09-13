# mdmcp — Minimal, Policy‑Driven MCP Server

mdmcp is a small, security‑focused [Model Context Protocol (MCP)] server with a
clear goal: enable powerful local tooling while keeping your machine safe.
It gates every filesystem and process action behind an explicit policy, and runs
approved commands in a sandbox with resource limits.

The companion CLI, `mdmcpcfg`, installs and updates the server, manages
policies, and (optionally) wires the server into Claude Desktop.


## Why mdmcp?
- Security first: All file access and command execution is policy‑gated.
- Sandboxed execution: Commands run with time, output, and environment
  restrictions; working directories are validated and path arguments are kept
  within allowed roots.
- Simple policy: A single `policy.yaml` defines allowed read/write paths and a
  catalog of commands with arguments you trust.
- Friendly tooling: `mdmcpcfg` helps install/update, edit policies, and
  integrate with Claude Desktop.


## Quick Start

- Build the workspace:

```
cargo build --workspace
```

- Install the server (select GitHub or Local if both are available):

```
cargo run -p mdmcpcfg -- install
```

- Run the MCP server over stdio (for testing):

```
cargo run -p mdmcpsrvr -- --config path/to/policy.yaml --stdio
```

- Show CLI help:

```
cargo run -p mdmcpcfg -- --help
```


## The `mdmcpcfg` CLI

`mdmcpcfg` manages the server binary and your policy:

- `install` — Download/install the server and (optionally) configure Claude Desktop.
  - Detects available sources and prompts: `[G]itHub / [L]ocal / [N]one`.
- `update` — Update the server to the latest release (or from a local binary).
  - Also prompts for the source as above.
- `policy` — Manage policy files:
  - `show` — Print the current policy.
  - `edit` — Open the policy in your default editor.
  - `validate --file <path>` — Validate a policy file against the schema.
  - `add-root <path> [--write]` — Add an allowed root; optionally allow writing.
  - `add-command <id> --exec <path> [--allow <arg>] [--pattern <regex>]` — Add a command.
- `doctor` — Run diagnostics.
- `uninstall [--remove-policy] [--remove-claude-config]` — Remove the server and config.

Common examples:

```
# Install and configure Claude Desktop
mdmcpcfg install

# Show current policy
mdmcpcfg policy show

# Add an allowed root (read‑only)
mdmcpcfg policy add-root "C:/Users/you/projects"

# Add an allowed root with write permission
mdmcpcfg policy add-root "C:/Users/you/mdmcp-workspace" --write

# Add a command with fixed exec and basic allow list
mdmcpcfg policy add-command echo --exec "/bin/echo" --allow hello --allow world
```


## Security Model (At a Glance)

- Allowed roots: All file operations are constrained to paths under
  `allowed_roots`. Any read/write outside is denied.
- Write rules: Writes are permitted only where a `write_rules` entry exists
  (path, recursive, max file size, and optional auto‑create directories).
- Network filesystems: Set `deny_network_fs: true` to prevent access on NFS/SMB/UNC mounts.
- Command sandbox:
  - Working directory validation: `cwd_policy` controls where a command may run
    (e.g., within an allowed root or fixed to the exec directory).
  - Path‑argument scoping: Path‑like arguments (absolute or relative) are
    validated to remain within allowed roots, even if a command opts into
    `allow_any_args`.
  - Environment filtering: Only a safe baseline plus `env_allowlist` variables
    are passed to processes.
  - Resource limits: Enforced per command for time and output size; Unix builds
    apply additional rlimits.
- Auditing: The server logs decisions and outcomes to stderr; avoid logging secrets.


## Policy File: `policy.yaml`

The server loads a single YAML policy file defining allowed roots, write rules,
limits, and a command catalog. A minimal example:

```yaml
version: 1
deny_network_fs: true
allowed_roots:
  - "~/"            # Home directory
  - "C:/Users"      # Example on Windows
write_rules:
  - path: "~/mdmcp-workspace"
    recursive: true
    max_file_bytes: 10000000
    create_if_missing: true
commands:
  - id: "echo"
    exec: "/bin/echo"
    args:
      allow: ["hello", "world"]
      fixed: []
      patterns: []         # optional regexes
    cwd_policy: within_root  # within_root | fixed | none
    env_allowlist: ["TEST_VAR"]
    timeout_ms: 5000
    max_output_bytes: 1000000
    platform: ["linux", "macos"]
    allow_any_args: false   # true to skip arg allow/pattern checks
```

Key sections

- `version`: Policy schema version.
- `deny_network_fs`: When true, blocks reads/writes on network filesystems.
- `allowed_roots`: Canonicalized roots that define where reads are allowed.
- `write_rules`: Paths where writes are allowed, with limits.
- `commands` (catalog):
  - `id`: Command identifier exposed via the MCP server.
  - `exec`: Absolute path to the executable.
  - `args`: Three independent controls:
    - `allow`: exact argument strings permitted
    - `fixed`: arguments always prepended (not user‑supplied)
    - `patterns`: regexes for flexible argument validation
  - `cwd_policy`:
    - `within_root`: CWD must be inside an allowed root (recommended default)
    - `fixed`: CWD is set to the exec directory
    - `none`: do not set or validate CWD
  - `env_allowlist`: Env vars that may pass through to the process.
  - `timeout_ms` / `max_output_bytes`: Per‑command resource limits.
  - `platform`: Optional list to restrict a command to specific OSes.
  - `allow_any_args`: If true, skip allow/pattern checks (path scoping still applies).

See `examples/policy.example.yaml` for a more complete template generated by the
CLI. The CLI’s `policy validate` command checks structure and common pitfalls.


## Claude Desktop Integration

`mdmcpcfg install` can add a `mdmcp` entry to Claude Desktop’s configuration
so Claude can launch the server over stdio. Configuration locations are handled
per‑platform by the CLI; a successful run prints the updated config path.
Restart Claude Desktop after installation.


## Development

- Build: `cargo build --workspace`
- Run server (stdio):
  `cargo run -p mdmcpsrvr -- --config tests/test_policy.yaml --stdio`
- Run CLIs:
  - `cargo run -p mdmcpcfg -- --help`
  - `cargo run -p mdaicli -- --help` (single-page full help)
  - See `mdaicli/docs/HELP.md` for the same help page in docs form
- Tests: `cargo test --workspace --all-features`
- Lint/format: `cargo fmt --all` and
  `cargo clippy --all-targets --all-features -D warnings`


## Troubleshooting

- Logs are written to stderr; adjust verbosity with `--log-level` when supported.
- If install/update can’t reach GitHub, place a local `mdmcpsrvr` binary next to
  `mdmcpcfg` and choose `[L]ocal` when prompted.
- Ensure your `policy.yaml` declares a writable workspace if tools need to
  create or modify files.


## Security Tips

- Keep `deny_network_fs: true` unless you have a specific need.
- Minimize `allowed_roots` and avoid broad patterns.
- Prefer `allow_any_args: false` for commands like `del`, `rmdir`, `copy`, etc.
- Review and prune `env_allowlist` to the minimum required.
- Do not log secrets in arguments or environment variables.

---

For a deeper dive, see:
- `examples/policy.example.yaml` — starter policy template
- `docs/INSTALLATION_AND_USAGE.md` — additional platform notes
- `docs/mcp-server-development-guide.md` — MCP implementation details


## Structured Error Responses

The server now attaches structured `error.data` to all JSON‑RPC error responses. These fields make failures easier to diagnose programmatically and in logs.

- Common fields (always present on errors):
  - `method`: The MCP method that failed (or `"unknown"` for parse errors).
  - `reason`: Short, machine‑friendly reason code (e.g., `invalidParameters`, `policyDenied`, `ioError`).
  - `requestId`: The JSON‑RPC id echoed back as a string/number/`null`.
  - `serverVersion`: mdmcpsrvr version string.
  - `policyHash`: Current active policy hash.

- File system errors (`fs.read`, `fs.write`):
  - `path`: The file path involved (when applicable).
  - `rule`: The policy rule name on denials (e.g., `pathNotAllowed`, `writeNotPermitted`, `networkFsDenied`, `fileTooLarge`).
  - `detail`: Short human‑readable hint.

- Command errors (`cmd.run`):
  - `commandId`: The command id from the catalog.
  - `timedOut`, `truncated`: Booleans set for timeout/output‑limit related cases (also `false` in validation/denial paths for clarity).
  - `exitCode`, `stderrSnippet` (<= 200 chars): Included when available for execution‑related failures. Note: non‑zero exit codes currently return success with result; these fields may be absent in error paths that occur before process completion (e.g., validation/denial/timeout).

Examples

```jsonc
// fs.read with invalid encoding
{
  "code": -32602,
  "message": "Invalid method parameter(s)",
  "data": {
    "method": "fs.read",
    "reason": "invalidEncoding",
    "requestId": "42",
    "serverVersion": "x.y.z",
    "policyHash": "<hash>",
    "encoding": "utf16",
    "detail": "Unsupported encoding"
  }
}
```

```jsonc
// cmd.run denied by policy (unknown command)
{
  "code": -32001,
  "message": "Policy denied: commandNotFound",
  "data": {
    "method": "cmd.run",
    "reason": "policyDenied",
    "requestId": "abc-123",
    "serverVersion": "x.y.z",
    "policyHash": "<hash>",
    "rule": "commandNotFound",
    "commandId": "not-a-command",
    "timedOut": false,
    "truncated": false
  }
}
```

```jsonc
// cmd.run timeout
{
  "code": -32002,
  "message": "Command timed out after 5000ms",
  "data": {
    "method": "cmd.run",
    "reason": "timeout",
    "requestId": 7,
    "serverVersion": "x.y.z",
    "policyHash": "<hash>",
    "commandId": "long_running",
    "timeoutMs": 5000,
    "timedOut": true,
    "truncated": false
  }
}
```
