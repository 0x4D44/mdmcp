# mdmcp — Minimal, Policy-Driven MCP Server + Rust Config Tool

**Goal:** A tiny, hardened Model Context Protocol (MCP) server exposing only three capabilities — `cmd.run`, `fs.read`, `fs.write` — plus a Rust CLI to install/update the server and manage policy. Everything else (dir listings, search, git, build, etc.) goes through curated command entries executed via `cmd.run`.

---

## 1) Repository Layout (Monorepo)

```
mdmcp/
├─ README.md
├─ LICENSE
├─ .editorconfig
├─ .gitignore
├─ Cargo.toml                 # workspace
├─ rust-toolchain.toml        # e.g., stable
├─ policy.schema.json         # JSON Schema for policy.yaml
├─ examples/
│  ├─ policy.example.yaml
│  └─ client-snippets/
│     ├─ mcp-example-requests.json
│     └─ mcp-example-session.md
├─ mdmcpsrvr/                 # Rust MCP server
│  ├─ Cargo.toml
│  └─ src/
│     ├─ main.rs
│     ├─ rpc.rs               # JSON-RPC 2.0 over stdio
│     ├─ server.rs            # MCP methods: fs.read, fs.write, cmd.run
│     ├─ policy.rs            # load/validate policy; runtime guard checks
│     ├─ fs_safety.rs         # path normalization, network fs checks
│     ├─ cmd_catalog.rs       # command catalog & arg policy
│     ├─ sandbox.rs           # subprocess isolation & limits
│     ├─ audit.rs             # JSONL logs, metrics hooks
│     └─ util.rs
├─ mdmcpcfg/                  # Rust CLI installer/policy tool
│  ├─ Cargo.toml
│  └─ src/
│     ├─ main.rs
│     ├─ commands/
│     │  ├─ install.rs
│     │  ├─ update.rs
│     │  ├─ policy.rs         # show/edit/validate/add-root/add-cmd
│     │  ├─ doctor.rs
│     │  └─ run.rs            # optional: talk to server for smoke tests
│     └─ io.rs
├─ crates/
│  ├─ mdmcp_policy/           # shared policy types & validation
│  │  ├─ Cargo.toml
│  │  └─ src/lib.rs
│  └─ mdmcp_common/           # shared protocol types (MCP payloads)
│     ├─ Cargo.toml
│     └─ src/lib.rs
└─ tests/
   ├─ e2e_basic.rs            # spawn server, exercise RPC
   ├─ e2e_policy.rs
   └─ fixtures/
      ├─ sample-project/
      └─ smb-mount/           # if available in CI, else skipped
```

---

## 2) Minimal Protocol Surface (MCP over JSON‑RPC 2.0 / stdio)

**Methods**
- `initialize(params) -> result` (standard MCP initialization)
- `fs.read(params) -> result`
- `fs.write(params) -> result`
- `cmd.run(params) -> result`

**Transport**: stdio (default). The server reads newline-delimited JSON-RPC messages from stdin and writes responses to stdout.

**Message framing**: one JSON object per line (NDJSON). Each request must include `{"jsonrpc":"2.0","id":<string|number>,"method":"...","params":{...}}`.

**Errors**: use JSON-RPC error with domain-specific `code` and `data` fields:
- `code`: `POLICY_DENY`, `INVALID_ARGS`, `TIMEOUT`, `OUTPUT_TRUNCATED`, `IO_ERROR`, `INTERNAL`.
- `data`: `{ "rule": "denyNetworkFS" | "outsideAllowedRoots" | ... }` where useful.

**Initialization**: follows standard MCP protocol - client sends `initialize` request, server responds with capabilities.

---

## 3) Endpoint Contracts

### 3.1 `fs.read`
**Input**
```json
{
  "path": "/abs/or/tilde/relative",        
  "offset": 0,                               
  "length": 1048576,                         
  "encoding": "utf8"                        
}
```
**Output**
```json
{
  "data": "…",                             
  "bytesRead": 1234,
  "sha256": "…"
}
```
**Rules**
- Path must resolve to absolute, after `~` expansion and normalization.
- Final path must be **beneath** an `allowedRoots` entry after resolving symlinks/junctions.
- Reject if mounted on **network FS** and `denyNetworkFS:true`.
- Reject special files (devices, fifos, sockets). Support regular files only.
- Enforce size caps (min(offset+length, policy.limits.maxReadBytes)).

### 3.2 `fs.write`
**Input**
```json
{
  "path": "/abs/within/writeZone/out.txt",
  "data": "…",
  "encoding": "utf8",                      
  "create": true,                           
  "overwrite": false                        
}
```
**Output**
```json
{ "bytesWritten": 42, "sha256": "…" }
```
**Rules**
- Only within `writeRules` zones; optional `createIfMissing` behavior per rule.
- Enforce `maxFileBytes` and atomic write via temp file + rename.
- Apply same path & network-FS guards as reads.
- Set default file mode conservatively (e.g., `0o600` on Unix).

### 3.3 `cmd.run`
**Input**
```json
{
  "commandId": "git",                      
  "args": ["status"],                     
  "cwd": "/abs/allowed/root/repo",        
  "stdin": "",                            
  "env": {"GIT_CONFIG_GLOBAL":"/dev/null"},
  "timeoutMs": 20000
}
```
**Output**
```json
{
  "exitCode": 0,
  "stdout": "…",
  "stderr": "",
  "timedOut": false,
  "truncated": false
}
```
**Rules**
- No shell: direct `exec`/`CreateProcess` of the catalog entry; deny metacharacters.
- `commandId` must be defined in `policy.commands` with:
  - `exec` absolute path (or safe PATH resolution performed once at load).
  - `args.allow` (fixed literals) and optional `args.patterns` (regex whitelist).
  - `cwdPolicy: withinRoot|fixed|none` (default `withinRoot`).
  - `envAllowlist` keys only.
  - `timeoutMs` and `maxOutputBytes` enforced.
- Output is streamed internally; if truncated by cap, return `truncated:true` and include `OUTPUT_TRUNCATED` warning in logs.

---

## 4) Policy File (YAML) & Schema

**`policy.yaml`** (loaded on startup; path via `--config` CLI flag). Example:

```yaml
version: 1

denyNetworkFS: true

allowedRoots:
  - "~/code"
  - "C:/Users/martin/Projects"

writeRules:
  - path: "~/code/scratch"
    recursive: true
    maxFileBytes: 10_000_000
    createIfMissing: true

commands:
  - id: "ls"
    exec: "/bin/ls"
    args:
      allow: ["-l", "-la", "-a", "-h"]
      patterns: []
    cwdPolicy: "withinRoot"
    envAllowlist: []
    timeoutMs: 5000
    maxOutputBytes: 1_000_000
    platform: ["linux","macos"]

  - id: "dir"
    exec: "C:/Windows/System32/cmd.exe"
    args:
      fixed: ["/c", "dir"]
    cwdPolicy: "withinRoot"
    envAllowlist: []
    timeoutMs: 5000
    maxOutputBytes: 1_000_000
    platform: ["windows"]

  - id: "rg"
    exec: "/usr/bin/rg"
    args:
      allow: ["--vimgrep","--hidden","--line-number","--no-messages"]
      patterns:
        - type: "regex"
          value: "^[\\w\\-\\./@:+#*?\\[\\]]+$"
    cwdPolicy: "withinRoot"
    envAllowlist: ["RIPGREP_CONFIG_PATH"]
    timeoutMs: 20000
    maxOutputBytes: 2_000_000

  - id: "git"
    exec: "/usr/bin/git"
    args:
      allow: ["status","log","show","diff","rev-parse","describe","branch","tag"]
    cwdPolicy: "withinRoot"
    envAllowlist: ["GIT_CONFIG_GLOBAL","GIT_ALLOW_PROTOCOL"]
    timeoutMs: 20000
    maxOutputBytes: 2_000_000

logging:
  level: "info"
  file: "~/.mcp/mdmcpsrvr.log.jsonl"
  redact: ["env"]

limits:
  maxReadBytes: 5_000_000
  maxCmdConcurrency: 2
```

**Schema** — `policy.schema.json` should be generated from `mdmcp_policy` Rust types using `schemars` so editors can validate.

---

## 5) Platform Safety & Network-FS Detection

Implement in `fs_safety.rs` with `cfg(target_os)` branches.

- **Normalization**: expand `~`, canonicalize via realpath-equivalent; reject if final path not beneath an allowed root. Ensure check is performed **after** resolving symlinks/junctions.
- **Special files**: reject sockets, fifos, block/char devices. On Windows, reject reparse points unless target remains beneath allowed roots.
- **Network FS**:
  - Linux: inspect `/proc/mounts` or `statfs` and disallow `nfs`, `cifs`, `smbfs`, `sshfs`, `afpfs`, `fuse.*` unless explicitly allowlisted (not in v1).
  - macOS: use `statfs` and inspect `f_fstypename`.
  - Windows: reject UNC `\\server\share` and volumes with `GetDriveTypeW()==DRIVE_REMOTE`.

Provide a utility `GuardedPath::open_for_read(path, policy) -> Result<File>` that enforces everything in one place.

---

## 6) Subprocess Sandbox & Limits (`sandbox.rs`)

- **Spawn**: `std::process::Command` with absolute `exec`. No shell. No inherited handles. Clean environment, then add allowed keys.
- **CWD**: verify per policy (withinRoot or fixed).
- **Timeout**: kill process tree on expiry.
  - Linux/macOS: track child pids; consider `setpgid` and killpg.
  - Windows: wrap in a Job Object and terminate job on timeout.
- **Output caps**: stream stdout/stderr to ring buffers with a global byte cap; mark `truncated:true` if exceeded.
- **Resource limits** (best-effort):
  - Unix: `setrlimit` for CPU/AS/NOFILE before exec.
  - Windows: Job Object memory/time limits.

---

## 7) Audit Logging (`audit.rs`)

Write JSONL entries per request/response:
```
{
  "ts": "2025-09-04T14:00:01Z",
  "reqId": "...",
  "tool": "fs.read|fs.write|cmd.run",
  "decision": "allow|deny",
  "path": "/…" ,
  "cwd": "/…",
  "bytes": 1234,
  "exitCode": 0,
  "timedOut": false,
  "policyHash": "…",
  "durationMs": 17
}
```
Redact env; hash content (sha256) instead of logging bodies.

---

## 8) Server CLI (`mdmcpsrvr`)

**Args**
```
mdmcpsrvr --config /path/policy.yaml [--log-level info] [--stdio]
```
- Default transport: stdio. (No websocket in v1.)
- On start: load policy, then service requests (starting with initialize).
- SIGHUP: optional policy reload (v1: disabled; provide `--reload` flag to opt-in).

**Crates**
- `tokio` (async IO), `serde`/`serde_json`, `serde_yaml`, `schemars` (schema), `sha2`, `anyhow`/`thiserror`, `regex`, `humantime`, `bytes`, `crossbeam-channel` or `tokio::sync`.
- Platform: `nix` (Unix rlimits), `windows-sys` (Job Objects, drive type).

---

## 9) Rust CLI (`mdmcpcfg`)

**Purpose**: Install/update server binaries, manage `policy.yaml`, and perform diagnostics.

**Commands**
- `mdmcpcfg install [--dest <dir>]` — download release asset, verify SHA/signature (minisign or cosign), place in OS-specific location, create default policy.
- `mdmcpcfg update [--channel stable|beta] [--rollback]` — atomic update with signature check.
- `mdmcpcfg policy show|edit|validate` — print, open in `$EDITOR`, validate against schema.
- `mdmcpcfg policy add-root <path> [--write]` — add allowed root / write rule.
- `mdmcpcfg cmd add <id> --exec <path> [--allow <arg>...] [--pattern <regex>...]` — manage catalog entries.
- `mdmcpcfg doctor` — check PATH, mounts, permissions, confirm server spawns and initialize works.
- `mdmcpcfg run -- <jsonrpc-file>` — optional helper to send a raw RPC for smoke tests.

**Crates**: `clap`, `serde_yaml`, `serde_json`, `schemars`, `reqwest` (TLS updates), `sha2`, `minisign`, `tempfile`, `dirs`, `edit`, `anyhow`.

**Install locations**
- Linux: `${XDG_DATA_HOME:-~/.local/share}/mdmcp/bin`, config `${XDG_CONFIG_HOME:-~/.config}/mdmcp/policy.yaml`.
- macOS: `~/Library/Application Support/mdmcp/bin`, config `~/Library/Preferences/mdmcp/policy.yaml`.
- Windows: `%LOCALAPPDATA%\mdmcp\bin`, config `%APPDATA%\mdmcp\policy.yaml`.

---

## 10) Cargo Workspace Templates

**Top-level `Cargo.toml`**
```toml
[workspace]
members = [
  "mdmcpsrvr",
  "mdmcpcfg",
  "crates/mdmcp_policy",
  "crates/mdmcp_common",
]
resolver = "2"

[workspace.package]
edition = "2021"
authors = ["Martin Davidson <martin@example.com>"]
license = "Apache-2.0"
```

**`crates/mdmcp_policy/Cargo.toml`**
```toml
[package]
name = "mdmcp_policy"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
schemars = "0.8"
serde_yaml = "0.9"
regex = "1"
```

**`crates/mdmcp_common/Cargo.toml`**
```toml
[package]
name = "mdmcp_common"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

**`mdmcpsrvr/Cargo.toml`**
```toml
[package]
name = "mdmcpsrvr"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
thiserror = "1"
tokio = { version = "1", features = ["rt-multi-thread","macros","io-std"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
schemars = "0.8"
regex = "1"
sha2 = "0.10"
hex = "0.4"
bytes = "1"
mdmcp_policy = { path = "../crates/mdmcp_policy" }
mdmcp_common = { path = "../crates/mdmcp_common" }
# platform-specific
cfg-if = "1"
# unix-only
nix = { version = "0.29", optional = true, features = ["resource"] }
# windows-only
windows-sys = { version = "0.59", optional = true, features = ["Win32_System_Threading","Win32_Storage_FileSystem"] }

[features]
unix = ["nix"]
windows = ["windows-sys"]
```

**`mdmcpcfg/Cargo.toml`**
```toml
[package]
name = "mdmcpcfg"
version = "0.1.0"
edition = "2021"

[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1"
schemars = "0.8"
reqwest = { version = "0.12", features = ["json","rustls-tls"] }
sha2 = "0.10"
minisign-verify = "0.2"
tempfile = "3"
dirs = "5"
edit = "0.1"
mdmcp_policy = { path = "../crates/mdmcp_policy" }
mdmcp_common = { path = "../crates/mdmcp_common" }
```

---

## 11) Key Module Sketches

### 11.1 `mdmcpsrvr/src/rpc.rs`
- Read NDJSON lines from stdin via `tokio::io::BufReader`.
- Parse to `RpcRequest { id, method, params }` using `serde_json::Value`.
- Dispatch to `server::handle_request`.
- Write `RpcResponse` to stdout.
- Generate request ids for internal progress notifications if needed (not required in v1).

### 11.2 `mdmcpsrvr/src/server.rs`
- Struct `Server { policy: Arc<Policy>, auditor: Auditor, cmd_exec: CmdExec }`.
- Methods `handle_initialize`, `handle_fs_read`, `handle_fs_write`, `handle_cmd_run`.

### 11.3 `mdmcpsrvr/src/policy.rs` (in tandem with `mdmcp_policy` crate)
- Load YAML, expand `~`, canonicalize paths in `allowedRoots` and `writeRules`.
- Pre-resolve command `exec` absolute paths; filter by platform.
- Produce a stable `policyHash` (sha256 of canonicalized JSON form).

### 11.4 `mdmcpsrvr/src/fs_safety.rs`
- `fn normalize_and_guard_read(path: &str, pol: &Policy) -> Result<GuardedFile>`.
- `fn normalize_and_guard_write(path: &str, pol: &Policy) -> Result<GuardedPath>`.
- Helpers: `is_network_fs(&Path) -> bool` using `cfg` platform checks.

### 11.5 `mdmcpsrvr/src/cmd_catalog.rs`
- Types mirror policy `commands[]` with compiled regexes and resolved exec.
- `fn validate_args(cmd: &Cmd, args: &[String]) -> Result<()>` (allowlist + regex patterns).
- `fn validate_env(cmd: &Cmd, env: &HashMap<String,String>) -> Result<HashMap<..>>`.
- `fn validate_cwd(cmd: &Cmd, cwd: &Path, pol: &Policy) -> Result<PathBuf>`.

### 11.6 `mdmcpsrvr/src/sandbox.rs`
- `fn run(cmd: &ResolvedCmd, spec: RunSpec) -> Result<RunResult>`
- Apply rlimits/Job Object, timeout, and output cap.

### 11.7 `mdmcpsrvr/src/audit.rs`
- `Auditor::log(RequestSummary, DecisionSummary)` to JSONL with rotation by size (simple: reopen daily or when file > N MB).

---

## 12) Example JSON-RPC Calls

**Read file**
```json
{"jsonrpc":"2.0","id":1,"method":"fs.read","params":{
  "path":"~/code/project/README.md","offset":0,"length":1048576,"encoding":"utf8"
}}
```

**Write file**
```json
{"jsonrpc":"2.0","id":2,"method":"fs.write","params":{
  "path":"~/code/scratch/out.txt","data":"SGVsbG8=","encoding":"base64","create":true,"overwrite":true
}}
```

**Run command**
```json
{"jsonrpc":"2.0","id":3,"method":"cmd.run","params":{
  "commandId":"git","args":["status"],"cwd":"~/code/project","timeoutMs":20000
}}
```

---

## 13) Development Flow (Claude Code Checklist)

1. **Scaffold workspace**: create `Cargo.toml` workspace and sub-crates as above.
2. **Implement `mdmcp_policy`** types + `schemars` derivations and `Policy::load(path)`.
3. **Generate `policy.schema.json`** from `mdmcp_policy` and place at repo root.
4. **Implement `mdmcpsrvr`**:
   - `rpc.rs`: JSON-RPC plumbing (stdio, NDJSON framing).
   - `policy.rs` loader & `policyHash`.
   - `fs_safety.rs` guards + network-FS checks per OS.
   - `cmd_catalog.rs` + `sandbox.rs` to execute curated commands.
   - `server.rs` dispatch; handle standard MCP initialize.
5. **Implement `mdmcpcfg`** with `clap` subcommands: `install`, `update`, `policy`, `doctor`.
6. **Write `tests/e2e_basic.rs`**: start server as a child process, send a few RPCs, assert outputs.
7. **Add CI**: Rust stable, run `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`.

---

## 14) Definition of Done (v1)

- MCP server compiles on Windows/macOS/Linux and passes unit + e2e tests.
- Exposes **only** `fs.read`, `fs.write`, `cmd.run`.
- Enforces allowed roots, network-FS block, write zones, command catalog constraints, time/output caps.
- Handles standard MCP initialize request/response.
- JSONL audit log with redact + sha256 content hashing.
- CLI can create a default policy, validate it, add a root, add a command, and run `doctor` successfully.

---

## 15) Test Matrix & Cases

**Unit tests**
- Path normalization: `~/x/../y` → canonical beneath root; symlink escape rejected.
- Network FS: stubbed detectors; integration on supported CI (optional, mark `#[ignore]`).
- Policy parsing: invalid regex, duplicate command id, missing exec → error.
- Arg filtering: unknown arg rejected; regex pattern matching works.

**E2E tests**
- Read within root succeeds; outside root denied (`POLICY_DENY`).
- Write in write zone ok; write outside → denied.
- `cmd.run` with allowed command + args succeeds; disallowed arg → `POLICY_DENY`.
- Timeout test: run `sleep 2` with `timeoutMs=500`, expect `TIMEOUT`.
- Output cap test: command producing > cap marks `truncated:true`.

---

## 16) Security Notes & Future Hardening

- Prefer handle-based open + `O_NOFOLLOW` semantics where available to resist TOCTOU.
- Consider Linux `openat2(RESOLVE_*)` where kernel permits.
- Consider chroot/bind-mount sandbox for commands in a future version.
- Add per-command `network: false` gating via OS firewall APIs or namespaces (future).

---

## 17) Quickstart (Developer)

```bash
# Build everything
cargo build --workspace

# Generate schema (from mdmcp_policy)
cargo run -p mdmcp_policy --example emit-schema > policy.schema.json

# Run server with example policy
cargo run -p mdmcpsrvr -- --config examples/policy.example.yaml --stdio

# In another shell, send a JSON-RPC request
printf '{"jsonrpc":"2.0","id":1,"method":"fs.read","params":{"path":"examples/policy.example.yaml","offset":0,"length":4096,"encoding":"utf8"}}\n' | \
  cargo run -p mdmcpsrvr -- --config examples/policy.example.yaml --stdio
```

---

## 18) Nice-to-Haves (Post‑v1)

- Hot-reload policy on SIGHUP with safe swap.
- Per-client policy profiles (tighten for weaker clients).
- Metrics via OpenTelemetry, `/metrics` text endpoint (when WS/http transport is added).
- Policy dry-run tool in CLI to explain allow/deny decisions.
- GUI for `mdmcpcfg` to visualize recent audit events.

---

**End of Spec v1** — This is sized for Claude Code to implement incrementally (modules and tests ordered). Keep the surface minimal and the policy strict; expand only as needed.

