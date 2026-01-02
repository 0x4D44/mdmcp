# mdmcp — Minimal, Policy‑Driven MCP Server

[![CI](https://github.com/0x4D44/mdmcp/actions/workflows/ci.yml/badge.svg)](https://github.com/0x4D44/mdmcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

**mdmcp** is a security‑focused, policy‑driven [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built in Rust. It empowers LLMs with local tooling while maintaining strict control over filesystem access and command execution.

## 🚀 Key Features

*   **🛡️ Security First:** Every file operation and command execution is gated by an explicit `policy.yaml`. No access is granted by default.
*   **📦 Sandboxed Execution:** Commands run with strict resource limits (time, output size) and environment variable filtering.
*   **🔌 Plugin Ecosystem:** Extensible architecture with a suite of CLI plugins for AI (`mdaicli`), Jira, Slack, Mail, and Confluence.
*   **🛠️ Robust Tooling:** Includes `mdmcpcfg`, a powerful CLI for installation, updates, policy management, and diagnostics.
*   **💻 Cross-Platform:** Native support for Windows, macOS, and Linux (including WSL integration).

## 📦 Components

The repository is organized as a Cargo workspace with the following core members:

| Component | Description |
| :--- | :--- |
| **`mdmcpsrvr`** | The core MCP server binary. Implements the MCP protocol over stdio and enforces security policies. |
| **`mdmcpcfg`** | Configuration CLI. Handles installation, updates, Claude Desktop integration, and policy editing. |
| **`plugins/`** | A collection of specialized CLI tools that extend the server's capabilities (see [Plugins](#-plugins)). |

## 🛠️ Installation

### Quick Start

1.  **Build the workspace:**
    ```bash
    cargo build --workspace --release
    ```

2.  **Install the server and configure Claude Desktop:**
    ```bash
    cargo run -p mdmcpcfg -- install
    ```
    This command will:
    *   Install the `mdmcpsrvr` binary.
    *   Create a default secure policy.
    *   Automatically configure Claude Desktop to use the server.

3.  **Restart Claude Desktop** to load the new configuration.

### Manual Setup

If you prefer manual configuration, you can run the server directly:

```bash
cargo run -p mdmcpsrvr -- --config path/to/policy.yaml --stdio
```

## ⚙️ Configuration (Policy)

The heart of `mdmcp` is the `policy.yaml` file. It defines exactly what the LLM is allowed to do.

**Example `policy.yaml`:**

```yaml
version: 1
network_fs_policy: deny_all  # Block network shares (NFS/SMB) for safety
allowed_roots:
  - "C:/Users/alice/projects" # Only allow reading from this directory
write_rules:
  - path: "C:/Users/alice/projects/logs" # Only allow writing to this subdirectory
    recursive: true
    max_file_bytes: 1048576 # 1MB limit
commands:
  - id: "echo"
    exec: "/bin/echo"
    args:
      allow: ["hello", "world"] # Whitelist specific arguments
    timeout_ms: 5000
```

### Managing Policy via CLI

Use `mdmcpcfg` to safely modify your policy:

*   **View Policy:** `mdmcpcfg policy show`
*   **Add Allowed Root:** `mdmcpcfg policy add-root "/path/to/project"`
*   **Add Write Permission:** `mdmcpcfg policy add-root "/path/to/scratch" --write`
*   **Add Command:** `mdmcpcfg policy add-command git --exec "/usr/bin/git"`
*   **Validate Policy:** `mdmcpcfg policy validate`

## 🔌 Plugins

`mdmcp` includes several plugins located in the `plugins/` directory. These are standalone CLIs that can be added to your policy to provide specialized capabilities to the LLM.

*   **`mdaicli`**: Unified CLI for accessing AI providers (OpenAI, Anthropic, Ollama, OpenRouter).
*   **`mdconfcli`**: Interface with Confluence.
*   **`mdjiracli`**: Interact with Jira issues.
*   **`mdmailcli`**: Send and read emails.
*   **`mdslackcli`**: Send messages and read Slack channels.

To use a plugin, build it and add it to your policy using `mdmcpcfg policy add-command`.

## 🛡️ Security Model

1.  **Path Confinement:** File operations (`fs.read`, `fs.write`, `list_directory`) are strictly confined to `allowed_roots`. Path traversal attacks are blocked.
2.  **Network Isolation:** By default, network filesystems (UNC paths, mapped drives) are blocked to prevent data exfiltration or access to shared resources.
3.  **Command Whitelisting:** Only commands explicitly defined in the `commands` catalog can be executed.
4.  **Argument Validation:** Command arguments are validated against allowlists or regex patterns to prevent injection attacks.
5.  **Environment Filtering:** Child processes run with a sanitized environment. Only whitelisted variables are passed through.

## 🤝 Contributing

We welcome contributions!

1.  **Clone the repo:** `git clone https://github.com/0x4D44/mdmcp.git`
2.  **Run tests:** `cargo test --workspace --all-features`
3.  **Format code:** `cargo fmt --all`
4.  **Lint:** `cargo clippy --workspace --all-targets --all-features`

See [CLAUDE.md](CLAUDE.md) for detailed development guidelines.

## 📄 License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.