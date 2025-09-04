# MCP Server Installation and Usage Guide

## Overview

The `mdmcpsrvr` is a minimal, policy-driven Model Context Protocol (MCP) server that provides secure file system access and command execution capabilities. It enforces strict policy controls on all operations and maintains comprehensive audit logs for security monitoring.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)
7. [API Reference](#api-reference)

## System Requirements

### Supported Platforms
- Linux (x86_64, arm64)
- macOS (x86_64, arm64)
- Windows (x86_64)

### Dependencies
- Rust toolchain 1.70+ (for building from source)
- System utilities for command execution (varies by platform)

### Recommended System Resources
- RAM: 256MB minimum, 512MB recommended
- Disk: 100MB for installation, additional space for logs and temporary files
- CPU: Any modern processor (single-core sufficient for most workloads)

## Installation

### Option 1: Build from Source

1. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **Clone and build the project**:
   ```bash
   git clone <repository-url>
   cd mdmcp
   cargo build --release --workspace
   ```

3. **Install the binary**:
   ```bash
   # Copy to a directory in your PATH
   cp target/release/mdmcpsrvr ~/.local/bin/
   # or system-wide
   sudo cp target/release/mdmcpsrvr /usr/local/bin/
   ```

### Option 2: Using Pre-built Binaries (Future Release)

Pre-built binaries will be available on the project releases page once the project reaches v1.0.

## Configuration

### Policy File Creation

The server requires a YAML policy file that defines security constraints and allowed operations. 

1. **Create a policy directory**:
   ```bash
   # Linux/macOS
   mkdir -p ~/.config/mdmcp
   # Windows
   mkdir %APPDATA%\mdmcp
   ```

2. **Copy the example policy**:
   ```bash
   cp examples/policy.example.yaml ~/.config/mdmcp/policy.yaml
   ```

3. **Edit the policy file** to match your environment:
   ```yaml
   version: 1
   denyNetworkFS: true
   allowedRoots:
     - "~/code"                    # Adjust to your project directories
     - "~/Documents/projects"
   # ... see examples/policy.example.yaml for full configuration
   ```

### Policy Configuration Sections

#### Required Sections

- **version**: Policy format version (currently 1)
- **allowedRoots**: Directories where file operations are permitted
- **commands**: Approved commands that can be executed

#### Optional Sections

- **denyNetworkFS**: Block network filesystem access (recommended: true)
- **writeRules**: Specific write permissions and constraints
- **logging**: Audit logging configuration
- **limits**: Resource consumption limits

### Platform-Specific Commands

Commands are filtered by platform. Include platform-specific entries:

```yaml
commands:
  # Unix/Linux commands
  - id: "ls"
    exec: "/bin/ls"
    platform: ["linux", "macos"]
    
  # Windows commands  
  - id: "dir"
    exec: "C:/Windows/System32/cmd.exe"
    args:
      fixed: ["/c", "dir"]
    platform: ["windows"]
```

## Usage

### Basic Server Operation

1. **Start the server**:
   ```bash
   mdmcpsrvr --config ~/.config/mdmcp/policy.yaml --log-level info
   ```

2. **The server communicates via stdio** using JSON-RPC 2.0 protocol with newline-delimited JSON messages.

3. **On startup**, the server sends a handshake notification:
   ```json
   {
     "jsonrpc": "2.0",
     "method": "mcp.handshake",
     "params": {
       "name": "mdmcpsrvr",
       "version": "0.1.0",
       "capabilities": {
         "fs.read": true,
         "fs.write": true,
         "cmd.run": {"streaming": false}
       },
       "policyHash": "a1b2c3d4..."
     }
   }
   ```

### Command Line Options

```bash
mdmcpsrvr [OPTIONS]

Options:
  --config <FILE>      Path to policy configuration file [REQUIRED]
  --log-level <LEVEL>  Log level: trace, debug, info, warn, error [default: info]
  --stdio              Use stdio transport [default: true]
  -h, --help          Print help information
```

### Example Client Interaction

Send JSON-RPC requests to the server's stdin:

```bash
# Read a file
echo '{"jsonrpc":"2.0","id":1,"method":"fs.read","params":{"path":"~/code/README.md","offset":0,"length":1024,"encoding":"utf8"}}' | mdmcpsrvr --config policy.yaml

# Write a file  
echo '{"jsonrpc":"2.0","id":2,"method":"fs.write","params":{"path":"~/code/output.txt","data":"Hello World","encoding":"utf8","create":true,"overwrite":true}}' | mdmcpsrvr --config policy.yaml

# Run a command
echo '{"jsonrpc":"2.0","id":3,"method":"cmd.run","params":{"commandId":"ls","args":["-la"],"cwd":"~/code"}}' | mdmcpsrvr --config policy.yaml
```

### Integration with MCP Clients

The server implements the standard MCP protocol and can be used with any compatible MCP client:

1. **Claude Desktop**: Configure as a local MCP server
2. **Custom Applications**: Use MCP client libraries
3. **Command Line Tools**: Direct JSON-RPC communication

### Logging and Monitoring

#### Audit Logs

If configured, the server writes JSONL audit logs:

```bash
# View recent audit entries
tail -f ~/.mdmcp/mdmcpsrvr.log.jsonl

# Filter by operation type
grep '"tool":"fs.read"' ~/.mdmcp/mdmcpsrvr.log.jsonl

# Check for policy denials
grep '"decision":"deny"' ~/.mdmcp/mdmcpsrvr.log.jsonl
```

#### Server Logs

Runtime logs are written to stderr:

```bash
# Run with debug logging
mdmcpsrvr --config policy.yaml --log-level debug 2> server.log
```

## Security Considerations

### Policy Best Practices

1. **Principle of Least Privilege**
   - Only include necessary directories in `allowedRoots`
   - Restrict commands to essential operations
   - Set conservative resource limits

2. **Network Security**
   - Keep `denyNetworkFS: true` unless network access is required
   - Avoid commands that can make network requests

3. **Path Security**
   - Use absolute paths in policy configuration
   - Avoid overly broad directory permissions
   - Review symlink implications

4. **Command Security**
   - Whitelist arguments rather than using broad regex patterns
   - Avoid shell commands or script interpreters
   - Set appropriate timeout limits

### Resource Limits

Configure appropriate limits to prevent resource exhaustion:

```yaml
limits:
  maxReadBytes: 20000000        # 20MB file read limit
  maxCmdConcurrency: 3          # Max concurrent commands
```

### Audit Requirements

Enable comprehensive logging for security monitoring:

```yaml
logging:
  level: "info"
  file: "~/.mdmcp/mdmcpsrvr.log.jsonl"
  redact: ["env"]              # Redact sensitive environment variables
```

## Troubleshooting

### Common Issues

#### Policy Loading Errors

```
Error: Failed to load policy from /path/to/policy.yaml
```

**Solutions:**
- Verify file path exists and is readable
- Check YAML syntax with `yamllint`
- Ensure all required fields are present

#### Permission Denied Errors

```
Error: Policy denied the operation: pathNotAllowed
```

**Solutions:**
- Check if path is within `allowedRoots`
- Verify write operations have corresponding `writeRules`
- Ensure the process has filesystem permissions

#### Command Not Found

```
Error: Command not found: unknown-command
```

**Solutions:**
- Add command definition to policy `commands` section
- Check command ID spelling
- Verify command is supported on current platform

### Debugging Steps

1. **Increase log level**:
   ```bash
   mdmcpsrvr --config policy.yaml --log-level debug
   ```

2. **Validate policy syntax**:
   ```bash
   # Use a YAML validator
   python -c "import yaml; yaml.safe_load(open('policy.yaml'))"
   ```

3. **Check file permissions**:
   ```bash
   ls -la ~/.config/mdmcp/policy.yaml
   ls -la /path/to/target/directory
   ```

4. **Test minimal policy**:
   Create a minimal policy file to isolate configuration issues.

### Performance Issues

- **High memory usage**: Reduce `maxReadBytes` and `maxOutputBytes`
- **Slow command execution**: Check timeout settings and system resources
- **Log file growth**: Implement log rotation or reduce logging verbosity

## API Reference

### Supported Methods

#### fs.read
Read file contents with policy enforcement.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "fs.read",
  "params": {
    "path": "/path/to/file",
    "offset": 0,
    "length": 1048576,
    "encoding": "utf8"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0", 
  "id": 1,
  "result": {
    "data": "file contents...",
    "bytesRead": 1234,
    "sha256": "hash..."
  }
}
```

#### fs.write
Write file contents with policy enforcement.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "fs.write", 
  "params": {
    "path": "/path/to/file",
    "data": "content to write",
    "encoding": "utf8",
    "create": true,
    "overwrite": false
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "bytesWritten": 15,
    "sha256": "hash..."
  }
}
```

#### cmd.run
Execute approved commands with sandboxing.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "cmd.run",
  "params": {
    "commandId": "ls",
    "args": ["-la"],
    "cwd": "/path/to/directory",
    "stdin": "",
    "env": {"VAR": "value"},
    "timeoutMs": 30000
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "exitCode": 0,
    "stdout": "command output...",
    "stderr": "",
    "timedOut": false,
    "truncated": false
  }
}
```

### Error Codes

- **-32001 POLICY_DENY**: Operation denied by policy
- **-32002 TIMEOUT**: Operation timed out  
- **-32003 OUTPUT_TRUNCATED**: Output was truncated due to size limits
- **-32004 IO_ERROR**: File system I/O error
- **-32602 INVALID_ARGS**: Invalid method parameters
- **-32603 INTERNAL**: Internal server error

## Support and Contributing

- **Documentation**: See `CLAUDE.md` for development information
- **Issues**: Report bugs and feature requests via the project repository
- **Contributing**: Follow the project's contribution guidelines

---

For detailed development information and architecture notes, see the `CLAUDE.md` file in the project root.