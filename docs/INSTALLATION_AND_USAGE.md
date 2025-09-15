# Installation and Usage

## WSL Installation Guide

There are two supported targets on Windows machines with WSL installed:

- Windows target: install and run the server on Windows; plugins install on Windows.
- WSL (Linux) target: install and run the server inside WSL; plugins still install on Windows and are invoked via /mnt/c paths from the Linux policy.

### Quick Start (Non-Interactive)

- Windows target
  - `mdmcpcfg install --server-target windows --plugins yes --yes`
  - Claude config points directly to `%LOCALAPPDATA%\mdmcp\bin\mdmcpsrvr.exe --stdio --config ...`

- WSL target
  - `mdmcpcfg install --server-target linux --plugins yes --yes [--wsl-distro <name>]`
  - Claude config points to `wsl.exe [-d <distro>] -- /home/<user>/.local/share/mdmcp/bin/mdmcpsrvr --stdio --config /home/<user>/.config/mdmcp/policy.user.yaml`
  - The installer adds `/mnt/c/Users/<you>` as an allowed root (read-only by default) in the WSL policy.

### Prompts (Interactive)

If `--server-target auto` (default) and WSL is available:

- "WSL detected. Where should mdmcpsrvr be installed?"
  - Choices: [W] Windows (default), [L] Linux (WSL), [N] Cancel
- "Install mdmcp plugins on Windows? [Y/n]" (default: Yes)

### Plugins

- Plugins always install on Windows at `%LOCALAPPDATA%\mdmcp\bin\plugins\*.exe`.
- Windows target policy uses Windows paths for plugin execs.
- WSL target policy uses `/mnt/c/Users/<you>/AppData/Local/mdmcp/bin/plugins/<plugin>.exe`.

### Doctor Checks

- `mdmcpcfg doctor` verifies:
  - Server binary location and executability.
  - Policy file presence and shape.
  - Claude Desktop config points to Windows exe or to `wsl.exe` wrapper.
  - On Windows with WSL target, also checks Linux server and policy paths via `wsl.exe`.

### Tips

- Keep `deny_network_fs: true` unless explicitly required.
- Limit `allowed_roots` and prefer precise command rules.
- Re-run `mdmcpcfg install` any time to refresh core policy defaults; user policy is never overwritten.
