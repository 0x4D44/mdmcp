# mdmcp Bootstrap Release

Thank you for downloading mdmcp.

Quick start:
- Windows: run `mdmcpcfg.exe install`
- macOS: run `./mdmcpcfg install`
- Linux/WSL: run `./mdmcpcfg install`

What happens:
- `mdmcpcfg install` downloads and installs the `mdmcpsrvr` (MCP server) and optional plugins into platform-appropriate locations.
- You can re-run `mdmcpcfg update` later to upgrade. Use `--help` for options.

Contents:
- `windows/`, `macos/`, `linux/` — pick the folder matching your OS. WSL users should use the `linux/` build.
  - `mdmcpcfg[.exe]` — the bootstrap CLI
  - `mdmcpcfg[.exe].sha256` — SHA256 checksum for the CLI
  - `SHA256SUMS.txt` — checksums for all files in this folder
  - `bin/` — server and plugin binaries for convenience/offline installs
    - `mdmcpsrvr[.exe]`
    - `plugins/` — CLI plugins:
      - `mdaicli[.exe]`
      - `mdconfcli[.exe]`
      - `mdjiracli[.exe]`
      - `mdmailcli[.exe]`
      - `mdslackcli[.exe]`

Notes:
- If your OS blocks execution, you may need to clear quarantine/SmartScreen and/or `chmod +x mdmcpcfg`.
- For offline environments, you can copy the relevant `bin/` contents into your install prefix and run `mdmcpcfg install --from-local` in a future release. For now, `mdmcpcfg install` expects network access.

For more documentation, see the repository README.
