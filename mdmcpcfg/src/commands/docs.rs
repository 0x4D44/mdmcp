use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::io::Paths;

#[derive(Debug, Serialize, Deserialize)]
struct ToolDoc {
    name: String,
    description: String,
    args: Vec<String>,
    example: String,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct CommandDoc {
    id: String,
    description: String,
    platform: Vec<String>,
    example: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct DocCache {
    version: String,
    generated_at: String,
    tools: Vec<ToolDoc>,
    commands: Vec<CommandDoc>,
    notes: Vec<String>,
}

fn build_tool_docs() -> Vec<ToolDoc> {
    vec![
        ToolDoc {
            name: "read_bytes".into(),
            description: "Read file by byte range (path, offset?, length?, encoding?)".into(),
            args: vec![
                "path".into(),
                "offset?".into(),
                "length?".into(),
                "encoding?".into(),
            ],
            example: "tools/call read_bytes { path: '/path/file', offset: 0, length: 4096 }".into(),
        },
        ToolDoc {
            name: "read_lines".into(),
            description: "Read file by lines (path, line_offset?, line_count?, encoding?)".into(),
            args: vec![
                "path".into(),
                "line_offset?".into(),
                "line_count?".into(),
                "encoding?".into(),
            ],
            example: "tools/call read_lines { path: '/path/file', line_offset: 0, line_count: 50 }"
                .into(),
        },
        ToolDoc {
            name: "write_file".into(),
            description:
                "Write or append to a file (path, data, append?, create?, overwrite?, encoding?)"
                    .into(),
            args: vec![
                "path".into(),
                "data".into(),
                "append?".into(),
                "create?".into(),
                "overwrite?".into(),
                "encoding?".into(),
            ],
            example: "tools/call write_file { path: '/path/file', data: 'hello', append: true }"
                .into(),
        },
        ToolDoc {
            name: "run_command".into(),
            description: "Execute a catalog command; use resources/read on 'mdmcp://commands/catalog' for full details".into(),
            args: vec!["command_id".into(), "args?[]".into(), "stdin?".into()],
            example:
                "tools/call run_command { command_id: 'grep', args: ['-RIn', 'cheese', '/mail'] }"
                    .into(),
        },
    ]
}

fn strip_ansi(s: &str) -> String {
    let re = Regex::new(r"\x1B\[[0-?]*[ -/]*[@-~]").unwrap();
    re.replace_all(s, "").to_string()
}

/// Build and cache documentation next to policy (Markdown)
pub async fn build() -> Result<()> {
    let paths = Paths::new()?;
    // Load merged policy: core + user (if core exists)
    let user_yaml = fs::read_to_string(&paths.policy_file).with_context(|| {
        format!(
            "Failed to read user policy: {}",
            paths.policy_file.display()
        )
    })?;
    let user: mdmcp_policy::Policy = mdmcp_policy::Policy::from_yaml(&user_yaml)?;
    let merged = if paths.core_policy_file.exists() {
        let core_yaml = fs::read_to_string(&paths.core_policy_file).with_context(|| {
            format!(
                "Failed to read core policy: {}",
                paths.core_policy_file.display()
            )
        })?;
        let core: mdmcp_policy::Policy = mdmcp_policy::Policy::from_yaml(&core_yaml)?;
        mdmcp_policy::merge_policies(core, user)
    } else {
        user
    };

    let mut md = String::new();
    md.push_str(&format!(
        "# MDMCP Tools and Commands\n\nGenerated: {}  ",
        chrono::Utc::now().to_rfc3339()
    ));
    md.push_str(&format!("Version: {}\n\n", env!("CARGO_PKG_VERSION")));

    md.push_str("## MCP Tools\n\n");
    for t in build_tool_docs() {
        md.push_str(&format!(
            "### {}\n\n{}\n\n- Args: {}\n- Example: `{}`\n\n",
            t.name,
            t.description,
            t.args.join(", "),
            t.example
        ));
    }

    md.push_str("## Command Catalog\n\n");
    for c in &merged.commands {
        md.push_str(&format!("### {}\n\n", c.id));
        if let Some(d) = &c.description {
            if !d.is_empty() {
                md.push_str(&format!("{}\n\n", d));
            }
        }
        if !c.platform.is_empty() {
            md.push_str(&format!("- Platforms: {}\n", c.platform.join(", ")));
        }
        md.push_str(&format!(
            "- Example: tools/call run_command {{ command_id: '{}', args: [] }}\n",
            c.id
        ));

        // Capture help for tools starting with 'md' or when help_capture is configured
        let exec_name = std::path::Path::new(&c.exec)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let mut help_args: Option<Vec<String>> = None;
        let mut timeout_ms: u64 = 1500;
        let mut max_bytes: usize = 4096;
        if c.help_capture.enabled && !c.help_capture.args.is_empty() {
            help_args = Some(c.help_capture.args.clone());
            timeout_ms = c.help_capture.timeout_ms;
            max_bytes = c.help_capture.max_bytes as usize;
        } else if exec_name.starts_with("md") {
            help_args = Some(vec!["--help".into()]);
        }
        if let Some(args) = help_args {
            let mut cmd = tokio::process::Command::new(&c.exec);
            cmd.args(&args);
            if let Ok(Ok(out)) =
                tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), cmd.output())
                    .await
            {
                let mut text = if !out.stdout.is_empty() {
                    String::from_utf8_lossy(&out.stdout).to_string()
                } else {
                    String::from_utf8_lossy(&out.stderr).to_string()
                };
                if text.len() > max_bytes {
                    text.truncate(max_bytes);
                    text.push_str("\n(truncated)");
                }
                let clean = strip_ansi(&text);
                md.push_str("\n`````text\n");
                md.push_str(&clean);
                md.push_str("\n`````\n\n");
            } else {
                md.push('\n');
            }
        } else {
            md.push('\n');
        }
    }

    md.push_str("\n---\n\nThis cache is generated by `mdmcpcfg docs --build`.  \\n+For the full machine-readable catalog (with server-side help snippets), see `mdmcp://commands/catalog`.\n");

    // Guidance on how to access resources vs files
    md.push_str("## File Operations vs Resources\n\n");
    md.push_str("File Tools (read_lines, read_bytes, write_file):\n");
    md.push_str("- Use for actual files within allowed directories\n");
    md.push_str("- Example: tools/call read_lines { path: '/home/user/document.txt' }\n\n");
    md.push_str("Resource Access (resources/read):\n");
    md.push_str("- Use for MCP server resources\n");
    md.push_str("- Example: resources/read { uri: 'mdmcp://commands/catalog' }\n");

    let cache_path = doc_cache_path(&paths.config_dir);
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&cache_path, md).with_context(|| {
        format!(
            "Failed to write documentation cache: {}",
            cache_path.display()
        )
    })?;
    println!("✅ Documentation cache updated: {}", cache_path.display());
    Ok(())
}

pub fn doc_cache_path(config_dir: &std::path::Path) -> PathBuf {
    config_dir.join("doc.cache.md")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_codes() {
        let s = "\x1b[31mRED\x1b[0m plain";
        let cleaned = strip_ansi(s);
        assert_eq!(cleaned, "RED plain");
    }

    #[test]
    fn test_doc_cache_path_join() {
        let base = PathBuf::from("/tmp/mdmcp");
        let p = doc_cache_path(&base);
        assert!(p.ends_with("doc.cache.md"));
    }
}
