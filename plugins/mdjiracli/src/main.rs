use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use dialoguer::{Confirm, Input, Password};
use keyring::Entry;
use reqwest::header::ACCEPT;
use serde_json::Value;

const SERVICE: &str = "jira-cli";
const KEY_BASE_URL: &str = "base_url";
const KEY_USERNAME: &str = "username";
const KEY_TOKEN: &str = "token";

#[derive(Parser)]
#[command(
    name = "jira",
    version,
    about = "Jira CLI using REST (Agile API) with credentials stored via OS keyring",
    long_about =
        "A lightweight Jira CLI focused on read-only Agile endpoints.\n\
         Credentials are stored securely using the OS credential manager via the `keyring` crate\n\
         (service: `jira-cli`, keys: `base_url`, `username`, `token`).\n\n\
         Global flags control JSON output formatting, and all subcommands share the same auth flow\n\
         (auto-prompt and verification against the Agile API).",
    after_long_help = include_str!("help_examples.txt")
)]
struct Cli {
    /// Maximum string length in JSON output (truncate beyond this)
    #[arg(global = true, long = "max-len", default_value_t = 512)]
    max_len: usize,

    /// Maximum array items in JSON output
    #[arg(global = true, long = "max-items", default_value_t = 50)]
    max_items: usize,

    /// Pretty-print JSON output
    #[arg(global = true, long = "pretty", default_value_t = false)]
    pretty: bool,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize credentials (prompts & saves to Windows Credential Manager)
    Init,
    /// Show the current user from Jira (/myself) - also triggers the auto auth flow
    Whoami,
    /// Agile: list boards
    AgileBoards(AgileBoardsArgs),
    /// Agile: list issues on a board (optional JQL)
    AgileBoardIssues(AgileBoardIssuesArgs),
    /// Agile: get an issue via Agile API
    AgileIssueGet(AgileIssueGetArgs),
    /// Clear stored credentials from Windows Credential Manager
    AuthReset,
    /// Display stored base URL and username (token masked)
    AuthShow,
}

#[derive(Clone)]
struct Creds {
    base_url: String,
    username: String, // Jira Cloud: your Atlassian account email
    token: String,    // Jira Cloud API token
}

struct Jira {
    http: reqwest::Client,
    creds: Creds,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Init => init_interactive().await,
        Commands::Whoami => {
            // Verify Agile API access and show minimal status
            let jira = ensure_auth_interactive().await?;
            let _: Value = jira.get_agile_qs("/board", &[("maxResults", "1")]).await?;
            println!(
                "Auth OK (Agile) for {} @ {}",
                jira.creds.username, jira.creds.base_url
            );
            Ok(())
        }
        Commands::AgileBoards(ref args) => handle_agile_boards(args, &cli).await,
        Commands::AgileBoardIssues(ref args) => handle_agile_board_issues(args, &cli).await,
        Commands::AgileIssueGet(ref args) => handle_agile_issue_get(args, &cli).await,
        Commands::AuthReset => {
            delete_secret(KEY_BASE_URL);
            delete_secret(KEY_USERNAME);
            delete_secret(KEY_TOKEN);
            println!(
                "Credentials cleared from Windows Credential Manager (service: {})",
                SERVICE
            );
            Ok(())
        }
        Commands::AuthShow => {
            let base_url = read_secret(KEY_BASE_URL).unwrap_or_else(|| "<not set>".into());
            let username = read_secret(KEY_USERNAME).unwrap_or_else(|| "<not set>".into());
            let token = read_secret(KEY_TOKEN).unwrap_or_else(|| "<not set>".into());
            let masked = if token == "<not set>" {
                token
            } else {
                format!("{}***", &token.chars().take(4).collect::<String>())
            };
            println!("Base URL : {}", base_url);
            println!("Username : {}", username);
            println!("Token    : {}", masked);
            Ok(())
        }
    }
}

impl Jira {
    fn new(creds: Creds) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("jira-cli/0.1")
            .build()?;
        Ok(Self { http, creds })
    }

    // Core v3 helpers removed; Agile API helpers below

    fn api_agile(&self, path: &str) -> String {
        let mut base = self.creds.base_url.trim_end_matches('/').to_string();
        for suffix in ["/rest/api/3", "/rest/api/2", "/rest/agile/1.0"] {
            if let Some(stripped) = base.strip_suffix(suffix) {
                base = stripped.trim_end_matches('/').to_string();
                break;
            }
        }
        let full_path = if path.starts_with("/rest/agile/") {
            path.to_string()
        } else {
            format!("/rest/agile/1.0{}", path)
        };
        format!("{}{}", base, full_path)
    }

    async fn get_agile_qs<T: for<'de> serde::Deserialize<'de>, Q: serde::Serialize>(
        &self,
        path: &str,
        query: &Q,
    ) -> Result<T> {
        let resp = self
            .http
            .get(self.api_agile(path))
            .basic_auth(self.creds.username.clone(), Some(self.creds.token.clone()))
            .header(ACCEPT, "application/json")
            .query(query)
            .send()
            .await
            .with_context(|| format!("GET {}", path))?
            .error_for_status()
            .with_context(|| format!("GET {} returned error", path))?;
        Ok(resp.json::<T>().await?)
    }

    async fn get_agile<T: for<'de> serde::Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let resp = self
            .http
            .get(self.api_agile(path))
            .basic_auth(self.creds.username.clone(), Some(self.creds.token.clone()))
            .header(ACCEPT, "application/json")
            .send()
            .await
            .with_context(|| format!("GET {}", path))?
            .error_for_status()
            .with_context(|| format!("GET {} returned error", path))?;
        Ok(resp.json::<T>().await?)
    }
}

/// Public: single-shot init (prompts, saves, verifies).
async fn init_interactive() -> Result<()> {
    println!("Let's set up Jira credentials (stored in Windows Credential Manager).");

    let (base_url, username, token) = prompt_for_all()?;

    // Save first (per your requested flow), then test, then retry if needed.
    write_secret(KEY_BASE_URL, &base_url)?;
    write_secret(KEY_USERNAME, &username)?;
    write_secret(KEY_TOKEN, &token)?;

    match test_now(&base_url, &username, &token).await {
        Ok(_) => {
            println!("✅ Credentials verified and saved.");
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Verification failed: {e}");
            if Confirm::new()
                .with_prompt("Try entering values again?")
                .default(true)
                .interact()?
            {
                // Overwrite and retry once more
                let (base_url2, username2, token2) = prompt_for_all()?;
                write_secret(KEY_BASE_URL, &base_url2)?;
                write_secret(KEY_USERNAME, &username2)?;
                write_secret(KEY_TOKEN, &token2)?;
                test_now(&base_url2, &username2, &token2).await?;
                println!("✅ Credentials verified and saved.");
                Ok(())
            } else {
                anyhow::bail!("Credentials not verified.");
            }
        }
    }
}

/// Internal: used by commands. Load → test. If missing/invalid → prompt → save → retest.
async fn ensure_auth_interactive() -> Result<Jira> {
    // 1) Try existing from Credential Manager
    if let (Some(base_url), Some(username), Some(token)) = (
        read_secret(KEY_BASE_URL),
        read_secret(KEY_USERNAME),
        read_secret(KEY_TOKEN),
    ) {
        if let Ok(jira) = build_if_valid(&base_url, &username, &token).await {
            return Ok(jira);
        }
        eprintln!("Stored credentials failed verification. Let's update them…");
    } else {
        println!("No credentials found. Let's set them up…");
    }

    // 2) Prompt, save, verify
    let jira = loop {
        let (base_url, username, token) = prompt_for_all()?;
        write_secret(KEY_BASE_URL, &base_url)?;
        write_secret(KEY_USERNAME, &username)?;
        write_secret(KEY_TOKEN, &token)?;
        match build_if_valid(&base_url, &username, &token).await {
            Ok(j) => break j,
            Err(e) => {
                eprintln!("❌ Verification failed: {e}");
                if !Confirm::new()
                    .with_prompt("Try again?")
                    .default(true)
                    .interact()?
                {
                    anyhow::bail!("Credentials not verified.");
                }
            }
        }
    };

    println!("✅ Credentials verified and saved.");
    Ok(jira)
}

fn prompt_for_all() -> Result<(String, String, String)> {
    let base_url: String = Input::new()
        .with_prompt("Base URL (e.g. https://acme.atlassian.net)")
        .interact_text()?;
    let username: String = Input::new()
        .with_prompt("Email/username (e.g. you@acme.com)")
        .interact_text()?;
    let token: String = Password::new()
        .with_prompt("API token (paste; will be stored in Windows Credential Manager)")
        .interact()?;
    Ok((
        base_url.trim().to_string(),
        username.trim().to_string(),
        token.trim().to_string(),
    ))
}

async fn test_now(base_url: &str, username: &str, token: &str) -> Result<()> {
    build_if_valid(base_url, username, token).await.map(|_| ())
}

async fn build_if_valid(base_url: &str, username: &str, token: &str) -> Result<Jira> {
    let jira = Jira::new(Creds {
        base_url: base_url.to_string(),
        username: username.to_string(),
        token: token.to_string(),
    })?;
    // Verify via Agile API (list one board)
    let _: Value = jira.get_agile_qs("/board", &[("maxResults", "1")]).await?;
    Ok(jira)
}

/* ----- Windows Credential Manager helpers via keyring ----- */

fn read_secret(key: &str) -> Option<String> {
    Entry::new(SERVICE, key).ok()?.get_password().ok()
}
fn write_secret(key: &str, value: &str) -> Result<()> {
    Entry::new(SERVICE, key)?.set_password(value)?;
    Ok(())
}
fn delete_secret(key: &str) {
    let _ = Entry::new(SERVICE, key).and_then(|e| e.delete_password());
}

/* ----- Read-only commands: projects, issues get, search ----- */
// Core v3 read-only commands removed. Use Agile variants below.

/* ----- JSON print with truncation ----- */

fn print_json(mut v: Value, cli: &Cli) {
    truncate_value(&mut v, cli.max_len, cli.max_items);
    if cli.pretty {
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("{}", serde_json::to_string(&v).unwrap());
    }
}

/* ----- Agile (Jira Software) read-only helpers ----- */

#[derive(Args, Clone)]
struct AgileBoardsArgs {
    /// Max number of boards
    #[arg(long, default_value_t = 25)]
    limit: usize,
}

#[derive(Args, Clone)]
struct AgileBoardIssuesArgs {
    /// Board ID
    #[arg(long)]
    board: u64,
    /// Optional JQL to further filter issues on the board
    #[arg(long)]
    jql: Option<String>,
    /// Fields to include (comma-separated); defaults to common set
    #[arg(long)]
    fields: Option<String>,
    /// Max results
    #[arg(long, default_value_t = 25)]
    limit: usize,
}

#[derive(Args, Clone)]
struct AgileIssueGetArgs {
    /// Issue key, e.g. ABC-123
    key: String,
    /// Fields to include (comma-separated)
    #[arg(long)]
    fields: Option<String>,
}

async fn handle_agile_boards(args: &AgileBoardsArgs, cli: &Cli) -> Result<()> {
    let jira = ensure_auth_interactive().await?;
    let v: Value = jira
        .get_agile_qs("/board", &[("maxResults", args.limit.to_string())])
        .await?;
    let arr = v
        .get("values")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let simplified: Value = Value::Array(
        arr.into_iter()
            .map(|b| {
                let id = b.get("id").cloned().unwrap_or(Value::Null);
                let name = b.get("name").cloned().unwrap_or(Value::Null);
                let btype = b.get("type").cloned().unwrap_or(Value::Null);
                let mut o = serde_json::Map::new();
                o.insert("id".into(), id);
                o.insert("name".into(), name);
                o.insert("type".into(), btype);
                Value::Object(o)
            })
            .collect(),
    );
    print_json(simplified, cli);
    Ok(())
}

async fn handle_agile_board_issues(args: &AgileBoardIssuesArgs, cli: &Cli) -> Result<()> {
    let jira = ensure_auth_interactive().await?;
    let fields_csv = args
        .fields
        .clone()
        .unwrap_or_else(|| "summary,status,assignee,project,issuetype,priority,updated".into());
    let path = format!("/board/{}/issue", args.board);
    // build query
    let mut q: Vec<(String, String)> = vec![
        ("maxResults".into(), args.limit.to_string()),
        ("fields".into(), fields_csv.clone()),
    ];
    if let Some(j) = &args.jql {
        q.push(("jql".into(), j.clone()));
    }
    let v: Value = jira.get_agile_qs(&path, &q).await?;
    let issues = v
        .get("issues")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let simplified = Value::Array(
        issues
            .into_iter()
            .map(|it| {
                let key = it.get("key").cloned().unwrap_or(Value::Null);
                let fields = it.get("fields").cloned().unwrap_or(Value::Null);
                let mut o = serde_json::Map::new();
                o.insert("key".into(), key);
                o.insert("fields".into(), fields);
                Value::Object(o)
            })
            .collect(),
    );
    print_json(simplified, cli);
    Ok(())
}

async fn handle_agile_issue_get(args: &AgileIssueGetArgs, cli: &Cli) -> Result<()> {
    let jira = ensure_auth_interactive().await?;
    let path = format!("/issue/{}", args.key);
    let v: Value = if let Some(fields_csv) = &args.fields {
        jira.get_agile_qs(&path, &[("fields", fields_csv.clone())])
            .await?
    } else {
        jira.get_agile(&path).await?
    };
    print_json(v, cli);
    Ok(())
}

fn truncate_value(v: &mut Value, max_len: usize, max_items: usize) {
    match v {
        Value::String(s) => {
            if s.len() > max_len {
                let mut t = s.chars().take(max_len).collect::<String>();
                t.push('…');
                *s = t;
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                truncate_value(item, max_len, max_items);
            }
            if arr.len() > max_items {
                arr.truncate(max_items);
            }
        }
        Value::Object(map) => {
            for (_, val) in map.iter_mut() {
                truncate_value(val, max_len, max_items);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_includes_examples() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf).expect("write_long_help");
        let s = String::from_utf8(buf).expect("utf8");
        assert!(
            s.contains("EXAMPLES"),
            "help should include EXAMPLES section\n{s}"
        );
        assert!(
            s.contains("agile-board-issues"),
            "help should mention subcommand names\n{s}"
        );
    }

    #[test]
    fn clap_config_debug_assert() {
        // Ensure clap configuration is internally consistent
        Cli::command().debug_assert();
    }

    #[test]
    fn cli_parsing_defaults() {
        // Defaults should apply when only subcommand is provided
        let cli = Cli::try_parse_from(["mdjiracli", "agile-boards"]).expect("parse");
        assert_eq!(cli.max_len, 512);
        assert_eq!(cli.max_items, 50);
        assert!(!cli.pretty);
        match cli.cmd {
            Commands::AgileBoards(ref args) => {
                assert_eq!(args.limit, 25);
            }
            _ => panic!("expected AgileBoards"),
        }
    }

    #[test]
    fn cli_parsing_overrides() {
        // Override globals and subcommand args
        let cli = Cli::try_parse_from([
            "mdjiracli",
            "--pretty",
            "--max-len",
            "200",
            "--max-items",
            "10",
            "agile-board-issues",
            "--board",
            "123",
            "--fields",
            "summary,status",
            "--limit",
            "7",
        ])
        .expect("parse");
        assert!(cli.pretty);
        assert_eq!(cli.max_len, 200);
        assert_eq!(cli.max_items, 10);
        match cli.cmd {
            Commands::AgileBoardIssues(ref args) => {
                assert_eq!(args.board, 123);
                assert_eq!(args.fields.as_deref(), Some("summary,status"));
                assert_eq!(args.limit, 7);
                assert!(args.jql.is_none());
            }
            _ => panic!("expected AgileBoardIssues"),
        }
    }

    #[test]
    fn truncate_value_string_and_array_works() {
        let mut v = serde_json::json!({
            "name": "abcdefghijklmnopqrstuvwxyz",
            "items": [1, 2, 3, 4, 5, 6],
        });
        truncate_value(&mut v, 5, 3);
        let name = v["name"].as_str().unwrap();
        // Expect 5 chars + ellipsis
        assert_eq!(name, "abcde…");
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 3);
    }

    #[test]
    fn truncate_value_nested_objects() {
        let mut v = serde_json::json!({
            "outer": {
                "inner": {
                    "desc": "0123456789",
                    "list": ["aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc"],
                }
            }
        });
        truncate_value(&mut v, 3, 2);
        assert_eq!(v["outer"]["inner"]["desc"], serde_json::json!("012…"));
        let list = v["outer"]["inner"]["list"].as_array().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0], serde_json::json!("aaa…"));
        assert_eq!(list[1], serde_json::json!("bbb…"));
    }

    #[test]
    fn api_agile_builds_correct_urls() {
        // Helper to create Jira with varying base URLs
        let mk = |base: &str| -> Jira {
            Jira::new(Creds {
                base_url: base.to_string(),
                username: "u".into(),
                token: "t".into(),
            })
            .unwrap()
        };

        // Base URL with different suffixes should be normalized
        let j1 = mk("https://acme.atlassian.net");
        let j2 = mk("https://acme.atlassian.net/rest/api/3");
        let j3 = mk("https://acme.atlassian.net/rest/api/2/");
        let j4 = mk("https://acme.atlassian.net/rest/agile/1.0");
        assert_eq!(
            j1.api_agile("/board"),
            "https://acme.atlassian.net/rest/agile/1.0/board"
        );
        assert_eq!(
            j2.api_agile("/board"),
            "https://acme.atlassian.net/rest/agile/1.0/board"
        );
        assert_eq!(
            j3.api_agile("/board"),
            "https://acme.atlassian.net/rest/agile/1.0/board"
        );
        assert_eq!(
            j4.api_agile("/board"),
            "https://acme.atlassian.net/rest/agile/1.0/board"
        );

        // If path is already an Agile path, it should be used as-is
        assert_eq!(
            j1.api_agile("/rest/agile/1.0/board"),
            "https://acme.atlassian.net/rest/agile/1.0/board"
        );

        // Joining should not duplicate slashes
        let j5 = mk("https://acme.atlassian.net///rest/api/3///");
        assert_eq!(
            j5.api_agile("/issue/ABC-123"),
            "https://acme.atlassian.net/rest/agile/1.0/issue/ABC-123"
        );
    }
}
