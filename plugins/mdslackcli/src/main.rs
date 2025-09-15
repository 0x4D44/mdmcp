use anyhow::{anyhow, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use dialoguer::Password;
use keyring::Entry;
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;

const SERVICE: &str = "slackcli_user";
const USERNAME: &str = "token";
const API_BASE: &str = "https://slack.com/api";

#[derive(Parser, Debug)]
#[command(
    name = "slack",
    version,
    about = "A tiny Slack CLI in Rust",
    long_about = r#"A tiny, practical Slack CLI.

Primary capabilities:
- Initialize and validate a user token (stored via Windows Credential Manager).
- Explore your workspace: whoami, channels, users, and recent messages.
- Send messages (including threaded replies) and open DMs/MPDMs.

Quick examples:
  slack init --force
  slack whoami
  slack channels --types public_channel,im --limit 20
  slack find-person --query "Jane"
  slack open --users U123,U456 --text "Hello there!"
  slack msgs --channel C12345678 --limit 5
  slack send --channel C12345678 --text "Hi from the CLI"
  slack send --channel C12345678 --text "Thread reply" --thread-ts 1712345678.000100

To see detailed help for every command at once, run:
  slack --help

To see help for just one command, use:
  slack <command> --help
"#
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
#[command(rename_all = "lowercase")]
enum Commands {
    /// Initialize credentials (stores/validates token in Windows Credential Manager)
    #[command(long_about = r#"Initialize and validate a Slack user token.

By default, prompts for a token (masked) and stores it in the
Windows Credential Manager for key `slackcli_user/token`.

Examples:
  slack init
  slack init --force
  slack init --reset
  slack init --token xoxp-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX
"#)]
    Init(InitArgs),

    /// Show who you are (team, user)
    #[command(long_about = r#"Display the authenticated identity and team info.

Example:
  slack whoami
"#)]
    Whoami,

    /// Join a public channel so you can read/post
    #[command(long_about = r#"Join a public channel you know the ID for.
Note: You generally cannot join private channels without an invite.

Examples:
  slack join --channel C12345678
"#)]
    Join(JoinArgs),

    /// List recent 1:1 DMs you have access to
    #[command(
        alias = "direct-msgs",
        long_about = r#"List your direct message (IM) conversations.

Examples:
  slack directmsgs
  slack directmsgs --limit 50
"#
    )]
    DirectMsgs(DirectArgs),

    /// List recent multi-person DMs (MPIMs)
    #[command(
        alias = "direct-mp-msgs",
        long_about = r#"List multi-person direct message conversations (MPIMs).

Examples:
  slack directmpmsgs
  slack directmpmsgs --limit 50
"#
    )]
    DirectMpMsgs(DirectArgs),

    /// Find a person by name or email and show IDs
    #[command(
        alias = "find-person",
        long_about = r#"Search for users by display name, real name, email, or user ID.
Outputs: user_id, DM channel (if any), @display_name, real_name, email.

Examples:
  slack find-person --query "Jane Doe"
  slack find-person --query jane@example.com --limit 5
"#
    )]
    FindPerson(FindArgs),

    /// Open a DM/MPDM with one or more users (requires conversations:write)
    #[command(
        long_about = r#"Open a direct message or multi-person DM by user ID(s).
Optionally sends a message immediately to the opened conversation.

Examples:
  slack open --users U12345678
  slack open --users U12345678,U87654321 --text "Hello!"
"#
    )]
    Open(OpenArgs),

    /// List channels/DMs you can see
    #[command(long_about = r#"List conversations visible to you.
Supported types: public_channel, private_channel, mpim, im (comma-separated).

Examples:
  slack channels
  slack channels --types public_channel,im --limit 50
"#)]
    Channels(ListArgs),

    /// List recent messages in a channel
    #[command(long_about = r#"Show recent messages for a channel or DM by ID.

Examples:
  slack msgs --channel C12345678 --limit 10
  slack msgs --channel D23456789
"#)]
    Msgs(MsgsArgs),

    /// Send a message
    #[command(long_about = r#"Post a message to a channel or DM by ID.
Use --thread-ts to reply in an existing thread.

Examples:
  slack send --channel C12345678 --text "Hello from mdslackcli"
  slack send --channel C12345678 --text "Thread reply" --thread-ts 1712345678.000100
"#)]
    Send(SendArgs),
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Clear stored token first
    #[arg(long)]
    reset: bool,
    /// Replace existing token even if valid (re-prompt)
    #[arg(long)]
    force: bool,
    /// Provide token non-interactively (xoxp-…)
    #[arg(long)]
    token: Option<String>,
}

#[derive(Args, Debug)]
struct JoinArgs {
    /// Channel ID (e.g., C01234567)
    #[arg(long)]
    channel: String,
}

#[derive(Args, Debug)]
struct DirectArgs {
    /// Max number of conversations to list
    #[arg(long, default_value_t = 100)]
    limit: u32,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// conversation types (comma-separated)
    #[arg(long, default_value = "public_channel,private_channel,mpim,im")]
    types: String,
    #[arg(long, default_value_t = 200)]
    limit: u32,
}

#[derive(Args, Debug)]
struct MsgsArgs {
    /// Channel ID (e.g., C123… or D123…)
    #[arg(long)]
    channel: String,
    #[arg(long, default_value_t = 25)]
    limit: u32,
}

#[derive(Args, Debug)]
struct SendArgs {
    #[arg(long)]
    channel: String,
    #[arg(long)]
    text: String,
    /// Optional thread timestamp (to reply in a thread)
    #[arg(long)]
    thread_ts: Option<String>,
}

#[derive(Args, Debug)]
struct FindArgs {
    /// Substring to match against display name, real name, email, or user ID
    #[arg(long)]
    query: String,
    /// Max matches to show
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Args, Debug)]
struct OpenArgs {
    /// Comma-separated list of user IDs (e.g., U123,U456)
    #[arg(long)]
    users: String,
    /// Optional text to send immediately in the opened conversation
    #[arg(long)]
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthTest {
    ok: bool,
    team: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
    bot_id: Option<String>,
    error: Option<String>,
}

fn main() -> Result<()> {
    // If called with top-level --help/-h (no subcommand), print a full, AI-friendly help.
    if should_print_full_help() {
        print_full_help();
        return Ok(());
    }

    let cli = Cli::parse();
    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Whoami => {
            let token = ensure_token()?;
            let client = http();
            let info = auth_test(&client, &token)?;
            println!(
                "ok: {}\nteam: {:?}\nteam_id: {:?}\nuser_id: {:?}\nbot_id: {:?}",
                info.ok, info.team, info.team_id, info.user_id, info.bot_id
            );
            Ok(())
        }
        Commands::Join(args) => {
            let token = ensure_token()?;
            let client = http();
            let resp = slack_post(
                &client,
                "conversations.join",
                &token,
                Some(&[("channel", args.channel.as_str())]),
            )?;
            let name = resp
                .get("channel")
                .and_then(|c| c.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("(unknown)");
            println!("Joined #{name}");
            Ok(())
        }
        Commands::DirectMsgs(args) => {
            let token = ensure_token()?;
            let client = http();
            let resp = slack_post(
                &client,
                "conversations.list",
                &token,
                Some(&[("types", "im"), ("limit", &args.limit.to_string())]),
            )?;
            let ims = resp
                .get("channels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let users = fetch_users_map(&client, &token)?;
            for im in ims {
                let id = im.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                let uid = im.get("user").and_then(|v| v.as_str()).unwrap_or("-");
                let (disp, real, email) =
                    users.get(uid).cloned().unwrap_or(("?".into(), None, None));
                let real_s = real.as_deref().unwrap_or("");
                let email_s = email.as_deref().unwrap_or("");
                println!("{id}\t@{disp}\t{real_s}\t{email_s}");
            }
            Ok(())
        }
        Commands::DirectMpMsgs(args) => {
            let token = ensure_token()?;
            let client = http();
            let resp = slack_post(
                &client,
                "conversations.list",
                &token,
                Some(&[("types", "mpim"), ("limit", &args.limit.to_string())]),
            )?;
            let chans = resp
                .get("channels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for ch in chans {
                let id = ch.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                let name = ch.get("name").and_then(|v| v.as_str()).unwrap_or("(mpdm)");
                println!("{id}\t#{name}");
            }
            Ok(())
        }
        Commands::FindPerson(args) => {
            let token = ensure_token()?;
            let client = http();
            let users = fetch_users_map(&client, &token)?;
            // Build a user -> DM channel map by listing IMs
            let ims_resp = slack_post(
                &client,
                "conversations.list",
                &token,
                Some(&[("types", "im"), ("limit", "1000")]),
            )?;
            let mut user_to_dm: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            if let Some(ims) = ims_resp.get("channels").and_then(|v| v.as_array()) {
                for im in ims {
                    if let (Some(uid), Some(cid)) = (
                        im.get("user").and_then(|v| v.as_str()),
                        im.get("id").and_then(|v| v.as_str()),
                    ) {
                        user_to_dm.insert(uid.to_string(), cid.to_string());
                    }
                }
            }
            let q = args.query.to_lowercase();
            let mut rows: Vec<(String, String, String, String, String)> = Vec::new();
            for (uid, (disp, real, email)) in users.iter() {
                let real_s = real.as_deref().unwrap_or("");
                let email_s = email.as_deref().unwrap_or("");
                let inq = |s: &str| s.to_lowercase().contains(&q);
                if inq(disp) || inq(real_s) || inq(email_s) || inq(uid) {
                    let dm = user_to_dm.get(uid).cloned().unwrap_or_else(|| "-".into());
                    rows.push((
                        uid.clone(),
                        dm,
                        format!("@{}", disp),
                        real_s.to_string(),
                        email_s.to_string(),
                    ));
                }
            }
            rows.truncate(args.limit);
            for (uid, dm, atname, real, email) in rows {
                println!("{uid}\t{dm}\t{atname}\t{real}\t{email}");
            }
            Ok(())
        }
        Commands::Open(args) => {
            let token = ensure_token()?;
            let client = http();
            let users = args
                .users
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
            let resp = slack_post(
                &client,
                "conversations.open",
                &token,
                Some(&[("users", users.as_str())]),
            )?;
            let channel_id = resp
                .get("channel")
                .and_then(|c| c.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("-");
            println!("opened channel: {channel_id}");
            if let Some(text) = args.text.as_deref() {
                let _ = slack_post(
                    &client,
                    "chat.postMessage",
                    &token,
                    Some(&[("channel", channel_id), ("text", text)]),
                );
            }
            Ok(())
        }
        Commands::Channels(args) => {
            let token = ensure_token()?;
            let client = http();
            let resp = slack_post(
                &client,
                "conversations.list",
                &token,
                Some(&[
                    ("types", args.types.as_str()),
                    ("limit", &args.limit.to_string()),
                ]),
            )?;
            let chans = resp
                .get("channels")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for ch in chans {
                let id = ch.get("id").and_then(|v| v.as_str()).unwrap_or("-");
                let name = ch
                    .get("name")
                    .and_then(|v| v.as_str())
                    .or_else(|| ch.get("name_normalized").and_then(|v| v.as_str()))
                    .unwrap_or("(dm or unnamed)");
                let ctype = if ch.get("is_im").and_then(|v| v.as_bool()).unwrap_or(false) {
                    "im"
                } else if ch.get("is_mpim").and_then(|v| v.as_bool()).unwrap_or(false) {
                    "mpim"
                } else if ch
                    .get("is_private")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    "private_channel"
                } else {
                    "public_channel"
                };
                println!("{id}\t#{name}\t({ctype})");
            }
            Ok(())
        }
        Commands::Msgs(args) => {
            let token = ensure_token()?;
            let client = http();
            let resp = slack_post(
                &client,
                "conversations.history",
                &token,
                Some(&[
                    ("channel", args.channel.as_str()),
                    ("limit", &args.limit.to_string()),
                ]),
            )?;
            let msgs = resp
                .get("messages")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for m in msgs.iter().rev() {
                let ts = m.get("ts").and_then(|v| v.as_str()).unwrap_or("-");
                let user = m
                    .get("user")
                    .and_then(|v| v.as_str())
                    .or_else(|| m.get("bot_id").and_then(|v| v.as_str()))
                    .unwrap_or("unknown");
                let text = m.get("text").and_then(|v| v.as_str()).unwrap_or("");
                println!("{ts} {user}: {text}");
            }
            Ok(())
        }
        Commands::Send(args) => {
            let token = ensure_token()?;
            let client = http();
            let mut form = vec![
                ("channel", args.channel.as_str()),
                ("text", args.text.as_str()),
            ];
            if let Some(ts) = args.thread_ts.as_ref() {
                form.push(("thread_ts", ts.as_str()));
            }
            let resp = slack_post(&client, "chat.postMessage", &token, Some(&form))?;
            let ok = resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            let ts = resp.get("ts").and_then(|v| v.as_str()).unwrap_or("-");
            if ok {
                println!("sent ok, ts={ts}");
                Ok(())
            } else {
                let err = resp
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown_error");
                Err(anyhow!("Slack error: {err}"))
            }
        }
    }
}

fn should_print_full_help() -> bool {
    // Detect a top-level help request: `slack --help` or `slack -h` without a subcommand.
    // Keep subcommand help (`slack <cmd> --help`) handled by clap as usual.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "--help" || a == "-h") {
        return false;
    }
    // Known subcommands (kept in sync with `Commands` names; all lowercase).
    let subs = [
        "init",
        "whoami",
        "join",
        "directmsgs",
        "direct-msgs",
        "directmpmsgs",
        "direct-mp-msgs",
        "findperson",
        "find-person",
        "open",
        "channels",
        "msgs",
        "send",
    ];
    let has_sub = args.iter().any(|a| subs.contains(&a.as_str()));
    !has_sub
}

fn print_full_help() {
    // Render combined help: top-level long help + each subcommand's long help and examples.
    let mut top = Cli::command();
    // Header
    let name = top.get_name().to_string();
    let ver = top.get_version().unwrap_or("");
    println!("{name} {ver}");
    println!();
    // Top-level long help
    let _ = top.print_long_help();
    println!();

    // Extra, concise examples section to aid discovery
    println!("\nEXAMPLES:");
    println!("  {name} init");
    println!("  {name} whoami");
    println!("  {name} channels --types public_channel,im --limit 20");
    println!("  {name} find-person --query Jane");
    println!("  {name} open --users U123,U456 --text \"Hello\"");
    println!("  {name} msgs --channel C12345678 --limit 5");
    println!("  {name} send --channel C12345678 --text \"Hi\"");
    println!("  {name} send --channel C12345678 --text \"Reply\" --thread-ts 1712345678.000100");

    // Detailed per-command help
    println!("\nCOMMAND DETAILS:");
    let mut subs = Cli::command();
    for sc in subs.get_subcommands_mut() {
        println!("\n== {} ==", sc.get_name());
        let _ = sc.print_long_help();
        println!();
    }
}

fn api_base() -> String {
    std::env::var("SLACK_API_BASE").unwrap_or_else(|_| API_BASE.to_string())
}

/// --- Init & credential helpers ---
fn init(args: InitArgs) -> Result<()> {
    if args.reset {
        let _ = delete_token();
    }
    if args.force || args.token.is_some() {
        let token = match args.token {
            Some(t) => t,
            None => prompt_for_token()?,
        };
        store_token(&token)?;
        let client = http();
        let info = auth_test(&client, &token)?;
        if info.ok {
            println!("Saved valid token for team {:?}.", info.team);
            return Ok(());
        } else {
            return Err(anyhow!(info.error.unwrap_or_else(|| "invalid_auth".into())));
        }
    }
    match ensure_token() {
        Ok(_) => {
            println!("Token is present and valid.");
            Ok(())
        }
        Err(_) => {
            // Prompt loop until we succeed or user aborts
            for _ in 0..3 {
                let token = prompt_for_token()?;
                store_token(&token)?;
                let client = http();
                match auth_test(&client, &token) {
                    Ok(info) if info.ok => {
                        println!("Saved valid token for team {:?}.", info.team);
                        return Ok(());
                    }
                    Ok(info) => eprintln!("Token didn't validate: {:?}", info.error),
                    Err(e) => eprintln!("Validation call failed: {e}"),
                }
            }
            Err(anyhow!("Could not obtain a working token."))
        }
    }
}

fn ensure_token() -> Result<String> {
    // Test-friendly: allow env override without keyring interaction
    if let Ok(t) = std::env::var("SLACK_TOKEN") {
        let tok = t.trim().to_string();
        if !tok.is_empty() {
            return Ok(tok);
        }
    }

    if let Some(tok) = read_token()? {
        let client = http();
        let info = auth_test(&client, &tok)?;
        if info.ok {
            return Ok(tok);
        }
    }
    let token = prompt_for_token()?;
    store_token(&token)?;
    let client = http();
    let info = auth_test(&client, &token)?;
    if info.ok {
        Ok(token)
    } else {
        Err(anyhow!(info.error.unwrap_or_else(|| "invalid_auth".into())))
    }
}

fn read_token() -> Result<Option<String>> {
    let entry = Entry::new(SERVICE, USERNAME)?;
    match entry.get_password() {
        Ok(s) if s.trim().is_empty() => Ok(None),
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow!("keyring read error: {e}")),
    }
}

fn store_token(token: &str) -> Result<()> {
    let entry = Entry::new(SERVICE, USERNAME)?;
    entry
        .set_password(token)
        .map_err(|e| anyhow!("keyring write error: {e}"))
}

fn delete_token() -> Result<()> {
    let entry = Entry::new(SERVICE, USERNAME)?;
    entry
        .set_password("")
        .map_err(|e| anyhow!("keyring delete/overwrite error: {e}"))
}

/// --- Slack HTTP helpers ---
fn http() -> Client {
    Client::builder()
        .user_agent("slackcli/0.1 (+https://example.local)")
        .build()
        .expect("client build")
}

fn auth_test(client: &Client, token: &str) -> Result<AuthTest> {
    let url = format!("{}/auth.test", api_base());
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .send()
        .context("auth.test http failed")?;
    let st = resp.status();
    let body = resp.text()?;
    if !st.is_success() {
        return Err(anyhow!("HTTP {st} from Slack: {body}"));
    }
    let at: AuthTest = serde_json::from_str(&body)?;
    Ok(at)
}

fn slack_post(
    client: &Client,
    method: &str,
    token: &str,
    form: Option<&[(&str, &str)]>,
) -> Result<Value> {
    let url = format!("{}/{}", api_base(), method);
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .form(form.unwrap_or(&[]))
        .send()
        .with_context(|| format!("{method} http failed"))?;
    let st = resp.status();
    let v: Value = resp.json().context("Slack JSON parse failed")?;
    if !st.is_success() {
        return Err(anyhow!("HTTP {st} error from Slack"));
    }
    if !v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
        let err = v
            .get("error")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown_error");
        return Err(anyhow!("Slack error: {err}"));
    }
    Ok(v)
}

use std::collections::HashMap;

type UserInfo = (String, Option<String>, Option<String>);

/// Fetch users.list and return a map from user_id to (display_name, real_name, email)
fn fetch_users_map(client: &Client, token: &str) -> Result<HashMap<String, UserInfo>> {
    let mut map: HashMap<String, UserInfo> = HashMap::new();
    let resp = slack_post(client, "users.list", token, Some(&[("limit", "200")]))?;
    let members = resp
        .get("members")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for m in members {
        if let Some(uid) = m.get("id").and_then(|v| v.as_str()) {
            let prof = m.get("profile").cloned().unwrap_or(Value::Null);
            let disp = prof
                .get("display_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .or_else(|| {
                    m.get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| uid.to_string());
            let real = prof
                .get("real_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let email = prof
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            map.insert(uid.to_string(), (disp, real, email));
        }
    }
    Ok(map)
}

/// Prompt user for a Slack user token and return it.
fn prompt_for_token() -> Result<String> {
    let token = Password::new()
        .with_prompt("Slack user token (xoxp-…)")
        .interact()
        .context("failed to read token from prompt")?;
    let token = token.trim().to_string();
    if token.is_empty() {
        Err(anyhow!("Token must not be empty"))
    } else {
        Ok(token)
    }
}
