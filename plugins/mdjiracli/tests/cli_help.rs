use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn help_shows_examples_and_commands_works() {
    let mut cmd = Command::cargo_bin("mdjiracli").expect("bin");
    let assert = cmd.env("NO_COLOR", "1").arg("--help").assert();
    assert.success().stdout(
        predicate::str::contains("EXAMPLES")
            .and(predicate::str::contains("Commands:"))
            .and(predicate::str::contains("Options:"))
            .and(predicate::str::contains("agile-boards"))
            .and(predicate::str::contains("agile-board-issues"))
            .and(predicate::str::contains("agile-issue-get"))
            .and(predicate::str::contains("auth-show"))
            .and(predicate::str::contains("auth-reset")),
    );
}

#[test]
fn version_smoke_works() {
    let mut cmd = Command::cargo_bin("mdjiracli").expect("bin");
    let out = cmd.arg("--version").output().expect("run");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).expect("utf8");
    // Expect format like: "jira 0.2.2"
    assert!(s.trim().starts_with("jira "));
}

#[test]
fn help_examples_snapshot() {
    let mut cmd = Command::cargo_bin("mdjiracli").expect("bin");
    let out = cmd
        .env("NO_COLOR", "1")
        .arg("--help")
        .output()
        .expect("run");
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).expect("utf8");
    // Pull out the examples block as printed in help (we expect it to match the file contents)
    let idx = s.find("EXAMPLES").expect("has EXAMPLES section");
    let examples_help = &s[idx..];

    // Snapshot the canonical examples text (as kept in the repo)
    let examples_file = include_str!("../src/help_examples.txt");

    // Sanity: check a few representative lines from the examples appear in --help
    for needle in [
        "Setup credentials and verify access:",
        "jira agile-boards --limit 5 --pretty",
        "Notes",
    ] {
        assert!(
            examples_help.contains(needle),
            "--help output should contain: {needle}\n\nGot:\n{examples_help}"
        );
    }

    // Also snapshot the examples file to detect unintentional edits
    insta::assert_snapshot!(
        examples_file,
        @r###"EXAMPLES

Setup credentials and verify access:
  jira init
    • Prompts for base URL (e.g., https://acme.atlassian.net), username (email), and API token
    • Saves to OS keyring (service: jira-cli; keys: base_url, username, token)
    • Verifies access via Agile API (/rest/agile/1.0/board?maxResults=1)

Quick auth check and identity:
  jira whoami
    • Triggers the same Agile API verification
    • Prints: "Auth OK (Agile) for <username> @ <base_url>"

Show stored credentials (token masked) or reset them:
  jira auth-show
  jira auth-reset

List Agile boards (simplified fields):
  jira agile-boards --limit 10

List issues on a board:
  jira agile-board-issues --board 123 --limit 20
  jira agile-board-issues --board 123 --fields summary,assignee,status,updated
  jira agile-board-issues --board 123 --jql "assignee = currentUser() ORDER BY updated DESC"

Get a single issue via Agile API:
  jira agile-issue-get ABC-123
  jira agile-issue-get ABC-123 --fields summary,description,status,assignee

JSON output controls (apply to all commands):
  --pretty             Pretty-print JSON
  --max-len <N>        Truncate strings longer than N (default: 512)
  --max-items <N>      Truncate arrays beyond N items (default: 50)

Examples with JSON flags:
  jira agile-boards --limit 5 --pretty
  jira agile-board-issues --board 123 --fields summary,updated --max-len 200 --max-items 10

Notes
  - Base URL must be your Jira Cloud site (e.g., https://acme.atlassian.net). The CLI normalizes URLs
    if you include /rest/api/* segments.
  - The Agile API is used to validate credentials for a consistent, read-only experience.
  - Credentials are only stored in the OS keyring and are never logged. Use `auth-reset` to clear them.

"###
    );
}
