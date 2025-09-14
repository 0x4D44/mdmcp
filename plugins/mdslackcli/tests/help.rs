use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn top_level_help_shows_aggregate_and_examples() {
    let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("COMMAND DETAILS:"))
        .stdout(predicate::str::contains("EXAMPLES:"))
        .stdout(predicate::str::contains("== send =="));
}

#[test]
fn send_help_is_scoped() {
    let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
    cmd.args(["send", "--help"]);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Post a message to a channel"))
        .stdout(predicate::str::contains("COMMAND DETAILS:").not());
}
