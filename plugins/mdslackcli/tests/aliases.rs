use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn aliases_for_find_person() {
    for sub in ["findperson", "find-person"] {
        let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
        cmd.args([sub, "--help"]);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("Search for users"));
    }
}

#[test]
fn aliases_for_direct_msgs() {
    for sub in ["directmsgs", "direct-msgs"] {
        let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
        cmd.args([sub, "--help"]);
        cmd.assert().success().stdout(predicate::str::contains(
            "direct message (IM) conversations",
        ));
    }
}

#[test]
fn aliases_for_direct_mp_msgs() {
    for sub in ["directmpmsgs", "direct-mp-msgs"] {
        let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
        cmd.args([sub, "--help"]);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains("multi-person direct message"));
    }
}
