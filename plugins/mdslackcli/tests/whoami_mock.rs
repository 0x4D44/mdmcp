use assert_cmd::prelude::*;
use httpmock::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn whoami_uses_api_base_and_token_from_env() {
    let server = MockServer::start();

    // Stub auth.test
    let _m = server.mock(|when, then| {
        when.method(POST).path("/api/auth.test");
        then.status(200).json_body(serde_json::json!({
            "ok": true,
            "team": "Acme Co",
            "team_id": "T123",
            "user_id": "U234",
            "bot_id": null
        }));
    });

    let api_base = format!("{}/api", server.base_url());

    let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
    cmd.env("SLACK_TOKEN", "xoxp-test")
        .env("SLACK_API_BASE", &api_base)
        .arg("whoami");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("ok: true"))
        .stdout(predicate::str::contains("team: Some(\"Acme Co\")"))
        .stdout(predicate::str::contains("team_id: Some(\"T123\")"))
        .stdout(predicate::str::contains("user_id: Some(\"U234\")"));
}
