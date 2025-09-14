use assert_cmd::prelude::*;
use httpmock::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn channels_lists_public_and_im() {
    let server = MockServer::start();

    // auth.test
    let _m_auth = server.mock(|when, then| {
        when.method(POST).path("/api/auth.test");
        then.status(200)
            .json_body(serde_json::json!({ "ok": true }));
    });

    // conversations.list
    let _m_list = server.mock(|when, then| {
        when.method(POST).path("/api/conversations.list");
        then.status(200).json_body(serde_json::json!({
            "ok": true,
            "channels": [
                { "id": "C1", "name": "general", "is_private": false },
                { "id": "D1", "is_im": true }
            ]
        }));
    });

    let api_base = format!("{}/api", server.base_url());

    let mut cmd = Command::cargo_bin("mdslackcli").unwrap();
    cmd.env("SLACK_TOKEN", "xoxp-test")
        .env("SLACK_API_BASE", &api_base)
        .args(["channels", "--types", "public_channel,im", "--limit", "10"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("C1\t#general"))
        .stdout(predicate::str::contains("(public_channel)"))
        .stdout(predicate::str::contains("D1\t#(dm or unnamed)\t(im)"));
}
