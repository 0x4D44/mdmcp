use mdaicli::config::Config;
use mdaicli::opts::Query;
use mdaicli::providers;
use mockito::Server;
use serial_test::serial;

fn base_cfg(tmp: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default();
    cfg.logging.directory = tmp.path().join("logs").to_string_lossy().to_string();
    cfg.cache.directory = tmp.path().join("cache").to_string_lossy().to_string();
    cfg.cache.enabled = false;
    cfg
}

#[test]
#[serial]
fn openai_streaming_json() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENAI", "test");
    let mut server = Server::new();
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
        "data: [DONE]\n\n",
    );
    let ep = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(body)
        .create();

    // point openai base_url
    let idx_path = td.path().join("credentials.json");
    let index = serde_json::json!({"providers":{"openai":{"default":{"base_url": server.url(),"org_id":null,"storage":null}}}});
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "openai".into();
    cfg.default.models.insert("openai".into(), "gpt-4".into());

    let q = Query {
        model: Some("gpt-4".into()),
        system: None,
        user: Some("hi".into()),
        messages_file: None,
        input_files: vec![],
        input_role: "user".into(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: true,
        format: "json".into(),
        timeout: Some(5),
        tools_file: None,
        output: None,
    };
    let res = providers::run_query(&cfg, "default", &q);
    ep.assert();
    assert!(res.is_ok());
}

#[test]
#[serial]
fn anthropic_streaming_json() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    std::env::set_var("MDAICLI_TEST_SECRET_ANTHROPIC", "test");
    let mut server = Server::new();
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hi\"}}\n\n",
        "data: [DONE]\n\n",
    );
    let ep = server
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(body)
        .create();

    let idx_path = td.path().join("credentials.json");
    let index = serde_json::json!({"providers":{"anthropic":{"default":{"base_url": server.url(),"org_id":null,"storage":null}}}});
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "anthropic".into();
    cfg.default
        .models
        .insert("anthropic".into(), "claude-3-opus-20240229".into());

    let q = Query {
        model: Some("claude-3-opus-20240229".into()),
        system: None,
        user: Some("hi".into()),
        messages_file: None,
        input_files: vec![],
        input_role: "user".into(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: true,
        format: "json".into(),
        timeout: Some(5),
        tools_file: None,
        output: None,
    };
    let res = providers::run_query(&cfg, "default", &q);
    ep.assert();
    assert!(res.is_ok());
}

#[test]
#[serial]
fn openrouter_streaming_json() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENROUTER", "test");
    let mut server = Server::new();
    let body = concat!(
        "data: {\"choices\":[{\"delta\":{\"content\":\"Yo\"}}]}\n\n",
        "data: [DONE]\n\n",
    );
    let ep = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(body)
        .create();

    let idx_path = td.path().join("credentials.json");
    let index = serde_json::json!({"providers":{"openrouter":{"default":{"base_url": server.url(),"org_id":null,"storage":null}}}});
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "openrouter".into();
    cfg.default
        .models
        .insert("openrouter".into(), "auto".into());

    let q = Query {
        model: Some("auto".into()),
        system: None,
        user: Some("hi".into()),
        messages_file: None,
        input_files: vec![],
        input_role: "user".into(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: true,
        format: "json".into(),
        timeout: Some(5),
        tools_file: None,
        output: None,
    };
    let res = providers::run_query(&cfg, "default", &q);
    ep.assert();
    assert!(res.is_ok());
}
