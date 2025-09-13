use mdaicli::config::Config;
use mockito::Server;
use serial_test::serial;

fn base_cfg(tmp: &tempfile::TempDir) -> Config {
    let mut cfg = Config::default();
    cfg.logging.directory = tmp.path().join("logs").to_string_lossy().to_string();
    cfg.cache.directory = tmp.path().join("cache").to_string_lossy().to_string();
    cfg.cache.enabled = false;
    cfg.limits.insert(
        "openai".into(),
        mdaicli::config::LimitsConfig {
            requests_per_minute: 10,
            tokens_per_minute: 100000,
            max_retries: Some(0),
            backoff_base_ms: Some(1),
            backoff_max_ms: Some(2),
        },
    );
    cfg
}

#[test]
#[serial]
fn openai_nonstream_success() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENAI", "test-key");
    let mut server = Server::new();
    let ep = server.mock("POST", "/chat/completions")
        .match_header("authorization", mockito::Matcher::Regex("Bearer ".into()))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#)
        .create();

    // Write credentials index pointing to mock base_url
    let cred_dir = td.path();
    std::fs::create_dir_all(cred_dir).unwrap();
    let idx_path = cred_dir.join("credentials.json");
    let base_url = server.url();
    let index = serde_json::json!({"providers": {"openai": {"default": {"base_url": base_url, "org_id": null, "storage": null}}}});
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "openai".into();
    cfg.default.models.insert("openai".into(), "gpt-4".into());

    // Build query
    let q = mdaicli::opts::Query {
        model: Some("gpt-4".into()),
        system: None,
        user: Some("hi".into()),
        messages_file: None,
        input_files: vec![],
        input_role: "user".into(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: false,
        format: "json".into(),
        timeout: Some(10),
        tools_file: None,
        output: None,
    };

    let res = mdaicli::providers::run_query(&cfg, "default", &q);
    ep.assert();
    assert!(res.is_ok());
}

#[test]
#[serial]
fn openai_429_rate_limit_error() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENAI", "test-key");
    let mut server = Server::new();
    let ep = server
        .mock("POST", "/chat/completions")
        .with_status(429)
        .with_header("content-type", "application/json")
        .with_body("{}")
        .create();

    let idx_path = td.path().join("credentials.json");
    let base_url = server.url();
    let index = serde_json::json!({"providers": {"openai": {"default": {"base_url": base_url, "org_id": null, "storage": null}}}});
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "openai".into();
    cfg.default.models.insert("openai".into(), "gpt-4".into());
    // Limit retries to 0 for fast test
    if let Some(l) = cfg.limits.get_mut("openai") {
        l.max_retries = Some(0);
    }

    let q = mdaicli::opts::Query {
        model: Some("gpt-4".into()),
        system: None,
        user: Some("hi".into()),
        messages_file: None,
        input_files: vec![],
        input_role: "user".into(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: false,
        format: "json".into(),
        timeout: Some(5),
        tools_file: None,
        output: None,
    };

    let res = mdaicli::providers::run_query(&cfg, "default", &q);
    ep.assert();
    assert!(res.is_err());
    let err = res.err().unwrap();
    assert!(matches!(
        err.kind,
        mdaicli::errors::ErrorKind::RateLimit | mdaicli::errors::ErrorKind::Provider
    ));
}
