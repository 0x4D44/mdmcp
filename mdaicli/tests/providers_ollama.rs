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
fn ollama_streaming_ndjson() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    let mut server = Server::new();
    let body = concat!(
        "{\"model\":\"llama2\",\"message\":{\"role\":\"assistant\",\"content\":\"Hel\"},\"done\":false}\n",
        "{\"model\":\"llama2\",\"message\":{\"role\":\"assistant\",\"content\":\"lo\"},\"done\":false}\n",
        "{\"done\":true,\"prompt_eval_count\":3,\"eval_count\":2}\n",
    );
    let ep = server
        .mock("POST", "/api/chat")
        .with_status(200)
        .with_header("content-type", "application/x-ndjson")
        .with_body(body)
        .create();

    // index pointing ollama base_url
    let idx_path = td.path().join("credentials.json");
    let index = serde_json::json!({
        "providers": {"ollama": {"default": {"base_url": server.url(), "org_id": null, "storage": null}}}
    });
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let mut cfg = base_cfg(&td);
    cfg.default.provider = "ollama".into();
    cfg.default.models.insert("ollama".into(), "llama2".into());

    let q = Query {
        model: Some("llama2".into()),
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
fn ollama_models_list() {
    let td = tempfile::tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", td.path().to_str().unwrap());
    let mut server = Server::new();
    let ep = server
        .mock("GET", "/api/tags")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"models":[{"name":"llama2"},{"name":"mistral"}]}"#)
        .create();

    let idx_path = td.path().join("credentials.json");
    let index = serde_json::json!({
        "providers": {"ollama": {"default": {"base_url": server.url(), "org_id": null, "storage": null}}}
    });
    std::fs::write(&idx_path, serde_json::to_string_pretty(&index).unwrap()).unwrap();

    let cfg = base_cfg(&td);
    let res = providers::ollama_models_list(&cfg, "default");
    ep.assert();
    assert!(res.is_ok());
}
