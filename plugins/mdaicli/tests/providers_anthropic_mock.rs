use mdaicli::{config::Config, opts::Query, providers::anthropic};
use mockito::Server;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn test_anthropic_run_query_mock() {
    let mut server = Server::new();
    let url = server.url();

    let _m = server
        .mock("POST", "/v1/messages")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "id": "msg_123",
                "type": "message",
                "role": "assistant",
                "content": [{
                    "type": "text",
                    "text": "Hello from Claude"
                }],
                "model": "claude-3-opus-20240229",
                "stop_reason": "end_turn",
                "stop_sequence": null,
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5
                }
            })
            .to_string(),
        )
        .create();

    // Mock config with creds
    let temp = tempdir().unwrap();

    // Set up environment overrides
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());
    std::env::set_var("MDAICLI_TEST_SECRET_ANTHROPIC", "fake-key");

    // Create credentials.json with the mock base URL
    let creds_file = temp.path().join("credentials.json");
    let creds_content = json!({
        "providers": {
            "anthropic": {
                "default": {
                    "base_url": url,
                    "storage": "env"
                }
            }
        }
    });
    std::fs::write(&creds_file, creds_content.to_string()).unwrap();

    // Create a minimal config
    let config = Config::default();

    // Run the query
    let query = Query {
        model: Some("claude-3-opus".to_string()),
        user: Some("Hi".to_string()),
        system: None,
        messages_file: None,
        input_files: vec![],
        input_role: "user".to_string(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: false,
        format: "json".to_string(),
        timeout: None,
        tools_file: None,
        output: None,
    };

    let result = anthropic::run_query(&config, "default", &query);

    // Clean up
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    std::env::remove_var("MDAICLI_TEST_SECRET_ANTHROPIC");

    assert!(result.is_ok());
}
