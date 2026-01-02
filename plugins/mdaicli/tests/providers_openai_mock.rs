use mdaicli::{config::Config, opts::Query, providers::openai};
use mockito::{Matcher, Server};
use serde_json::json;
use serial_test::serial;
use tempfile::tempdir;

#[test]
#[serial]
fn test_openai_run_query_mock() {
    let mut server = Server::new();
    let url = server.url();

    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "id": "chatcmpl-123",
                "object": "chat.completion",
                "created": 1677652288,
                "model": "gpt-4",
                "usage": {
                    "prompt_tokens": 9,
                    "completion_tokens": 12,
                    "total_tokens": 21
                },
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Hello there!"
                    },
                    "finish_reason": "stop",
                    "index": 0
                }]
            })
            .to_string(),
        )
        .create();

    // Mock config with creds
    let temp = tempdir().unwrap();

    // Set up environment overrides
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENAI", "fake-key");

    // Create credentials.json with the mock base URL
    let creds_file = temp.path().join("credentials.json");
    let creds_content = json!({
        "providers": {
            "openai": {
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
        model: Some("gpt-4".to_string()),
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

    let result = openai::run_query(&config, "default", &query);

    // Clean up
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    std::env::remove_var("MDAICLI_TEST_SECRET_OPENAI");

    if let Err(e) = &result {
        println!("Error: {:?}", e);
    }
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_openai_run_query_stream_mock() {
    let mut server = Server::new();
    let url = server.url();

    // Use Matcher::Any for path to be safe, though /chat/completions is expected
    let _m = server.mock("POST", Matcher::Any)
        .with_status(200)
        .with_header("content-type", "text/event-stream")
        .with_body(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\ndata: [DONE]\n\n"
        )
        .create();

    // Mock config with creds
    let temp = tempdir().unwrap();

    // Set up environment overrides
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENAI", "fake-key");

    // Create credentials.json with the mock base URL
    let creds_file = temp.path().join("credentials.json");
    let creds_content = json!({
        "providers": {
            "openai": {
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

    // Run the query with stream=true
    let query = Query {
        model: Some("gpt-4".to_string()),
        user: Some("Hi".to_string()),
        system: None,
        messages_file: None,
        input_files: vec![],
        input_role: "user".to_string(),
        temperature: None,
        top_p: None,
        max_tokens: None,
        stream: true, // Enable streaming
        format: "text".to_string(),
        timeout: None,
        tools_file: None,
        output: None,
    };

    let result = openai::run_query(&config, "default", &query);

    // Clean up
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    std::env::remove_var("MDAICLI_TEST_SECRET_OPENAI");

    if let Err(e) = &result {
        println!("Error: {:?}", e);
    }
    assert!(result.is_ok());
}
