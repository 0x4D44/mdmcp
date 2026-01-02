use mdaicli::{
    config::Config,
    opts::Query,
    providers::{ollama, openrouter},
};
use mockito::Server;
use serde_json::json;
use serial_test::serial;
use tempfile::tempdir;

#[test]
#[serial]
fn test_ollama_run_query_mock() {
    let mut server = Server::new();
    let url = server.url();

    let _m = server
        .mock("POST", "/api/chat")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "model": "llama2",
                "created_at": "2023-08-04T19:22:45.499127Z",
                "message": {
                    "role": "assistant",
                    "content": "Hello from Ollama"
                },
                "done": true,
                "total_duration": 12345678,
                "load_duration": 123456,
                "prompt_eval_count": 10,
                "eval_count": 5
            })
            .to_string(),
        )
        .create();

    let temp = tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());

    let creds_file = temp.path().join("credentials.json");
    let creds_content = json!({
        "providers": {
            "ollama": {
                "default": {
                    "base_url": url,
                    "storage": "env"
                }
            }
        }
    });
    std::fs::write(&creds_file, creds_content.to_string()).unwrap();

    let config = Config::default();
    let query = Query {
        model: Some("llama2".to_string()),
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

    let result = ollama::run_query(&config, "default", &query);
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    assert!(result.is_ok());
}

#[test]
#[serial]
fn test_openrouter_run_query_mock() {
    let mut server = Server::new();
    let url = server.url();

    let _m = server
        .mock("POST", "/chat/completions")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "id": "gen-123",
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "Hello from OpenRouter"
                    }
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5
                }
            })
            .to_string(),
        )
        .create();

    let temp = tempdir().unwrap();
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());
    std::env::set_var("MDAICLI_TEST_SECRET_OPENROUTER", "fake-key");

    let creds_file = temp.path().join("credentials.json");
    let creds_content = json!({
        "providers": {
            "openrouter": {
                "default": {
                    "base_url": url,
                    "storage": "env"
                }
            }
        }
    });
    std::fs::write(&creds_file, creds_content.to_string()).unwrap();

    let config = Config::default();
    let query = Query {
        model: Some("auto".to_string()),
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

    let result = openrouter::run_query(&config, "default", &query);
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    std::env::remove_var("MDAICLI_TEST_SECRET_OPENROUTER");
    assert!(result.is_ok());
}
