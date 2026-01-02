use mdaicli::{config::Config, credentials};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_config_load_and_profile() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.toml");

    let content = r#"
[default]
provider = "openai"
format = "json"

[profiles.anthropic-opus]
provider = "anthropic"
model = "claude-3-opus"
temperature = 0.7

[cache]
enabled = true
ttl_seconds = 3600
max_size_mb = 500
directory = "~/.cache/mdaicli"

[limits]

[logging]
level = "info"
directory = "~/.local/share/mdaicli/logs"
max_files = 10
max_size_mb = 50
redact_sensitive = true
"#;
    fs::write(&config_path, content).unwrap();

    // Load default
    let cfg = Config::load(Some(config_path.to_str().unwrap()), None).unwrap();
    assert_eq!(cfg.default.provider, "openai");

    // Load with profile
    let cfg_prof =
        Config::load(Some(config_path.to_str().unwrap()), Some("anthropic-opus")).unwrap();
    assert_eq!(cfg_prof.default.provider, "anthropic");
    assert_eq!(
        cfg_prof.default.models.get("anthropic").unwrap(),
        "claude-3-opus"
    );
}

#[test]
fn test_credential_fallback_storage() {
    let temp = tempdir().unwrap();
    // Redirect config dir for credential file
    std::env::set_var("MDAICLI_CONFIG_DIR", temp.path());
    // Mock passphrase
    std::env::set_var("MDAICLI_TEST_PASSPHRASE", "test-pass");

    // Store
    credentials::store_fallback("test-provider", "default", "my-secret-key").unwrap();

    // Retrieve
    let secret = credentials::get_fallback("test-provider", "default").unwrap();
    assert_eq!(secret, "my-secret-key");

    // Cleanup
    std::env::remove_var("MDAICLI_CONFIG_DIR");
    std::env::remove_var("MDAICLI_TEST_PASSPHRASE");
}
