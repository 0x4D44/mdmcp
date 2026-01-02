pub mod anthropic;
pub mod ollama;
pub mod openai;
pub mod openrouter;

use crate::{
    config::Config,
    errors::{AppError, ErrorKind},
    opts::Query,
};

pub fn run_query(cfg: &Config, account: &str, q: &Query) -> Result<(), AppError> {
    let provider = cfg.default.provider.as_str();
    match provider {
        "openai" => openai::run_query(cfg, account, q),
        "anthropic" => anthropic::run_query(cfg, account, q),
        "openrouter" => openrouter::run_query(cfg, account, q),
        "ollama" => ollama::run_query(cfg, account, q),
        _ => Err(AppError::with_kind(
            ErrorKind::Validation,
            format!("Provider '{}' not implemented", provider),
        )),
    }
}

pub fn list_models(cfg: &Config, provider: &str, refresh: bool) -> Result<(), AppError> {
    match provider {
        "openai" => openai::list_models(cfg, refresh),
        "openrouter" => openrouter::list_models(cfg, refresh),
        "anthropic" => anthropic::list_models(cfg, refresh),
        "ollama" => ollama::list_models(cfg, refresh),
        other => Err(AppError::with_kind(
            ErrorKind::Validation,
            format!("Unknown provider: {}", other),
        )),
    }
}

pub fn openai_list_assistants(cfg: &Config, account: &str) -> Result<(), AppError> {
    openai::list_assistants(cfg, account)
}

pub fn openai_list_vector_stores(cfg: &Config, account: &str) -> Result<(), AppError> {
    openai::list_vector_stores(cfg, account)
}

pub fn openai_vector_store_create(
    cfg: &Config,
    account: &str,
    name: &str,
    files: &[String],
    expires_days: Option<u32>,
) -> Result<(), AppError> {
    openai::vector_store_create(cfg, account, name, files, expires_days)
}

pub fn openai_vector_store_upload(
    cfg: &Config,
    account: &str,
    store_id: &str,
    files: &[String],
) -> Result<(), AppError> {
    openai::vector_store_upload(cfg, account, store_id, files)
}

pub fn openai_vector_store_delete(
    cfg: &Config,
    account: &str,
    store_id: &str,
) -> Result<(), AppError> {
    openai::vector_store_delete(cfg, account, store_id)
}

// Ollama-specific operations
pub fn ollama_models_list(cfg: &Config, account: &str) -> Result<(), AppError> {
    ollama::models_list(cfg, account)
}

pub fn ollama_models_show(cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    ollama::models_show(cfg, account, name)
}

pub fn ollama_models_pull(cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    ollama::models_pull(cfg, account, name)
}

pub fn ollama_models_delete(cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    ollama::models_delete(cfg, account, name)
}

pub fn ollama_status(cfg: &Config, account: &str) -> Result<(), AppError> {
    ollama::status(cfg, account)
}
