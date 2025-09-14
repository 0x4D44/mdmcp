use crate::config::Config;
use crate::errors::{AppError, ErrorKind};
use crate::opts::Query;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug)]
pub struct DryRunRequest {
    pub provider: String,
    pub model: String,
    pub messages: String,
    pub parameters: Parameters,
    pub file_hashes: Vec<String>,
    pub tools_present: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Parameters {
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stream: bool,
    pub format: String,
    pub timeout: Option<u64>,
}

pub fn build_request_from_query(
    cfg: &Config,
    q: &Query,
    stdin_available: bool,
) -> Result<DryRunRequest, AppError> {
    let provider = cfg.default.provider.clone();
    let model = q
        .model
        .clone()
        .or_else(|| cfg.default.models.get(&provider).cloned())
        .unwrap_or_else(|| "gpt-4".into());

    // We redact messages; validate presence
    if q.user.is_none() && q.messages_file.is_none() && !stdin_available {
        return Err(AppError::with_kind(
            ErrorKind::Validation,
            "Must provide --user or --messages-file",
        ));
    }
    // If messages file provided, validate JSON/YAML shape
    if let Some(path) = &q.messages_file {
        let _ = parse_messages_file_value(path)?;
    }
    if let Some(tools) = &q.tools_file {
        let _ = parse_tools_file(tools)?;
    }

    // Hash input files for cache key composition visibility
    let mut hashes = Vec::new();
    for f in &q.input_files {
        hashes.push(hash_file(f)?);
    }

    Ok(DryRunRequest {
        provider,
        model,
        messages: "[redacted]".into(),
        parameters: Parameters {
            temperature: q.temperature,
            max_tokens: q.max_tokens,
            top_p: q.top_p,
            stream: q.stream,
            format: q.format.clone(),
            timeout: q.timeout,
        },
        file_hashes: hashes,
        tools_present: q.tools_file.is_some(),
    })
}

fn hash_file(path: &str) -> Result<String, AppError> {
    let data = fs::read(Path::new(path))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    Ok(format!("sha256:{}", hex::encode(digest)))
}

fn parse_messages_file_value(path: &str) -> Result<serde_json::Value, AppError> {
    let s = fs::read_to_string(path)?;
    if path.ends_with(".yaml") || path.ends_with(".yml") {
        Ok(serde_yaml::from_str(&s)?)
    } else {
        Ok(serde_json::from_str(&s)?)
    }
}

fn parse_tools_file(path: &str) -> Result<serde_json::Value, AppError> {
    let s = fs::read_to_string(path)?;
    if path.ends_with(".yaml") || path.ends_with(".yml") {
        Ok(serde_yaml::from_str(&s)?)
    } else {
        Ok(serde_json::from_str(&s)?)
    }
}

pub fn normalized_messages(
    _cfg: &Config,
    q: &Query,
) -> Result<(serde_json::Value, Vec<String>), AppError> {
    // Build messages array representation and compute file hashes
    let mut file_hashes = Vec::new();
    for f in &q.input_files {
        file_hashes.push(hash_file(f)?);
    }

    if let Some(path) = &q.messages_file {
        let v = parse_messages_file_value(path)?;
        let msgs = v
            .get("messages")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        return Ok((msgs, file_hashes));
    }

    // Otherwise build from system/user and file injections
    let mut system = String::new();
    if let Some(s) = &q.system {
        system.push_str(s);
    }
    if !q.input_files.is_empty() {
        let mut buf = String::new();
        for f in &q.input_files {
            match std::fs::read_to_string(f) {
                Ok(content) => buf.push_str(&format!("\n\n[file:{}]\n{}\n[/file]\n", f, content)),
                Err(_) => {
                    return Err(AppError::with_kind(
                        ErrorKind::FileAccess,
                        format!("Failed to read input file: {}", f),
                    ))
                }
            }
        }
        if q.input_role == "system" {
            system.push_str(&buf);
        }
    }
    let mut messages: Vec<serde_json::Value> = Vec::new();
    if !system.is_empty() {
        messages.push(serde_json::json!({"role":"system","content":system}));
    }
    let mut user_msg = q.user.clone().unwrap_or_default();
    if q.input_role != "system" && !q.input_files.is_empty() {
        let mut buf = String::new();
        for f in &q.input_files {
            if let Ok(content) = std::fs::read_to_string(f) {
                buf.push_str(&format!("\n\n[file:{}]\n{}\n[/file]\n", f, content));
            }
        }
        user_msg.push_str(&buf);
    }
    messages.push(serde_json::json!({"role":"user","content":user_msg}));
    Ok((serde_json::Value::Array(messages), file_hashes))
}

pub fn normalized_tools(q: &Query) -> Result<Option<serde_json::Value>, AppError> {
    if let Some(path) = &q.tools_file {
        Ok(Some(parse_tools_file(path)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_messages_json_and_yaml() {
        let td = tempdir().unwrap();
        let jsonp = td.path().join("m.json");
        let yamlp = td.path().join("m.yaml");
        std::fs::write(&jsonp, r#"{"messages":[{"role":"user","content":"hi"}]}"#).unwrap();
        std::fs::write(&yamlp, "messages:\n  - role: user\n    content: hi\n").unwrap();
        assert!(parse_messages_file_value(jsonp.to_str().unwrap()).is_ok());
        assert!(parse_messages_file_value(yamlp.to_str().unwrap()).is_ok());
    }
}
