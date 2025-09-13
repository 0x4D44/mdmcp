use crate::opts::Query;
use crate::{
    audit, cache,
    config::Config,
    errors::{AppError, ErrorKind},
    io, model, rate_limit,
};
use reqwest::blocking::Client;
use serde_json::json;
use std::io::BufRead;
use std::time::Duration;

fn resolve_base_url(account: &str) -> String {
    io::get_cred_meta("ollama", account)
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "http://localhost:11434".to_string())
}

fn resolve_model(cfg: &Config, q: &Query) -> String {
    q.model
        .clone()
        .or_else(|| cfg.default.models.get("ollama").cloned())
        .unwrap_or_else(|| "llama2".into())
}

pub fn run_query(cfg: &Config, account: &str, q: &Query) -> Result<(), AppError> {
    let base_url = resolve_base_url(account);
    let model = resolve_model(cfg, q);

    // Build normalized messages (reuse chat-style schema)
    let (messages, file_hashes) = model::normalized_messages(cfg, q)?;

    // Prepare body for native /api/chat
    let mut body = json!({
        "model": model,
        "messages": messages,
    });
    // Map parameters into Ollama options
    let mut options = serde_json::Map::new();
    if let Some(t) = q.temperature {
        options.insert("temperature".into(), json!(t));
    }
    if let Some(tp) = q.top_p {
        options.insert("top_p".into(), json!(tp));
    }
    if let Some(mt) = q.max_tokens {
        // Ollama uses num_predict for max tokens
        options.insert("num_predict".into(), json!(mt));
    }
    if !options.is_empty() {
        body["options"] = json!(options);
    }

    let timeout = q.timeout.unwrap_or(180);
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;

    let url = format!("{}/api/chat", base_url.trim_end_matches('/'));

    // If non-stream and cache enabled, try cache first
    if cfg.cache.enabled && !q.stream {
        let tools = model::normalized_tools(q)?;
        let key = cache::compute_cache_key(
            "ollama",
            &model,
            &messages,
            &tools,
            q.temperature,
            q.max_tokens,
            &file_hashes,
        );
        if let Some(j) = cache::try_get(cfg, "ollama", &key) {
            println!("{}", serde_json::to_string_pretty(&j).unwrap_or_default());
            return Ok(());
        }
        // Miss: perform request and save
        rate_limit::before_request(cfg, "ollama", account);
        let mut body_nostream = body.clone();
        body_nostream["stream"] = json!(false);
        let resp = client
            .post(&url)
            .json(&body_nostream)
            .send()
            .map_err(|e| AppError {
                kind: ErrorKind::Provider,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(AppError::with_kind(
                ErrorKind::Provider,
                format!("Ollama API error ({}): {}", status, text),
            ));
        }
        let j: serde_json::Value = resp.json().map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        let content = j
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Usage counts if present
        let mut usage = json!({});
        if let Some(pt) = j.get("prompt_eval_count").and_then(|v| v.as_u64()) {
            usage["prompt_tokens"] = json!(pt);
        }
        if let Some(ct) = j.get("eval_count").and_then(|v| v.as_u64()) {
            usage["completion_tokens"] = json!(ct);
        }
        usage["estimated_cost"] = json!(0.0);
        let out = json!({
            "success": true,
            "request": {"provider":"ollama","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
            "response": {"content": content, "role":"assistant", "tool_calls": []},
            "usage": usage,
            "metadata": {"endpoint": base_url, "cached": false, "cache_key": key, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
            "warnings": []
        });
        let _ = cache::save(cfg, "ollama", &key, &out);
        let _ = audit::append(cfg, &out);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    // Streaming path or non-cached path
    if q.stream {
        let mut body_stream = body.clone();
        body_stream["stream"] = json!(true);
        rate_limit::before_request(cfg, "ollama", account);
        let resp = client
            .post(&url)
            .json(&body_stream)
            .send()
            .map_err(|e| AppError {
                kind: ErrorKind::Provider,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(AppError::with_kind(
                ErrorKind::Provider,
                format!("Ollama API error ({}): {}", status, text),
            ));
        }
        if q.format == "json" {
            println!("{}", serde_json::to_string(&json!({"event":"start","model": model})).unwrap());
        } else {
            println!("[Streaming from Ollama {}...]", model);
        }
        let mut accum = String::new();
        let reader = std::io::BufReader::new(resp);
        for line in reader.lines() {
            let line = match line { Ok(l) => l, Err(_) => break };
            if line.trim().is_empty() { continue; }
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&line) {
                if obj.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
                    break;
                }
                if let Some(tok) = obj
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|v| v.as_str())
                {
                    accum.push_str(tok);
                    if q.format == "json" {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({"event":"delta","content": tok}))
                                .unwrap()
                        );
                    } else {
                        print!("{}", tok);
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
            }
        }
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"end","finish_reason":"stop"}))
                    .unwrap()
            );
        } else {
            println!("\n---\n(streaming complete)");
        }
        // Do not save streamed output to cache (consistent with other providers behavior only when cache enabled; here skip)
        return Ok(());
    }

    // Non-stream, cache disabled: simple request
    rate_limit::before_request(cfg, "ollama", account);
    let mut body_nostream = body.clone();
    body_nostream["stream"] = json!(false);
    let resp = client
        .post(&url)
        .json(&body_nostream)
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama API error ({}): {}", status, text),
        ));
    }
    let j: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    let content = j
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut usage = json!({});
    if let Some(pt) = j.get("prompt_eval_count").and_then(|v| v.as_u64()) {
        usage["prompt_tokens"] = json!(pt);
    }
    if let Some(ct) = j.get("eval_count").and_then(|v| v.as_u64()) {
        usage["completion_tokens"] = json!(ct);
    }
    usage["estimated_cost"] = json!(0.0);
    let out = json!({
        "success": true,
        "request": {"provider":"ollama","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
        "response": {"content": content, "role":"assistant", "tool_calls": []},
        "usage": usage,
        "metadata": {"endpoint": base_url, "cached": false, "cache_key": serde_json::Value::Null, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
        "warnings": []
    });
    let _ = audit::append(cfg, &out);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    Ok(())
}

pub fn list_models(_cfg: &Config, _refresh: bool) -> Result<(), AppError> {
    // Generic list via local default; use the models list API is exposed via subcommand
    println!("llama2\nllama2:7b\nllama3\nphi3\nmistral");
    Ok(())
}

fn base_and_client(account: &str, timeout: u64) -> Result<(String, Client), AppError> {
    let base_url = resolve_base_url(account);
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    Ok((base_url, client))
}

pub fn models_list(cfg: &Config, account: &str) -> Result<(), AppError> {
    let (base, client) = base_and_client(account, 15)?;
    let url = format!("{}/api/tags", base.trim_end_matches('/'));
    let resp = client.get(url).send().map_err(|e| AppError {
        kind: ErrorKind::Network,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama error: {}", resp.status()),
        ));
    }
    let j: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if let Some(arr) = j.get("models").and_then(|v| v.as_array()) {
        for m in arr {
            if let Some(name) = m.get("name").and_then(|v| v.as_str()) {
                println!("{}", name);
            }
        }
    } else {
        println!("No models found");
    }
    let _ = cfg; // silence unused warning if cfg not used later
    Ok(())
}

pub fn models_show(_cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    let (base, client) = base_and_client(account, 15)?;
    let url = format!("{}/api/show", base.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&json!({"name": name}))
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama error: {}", resp.status()),
        ));
    }
    let txt = resp.text().unwrap_or_default();
    println!("{}", txt);
    Ok(())
}

pub fn models_pull(_cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    let (base, client) = base_and_client(account, 600)?;
    let url = format!("{}/api/pull", base.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&json!({"name": name, "stream": true}))
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama error: {}", resp.status()),
        ));
    }
    let reader = std::io::BufReader::new(resp);
    for line in reader.lines() {
        if let Ok(l) = line {
            if l.trim().is_empty() {
                continue;
            }
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&l) {
                if let Some(status) = j.get("status").and_then(|v| v.as_str()) {
                    println!("{}", status);
                }
                if j.get("done").and_then(|v| v.as_bool()).unwrap_or(false) {
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn models_delete(_cfg: &Config, account: &str, name: &str) -> Result<(), AppError> {
    let (base, client) = base_and_client(account, 30)?;
    let url = format!("{}/api/delete", base.trim_end_matches('/'));
    let resp = client
        .post(url)
        .json(&json!({"name": name}))
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama error: {}", resp.status()),
        ));
    }
    println!("Deleted {}", name);
    Ok(())
}

pub fn status(_cfg: &Config, account: &str) -> Result<(), AppError> {
    let (base, client) = base_and_client(account, 5)?;
    let url = format!("{}/api/version", base.trim_end_matches('/'));
    let resp = client.get(url).send().map_err(|e| AppError {
        kind: ErrorKind::Network,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("Ollama error: {}", resp.status()),
        ));
    }
    println!("{}", resp.text().unwrap_or_default());
    Ok(())
}

