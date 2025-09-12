use crate::opts::Query;
use crate::rate_limit;
use crate::{
    audit, cache,
    config::Config,
    errors::{AppError, ErrorKind},
    io, model,
};
use reqwest::blocking::Client;
use serde_json::json;
use std::time::Duration;

pub fn run_query(cfg: &Config, account: &str, q: &Query) -> Result<(), AppError> {
    let api_key = crate::credentials::retrieve_secret("openrouter", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for OpenRouter; run: mdaicli store -p openrouter",
        )
    })?;

    let base_url = io::get_cred_meta("openrouter", account)
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://openrouter.ai/api/v1".to_string());
    let model = q
        .model
        .clone()
        .or_else(|| cfg.default.models.get("openrouter").cloned())
        .unwrap_or_else(|| "auto".into());

    let (messages, file_hashes) = model::normalized_messages(cfg, q)?;
    let tools = model::normalized_tools(q)?;

    let mut body = json!({
        "model": model,
        "messages": messages,
    });
    if let Some(t) = q.temperature {
        body["temperature"] = json!(t);
    }
    if let Some(mt) = q.max_tokens {
        body["max_tokens"] = json!(mt);
    }
    if let Some(tp) = q.top_p {
        body["top_p"] = json!(tp);
    }
    if let Some(t) = &tools {
        body["tools"] = t.clone();
        body["tool_choice"] = json!("auto");
    }

    let timeout = q.timeout.unwrap_or(120);
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if q.stream {
        let mut body_stream = body.clone();
        body_stream["stream"] = json!(true);
        let url2 = format!("{}/chat/completions", base_url);
        rate_limit::before_request(cfg, "openrouter", account);
        let resp = client
            .post(url2)
            .bearer_auth(&api_key)
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
                if status == 429 {
                    ErrorKind::RateLimit
                } else {
                    ErrorKind::Provider
                },
                format!("OpenRouter API error ({}): {}", status, text),
            ));
        }
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"start","model": model})).unwrap()
            );
        } else {
            println!("[Streaming from OpenRouter {}...]", model);
        }
        let reader = std::io::BufReader::new(resp);
        use std::io::BufRead;
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if !line.starts_with("data: ") {
                continue;
            }
            let data = &line[6..];
            if data.trim() == "[DONE]" {
                break;
            }
            if let Ok(chunk) = serde_json::from_str::<serde_json::Value>(data) {
                let delta = &chunk["choices"][0]["delta"]; // chat
                if let Some(token) = delta["content"].as_str() {
                    if q.format == "json" {
                        println!(
                            "{}",
                            serde_json::to_string(&json!({"event":"delta","content": token}))
                                .unwrap()
                        );
                    } else {
                        print!("{}", token);
                        let _ = std::io::Write::flush(&mut std::io::stdout());
                    }
                }
            }
        }
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"end","finish_reason":"stop"})).unwrap()
            );
        } else {
            println!("\n---\n(streaming complete)");
        }
        return Ok(());
    }
    let url = format!("{}/chat/completions", base_url);
    rate_limit::before_request(cfg, "openrouter", account);
    let req = client.post(url).bearer_auth(api_key).json(&body);

    if cfg.cache.enabled && !q.stream {
        let key = cache::compute_cache_key(
            "openrouter",
            &model,
            &messages,
            &tools,
            q.temperature,
            q.max_tokens,
            &file_hashes,
        );
        if let Some(j) = cache::try_get(cfg, "openrouter", &key) {
            println!("{}", serde_json::to_string_pretty(&j).unwrap_or_default());
            return Ok(());
        }
        let resp = req.send().map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(AppError::with_kind(
                if status == 429 {
                    ErrorKind::RateLimit
                } else {
                    ErrorKind::Provider
                },
                format!("OpenRouter API error ({}): {}", status, text),
            ));
        }
        let json: serde_json::Value = resp.json().map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("");
        let usage = json.get("usage").cloned().unwrap_or_else(|| json!({}));
        let out = json!({
            "success": true,
            "request": {"provider":"openrouter","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
            "response": {"content": content, "role":"assistant", "tool_calls": []},
            "usage": usage,
            "metadata": {"request_id": serde_json::Value::Null, "latency_ms": serde_json::Value::Null, "cached": false, "cache_key": key, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
            "warnings": []
        });
        let _ = cache::save(cfg, "openrouter", &key, &out);
        let _ = audit::append(cfg, &out);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    rate_limit::before_request(cfg, "openrouter", account);
    let resp = req.send().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        return Err(AppError::with_kind(
            if status == 429 {
                ErrorKind::RateLimit
            } else {
                ErrorKind::Provider
            },
            format!("OpenRouter API error ({}): {}", status, text),
        ));
    }
    let json: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    let usage = json.get("usage").cloned().unwrap_or_else(|| json!({}));
    // OpenRouter pricing varies by upstream; skip estimation unless usage is present with model mapping (not implemented)
    let out = json!({
        "success": true,
        "request": {"provider":"openrouter","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
        "response": {"content": content, "role":"assistant", "tool_calls": []},
        "usage": usage,
        "metadata": {"request_id": serde_json::Value::Null, "latency_ms": serde_json::Value::Null, "cached": false, "cache_key": serde_json::Value::Null, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
        "warnings": []
    });
    let _ = audit::append(cfg, &out);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    Ok(())
}

pub fn list_models(_cfg: &Config, refresh: bool) -> Result<(), AppError> {
    // If refresh, query remote; otherwise a minimal list
    if refresh {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| AppError {
                kind: ErrorKind::Network,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        let resp = client
            .get("https://openrouter.ai/api/v1/models")
            .send()
            .map_err(|e| AppError {
                kind: ErrorKind::Network,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        if !resp.status().is_success() {
            println!("Failed to refresh model list (status {})", resp.status());
        } else {
            let j: serde_json::Value = resp.json().map_err(|e| AppError {
                kind: ErrorKind::Network,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
            if let Some(arr) = j.get("data").and_then(|v| v.as_array()) {
                for m in arr {
                    if let Some(id) = m.get("id").and_then(|v| v.as_str()) {
                        println!("{}", id);
                    }
                }
                return Ok(());
            }
        }
    }
    println!("auto\ngpt-4\ngpt-4o\nclaude-3-opus-20240229");
    Ok(())
}
