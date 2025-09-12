use crate::opts::Query;
use crate::rate_limit;
use crate::{
    audit,
    config::Config,
    errors::{AppError, ErrorKind},
    io, model,
};
use reqwest::blocking::Client;
use serde_json::json;
use std::time::Duration;

pub fn run_query(cfg: &Config, account: &str, q: &Query) -> Result<(), AppError> {
    let api_key = crate::credentials::retrieve_secret("anthropic", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for Anthropic; run: mdaicli store -p anthropic",
        )
    })?;

    let meta = io::get_cred_meta("anthropic", account);
    let base_url = meta
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://api.anthropic.com".into());
    let model = q
        .model
        .clone()
        .or_else(|| cfg.default.models.get("anthropic").cloned())
        .unwrap_or_else(|| "claude-3-opus-20240229".into());

    // Build normalized messages; extract system and user/assistant content
    let (messages, _file_hashes) = model::normalized_messages(cfg, q)?;
    let mut system_txt = String::new();
    let mut chat_msgs = vec![];
    if let Some(arr) = messages.as_array() {
        for m in arr {
            let role = m["role"].as_str().unwrap_or("");
            if role == "system" {
                if let Some(s) = m["content"].as_str() {
                    system_txt.push_str(s);
                    system_txt.push('\n');
                }
            } else if role == "user" || role == "assistant" {
                let content = m["content"].as_str().unwrap_or("").to_string();
                chat_msgs.push(json!({"role": role, "content": content}));
            }
        }
    }

    let mut body = json!({
        "model": model,
        "messages": chat_msgs,
    });
    if !system_txt.is_empty() {
        body["system"] = json!(system_txt);
    }
    if let Some(t) = q.temperature {
        body["temperature"] = json!(t);
    }
    if let Some(mt) = q.max_tokens {
        body["max_tokens"] = json!(mt);
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
    let url = format!("{}/v1/messages", base_url.trim_end_matches('/'));
    rate_limit::before_request(cfg, "anthropic", account);
    let req = client
        .post(url)
        .header("x-api-key", api_key.clone())
        .header("anthropic-version", "2023-06-01")
        .json(&body);

    let started = std::time::Instant::now();
    if q.stream {
        // Streaming via SSE
        let req = client
            .post(format!("{}/v1/messages", base_url.trim_end_matches('/')))
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("accept", "text/event-stream")
            .json(&{
                let mut b = body.clone();
                b["stream"] = json!(true);
                b
            });
        rate_limit::before_request(cfg, "anthropic", account);
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
                format!("Anthropic API error ({}): {}", status, text),
            ));
        }
        // Emit streaming events
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"start","model": model})).unwrap()
            );
        } else {
            println!("[Streaming from Anthropic {}...]", model);
        }
        let reader = std::io::BufReader::new(resp);
        use std::io::BufRead;
        let mut accum = String::new();
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.starts_with("event: ") {
                // ignore separate event line
                continue;
            }
            if !line.starts_with("data: ") {
                continue;
            }
            let data = &line[6..];
            if data.trim() == "[DONE]" {
                break;
            }
            if let Ok(evt) = serde_json::from_str::<serde_json::Value>(data) {
                let et = evt.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if et == "content_block_delta" {
                    if let Some(token) = evt
                        .get("delta")
                        .and_then(|d| d.get("text"))
                        .and_then(|v| v.as_str())
                    {
                        accum.push_str(token);
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
            format!("Anthropic API error ({}): {}", status, text),
        ));
    }
    let json: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    let latency = started.elapsed().as_millis() as u64;
    let content = json["content"][0]["text"].as_str().unwrap_or("");
    let mut usage = json.get("usage").cloned().unwrap_or_else(|| json!({}));
    if usage.is_object() {
        let pt = usage.get("input_tokens").and_then(|v| v.as_u64());
        let ct = usage.get("output_tokens").and_then(|v| v.as_u64());
        if let Some(cost) = crate::pricing::estimate_cost("anthropic", &model, pt, ct) {
            usage["estimated_cost"] = cost;
        }
    }

    let out = json!({
        "success": true,
        "request": {"provider":"anthropic","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
        "response": {"content": content, "role":"assistant", "tool_calls": []},
        "usage": usage,
        "metadata": {"request_id": serde_json::Value::Null, "latency_ms": latency, "cached": false, "cache_key": serde_json::Value::Null, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
        "warnings": []
    });
    let _ = audit::append(cfg, &out);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    Ok(())
}

pub fn list_models(_cfg: &Config, _refresh: bool) -> Result<(), AppError> {
    // Anthropic has no public models list endpoint; present a curated list
    println!("claude-3-opus-20240229\nclaude-3-sonnet-20240229\nclaude-3-haiku-20240307");
    Ok(())
}
