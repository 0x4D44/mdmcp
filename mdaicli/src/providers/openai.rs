use crate::opts::Query;
use crate::{
    audit, cache,
    config::Config,
    errors::{AppError, ErrorKind},
    io, model, rate_limit,
};
use reqwest::blocking::multipart;
use reqwest::blocking::Client;
use serde_json::json;
use std::time::Duration;

pub fn run_query(cfg: &Config, account: &str, q: &Query) -> Result<(), AppError> {
    // Resolve API key
    let api_key = crate::credentials::retrieve_secret("openai", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for OpenAI; run: mdaicli store -p openai",
        )
    })?;

    let meta = io::get_cred_meta("openai", account);
    let base_url = meta
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://api.openai.com/v1".into());
    let org_id = io::get_cred_meta("openai", account).and_then(|m| m.org_id);

    let model = q
        .model
        .clone()
        .or_else(|| cfg.default.models.get("openai").cloned())
        .unwrap_or_else(|| "gpt-4".into());

    // Build normalized messages and tools
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
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let mut req = client.post(url).bearer_auth(&api_key).json(&body);
    if let Some(ref org) = org_id {
        req = req.header("OpenAI-Organization", org);
    }
    // Check cache for non-streaming
    if cfg.cache.enabled && !q.stream {
        let key = cache::compute_cache_key(
            "openai",
            &model,
            &messages,
            &tools,
            q.temperature,
            q.max_tokens,
            &file_hashes,
        );
        if let Some(j) = cache::try_get(cfg, "openai", &key) {
            println!("{}", serde_json::to_string_pretty(&j).unwrap_or_default());
            return Ok(());
        }
        // If miss, proceed and save below
        rate_limit::before_request(cfg, "openai", account);
        let started = std::time::Instant::now();
        let resp = send_with_retries(req, cfg)?;
        let req_id = resp
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(AppError::with_kind(
                if status == 429 {
                    ErrorKind::RateLimit
                } else {
                    ErrorKind::Provider
                },
                format!("OpenAI API error ({}): {}", status, text),
            ));
        }
        let json: serde_json::Value = resp.json().map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        let latency = started.elapsed().as_millis() as u64;
        let content = json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("");
        let mut usage = json.get("usage").cloned().unwrap_or_else(|| json!({}));
        if usage.is_object() {
            let pt = usage.get("prompt_tokens").and_then(|v| v.as_u64());
            let ct = usage.get("completion_tokens").and_then(|v| v.as_u64());
            if let Some(cost) = crate::pricing::estimate_cost("openai", &model, pt, ct) {
                usage["estimated_cost"] = cost;
            }
        }
        let out = json!({
            "success": true,
            "request": {
                "provider": "openai",
                "model": model,
                "messages": "[redacted]",
                "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}
            },
            "response": {"content": content, "role": "assistant", "tool_calls": []},
            "usage": usage,
            "metadata": {
                "request_id": req_id,
                "latency_ms": latency,
                "cached": false,
                "cache_key": key,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "account": account
            },
            "warnings": []
        });
        // Save to cache
        let _ = cache::save(cfg, "openai", &key, &out);
        let _ = audit::append(cfg, &out);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return Ok(());
    }

    // Streaming path or non-cached path
    if q.stream {
        let mut body_stream = body.clone();
        body_stream["stream"] = json!(true);
        let url2 = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let mut req = client.post(url2).bearer_auth(&api_key).json(&body_stream);
        if let Some(ref org) = org_id {
            req = req.header("OpenAI-Organization", org);
        }
        rate_limit::before_request(cfg, "openai", account);
        let resp = send_with_retries(req, cfg)?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().unwrap_or_default();
            return Err(AppError::with_kind(
                if status == 429 {
                    ErrorKind::RateLimit
                } else {
                    ErrorKind::Provider
                },
                format!("OpenAI API error ({}): {}", status, text),
            ));
        }
        // Print JSONL or text stream
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"start","model": model})).unwrap()
            );
        } else {
            println!("[Streaming from OpenAI {}...]", model);
        }
        let reader = std::io::BufReader::new(resp);
        use std::io::BufRead;
        let mut accum = String::new();
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
        if q.format == "json" {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"end","finish_reason":"stop"})).unwrap()
            );
        } else {
            println!("\n---\n(streaming complete)");
        }
        // Save final output to cache if enabled
        if cfg.cache.enabled {
            let (messages, file_hashes) = model::normalized_messages(cfg, q)?;
            let tools = model::normalized_tools(q)?;
            let key = cache::compute_cache_key(
                "openai",
                &model,
                &messages,
                &tools,
                q.temperature,
                q.max_tokens,
                &file_hashes,
            );
            let out = json!({
                "success": true,
                "request": {"provider":"openai","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
                "response": {"content": accum, "role":"assistant", "tool_calls": []},
                "usage": serde_json::Value::Null,
                "metadata": {"request_id": serde_json::Value::Null, "latency_ms": serde_json::Value::Null, "cached": false, "cache_key": key, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
                "warnings": []
            });
            let _ = cache::save(cfg, "openai", &key, &out);
            let _ = audit::append(cfg, &out);
        }
        return Ok(());
    }

    // Non-stream, cache disabled
    rate_limit::before_request(cfg, "openai", account);
    let started = std::time::Instant::now();
    let resp = send_with_retries(req, cfg)?;
    let req_id = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        return Err(AppError::with_kind(
            if status == 429 {
                ErrorKind::RateLimit
            } else {
                ErrorKind::Provider
            },
            format!("OpenAI API error ({}): {}", status, text),
        ));
    }
    let json: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    let latency = started.elapsed().as_millis() as u64;
    let content = json["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("");
    let mut usage = json.get("usage").cloned().unwrap_or_else(|| json!({}));
    if usage.is_object() {
        let pt = usage.get("prompt_tokens").and_then(|v| v.as_u64());
        let ct = usage.get("completion_tokens").and_then(|v| v.as_u64());
        if let Some(cost) = crate::pricing::estimate_cost("openai", &model, pt, ct) {
            usage["estimated_cost"] = cost;
        }
    }
    let out = json!({
        "success": true,
        "request": {"provider":"openai","model": model, "messages":"[redacted]", "parameters": {"temperature": q.temperature, "max_tokens": q.max_tokens}},
        "response": {"content": content, "role":"assistant", "tool_calls": []},
        "usage": usage,
        "metadata": {"request_id": req_id, "latency_ms": latency, "cached": false, "cache_key": serde_json::Value::Null, "timestamp": chrono::Utc::now().to_rfc3339(), "account": account},
        "warnings": []
    });
    let _ = audit::append(cfg, &out);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
    Ok(())
}

pub fn list_models(_cfg: &Config, refresh: bool) -> Result<(), AppError> {
    // If refresh, call OpenAI /v1/models, else print a minimal list
    if refresh {
        let api_key = if let Ok(k) = crate::credentials::retrieve_secret("openai", "default") {
            Some(k)
        } else {
            None
        };
        let base_url = io::get_cred_meta("openai", "default")
            .and_then(|m| m.base_url)
            .unwrap_or_else(|| "https://api.openai.com/v1".into());
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| AppError {
                kind: ErrorKind::Network,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        let url = format!("{}/models", base_url.trim_end_matches('/'));
        let mut req = client.get(url);
        if let Some(k) = api_key {
            req = req.bearer_auth(k);
        }
        let resp = req.send().map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if resp.status().is_success() {
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
        } else {
            println!("Failed to refresh model list (status {})", resp.status());
        }
    }
    println!("gpt-4\ngpt-4o\ngpt-4-turbo\ngpt-3.5-turbo");
    Ok(())
}

fn send_with_retries(
    req: reqwest::blocking::RequestBuilder,
    cfg: &Config,
) -> Result<reqwest::blocking::Response, AppError> {
    let mut attempt = 0u32;
    let provider = "openai".to_string();
    let lim = cfg.limits.get(&provider);
    let max_retries = lim.and_then(|l| l.max_retries).unwrap_or(3);
    let base_ms = lim.and_then(|l| l.backoff_base_ms).unwrap_or(1000);
    let max_ms = lim.and_then(|l| l.backoff_max_ms).unwrap_or(60_000);
    loop {
        match req.try_clone().unwrap().send() {
            Ok(resp) => {
                if resp.status().as_u16() == 429 {
                    if attempt >= max_retries {
                        return Ok(resp);
                    }
                    // Honor Retry-After
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                    let delay = retry_after
                        .map(|s| s * 1000)
                        .unwrap_or_else(|| ((base_ms as f64) * 2f64.powi(attempt as i32)) as u64);
                    std::thread::sleep(std::time::Duration::from_millis(delay.min(max_ms)));
                    attempt += 1;
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if attempt >= max_retries {
                    return Err(AppError {
                        kind: ErrorKind::Network,
                        message: e.to_string(),
                        source: Some(anyhow::Error::from(e)),
                    });
                }
                let delay = ((base_ms as f64) * 2f64.powi(attempt as i32)) as u64;
                std::thread::sleep(std::time::Duration::from_millis(delay.min(max_ms)));
                attempt += 1;
            }
        }
    }
}

pub fn list_assistants(_cfg: &Config, account: &str) -> Result<(), AppError> {
    let api_key = crate::credentials::retrieve_secret("openai", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for OpenAI; run: mdaicli store -p openai",
        )
    })?;
    let base_url = io::get_cred_meta("openai", account)
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://api.openai.com/v1".into());
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let url = format!("{}/assistants", base_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .bearer_auth(&api_key)
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("OpenAI error: {}", resp.status()),
        ));
    }
    let j: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if let Some(arr) = j.get("data").and_then(|v| v.as_array()) {
        for a in arr {
            let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            println!("{}\t{}", id, name);
        }
    } else {
        println!("No assistants found");
    }
    Ok(())
}

pub fn list_vector_stores(_cfg: &Config, account: &str) -> Result<(), AppError> {
    let api_key = crate::credentials::retrieve_secret("openai", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for OpenAI; run: mdaicli store -p openai",
        )
    })?;
    let base_url = io::get_cred_meta("openai", account)
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://api.openai.com/v1".into());
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let url = format!("{}/vector_stores", base_url.trim_end_matches('/'));
    let resp = client
        .get(url)
        .bearer_auth(&api_key)
        .send()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("OpenAI error: {}", resp.status()),
        ));
    }
    let j: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if let Some(arr) = j.get("data").and_then(|v| v.as_array()) {
        for a in arr {
            let id = a.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let name = a.get("name").and_then(|v| v.as_str()).unwrap_or("");
            println!("{}\t{}", id, name);
        }
    } else {
        println!("No vector stores found");
    }
    Ok(())
}

fn openai_auth(_cfg: &Config, account: &str) -> Result<(String, String, Option<String>), AppError> {
    let api_key = crate::credentials::retrieve_secret("openai", account).map_err(|_| {
        AppError::with_kind(
            ErrorKind::Credential,
            "Missing credentials for OpenAI; run: mdaicli store -p openai",
        )
    })?;
    let base_url = io::get_cred_meta("openai", account)
        .and_then(|m| m.base_url)
        .unwrap_or_else(|| "https://api.openai.com/v1".into());
    let org_id = io::get_cred_meta("openai", account).and_then(|m| m.org_id);
    Ok((api_key, base_url, org_id))
}

pub fn vector_store_create(
    cfg: &Config,
    account: &str,
    name: &str,
    files: &[String],
    expires_days: Option<u32>,
) -> Result<(), AppError> {
    let (api_key, base_url, org) = openai_auth(cfg, account)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let url = format!("{}/vector_stores", base_url.trim_end_matches('/'));
    let mut body = json!({ "name": name });
    if let Some(days) = expires_days {
        body["expires_after"] = json!({"anchor":"last_active_at","days": days});
    }
    let mut req = client
        .post(&url)
        .bearer_auth(&api_key)
        .json(&body)
        .header("OpenAI-Beta", "assistants=v2");
    if let Some(ref o) = org {
        req = req.header("OpenAI-Organization", o.clone());
    }
    let resp = req.send().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("OpenAI error: {}", resp.status()),
        ));
    }
    let j: serde_json::Value = resp.json().map_err(|e| AppError {
        kind: ErrorKind::Provider,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    let store_id = j
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    println!("Created vector store: {}\t{}", store_id, name);
    if !files.is_empty() {
        vector_store_upload(cfg, account, &store_id, files)?;
    }
    Ok(())
}

pub fn vector_store_upload(
    cfg: &Config,
    account: &str,
    store_id: &str,
    files: &[String],
) -> Result<(), AppError> {
    let (api_key, base_url, org) = openai_auth(cfg, account)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let mut file_ids: Vec<String> = Vec::new();
    for path in files {
        let form = multipart::Form::new()
            .text("purpose", "assistants")
            .file("file", path)
            .map_err(|e| AppError {
                kind: ErrorKind::FileAccess,
                message: e.to_string(),
                source: Some(anyhow::Error::from(e)),
            })?;
        let mut req = client
            .post(format!("{}/files", base_url.trim_end_matches('/')))
            .bearer_auth(&api_key)
            .multipart(form);
        if let Some(ref o) = org {
            req = req.header("OpenAI-Organization", o.clone());
        }
        let resp = req.send().map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if !resp.status().is_success() {
            return Err(AppError::with_kind(
                ErrorKind::Provider,
                format!("OpenAI file upload failed: {}", resp.status()),
            ));
        }
        let j: serde_json::Value = resp.json().map_err(|e| AppError {
            kind: ErrorKind::Provider,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if let Some(id) = j.get("id").and_then(|v| v.as_str()) {
            file_ids.push(id.to_string());
        }
    }
    if !file_ids.is_empty() {
        let mut req = client
            .post(format!(
                "{}/vector_stores/{}/file_batches",
                base_url.trim_end_matches('/'),
                store_id
            ))
            .bearer_auth(&api_key)
            .json(&json!({"file_ids": file_ids}))
            .header("OpenAI-Beta", "assistants=v2");
        if let Some(ref o) = org {
            req = req.header("OpenAI-Organization", o.clone());
        }
        let resp = req.send().map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        if !resp.status().is_success() {
            return Err(AppError::with_kind(
                ErrorKind::Provider,
                format!("OpenAI file attach failed: {}", resp.status()),
            ));
        }
        println!(
            "Uploaded {} file(s) to vector store {}",
            files.len(),
            store_id
        );
    }
    Ok(())
}

pub fn vector_store_delete(cfg: &Config, account: &str, store_id: &str) -> Result<(), AppError> {
    let (api_key, base_url, org) = openai_auth(cfg, account)?;
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| AppError {
            kind: ErrorKind::Network,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
    let mut req = client
        .delete(format!(
            "{}/vector_stores/{}",
            base_url.trim_end_matches('/'),
            store_id
        ))
        .bearer_auth(&api_key)
        .header("OpenAI-Beta", "assistants=v2");
    if let Some(ref o) = org {
        req = req.header("OpenAI-Organization", o.clone());
    }
    let resp = req.send().map_err(|e| AppError {
        kind: ErrorKind::Network,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if !resp.status().is_success() {
        return Err(AppError::with_kind(
            ErrorKind::Provider,
            format!("OpenAI delete failed: {}", resp.status()),
        ));
    }
    println!("Deleted vector store {}", store_id);
    Ok(())
}
