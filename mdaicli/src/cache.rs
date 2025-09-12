use crate::config::Config;
use crate::errors::AppError;
use directories::BaseDirs;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

pub fn list_cache(cfg: &Config, provider: Option<&str>) -> Result<(), AppError> {
    let dir = cache_dir(cfg);
    let p = Path::new(&dir);
    if !p.exists() {
        println!("Cache directory empty: {}", dir);
        return Ok(());
    }
    let mut count = 0;
    for entry in fs::read_dir(p)? {
        let e = entry?;
        let name = e.file_name();
        let name = name.to_string_lossy();
        if let Some(prov) = provider {
            if !name.starts_with(prov) {
                continue;
            }
        }
        println!("{}", name);
        count += 1;
    }
    if count == 0 {
        println!("No cache entries.");
    }
    Ok(())
}

pub fn remove_cache(
    cfg: &Config,
    provider: Option<&str>,
    older_than_days: Option<u64>,
    all: bool,
) -> Result<(), AppError> {
    let dir = cache_dir(cfg);
    let p = Path::new(&dir);
    if !p.exists() {
        return Ok(());
    }
    let now = std::time::SystemTime::now();
    for entry in fs::read_dir(p)? {
        let e = entry?;
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !all {
            if let Some(prov) = provider {
                if !name.starts_with(prov) {
                    continue;
                }
            }
        }
        if let Some(days) = older_than_days {
            if let Ok(meta) = e.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(elapsed) = now.duration_since(modified) {
                        if elapsed.as_secs() < days * 86400 {
                            continue;
                        }
                    }
                }
            }
        }
        let _ = fs::remove_file(e.path());
    }
    Ok(())
}

fn cache_dir(cfg: &Config) -> String {
    if cfg.cache.directory.is_empty() {
        if let Some(b) = BaseDirs::new() {
            return b.cache_dir().join("mdaicli").to_string_lossy().to_string();
        }
        return "~/.cache/mdaicli".into();
    }
    cfg.cache.directory.clone()
}

pub fn compute_cache_key(
    provider: &str,
    model: &str,
    messages: &serde_json::Value,
    tools: &Option<serde_json::Value>,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    file_hashes: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update(model.as_bytes());
    hasher.update(serde_json::to_string(messages).unwrap_or_default());
    if let Some(t) = tools {
        hasher.update(serde_json::to_string(t).unwrap_or_default());
    }
    if let Some(t) = temperature {
        hasher.update(format!("{:.3}", t));
    }
    if let Some(mt) = max_tokens {
        hasher.update(format!("{}", mt));
    }
    for h in file_hashes {
        hasher.update(h.as_bytes());
    }
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

pub fn try_get(cfg: &Config, provider: &str, key: &str) -> Option<serde_json::Value> {
    let path = std::path::Path::new(&cache_dir(cfg)).join(format!("{}-{}.json", provider, key));
    if !path.exists() {
        return None;
    }
    // TTL check
    if let Ok(meta) = std::fs::metadata(&path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                if elapsed.as_secs() > cfg.cache.ttl_seconds {
                    return None;
                }
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string(path) {
        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&s) {
            return Some(j);
        }
    }
    None
}

pub fn save(
    cfg: &Config,
    provider: &str,
    key: &str,
    value: &serde_json::Value,
) -> Result<(), AppError> {
    let dir = cache_dir(cfg);
    let path = std::path::Path::new(&dir).join(format!("{}-{}.json", provider, key));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(value).unwrap_or_default(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn key_is_deterministic() {
        let msgs = serde_json::json!([{"role":"user","content":"hi"}]);
        let tools = None;
        let k1 = compute_cache_key("openai", "gpt-4", &msgs, &tools, Some(0.7), Some(100), &[]);
        let k2 = compute_cache_key("openai", "gpt-4", &msgs, &tools, Some(0.7), Some(100), &[]);
        assert_eq!(k1, k2);
    }

    #[test]
    fn try_get_respects_ttl() {
        let td = tempdir().unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.cache.directory = td.path().to_string_lossy().to_string();
        cfg.cache.ttl_seconds = 3600;
        let val = serde_json::json!({"ok":true});
        save(&cfg, "openai", "k", &val).unwrap();
        assert!(try_get(&cfg, "openai", "k").is_some());
        cfg.cache.ttl_seconds = 0;
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(try_get(&cfg, "openai", "k").is_none());
    }
}
