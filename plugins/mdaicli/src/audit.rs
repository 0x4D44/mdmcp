use crate::config::Config;
use crate::errors::AppError;
use directories::BaseDirs;
use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

fn audit_log_path(cfg: &Config) -> PathBuf {
    let dir = if cfg.logging.directory.is_empty() {
        BaseDirs::new()
            .map(|b| b.data_local_dir().join("mdaicli").join("logs"))
            .unwrap_or_else(|| PathBuf::from("~/.local/share/mdaicli/logs"))
    } else {
        PathBuf::from(crate::io::expand_home(&cfg.logging.directory))
    };
    dir.join("audit.log.jsonl")
}

pub fn append(cfg: &Config, json: &serde_json::Value) -> Result<(), AppError> {
    let p = audit_log_path(cfg);
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let mut line = serde_json::to_string(json).unwrap_or_default();
    line.push('\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)?;
    file.write_all(line.as_bytes())?;
    Ok(())
}

pub fn summarize(
    cfg: &Config,
    provider: Option<&str>,
    account: Option<&str>,
    days: u32,
) -> Result<serde_json::Value, AppError> {
    use std::io::Read;
    let p = audit_log_path(cfg);
    let mut f = match std::fs::File::open(p) {
        Ok(f) => f,
        Err(_) => return Ok(serde_json::json!({"summary": {"requests": 0, "total_tokens": 0}})),
    };
    let mut s = String::new();
    let _ = f.read_to_string(&mut s);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
    let mut requests = 0u64;
    let mut total_tokens = 0u64;
    for line in s.lines() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
            let ts = v
                .get("metadata")
                .and_then(|m| m.get("timestamp"))
                .and_then(|t| t.as_str())
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|dt| dt.with_timezone(&chrono::Utc));
            if let Some(ts) = ts {
                if ts < cutoff {
                    continue;
                }
            }
            if let Some(pv) = provider {
                if v.get("request")
                    .and_then(|r| r.get("provider"))
                    .and_then(|p| p.as_str())
                    != Some(pv)
                {
                    continue;
                }
            }
            if let Some(av) = account {
                if v.get("metadata")
                    .and_then(|m| m.get("account"))
                    .and_then(|a| a.as_str())
                    != Some(av)
                {
                    continue;
                }
            }
            requests += 1;
            if let Some(tt) = v
                .get("usage")
                .and_then(|u| u.get("total_tokens"))
                .and_then(|n| n.as_u64())
            {
                total_tokens += tt;
            } else if let Some(inp) = v
                .get("usage")
                .and_then(|u| u.get("input_tokens"))
                .and_then(|n| n.as_u64())
            {
                total_tokens += inp
                    + v.get("usage")
                        .and_then(|u| u.get("output_tokens"))
                        .and_then(|n| n.as_u64())
                        .unwrap_or(0);
            }
        }
    }
    Ok(serde_json::json!({"summary": {"requests": requests, "total_tokens": total_tokens}}))
}

// No custom write trait: rely on std::io::Write::write_all for safety
