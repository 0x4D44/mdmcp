use crate::config::Config;
use crate::credentials;
use crate::errors::{AppError, ErrorKind};
use directories::BaseDirs;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub fn ensure_dirs(cfg: &Config) -> Result<(), AppError> {
    if !cfg.cache.directory.is_empty() {
        let p = PathBuf::from(expand_home(&cfg.cache.directory));
        fs::create_dir_all(&p)?;
    }
    if !cfg.logging.directory.is_empty() {
        let p = PathBuf::from(expand_home(&cfg.logging.directory));
        fs::create_dir_all(&p)?;
    }
    Ok(())
}

pub fn looks_like_uri(s: &str) -> bool {
    s.starts_with("mdmcp://")
        || s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("file://")
}

pub fn enforce_allowed_roots(cfg: &Config, inputs: &[String]) -> Result<(), AppError> {
    if cfg.allowed_roots.is_empty() || inputs.is_empty() {
        return Ok(());
    }
    let allowed: Vec<PathBuf> = cfg
        .allowed_roots
        .iter()
        .filter_map(|p| canonicalize_if_exists(p))
        .collect();
    for s in inputs {
        let p = PathBuf::from(s);
        if looks_like_uri(s) {
            return Err(AppError::with_kind(
                ErrorKind::FileAccess,
                format!(
                    "URI not allowed for --input-file: {}. Use MCP resources instead.",
                    s
                ),
            ));
        }
        let cp = canonicalize_if_exists(&p).ok_or_else(|| {
            AppError::with_kind(
                ErrorKind::FileAccess,
                format!("Input file not found: {}", s),
            )
        })?;
        let mut ok = false;
        for root in &allowed {
            if is_within(&cp, root) {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(AppError::with_kind(
                ErrorKind::FileAccess,
                format!(
                    "Path '{}' is not within allowed roots. Set MDAICLI_ALLOWED_ROOTS or adjust MCP policy.",
                    s
                ),
            ));
        }
    }
    Ok(())
}

fn is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

fn canonicalize_if_exists(p: &Path) -> Option<PathBuf> { std::fs::canonicalize(p).ok() }

pub fn read_secret_from_stdin_or_tty(no_interactive: bool) -> Result<String, AppError> {
    // If stdin is piped, read it
    if atty::isnt(atty::Stream::Stdin) {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        let key = buf.trim().to_string();
        if key.is_empty() {
            return Err(AppError::with_kind(
                ErrorKind::Credential,
                "No input read from stdin for API key",
            ));
        }
        return Ok(key);
    }
    if no_interactive {
        return Err(AppError::with_kind(
            ErrorKind::Credential,
            "--no-interactive set but no stdin provided",
        ));
    }
    eprint!("Enter API key: ");
    let key = read_password().map_err(|e| AppError {
        kind: ErrorKind::Credential,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    if key.trim().is_empty() {
        return Err(AppError::with_kind(ErrorKind::Credential, "Empty API key"));
    }
    Ok(key.trim().into())
}

// Credential metadata index with per-account settings
#[derive(Default, Serialize, Deserialize)]
struct CredIndex {
    providers: std::collections::HashMap<String, std::collections::HashMap<String, CredMeta>>,
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct CredMeta {
    pub base_url: Option<String>,
    pub org_id: Option<String>,
    pub storage: Option<String>,
}

fn cred_index_path() -> PathBuf {
    if let Ok(dir) = std::env::var("MDAICLI_CONFIG_DIR") {
        return PathBuf::from(dir).join("credentials.json");
    }
    if let Some(b) = BaseDirs::new() {
        b.config_dir().join("mdaicli").join("credentials.json")
    } else {
        PathBuf::from("~/.config/mdaicli/credentials.json")
    }
}

fn load_index() -> CredIndex {
    let p = cred_index_path();
    if let Ok(s) = fs::read_to_string(p) {
        serde_json::from_str(&s).unwrap_or_default()
    } else {
        CredIndex::default()
    }
}

fn save_index(idx: &CredIndex) -> Result<(), AppError> {
    let p = cred_index_path();
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(idx).map_err(|e| AppError {
        kind: ErrorKind::General,
        message: e.to_string(),
        source: Some(anyhow::Error::from(e)),
    })?;
    fs::write(p, s)?;
    Ok(())
}

pub fn store_secret(
    _cfg: &Config,
    provider: &str,
    account: &str,
    secret: &str,
    base_url: Option<String>,
    org_id: Option<String>,
) -> Result<(), AppError> {
    let method = credentials::store_secret(provider, account, secret)?;
    // Update metadata index
    let mut idx = load_index();
    let prov_map = idx.providers.entry(provider.to_string()).or_default();
    let storage = match method {
        credentials::StorageMethod::Keyring => Some("keyring".into()),
        credentials::StorageMethod::FallbackFile => Some("file".into()),
    };
    prov_map.insert(
        account.to_string(),
        CredMeta {
            base_url,
            org_id,
            storage,
        },
    );
    save_index(&idx)
}

pub fn list_credentials() -> Result<(), AppError> {
    let idx = load_index();
    if idx.providers.is_empty() {
        println!("No credentials stored.");
    } else {
        for (p, accounts) in idx.providers.iter() {
            println!("{}:", p);
            for (a, meta) in accounts {
                let mut extra = String::new();
                if let Some(s) = &meta.storage {
                    extra.push_str(&format!(" storage:{}", s));
                }
                if meta.base_url.is_some() {
                    extra.push_str(" base-url:yes");
                }
                if meta.org_id.is_some() {
                    extra.push_str(" org-id:yes");
                }
                println!(
                    "  - {}{}",
                    a,
                    if extra.is_empty() {
                        "".into()
                    } else {
                        format!(" ({})", extra.trim())
                    }
                );
            }
        }
    }
    Ok(())
}

pub fn remove_credential(provider: &str, account: &str) -> Result<(), AppError> {
    let mut idx = load_index();
    let mut changed = false;
    credentials::remove_secret(provider, account)?;
    let mut empty_provider = false;
    if let Some(map) = idx.providers.get_mut(provider) {
        if map.remove(account).is_some() {
            changed = true;
        }
        if map.is_empty() {
            empty_provider = true;
        }
    }
    if empty_provider {
        idx.providers.remove(provider);
    }
    if changed {
        save_index(&idx)?;
    }
    Ok(())
}

pub fn remove_all_credentials() -> Result<(), AppError> {
    let p = cred_index_path();
    let _ = fs::remove_file(p);
    Ok(())
}

pub fn get_cred_meta(provider: &str, account: &str) -> Option<CredMeta> {
    let idx = load_index();
    idx.providers
        .get(provider)
        .and_then(|m| m.get(account))
        .cloned()
}

pub fn expand_home(p: &str) -> String {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Some(b) = BaseDirs::new() {
            return b.home_dir().join(stripped).to_string_lossy().to_string();
        }
    }
    p.to_string()
}

#[allow(dead_code)]
pub fn is_wsl_runtime() -> bool {
    // Heuristic based on presence of WSL interop file or env var
    std::path::Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
        || std::env::var("WSL_DISTRO_NAME").is_ok()
}

#[allow(dead_code)]
pub fn windows_path_to_wsl(path: &str) -> Option<String> {
    // Convert like C:\Users\Name -> /mnt/c/Users/Name
    if path.len() > 2 {
        let bytes = path.as_bytes();
        let drive = bytes[0] as char;
        let colon = bytes[1] as char;
        if colon == ':' && drive.is_ascii_alphabetic() {
            let rest = &path[2..].replace('\\', "/");
            let drive_l = drive.to_ascii_lowercase();
            return Some(format!("/mnt/{}/{}", drive_l, rest.trim_start_matches('/')));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn detects_uri_schemes() {
        assert!(looks_like_uri("http://a"));
        assert!(looks_like_uri("https://a"));
        assert!(looks_like_uri("mdmcp://a"));
        assert!(looks_like_uri("file://a"));
        assert!(!looks_like_uri("/a/b"));
    }

    #[test]
    fn enforces_allowed_roots_simple() {
        let dir = tempdir().unwrap();
        let fpath = dir.path().join("x.txt");
        std::fs::write(&fpath, "hi").unwrap();

        let mut cfg = crate::config::Config::default();
        cfg.allowed_roots = vec![dir.path().to_path_buf()];
        enforce_allowed_roots(&cfg, &[fpath.to_string_lossy().to_string()]).unwrap();
    }

    #[test]
    fn denies_outside_roots() {
        let d1 = tempdir().unwrap();
        let d2 = tempdir().unwrap();
        let f = d2.path().join("a.txt");
        std::fs::write(&f, "hi").unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.allowed_roots = vec![d1.path().to_path_buf()];
        let err = enforce_allowed_roots(&cfg, &[f.to_string_lossy().to_string()]).unwrap_err();
        assert!(format!("{}", err).contains("not within allowed roots"));
    }
}
