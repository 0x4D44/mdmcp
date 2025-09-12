use crate::errors::{AppError, ErrorKind};
use crate::opts::{Cli, ConfigCmd};
use directories::BaseDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub default: DefaultSection,
    pub profiles: HashMap<String, Profile>,
    pub cache: CacheConfig,
    pub limits: HashMap<String, LimitsConfig>,
    pub logging: LoggingConfig,

    #[serde(skip)]
    pub config_path: Option<PathBuf>,
    #[serde(skip)]
    pub profile_name: Option<String>,
    #[serde(skip)]
    pub allowed_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultSection {
    pub provider: String,
    pub format: String,
    #[serde(default)]
    pub models: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Profile {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub ttl_seconds: u64,
    pub max_size_mb: u64,
    pub directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    pub requests_per_minute: u32,
    pub tokens_per_minute: u32,
    #[serde(default)]
    pub max_retries: Option<u32>,
    #[serde(default)]
    pub backoff_base_ms: Option<u64>,
    #[serde(default)]
    pub backoff_max_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub directory: String,
    pub max_files: u32,
    pub max_size_mb: u64,
    pub redact_sensitive: bool,
}

impl Default for Config {
    fn default() -> Self {
        let mut models = HashMap::new();
        models.insert("openai".into(), "gpt-4".into());
        models.insert("anthropic".into(), "claude-3-opus-20240229".into());
        models.insert("openrouter".into(), "auto".into());

        let base = BaseDirs::new();
        let cache_dir = base
            .as_ref()
            .map(|b| b.cache_dir().join("mdaicli").to_string_lossy().to_string())
            .unwrap_or_else(|| "~/.cache/mdaicli".into());
        let log_dir = base
            .as_ref()
            .map(|b| {
                b.data_local_dir()
                    .join("mdaicli")
                    .join("logs")
                    .to_string_lossy()
                    .to_string()
            })
            .unwrap_or_else(|| "~/.local/share/mdaicli/logs".into());

        Self {
            default: DefaultSection {
                provider: "openai".into(),
                format: "json".into(),
                models,
            },
            profiles: HashMap::new(),
            cache: CacheConfig {
                enabled: true,
                ttl_seconds: 3600,
                max_size_mb: 500,
                directory: cache_dir,
            },
            limits: HashMap::new(),
            logging: LoggingConfig {
                level: "info".into(),
                directory: log_dir,
                max_files: 10,
                max_size_mb: 50,
                redact_sensitive: true,
            },
            config_path: None,
            profile_name: None,
            allowed_roots: vec![],
        }
    }
}

impl Config {
    pub fn load(path_opt: Option<&str>, profile: Option<&str>) -> Result<Self, AppError> {
        // Resolve config path
        let path = if let Some(p) = path_opt {
            PathBuf::from(p)
        } else {
            default_config_path()
        };
        let mut cfg = if path.exists() {
            let s = fs::read_to_string(&path)?;
            let mut c: Config = toml::from_str(&s)?;
            c.config_path = Some(path);
            c
        } else {
            let mut c = Config::default();
            c.config_path = Some(path);
            c
        };

        // Apply profile section
        if let Some(pname) = profile {
            if let Some(p) = cfg.profiles.get(pname) {
                if let Some(provider) = &p.provider {
                    cfg.default.provider = provider.clone();
                }
                if let Some(model) = &p.model {
                    cfg.default
                        .models
                        .insert(cfg.default.provider.clone(), model.clone());
                }
            }
            cfg.profile_name = Some(pname.to_string());
        }

        Ok(cfg)
    }

    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("MDAICLI_PROVIDER") {
            self.default.provider = v;
        }
        if let Ok(v) = std::env::var("MDAICLI_MODEL") {
            self.default.models.insert(self.default.provider.clone(), v);
        }
        if let Ok(v) = std::env::var("MDAICLI_FORMAT") {
            self.default.format = v;
        }
        if let Ok(v) = std::env::var("MDAICLI_CACHE_DIR") {
            self.cache.directory = v;
        }
        if let Ok(v) = std::env::var("MDAICLI_PROFILE") {
            self.profile_name = Some(v);
        }
        if let Ok(v) = std::env::var("MDAICLI_ALLOWED_ROOTS") {
            self.allowed_roots = v
                .split(',')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect();
        }
        if std::env::var("MDAICLI_NO_CACHE").is_ok() {
            self.cache.enabled = false;
        }
    }

    pub fn apply_cli_overrides(&mut self, cli: &Cli) {
        if let Some(p) = &cli.provider {
            self.default.provider = p.clone();
        }
        if let Some(m) = &cli.command_model() {
            self.default
                .models
                .insert(self.default.provider.clone(), m.clone());
        }
        if cli.no_cache {
            self.cache.enabled = false;
        }
    }

    pub fn handle_config_command(&mut self, cmd: ConfigCmd) -> Result<(), AppError> {
        match cmd {
            ConfigCmd::Get { key } => {
                let v = self.get_key(&key).unwrap_or_else(|| "".into());
                println!("{}", v);
                Ok(())
            }
            ConfigCmd::Set { key, value } => {
                self.set_key(&key, &value)?;
                self.save()
            }
            ConfigCmd::List => {
                let s = toml::to_string_pretty(self).map_err(|e| AppError {
                    kind: ErrorKind::Config,
                    message: e.to_string(),
                    source: Some(anyhow::Error::from(e)),
                })?;
                println!("{}", s);
                Ok(())
            }
            ConfigCmd::Validate => {
                // Minimal validation
                if self.default.provider.is_empty() {
                    return Err(AppError::with_kind(
                        ErrorKind::Config,
                        "default.provider is empty",
                    ));
                }
                Ok(())
            }
            ConfigCmd::Reset => {
                let path = self.config_path.clone().unwrap_or_else(default_config_path);
                *self = Config::default();
                self.config_path = Some(path);
                self.save()
            }
        }
    }

    fn get_key(&self, key: &str) -> Option<String> {
        match key {
            "default.provider" => Some(self.default.provider.clone()),
            "default.format" => Some(self.default.format.clone()),
            k if k.starts_with("default.models.") => {
                let p = &k[15..];
                self.default.models.get(p).cloned()
            }
            "cache.enabled" => Some(self.cache.enabled.to_string()),
            "cache.ttl_seconds" => Some(self.cache.ttl_seconds.to_string()),
            "cache.max_size_mb" => Some(self.cache.max_size_mb.to_string()),
            "cache.directory" => Some(self.cache.directory.clone()),
            k if k.starts_with("limits.") && k.ends_with(".requests_per_minute") => {
                let prov = k
                    .trim_start_matches("limits.")
                    .trim_end_matches(".requests_per_minute");
                self.limits
                    .get(prov)
                    .map(|l| l.requests_per_minute.to_string())
            }
            k if k.starts_with("limits.") && k.ends_with(".tokens_per_minute") => {
                let prov = k
                    .trim_start_matches("limits.")
                    .trim_end_matches(".tokens_per_minute");
                self.limits
                    .get(prov)
                    .map(|l| l.tokens_per_minute.to_string())
            }
            _ => None,
        }
    }

    fn set_key(&mut self, key: &str, value: &str) -> Result<(), AppError> {
        match key {
            "default.provider" => self.default.provider = value.into(),
            "default.format" => self.default.format = value.into(),
            k if k.starts_with("default.models.") => {
                let p = &k[15..];
                self.default.models.insert(p.into(), value.into());
            }
            "cache.enabled" => self.cache.enabled = value.parse().unwrap_or(self.cache.enabled),
            "cache.ttl_seconds" => {
                self.cache.ttl_seconds = value.parse().unwrap_or(self.cache.ttl_seconds)
            }
            "cache.max_size_mb" => {
                self.cache.max_size_mb = value.parse().unwrap_or(self.cache.max_size_mb)
            }
            "cache.directory" => self.cache.directory = value.into(),
            k if k.starts_with("limits.") && k.ends_with(".requests_per_minute") => {
                let prov = k
                    .trim_start_matches("limits.")
                    .trim_end_matches(".requests_per_minute");
                let e = self.limits.entry(prov.into()).or_insert(LimitsConfig {
                    requests_per_minute: 60,
                    tokens_per_minute: 90000,
                    max_retries: None,
                    backoff_base_ms: None,
                    backoff_max_ms: None,
                });
                e.requests_per_minute = value.parse().unwrap_or(e.requests_per_minute);
            }
            k if k.starts_with("limits.") && k.ends_with(".tokens_per_minute") => {
                let prov = k
                    .trim_start_matches("limits.")
                    .trim_end_matches(".tokens_per_minute");
                let e = self.limits.entry(prov.into()).or_insert(LimitsConfig {
                    requests_per_minute: 60,
                    tokens_per_minute: 90000,
                    max_retries: None,
                    backoff_base_ms: None,
                    backoff_max_ms: None,
                });
                e.tokens_per_minute = value.parse().unwrap_or(e.tokens_per_minute);
            }
            _ => {
                return Err(AppError::with_kind(
                    ErrorKind::Config,
                    format!("Unknown config key: {}", key),
                ))
            }
        }
        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let path = self.config_path.clone().unwrap_or_else(default_config_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(|e| AppError {
            kind: ErrorKind::Config,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        })?;
        fs::write(&path, s)?;
        println!("Saved config to {}", path.to_string_lossy());
        Ok(())
    }
}

fn default_config_path() -> PathBuf {
    if let Some(b) = BaseDirs::new() {
        b.config_dir().join("mdaicli").join("config.toml")
    } else {
        PathBuf::from("~/.config/mdaicli/config.toml")
    }
}

// Helper to peek model from CLI variants
trait CommandModel {
    fn command_model(&self) -> Option<String>;
}

impl CommandModel for crate::opts::Cli {
    fn command_model(&self) -> Option<String> {
        use crate::opts::Commands::*;
        match &self.command {
            Query(q) => q.model.clone(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_get_keys() {
        let mut c = Config::default();
        c.set_key("default.provider", "openai").unwrap();
        c.set_key("default.models.openai", "gpt-4").unwrap();
        assert_eq!(c.get_key("default.provider").unwrap(), "openai");
        assert_eq!(c.get_key("default.models.openai").unwrap(), "gpt-4");
    }

    #[test]
    fn env_overrides_apply() {
        let mut c = Config::default();
        std::env::set_var("MDAICLI_PROVIDER", "anthropic");
        std::env::set_var("MDAICLI_MODEL", "claude-3-opus-20240229");
        std::env::set_var("MDAICLI_NO_CACHE", "1");
        c.apply_env_overrides();
        assert_eq!(c.default.provider, "anthropic");
        assert_eq!(c.default.models.get("anthropic").unwrap(), "claude-3-opus-20240229");
        assert!(!c.cache.enabled);
        std::env::remove_var("MDAICLI_PROVIDER");
        std::env::remove_var("MDAICLI_MODEL");
        std::env::remove_var("MDAICLI_NO_CACHE");
    }
}
