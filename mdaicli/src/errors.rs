use std::fmt::{Display, Formatter};
use std::io;
use std::process::ExitCode;
use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum ErrorKind {
    General = 1,
    Validation = 2,
    Provider = 3,
    Network = 4,
    Credential = 5,
    FileAccess = 6,
    Config = 7,
    RateLimit = 8,
    Cache = 9,
}

#[derive(Error, Debug)]
pub struct AppError {
    pub kind: ErrorKind,
    pub message: String,
    #[source]
    pub source: Option<anyhow::Error>,
}

impl AppError {
    pub fn with_kind(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            source: None,
        }
    }
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<io::Error> for AppError {
    fn from(e: io::Error) -> Self {
        Self {
            kind: ErrorKind::General,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        }
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self {
            kind: ErrorKind::Validation,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        }
    }
}

impl From<serde_yaml::Error> for AppError {
    fn from(e: serde_yaml::Error) -> Self {
        Self {
            kind: ErrorKind::Validation,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        }
    }
}

impl From<toml::de::Error> for AppError {
    fn from(e: toml::de::Error) -> Self {
        Self {
            kind: ErrorKind::Config,
            message: e.to_string(),
            source: Some(anyhow::Error::from(e)),
        }
    }
}

pub fn exit_with(err: AppError) -> ExitCode {
    eprintln!("Error: {}", err);
    ExitCode::from(err.kind as u8)
}
