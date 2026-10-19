use thiserror::Error;

#[derive(Debug, Error)]
pub enum YasecretError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("wrong master password or corrupted database")]
    WrongPassword,
    #[error("encryption error")]
    Crypto,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied")]
    PermissionDenied,
    /// A shared project this device may read but not change.
    #[error("{0}")]
    ReadOnly(String),
    #[error("invalid .env format: {0}")]
    EnvParse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, YasecretError>;
