pub mod applier;
pub mod doc_manager;
pub mod node;
pub mod peer_key;
pub mod types;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("core: {0}")]
    Core(#[from] yasecret_core::YasecretError),
    #[error("iroh: {0}")]
    Iroh(#[from] anyhow::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("invalid ticket")]
    InvalidTicket,
    #[error("no sync doc for project {0}")]
    NoDoc(String),
    #[error("peer key not found")]
    NoPeerKey,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("db: {0}")]
    Db(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, SyncError>;
