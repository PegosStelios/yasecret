pub mod live;
pub mod node;

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
    #[error("This invite link can't be used: {0}")]
    InvalidLink(String),
    #[error("That device code isn't valid — it should be 64 characters (letters a–f and digits)")]
    InvalidDeviceCode,
    #[error("Sync is already running for this vault in another process (another Yasecret window or `yasecret share`). Close it and try again")]
    InUse,
    #[error("Only the project owner can do that")]
    NotOwner,
    #[error("You already have this project")]
    AlreadyJoined,
    #[error("Couldn't reach the person who shared this. They need Yasecret open and unlocked; try again in a moment")]
    OwnerOffline,
    #[error("This invite link was already used. Ask for a new one")]
    InviteUsed,
    #[error("This invite link has expired. Ask for a new one")]
    InviteExpired,
}

pub type Result<T> = std::result::Result<T, SyncError>;
