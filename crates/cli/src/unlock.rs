use std::path::{Path, PathBuf};
use yasecret_core::{crypto, db::Db, error::Result, identity, models::Identity};
use zeroize::Zeroizing;

pub struct Session {
    pub db: Db,
    pub db_key: Zeroizing<[u8; 32]>,
    pub identity: Identity,
    pub password: String,
}

pub fn db_path(override_path: Option<&str>) -> PathBuf {
    if let Some(p) = override_path {
        return PathBuf::from(p);
    }
    let mut base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    base.push("yasecret");
    std::fs::create_dir_all(&base).ok();
    base.push("db.sqlite");
    base
}

static STDIN_PASSWORD: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Used instead of prompting (`--password-stdin`).
pub fn set_stdin_password(password: String) {
    let _ = STDIN_PASSWORD.set(password);
}

pub fn unlock(path: &Path, password_override: Option<&str>) -> Result<Session> {
    let password = match password_override.or(STDIN_PASSWORD.get().map(String::as_str)) {
        Some(p) => p.to_string(),
        None => rpassword::prompt_password("Master password: ")
            .map_err(yasecret_core::YasecretError::Io)?,
    };

    let salt = yasecret_core::vault::load_or_create_salt(path)?;
    let db_key = crypto::derive_db_key(&password, &salt);
    let db = Db::open(path, &password)?;
    let id = identity::load_or_create(&db, "local")?;
    Ok(Session { db, db_key, identity: id, password })
}
