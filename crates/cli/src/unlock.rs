use std::path::{Path, PathBuf};
use yasecret_core::{crypto, db::Db, error::Result, identity, models::Identity};
use zeroize::Zeroizing;

pub struct Session {
    pub db: Db,
    pub db_key: Zeroizing<[u8; 32]>,
    pub identity: Identity,
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

fn salt_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("salt")
}

fn load_or_create_salt(db_path: &Path) -> Result<[u8; 16]> {
    let sp = salt_path(db_path);
    if sp.exists() {
        let bytes = std::fs::read(&sp)?;
        Ok(bytes.try_into().unwrap_or_else(|_| crypto::generate_salt()))
    } else {
        let s = crypto::generate_salt();
        std::fs::write(&sp, s)?;
        Ok(s)
    }
}

pub fn unlock(path: &Path, password_override: Option<&str>) -> Result<Session> {
    let password = match password_override {
        Some(p) => p.to_string(),
        None => rpassword::prompt_password("Master password: ")
            .map_err(yasecret_core::YasecretError::Io)?,
    };

    let salt = load_or_create_salt(path)?;
    let db_key = crypto::derive_db_key(&password, &salt);
    let db = Db::open(path, &password)?;
    let id = identity::load_or_create(&db, "local")?;
    Ok(Session { db, db_key, identity: id })
}
