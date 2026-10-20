//! Whole-vault operations: the key-derivation salt, changing the master password, recovery
//! keys and backups.
//!
//! The recovery file next to the vault holds the master password encrypted with the
//! recovery key, and the recovery key encrypted with the password-derived key. The first lets
//! a forgotten password be reset; the second lets a password change re-encrypt the first
//! without asking for the recovery key.

use std::path::{Path, PathBuf};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto,
    db::Db,
    error::{Result, YasecretError},
};

pub fn salt_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("salt")
}

pub fn recovery_path(db_path: &Path) -> PathBuf {
    db_path.with_extension("recovery")
}

pub fn load_or_create_salt(db_path: &Path) -> Result<[u8; 16]> {
    let path = salt_path(db_path);
    if path.exists() {
        return std::fs::read(&path)?.try_into().map_err(|_| {
            YasecretError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("salt file corrupt (expected 16 bytes): {}", path.display()),
            ))
        });
    }
    let salt = crypto::generate_salt();
    write_atomic(&path, &salt)?;
    Ok(salt)
}

#[derive(Serialize, Deserialize, Clone)]
struct Sealed {
    ct: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct RecoveryFile {
    version: u32,
    /// Master password, encrypted with the recovery key.
    password: Sealed,
    /// Recovery key, encrypted with the password-derived key.
    key: Sealed,
}

fn seal(key: &[u8; 32], plain: &[u8]) -> Result<Sealed> {
    let (ct, nonce) = crypto::encrypt(plain, key)?;
    Ok(Sealed { ct, nonce: nonce.to_vec() })
}

fn open(key: &[u8; 32], s: &Sealed) -> Option<Zeroizing<Vec<u8>>> {
    let nonce: [u8; 12] = s.nonce.clone().try_into().ok()?;
    crypto::decrypt(&s.ct, &nonce, key).ok()
}

fn read_recovery(db_path: &Path) -> Result<Option<RecoveryFile>> {
    match std::fs::read(recovery_path(db_path)) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn write_recovery(db_path: &Path, recovery_key: &[u8; 32], password: &str, db_key: &[u8; 32]) -> Result<()> {
    let file = RecoveryFile { version: 1, password: seal(recovery_key, password.as_bytes())?, key: seal(db_key, recovery_key)? };
    write_atomic(&recovery_path(db_path), &serde_json::to_vec(&file)?)
}

/// Writes through a temporary file and a rename, readable only by this user on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", path.extension().and_then(|e| e.to_str()).unwrap_or("")));
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn has_recovery_key(db_path: &Path) -> bool {
    recovery_path(db_path).exists()
}

/// Re-encrypts the vault under a new master password. The vault must not be open elsewhere.
pub fn change_password(db_path: &Path, old: &str, new: &str) -> Result<()> {
    if new.is_empty() {
        return Err(YasecretError::EnvParse("the new password can't be empty".into()));
    }
    let db = Db::open(db_path, old)?;
    let old_key = crypto::derive_db_key(old, &load_or_create_salt(db_path)?);
    let recovery_key: Option<Zeroizing<Vec<u8>>> = match read_recovery(db_path)? {
        Some(f) => Some(open(&old_key, &f.key).ok_or(YasecretError::Crypto)?),
        None => None,
    };
    let new_salt = crypto::generate_salt();
    let new_key = crypto::derive_db_key(new, &new_salt);

    // Project keys are wrapped with the password-derived key.
    let tx = db.conn().unchecked_transaction()?;
    let rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
        let mut stmt = tx.prepare("SELECT project_id, encrypted_key, key_nonce FROM project_key")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<rusqlite::Result<_>>()?
    };
    for (project_id, enc, nonce) in rows {
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| YasecretError::Crypto)?;
        let plain = crypto::decrypt(&enc, &nonce, &old_key)?;
        let (enc, nonce) = crypto::encrypt(&plain, &new_key)?;
        tx.execute(
            "UPDATE project_key SET encrypted_key = ?1, key_nonce = ?2 WHERE project_id = ?3",
            rusqlite::params![&enc, nonce.as_ref(), &project_id],
        )?;
    }
    tx.commit()?;
    let escaped = new.replace('\'', "''");
    db.conn().execute_batch(&format!("PRAGMA rekey = '{escaped}';"))?;
    drop(db);
    write_atomic(&salt_path(db_path), &new_salt)?;
    if let Some(rk) = recovery_key {
        let rk: [u8; 32] = rk.as_slice().try_into().map_err(|_| YasecretError::Crypto)?;
        write_recovery(db_path, &rk, new, &new_key)?;
    }
    Ok(())
}

/// Makes a new recovery key (retiring any previous one) and returns it for the user to keep.
pub fn create_recovery_key(db_path: &Path, password: &str) -> Result<String> {
    drop(Db::open(db_path, password)?);
    let db_key = crypto::derive_db_key(password, &load_or_create_salt(db_path)?);
    let mut rk = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(rk.as_mut());
    write_recovery(db_path, &rk, password, &db_key)?;
    Ok(format_key(&rk))
}

/// Sets a new master password using the recovery key. The vault must not be open elsewhere.
pub fn recover(db_path: &Path, recovery_key: &str, new_password: &str) -> Result<()> {
    let bad = || YasecretError::InvalidRecoveryKey;
    let rk = parse_key(recovery_key).ok_or_else(bad)?;
    let file = read_recovery(db_path)?.ok_or_else(bad)?;
    let password = open(&rk, &file.password).ok_or_else(bad)?;
    let password = Zeroizing::new(String::from_utf8(password.to_vec()).map_err(|_| bad())?);
    change_password(db_path, &password, new_password)
}

const BACKUP_MAGIC: &[u8] = b"YASECRET-BACKUP-1\n";

#[derive(Serialize, Deserialize)]
struct BackupHeader {
    salt: Vec<u8>,
    recovery: Option<RecoveryFile>,
}

/// Writes an encrypted copy of the open vault, with what's needed to unlock it, to `dest`.
pub fn backup(db: &Db, db_path: &Path, dest: &Path) -> Result<()> {
    let copy = dest.with_extension("backup-db.tmp");
    let _ = std::fs::remove_file(&copy);
    // SQLCipher writes the copy encrypted with the vault's key.
    db.conn().execute("VACUUM INTO ?1", [copy.to_string_lossy()])?;
    let bytes = std::fs::read(&copy);
    let _ = std::fs::remove_file(&copy);
    let header = BackupHeader { salt: load_or_create_salt(db_path)?.to_vec(), recovery: read_recovery(db_path)? };
    let mut out = BACKUP_MAGIC.to_vec();
    out.extend_from_slice(&serde_json::to_vec(&header)?);
    out.push(b'\n');
    out.extend_from_slice(&bytes?);
    write_atomic(dest, &out)
}

/// Replaces the vault at `db_path` with a backup, after checking `password` opens it. The
/// vault must not be open.
pub fn restore(backup_file: &Path, db_path: &Path, password: &str) -> Result<()> {
    let bad = |why: &str| YasecretError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("not a Yasecret backup ({why})")));
    let bytes = std::fs::read(backup_file)?;
    let rest = bytes.strip_prefix(BACKUP_MAGIC).ok_or_else(|| bad("wrong format"))?;
    let split = rest.iter().position(|b| *b == b'\n').ok_or_else(|| bad("damaged"))?;
    let header: BackupHeader = serde_json::from_slice(&rest[..split]).map_err(|_| bad("damaged header"))?;
    let salt: [u8; 16] = header.salt.try_into().map_err(|_| bad("damaged salt"))?;

    if let Some(dir) = db_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let staged = db_path.with_extension("restore.tmp");
    std::fs::write(&staged, &rest[split + 1..])?;
    let check = Db::open(&staged, password).and_then(|db| {
        // Opening with the password proves the database key; the salt proves the project keys.
        let db_key = crypto::derive_db_key(password, &salt);
        let mut stmt = db.conn().prepare("SELECT encrypted_key, key_nonce FROM project_key LIMIT 1")?;
        let row: Option<(Vec<u8>, Vec<u8>)> = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.next().transpose()?;
        if let Some((enc, nonce)) = row {
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| YasecretError::Crypto)?;
            crypto::decrypt(&enc, &nonce, &db_key)?;
        }
        Ok(())
    });
    if let Err(e) = check {
        for f in [staged.clone(), staged.with_extension("tmp-wal"), staged.with_extension("tmp-shm")] {
            let _ = std::fs::remove_file(f);
        }
        return Err(e);
    }
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(PathBuf::from(format!("{}{suffix}", db_path.display())));
    }
    std::fs::rename(&staged, db_path)?;
    write_atomic(&salt_path(db_path), &salt)?;
    match header.recovery {
        Some(r) => write_atomic(&recovery_path(db_path), &serde_json::to_vec(&r)?)?,
        None => {
            let _ = std::fs::remove_file(recovery_path(db_path));
        }
    }
    Ok(())
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 32 bytes as base32 in groups of four: 13 groups, easy to write down.
fn format_key(key: &[u8; 32]) -> String {
    let mut bits = 0u32;
    let mut n = 0;
    let mut chars = String::new();
    for b in key {
        bits = (bits << 8) | *b as u32;
        n += 8;
        while n >= 5 {
            n -= 5;
            chars.push(ALPHABET[((bits >> n) & 31) as usize] as char);
        }
    }
    if n > 0 {
        chars.push(ALPHABET[((bits << (5 - n)) & 31) as usize] as char);
    }
    chars.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

/// Accepts any case, with or without dashes and spaces.
fn parse_key(text: &str) -> Option<[u8; 32]> {
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::with_capacity(32);
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        let v = ALPHABET.iter().position(|a| *a as char == c.to_ascii_uppercase())? as u32;
        bits = (bits << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    out.try_into().ok()
}
