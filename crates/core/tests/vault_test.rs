//! Password changes, recovery keys and backups for a whole vault.

use std::path::{Path, PathBuf};
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret, vault, YasecretError};

/// A vault at `dir/db.sqlite` with one project holding API_KEY=value-1, opened the way the apps do.
fn make_vault(dir: &Path, password: &str) -> (PathBuf, String) {
    let path = dir.join("db.sqlite");
    let salt = vault::load_or_create_salt(&path).unwrap();
    let db_key = crypto::derive_db_key(password, &salt);
    let db = Db::open(&path, password).unwrap();
    let p = project::create(&db, "shop", None, "me").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let k = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    secret::create(&db, &e.id, "API_KEY", b"value-1", &k, "me", None).unwrap();
    (path, p.id)
}

/// Reads API_KEY the way an unlock does: salt file + password.
fn read_value(path: &Path, project_id: &str, password: &str) -> Result<String, YasecretError> {
    let salt = vault::load_or_create_salt(path)?;
    let db_key = crypto::derive_db_key(password, &salt);
    let db = Db::open(path, password)?;
    let k = project_key::load(&db, project_id, &db_key)?;
    let env = environment::list(&db, project_id)?.remove(0);
    let s = secret::list(&db, &env.id)?.remove(0);
    Ok(String::from_utf8(secret::get_plaintext(&db, &s.id, &k)?.to_vec()).unwrap())
}

#[test]
fn changing_the_password_keeps_everything_readable() {
    let dir = tempfile::tempdir().unwrap();
    let (path, pid) = make_vault(dir.path(), "old-pw");
    assert!(matches!(vault::change_password(&path, "wrong", "new-pw"), Err(YasecretError::WrongPassword)));
    vault::change_password(&path, "old-pw", "new-pw").unwrap();
    assert_eq!(read_value(&path, &pid, "new-pw").unwrap(), "value-1");
    assert!(read_value(&path, &pid, "old-pw").is_err());
}

#[test]
fn a_recovery_key_resets_a_forgotten_password_even_after_password_changes() {
    let dir = tempfile::tempdir().unwrap();
    let (path, pid) = make_vault(dir.path(), "pw-1");
    assert!(!vault::has_recovery_key(&path));
    let key = vault::create_recovery_key(&path, "pw-1").unwrap();
    assert!(vault::has_recovery_key(&path));
    assert_eq!(key.replace('-', "").len(), 52, "256 bits in base32: {key}");

    // A later password change keeps the same recovery key working.
    vault::change_password(&path, "pw-1", "pw-2").unwrap();
    assert!(vault::recover(&path, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", "pw-3").is_err());
    vault::recover(&path, &key.to_lowercase().replace('-', " "), "pw-3").unwrap();
    assert_eq!(read_value(&path, &pid, "pw-3").unwrap(), "value-1");

    // Making a new recovery key retires the old one.
    let newer = vault::create_recovery_key(&path, "pw-3").unwrap();
    assert!(vault::recover(&path, &key, "pw-4").is_err());
    vault::recover(&path, &newer, "pw-4").unwrap();
    assert_eq!(read_value(&path, &pid, "pw-4").unwrap(), "value-1");
}

#[test]
fn a_backup_restores_into_an_empty_location_and_stays_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let (path, pid) = make_vault(dir.path(), "pw");
    vault::create_recovery_key(&path, "pw").unwrap();
    let file = dir.path().join("vault.yasecret-backup");
    {
        let db = Db::open(&path, "pw").unwrap();
        vault::backup(&db, &path, &file).unwrap();
    }
    let bytes = std::fs::read(&file).unwrap();
    assert!(!bytes.windows(7).any(|w| w == b"value-1") && !bytes.windows(4).any(|w| w == b"shop"), "backup is encrypted");

    let other = tempfile::tempdir().unwrap();
    let restored = other.path().join("db.sqlite");
    assert!(matches!(vault::restore(&file, &restored, "wrong"), Err(YasecretError::WrongPassword)));
    assert!(!restored.exists(), "a failed restore leaves nothing behind");
    vault::restore(&file, &restored, "pw").unwrap();
    assert_eq!(read_value(&restored, &pid, "pw").unwrap(), "value-1");
    assert!(vault::has_recovery_key(&restored), "the recovery key comes along");

    // Restoring over an existing vault replaces it.
    vault::change_password(&restored, "pw", "changed").unwrap();
    vault::restore(&file, &restored, "pw").unwrap();
    assert_eq!(read_value(&restored, &pid, "pw").unwrap(), "value-1");
}
