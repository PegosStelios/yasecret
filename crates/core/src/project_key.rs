use zeroize::Zeroizing;

use crate::{
    crypto,
    db::Db,
    error::{Result, YasecretError},
};

pub fn create(db: &Db, project_id: &str, db_key: &[u8; 32]) -> Result<()> {
    let project_key = crypto::generate_project_key();
    let (encrypted_key, nonce) = crypto::encrypt(project_key.as_ref(), db_key)?;
    db.conn().execute(
        "INSERT OR IGNORE INTO project_key (project_id, encrypted_key, key_nonce) VALUES (?1,?2,?3)",
        rusqlite::params![project_id, &encrypted_key, nonce.as_ref()],
    )?;
    Ok(())
}

pub fn load(db: &Db, project_id: &str, db_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let (enc_key, nonce_vec): (Vec<u8>, Vec<u8>) = db
        .conn()
        .query_row(
            "SELECT encrypted_key, key_nonce FROM project_key WHERE project_id = ?1",
            [project_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| YasecretError::NotFound(format!("project key for {project_id}")))?;

    let nonce: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| YasecretError::Crypto)?;
    let decrypted = crypto::decrypt(&enc_key, &nonce, db_key)?;
    let key_bytes: [u8; 32] = decrypted
        .as_slice()
        .try_into()
        .map_err(|_| YasecretError::Crypto)?;
    Ok(Zeroizing::new(key_bytes))
}

/// Stores a project key received from another peer.
pub fn store(db: &Db, project_id: &str, key: &[u8; 32], db_key: &[u8; 32]) -> Result<()> {
    let (encrypted_key, nonce) = crypto::encrypt(key, db_key)?;
    db.conn().execute(
        "INSERT OR REPLACE INTO project_key (project_id, encrypted_key, key_nonce) VALUES (?1,?2,?3)",
        rusqlite::params![project_id, &encrypted_key, nonce.as_ref()],
    )?;
    Ok(())
}

/// Replaces the project key and re-encrypts every value and version in the project.
/// Anyone holding the old key can no longer read values written after this.
pub fn rotate(db: &Db, project_id: &str, db_key: &[u8; 32]) -> Result<[u8; 32]> {
    let new = crypto::generate_project_key();
    rekey(db, project_id, db_key, &new)?;
    Ok(*new)
}

/// Switches the project to `new_key`, re-encrypting local values and history. Rows already
/// encrypted with `new_key` (e.g. synced after a rotation) are left as they are.
pub fn rekey(db: &Db, project_id: &str, db_key: &[u8; 32], new_key: &[u8; 32]) -> Result<()> {
    let old = load(db, project_id, db_key)?;
    if *old == *new_key {
        return Ok(());
    }
    let tx = db.conn().unchecked_transaction()?;
    for (table, query) in [
        ("secret", "SELECT s.id, s.encrypted_value, s.nonce FROM secret s JOIN environment e ON e.id = s.env_id WHERE e.project_id = ?1"),
        ("secret_version", "SELECT v.id, v.encrypted_value, v.nonce FROM secret_version v JOIN secret s ON s.id = v.secret_id JOIN environment e ON e.id = s.env_id WHERE e.project_id = ?1"),
    ] {
        let rows: Vec<(String, Vec<u8>, Vec<u8>)> = {
            let mut stmt = tx.prepare(query)?;
            let mapped = stmt.query_map([project_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            mapped.collect::<rusqlite::Result<_>>()?
        };
        for (id, enc, nonce) in rows {
            let nonce: [u8; 12] = nonce.try_into().map_err(|_| YasecretError::Crypto)?;
            let Ok(plain) = crypto::decrypt(&enc, &nonce, &old) else {
                continue;
            };
            let (enc2, nonce2) = crypto::encrypt(&plain, new_key)?;
            tx.execute(
                &format!("UPDATE {table} SET encrypted_value = ?1, nonce = ?2 WHERE id = ?3"),
                rusqlite::params![&enc2, nonce2.as_ref(), &id],
            )?;
        }
    }
    let (encrypted_key, nonce) = crypto::encrypt(new_key, db_key)?;
    tx.execute(
        "UPDATE project_key SET encrypted_key = ?1, key_nonce = ?2 WHERE project_id = ?3",
        rusqlite::params![&encrypted_key, nonce.as_ref(), project_id],
    )?;
    tx.commit()?;
    Ok(())
}
