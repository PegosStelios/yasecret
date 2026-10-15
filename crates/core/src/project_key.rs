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
