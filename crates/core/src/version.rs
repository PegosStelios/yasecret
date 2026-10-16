use crate::{
    crypto,
    db::Db,
    error::{Result, YasecretError},
    models::SecretVersion,
    secret,
};

pub fn list(db: &Db, secret_id: &str) -> Result<Vec<SecretVersion>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,secret_id,encrypted_value,nonce,changed_by,changed_at,note FROM secret_version WHERE secret_id=?1 ORDER BY changed_at DESC, rowid DESC",
    )?;
    let rows = stmt.query_map([secret_id], |r| {
        Ok(SecretVersion {
            id: r.get(0)?,
            secret_id: r.get(1)?,
            encrypted_value: r.get(2)?,
            nonce: r.get(3)?,
            changed_by: r.get(4)?,
            changed_at: r.get(5)?,
            note: r.get(6)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn rollback(
    db: &Db,
    secret_id: &str,
    version_id: &str,
    project_key: &[u8; 32],
    caller_id: &str,
) -> Result<()> {
    let v: SecretVersion = db
        .conn()
        .query_row(
            "SELECT id,secret_id,encrypted_value,nonce,changed_by,changed_at,note FROM secret_version WHERE id=?1",
            [version_id],
            |r| {
                Ok(SecretVersion {
                    id: r.get(0)?,
                    secret_id: r.get(1)?,
                    encrypted_value: r.get(2)?,
                    nonce: r.get(3)?,
                    changed_by: r.get(4)?,
                    changed_at: r.get(5)?,
                    note: r.get(6)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("version {version_id}")))?;
    if v.secret_id != secret_id {
        return Err(YasecretError::NotFound(format!("version {version_id} of {secret_id}")));
    }

    let nonce: [u8; 12] = v.nonce.try_into().map_err(|_| YasecretError::Crypto)?;
    let plaintext = crypto::decrypt(&v.encrypted_value, &nonce, project_key)?;
    secret::update(db, secret_id, &plaintext, project_key, caller_id, Some("rollback"))?;
    Ok(())
}
