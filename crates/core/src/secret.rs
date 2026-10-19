use zeroize::Zeroizing;

use crate::{
    audit,
    crypto,
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Secret},
};

pub fn create(
    db: &Db,
    env_id: &str,
    key: &str,
    plaintext: &[u8],
    project_key: &[u8; 32],
    caller_id: &str,
    expires_at: Option<i64>,
) -> Result<Secret> {
    create_with_kind(db, env_id, key, plaintext, project_key, caller_id, expires_at, true)
}

#[allow(clippy::too_many_arguments)]
pub fn create_with_kind(
    db: &Db,
    env_id: &str,
    key: &str,
    plaintext: &[u8],
    project_key: &[u8; 32],
    caller_id: &str,
    expires_at: Option<i64>,
    is_secret: bool,
) -> Result<Secret> {
    let (enc, nonce) = crypto::encrypt(plaintext, project_key)?;
    let s = Secret {
        id: new_id(),
        env_id: env_id.to_string(),
        key: key.to_string(),
        encrypted_value: enc,
        nonce: nonce.to_vec(),
        created_at: now(),
        updated_at: now(),
        created_by: caller_id.to_string(),
        expires_at,
        is_secret,
    };
    db.conn().execute(
        "INSERT INTO secret (id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            &s.id, &s.env_id, &s.key,
            &s.encrypted_value, &s.nonce,
            s.created_at, s.updated_at,
            &s.created_by, s.expires_at, s.is_secret
        ],
    )?;
    audit::append(db, caller_id, "created_secret", "secret", &s.id, None)?;
    Ok(s)
}

/// create_checked enforces role before writing.
pub fn create_checked(
    db: &Db,
    env_id: &str,
    project_id: &str,
    key: &str,
    plaintext: &[u8],
    project_key: &[u8; 32],
    caller_id: &str,
    expires_at: Option<i64>,
) -> Result<Secret> {
    let level = crate::role::check(db, project_id, Some(env_id), caller_id)
        .or_else(|_| crate::role::check(db, project_id, None, caller_id))?;
    if !level.can_write() {
        return Err(YasecretError::PermissionDenied);
    }
    create(db, env_id, key, plaintext, project_key, caller_id, expires_at)
}

pub fn get_plaintext(db: &Db, secret_id: &str, project_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let s = get_raw(db, secret_id)?;
    let nonce: [u8; 12] = s.nonce.try_into().map_err(|_| YasecretError::Crypto)?;
    crypto::decrypt(&s.encrypted_value, &nonce, project_key)
}

pub fn list(db: &Db, env_id: &str) -> Result<Vec<Secret>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret FROM secret WHERE env_id=?1 ORDER BY key",
    )?;
    let rows = stmt.query_map([env_id], |r| {
        Ok(Secret {
            id: r.get(0)?,
            env_id: r.get(1)?,
            key: r.get(2)?,
            encrypted_value: r.get(3)?,
            nonce: r.get(4)?,
            created_at: r.get(5)?,
            updated_at: r.get(6)?,
            created_by: r.get(7)?,
            expires_at: r.get(8)?,
            is_secret: r.get(9)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn update(
    db: &Db,
    secret_id: &str,
    new_plaintext: &[u8],
    project_key: &[u8; 32],
    caller_id: &str,
    note: Option<&str>,
) -> Result<Secret> {
    let old = get_raw(db, secret_id)?;
    // Archive current value as a version
    db.conn().execute(
        "INSERT INTO secret_version (id,secret_id,encrypted_value,nonce,changed_by,changed_at,note) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![new_id(), &old.id, &old.encrypted_value, &old.nonce, caller_id, now(), note],
    )?;
    let (enc, nonce) = crypto::encrypt(new_plaintext, project_key)?;
    db.conn().execute(
        "UPDATE secret SET encrypted_value=?1, nonce=?2, updated_at=MAX(?3, updated_at + 1) WHERE id=?4",
        rusqlite::params![&enc, nonce.as_ref(), now(), secret_id],
    )?;
    audit::append(db, caller_id, "updated_secret", "secret", secret_id, None)?;
    get_raw(db, secret_id)
}

pub fn set_kind(db: &Db, secret_id: &str, is_secret: bool, caller_id: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE secret SET is_secret=?1, updated_at=MAX(?2, updated_at + 1) WHERE id=?3",
        rusqlite::params![is_secret, now(), secret_id],
    )?;
    if n == 0 {
        return Err(YasecretError::NotFound(format!("secret {secret_id}")));
    }
    let detail = if is_secret { "secret" } else { "plain" };
    audit::append(db, caller_id, "changed_kind", "secret", secret_id, Some(detail))?;
    Ok(())
}

pub fn set_expiry(db: &Db, secret_id: &str, expires_at: Option<i64>, caller_id: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE secret SET expires_at=?1, updated_at=MAX(?2, updated_at + 1) WHERE id=?3",
        rusqlite::params![expires_at, now(), secret_id],
    )?;
    if n == 0 {
        return Err(YasecretError::NotFound(format!("secret {secret_id}")));
    }
    audit::append(db, caller_id, "changed_expiry", "secret", secret_id, None)?;
    Ok(())
}

pub fn rename_key(db: &Db, secret_id: &str, new_key: &str, caller_id: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE secret SET key=?1, updated_at=MAX(?2, updated_at + 1) WHERE id=?3",
        rusqlite::params![new_key, now(), secret_id],
    )?;
    if n == 0 {
        return Err(YasecretError::NotFound(format!("secret {secret_id}")));
    }
    audit::append(db, caller_id, "renamed_secret", "secret", secret_id, Some(new_key))?;
    Ok(())
}

pub fn delete(db: &Db, secret_id: &str, caller_id: &str) -> Result<()> {
    let project_id: Option<String> = db.conn().query_row(
        "SELECT e.project_id FROM secret s JOIN environment e ON e.id = s.env_id WHERE s.id = ?1",
        [secret_id],
        |r| r.get(0),
    ).ok();
    if let Some(pid) = project_id {
        crate::tombstone::record(db, secret_id, "secret", &pid)?;
    }
    let key: Option<String> = db.conn()
        .query_row("SELECT key FROM secret WHERE id=?1", [secret_id], |r| r.get(0))
        .ok();
    db.conn()
        .execute("DELETE FROM secret WHERE id=?1", [secret_id])?;
    audit::append(db, caller_id, "deleted_secret", "secret", secret_id, key.as_deref())?;
    Ok(())
}

pub(crate) fn get_raw(db: &Db, id: &str) -> Result<Secret> {
    db.conn()
        .query_row(
            "SELECT id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret FROM secret WHERE id=?1",
            [id],
            |r| {
                Ok(Secret {
                    id: r.get(0)?,
                    env_id: r.get(1)?,
                    key: r.get(2)?,
                    encrypted_value: r.get(3)?,
                    nonce: r.get(4)?,
                    created_at: r.get(5)?,
                    updated_at: r.get(6)?,
                    created_by: r.get(7)?,
                    expires_at: r.get(8)?,
                    is_secret: r.get(9)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("secret {id}")))
}
