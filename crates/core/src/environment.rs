use crate::{
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Environment},
};

pub fn create(db: &Db, project_id: &str, name: &str) -> Result<Environment> {
    let e = Environment {
        id: new_id(),
        project_id: project_id.to_string(),
        name: name.to_string(),
        created_at: now(),
        updated_at: now(),
        inherits_from: None,
    };
    db.conn().execute(
        "INSERT INTO environment (id, project_id, name, created_at, updated_at) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![&e.id, &e.project_id, &e.name, e.created_at, e.updated_at],
    )?;
    Ok(e)
}

pub fn get(db: &Db, id: &str) -> Result<Environment> {
    db.conn()
        .query_row(
            "SELECT id, project_id, name, created_at, updated_at, inherits_from FROM environment WHERE id = ?1",
            [id],
            |r| {
                Ok(Environment {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    name: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                    inherits_from: r.get(5)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("environment {id}")))
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Environment>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, project_id, name, created_at, updated_at, inherits_from FROM environment WHERE project_id = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok(Environment {
            id: r.get(0)?,
            project_id: r.get(1)?,
            name: r.get(2)?,
            created_at: r.get(3)?,
            updated_at: r.get(4)?,
            inherits_from: r.get(5)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

/// Makes `env_id` inherit `parent`'s variables, or stop inheriting with `None`. The parent
/// must be in the same project and must not (directly or not) inherit from `env_id`.
pub fn set_parent(db: &Db, env_id: &str, parent: Option<&str>) -> Result<()> {
    let env = get(db, env_id)?;
    if let Some(parent_id) = parent {
        let mut cur = Some(parent_id.to_string());
        let mut depth = 0;
        while let Some(id) = cur {
            if id == env_id || depth > 32 {
                return Err(YasecretError::EnvParse(format!("“{}” can't inherit from an environment that inherits from it", env.name)));
            }
            let e = get(db, &id)?;
            if e.project_id != env.project_id {
                return Err(YasecretError::EnvParse("an environment can only inherit from one in the same project".into()));
            }
            cur = e.inherits_from;
            depth += 1;
        }
    }
    db.conn().execute(
        "UPDATE environment SET inherits_from = ?1, updated_at = MAX(?2, updated_at + 1) WHERE id = ?3",
        rusqlite::params![parent, now(), env_id],
    )?;
    Ok(())
}

pub fn rename(db: &Db, id: &str, new_name: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE environment SET name = ?1, updated_at = MAX(?2, updated_at + 1) WHERE id = ?3",
        rusqlite::params![new_name, now(), id],
    )?;
    if n == 0 { return Err(YasecretError::NotFound(format!("environment {id}"))); }
    Ok(())
}

pub fn clone(db: &Db, source_id: &str, new_name: &str) -> Result<Environment> {
    let src = get(db, source_id)?;
    let mut e = create(db, &src.project_id, new_name)?;
    if let Some(parent) = &src.inherits_from {
        set_parent(db, &e.id, Some(parent))?;
        e.inherits_from = Some(parent.clone());
    }
    let ts = now();
    for s in crate::secret::list(db, source_id)? {
        db.conn().execute(
            "INSERT INTO secret (id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret)
             VALUES (?1,?2,?3,?4,?5,?6,?6,?7,?8,?9)",
            rusqlite::params![new_id(), &e.id, &s.key, &s.encrypted_value, &s.nonce, ts, &s.created_by, s.expires_at, s.is_secret],
        )?;
    }
    Ok(e)
}

pub fn secret_count(db: &Db, id: &str) -> Result<u32> {
    let n: i64 = db.conn().query_row(
        "SELECT count(*) FROM secret WHERE env_id = ?1",
        [id],
        |r| r.get(0),
    )?;
    Ok(n as u32)
}

pub fn delete(db: &Db, id: &str) -> Result<()> {
    let env = get(db, id)?;
    for s in crate::secret::list(db, id)? {
        crate::tombstone::record(db, &s.id, "secret", &env.project_id)?;
    }
    db.conn()
        .execute("DELETE FROM environment WHERE id = ?1", [id])?;
    crate::tombstone::record(db, id, "env", &env.project_id)?;
    // Environments that inherited from it stand on their own now.
    db.conn().execute(
        "UPDATE environment SET inherits_from = NULL, updated_at = MAX(?1, updated_at + 1) WHERE inherits_from = ?2",
        rusqlite::params![now(), id],
    )?;
    Ok(())
}
