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
            "SELECT id, project_id, name, created_at, updated_at FROM environment WHERE id = ?1",
            [id],
            |r| {
                Ok(Environment {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    name: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("environment {id}")))
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Environment>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, project_id, name, created_at, updated_at FROM environment WHERE project_id = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok(Environment {
            id: r.get(0)?,
            project_id: r.get(1)?,
            name: r.get(2)?,
            created_at: r.get(3)?,
            updated_at: r.get(4)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn rename(db: &Db, id: &str, new_name: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE environment SET name = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![new_name, now(), id],
    )?;
    if n == 0 { return Err(YasecretError::NotFound(format!("environment {id}"))); }
    Ok(())
}

pub fn clone(db: &Db, source_id: &str, new_name: &str) -> Result<Environment> {
    let src = get(db, source_id)?;
    let e = create(db, &src.project_id, new_name)?;
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
    Ok(())
}
