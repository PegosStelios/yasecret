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
    };
    db.conn().execute(
        "INSERT INTO environment (id, project_id, name, created_at) VALUES (?1,?2,?3,?4)",
        rusqlite::params![&e.id, &e.project_id, &e.name, e.created_at],
    )?;
    Ok(e)
}

pub fn get(db: &Db, id: &str) -> Result<Environment> {
    db.conn()
        .query_row(
            "SELECT id, project_id, name, created_at FROM environment WHERE id = ?1",
            [id],
            |r| {
                Ok(Environment {
                    id: r.get(0)?,
                    project_id: r.get(1)?,
                    name: r.get(2)?,
                    created_at: r.get(3)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("environment {id}")))
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Environment>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, project_id, name, created_at FROM environment WHERE project_id = ?1 ORDER BY created_at",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok(Environment {
            id: r.get(0)?,
            project_id: r.get(1)?,
            name: r.get(2)?,
            created_at: r.get(3)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn rename(db: &Db, id: &str, new_name: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE environment SET name = ?1 WHERE id = ?2",
        rusqlite::params![new_name, id],
    )?;
    if n == 0 { return Err(YasecretError::NotFound(format!("environment {id}"))); }
    Ok(())
}

pub fn delete(db: &Db, id: &str) -> Result<()> {
    db.conn()
        .execute("DELETE FROM environment WHERE id = ?1", [id])?;
    Ok(())
}
