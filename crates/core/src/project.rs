use crate::{
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Project},
};

pub fn create(db: &Db, name: &str, description: Option<&str>, owner_id: &str) -> Result<Project> {
    let p = Project {
        id: new_id(),
        name: name.to_string(),
        description: description.map(String::from),
        created_at: now(),
        owner_id: owner_id.to_string(),
        updated_at: now(),
    };
    db.conn().execute(
        "INSERT INTO project (id, name, description, created_at, owner_id, updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![&p.id, &p.name, &p.description, p.created_at, &p.owner_id, p.updated_at],
    )?;
    Ok(p)
}

pub fn get(db: &Db, id: &str) -> Result<Project> {
    db.conn()
        .query_row(
            "SELECT id, name, description, created_at, owner_id, updated_at FROM project WHERE id = ?1",
            [id],
            |r| {
                Ok(Project {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    created_at: r.get(3)?,
                    owner_id: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound(format!("project {id}")))
}

pub fn list(db: &Db) -> Result<Vec<Project>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, description, created_at, owner_id, updated_at FROM project ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(Project {
            id: r.get(0)?,
            name: r.get(1)?,
            description: r.get(2)?,
            created_at: r.get(3)?,
            owner_id: r.get(4)?,
            updated_at: r.get(5)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn rename(db: &Db, id: &str, new_name: &str) -> Result<()> {
    let n = db.conn().execute(
        "UPDATE project SET name = ?1, updated_at = MAX(?2, updated_at + 1) WHERE id = ?3",
        rusqlite::params![new_name, now(), id],
    )?;
    if n == 0 { return Err(YasecretError::NotFound(format!("project {id}"))); }
    Ok(())
}

pub fn delete(db: &Db, id: &str) -> Result<()> {
    db.conn()
        .execute("DELETE FROM project WHERE id = ?1", [id])?;
    Ok(())
}
