use crate::{db::Db, error::Result, models::now};

#[derive(Debug, Clone)]
pub struct Tombstone {
    pub id: String,
    pub kind: String,
    pub project_id: String,
    pub deleted_at: i64,
}

pub fn record(db: &Db, id: &str, kind: &str, project_id: &str) -> Result<()> {
    db.conn().execute(
        "INSERT OR REPLACE INTO tombstone (id, kind, project_id, deleted_at) VALUES (?1,?2,?3,?4)",
        rusqlite::params![id, kind, project_id, now()],
    )?;
    Ok(())
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Tombstone>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, kind, project_id, deleted_at FROM tombstone WHERE project_id = ?1",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok(Tombstone { id: r.get(0)?, kind: r.get(1)?, project_id: r.get(2)?, deleted_at: r.get(3)? })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}
