use crate::{
    db::Db,
    error::Result,
    models::{now, new_id, AuditEntry},
};

pub fn append(
    db: &Db,
    peer_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    detail: Option<&str>,
) -> Result<()> {
    db.conn().execute(
        "INSERT INTO audit_entry (id,peer_id,action,target_type,target_id,timestamp,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![new_id(), peer_id, action, target_type, target_id, now(), detail],
    )?;
    Ok(())
}

pub fn list(db: &Db, limit: i64) -> Result<Vec<AuditEntry>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,peer_id,action,target_type,target_id,timestamp,detail FROM audit_entry ORDER BY timestamp DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit], |r| {
        Ok(AuditEntry {
            id: r.get(0)?,
            peer_id: r.get(1)?,
            action: r.get(2)?,
            target_type: r.get(3)?,
            target_id: r.get(4)?,
            timestamp: r.get(5)?,
            detail: r.get(6)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}
