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
        "SELECT id,peer_id,action,target_type,target_id,timestamp,detail,origin,actor_name FROM audit_entry ORDER BY timestamp DESC LIMIT ?1",
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
            origin: r.get(7)?,
            actor_name: r.get(8)?,
        })
    })?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

/// This device's own activity on a project's variables that isn't in `published` yet.
pub fn unpublished(db: &Db, project_id: &str, published: &std::collections::HashSet<String>, limit: usize) -> Result<Vec<AuditEntry>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,peer_id,action,target_type,target_id,timestamp,detail,origin,actor_name FROM audit_entry
         WHERE origin IS NULL AND peer_id != 'sync'
           AND (target_id IN (SELECT s.id FROM secret s JOIN environment e ON e.id = s.env_id WHERE e.project_id = ?1)
                OR target_id IN (SELECT id FROM tombstone WHERE project_id = ?1))
         ORDER BY timestamp",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        Ok(AuditEntry {
            id: r.get(0)?,
            peer_id: r.get(1)?,
            action: r.get(2)?,
            target_type: r.get(3)?,
            target_id: r.get(4)?,
            timestamp: r.get(5)?,
            detail: r.get(6)?,
            origin: r.get(7)?,
            actor_name: r.get(8)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        let e = row?;
        if !published.contains(&e.id) {
            out.push(e);
            if out.len() >= limit {
                break;
            }
        }
    }
    Ok(out)
}

/// Records an entry that happened on another device; ignored if it's already here.
#[allow(clippy::too_many_arguments)]
pub fn insert_remote(
    db: &Db,
    id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    timestamp: i64,
    detail: Option<&str>,
    origin: &str,
    actor_name: &str,
) -> Result<bool> {
    let n = db.conn().execute(
        "INSERT OR IGNORE INTO audit_entry (id,peer_id,action,target_type,target_id,timestamp,detail,origin,actor_name)
         VALUES (?1,'remote',?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![id, action, target_type, target_id, timestamp, detail, origin, actor_name],
    )?;
    Ok(n > 0)
}
