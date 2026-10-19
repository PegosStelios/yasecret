//! Write access to shared projects for code that runs without the sync service (CLI, MCP).
//! Changes from viewers or not-yet-admitted members never sync, so they're refused up front.

use crate::{db::Db, error::YasecretError, identity, project, Result};

pub fn ensure_can_write(db: &Db, project_id: &str) -> Result<()> {
    let row: Option<(Option<String>, Option<String>)> = db
        .conn()
        .query_row(
            "SELECT owner_sign_pub, my_level FROM sync_doc WHERE project_id = ?1",
            [project_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let Some((Some(owner), level)) = row else { return Ok(()) };
    let mine = hex::encode(identity::load(db)?.signing_key().verifying_key().to_bytes());
    if owner == mine {
        return Ok(());
    }
    let name = project::get(db, project_id)?.name;
    match level.as_deref() {
        Some("owner") | Some("editor") => Ok(()),
        Some("viewer") => Err(YasecretError::ReadOnly(format!(
            "“{name}” was shared with you as view-only, so changes can't be made here"
        ))),
        Some("removed") => Err(YasecretError::ReadOnly(format!("You no longer have access to change “{name}”"))),
        // Pending, or not synced since joining: the owner hasn't admitted this device yet.
        _ => Err(YasecretError::ReadOnly(format!(
            "“{name}” is waiting for its owner to admit this device; changes can be made once they have"
        ))),
    }
}
