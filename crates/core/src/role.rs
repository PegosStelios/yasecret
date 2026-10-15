use ed25519_dalek::SigningKey;

use crate::{
    crypto,
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Role, RoleLevel},
};

fn sign_role_msg(project_id: &str, env_id: Option<&str>, peer_id: &str, level: &RoleLevel, granted_at: i64) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        project_id,
        env_id.unwrap_or("*"),
        peer_id,
        level.as_str(),
        granted_at
    )
}

pub fn grant(
    db: &Db,
    project_id: &str,
    env_id: Option<&str>,
    peer_id: &str,
    level: RoleLevel,
    signing_key: &SigningKey,
) -> Result<Role> {
    let granted_at = now();
    let msg = sign_role_msg(project_id, env_id, peer_id, &level, granted_at);
    let sig = crypto::sign(msg.as_bytes(), signing_key);
    let r = Role {
        id: new_id(),
        project_id: project_id.to_string(),
        env_id: env_id.map(String::from),
        peer_id: peer_id.to_string(),
        level,
        granted_at,
        signature: sig,
    };
    db.conn().execute(
        "INSERT INTO role (id,project_id,env_id,peer_id,level,granted_at,signature) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            &r.id, &r.project_id, &r.env_id, &r.peer_id,
            r.level.as_str(), r.granted_at, &r.signature
        ],
    )?;
    Ok(r)
}

/// Returns the most specific role for peer_id: env-specific beats project-wide.
pub fn check(db: &Db, project_id: &str, env_id: Option<&str>, peer_id: &str) -> Result<RoleLevel> {
    let mut stmt = db.conn().prepare(
        "SELECT level FROM role
         WHERE project_id=?1 AND peer_id=?2
           AND (env_id=?3 OR env_id IS NULL)
         ORDER BY CASE WHEN env_id IS NOT NULL THEN 0 ELSE 1 END
         LIMIT 1",
    )?;
    let level_str: String = stmt
        .query_row(rusqlite::params![project_id, peer_id, env_id], |r| r.get(0))
        .map_err(|_| YasecretError::PermissionDenied)?;
    RoleLevel::from_str(&level_str).ok_or(YasecretError::PermissionDenied)
}

pub fn verify_signature(role: &Role, owner_vk_bytes: &[u8; 32]) -> Result<()> {
    let msg = sign_role_msg(
        &role.project_id,
        role.env_id.as_deref(),
        &role.peer_id,
        &role.level,
        role.granted_at,
    );
    crypto::verify(msg.as_bytes(), &role.signature, owner_vk_bytes)
}

pub fn revoke(db: &Db, role_id: &str) -> Result<()> {
    db.conn()
        .execute("DELETE FROM role WHERE id=?1", [role_id])?;
    Ok(())
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Role>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,project_id,env_id,peer_id,level,granted_at,signature FROM role WHERE project_id=?1",
    )?;
    let rows = stmt.query_map([project_id], |r| {
        let level_str: String = r.get(4)?;
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, Option<String>>(2)?,
            r.get::<_, String>(3)?,
            level_str,
            r.get::<_, i64>(5)?,
            r.get::<_, Vec<u8>>(6)?,
        ))
    })?;
    let mut out = vec![];
    for row in rows {
        let (id, pid, eid, peer_id, level_str, granted_at, sig) = row?;
        out.push(Role {
            id,
            project_id: pid,
            env_id: eid,
            peer_id,
            level: RoleLevel::from_str(&level_str).unwrap_or(RoleLevel::Read),
            granted_at,
            signature: sig,
        });
    }
    Ok(out)
}
