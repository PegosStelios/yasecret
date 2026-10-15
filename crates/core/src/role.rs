// Stub — full implementation in Task 8
use ed25519_dalek::SigningKey;
use crate::{
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Role, RoleLevel},
};

pub fn grant(_db: &Db, _project_id: &str, _env_id: Option<&str>, _peer_id: &str, _level: RoleLevel, _signing_key: &SigningKey) -> Result<Role> {
    unimplemented!("Task 8")
}

pub fn check(_db: &Db, _project_id: &str, _env_id: Option<&str>, _peer_id: &str) -> Result<RoleLevel> {
    Err(YasecretError::PermissionDenied)
}

pub fn verify_signature(_role: &Role, _owner_vk_bytes: &[u8; 32]) -> Result<()> {
    unimplemented!("Task 8")
}

pub fn revoke(_db: &Db, _role_id: &str) -> Result<()> {
    unimplemented!("Task 8")
}

pub fn list(_db: &Db, _project_id: &str) -> Result<Vec<Role>> {
    unimplemented!("Task 8")
}
