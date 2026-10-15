use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, models::RoleLevel, project, project_key, role, secret};

fn setup() -> (tempfile::TempDir, Db, SigningKey, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let p = project::create(&db, "app", None, "owner").unwrap();
    (dir, db, sk, p.id)
}

#[test]
fn grant_and_check_role() {
    let (_dir, db, sk, pid) = setup();
    role::grant(&db, &pid, None, "peer-1", RoleLevel::Write, &sk).unwrap();
    let level = role::check(&db, &pid, None, "peer-1").unwrap();
    assert!(level.can_write());
}

#[test]
fn env_specific_role_overrides_project_role() {
    let (_dir, db, sk, pid) = setup();
    role::grant(&db, &pid, None, "peer-1", RoleLevel::Read, &sk).unwrap();
    role::grant(&db, &pid, Some("env-1"), "peer-1", RoleLevel::Admin, &sk).unwrap();
    let level = role::check(&db, &pid, Some("env-1"), "peer-1").unwrap();
    assert_eq!(level, RoleLevel::Admin);
}

#[test]
fn no_role_returns_permission_denied() {
    let (_dir, db, _, pid) = setup();
    let result = role::check(&db, &pid, None, "unknown-peer");
    assert!(result.is_err());
}

#[test]
fn signature_verifies_correctly() {
    let (_dir, db, sk, pid) = setup();
    let r = role::grant(&db, &pid, None, "peer-2", RoleLevel::Read, &sk).unwrap();
    let vk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    assert!(role::verify_signature(&r, &vk_bytes).is_ok());
}

#[test]
fn tampered_signature_rejected() {
    let (_dir, db, sk, pid) = setup();
    let mut r = role::grant(&db, &pid, None, "peer-2", RoleLevel::Read, &sk).unwrap();
    r.signature[0] ^= 0xff; // corrupt
    let vk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    assert!(role::verify_signature(&r, &vk_bytes).is_err());
}

#[test]
fn revoke_removes_role() {
    let (_dir, db, sk, pid) = setup();
    let r = role::grant(&db, &pid, None, "peer-3", RoleLevel::Write, &sk).unwrap();
    role::revoke(&db, &r.id).unwrap();
    assert!(role::check(&db, &pid, None, "peer-3").is_err());
}

// Review Focus: create_checked blocks read-only peer
#[test]
fn write_blocked_for_read_only_peer() {
    let (_dir, db, sk, pid) = setup();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);
    project_key::create(&db, &pid, &db_key).unwrap();
    let proj_key = project_key::load(&db, &pid, &db_key).unwrap();

    let e = environment::create(&db, &pid, "dev").unwrap();
    role::grant(&db, &pid, None, "reader", RoleLevel::Read, &sk).unwrap();

    let result = secret::create_checked(
        &db, &e.id, &pid, "KEY", b"val", &proj_key, "reader", None,
    );
    assert!(matches!(result, Err(yasecret_core::YasecretError::PermissionDenied)));
}

// Review Focus: write-level peer succeeds
#[test]
fn write_allowed_for_write_peer() {
    let (_dir, db, sk, pid) = setup();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);
    project_key::create(&db, &pid, &db_key).unwrap();
    let proj_key = project_key::load(&db, &pid, &db_key).unwrap();

    let e = environment::create(&db, &pid, "dev").unwrap();
    role::grant(&db, &pid, None, "writer", RoleLevel::Write, &sk).unwrap();

    secret::create_checked(
        &db, &e.id, &pid, "KEY", b"val", &proj_key, "writer", None,
    ).unwrap();
}
