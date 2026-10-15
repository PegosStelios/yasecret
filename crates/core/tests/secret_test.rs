use tempfile::tempdir;
use yasecret_core::{audit, crypto, db::Db, environment, project, project_key, secret, version};

fn setup() -> (tempfile::TempDir, Db, [u8; 32], String, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);

    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key_raw = project_key::load(&db, &p.id, &db_key).unwrap();
    let proj_key: [u8; 32] = *proj_key_raw;

    let e = environment::create(&db, &p.id, "dev").unwrap();
    (dir, db, proj_key, e.id, p.id)
}

#[test]
fn create_and_read_secret() {
    let (_dir, db, proj_key, env_id, _pid) = setup();
    let s = secret::create(&db, &env_id, "API_KEY", b"super-secret", &proj_key, "owner", None).unwrap();
    let plaintext = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(plaintext.as_slice(), b"super-secret");
}

#[test]
fn update_creates_version() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "DB_URL", b"v1", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let versions = version::list(&db, &s.id).unwrap();
    assert_eq!(versions.len(), 1);
    let current = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(current.as_slice(), b"v2");
}

#[test]
fn rollback_restores_old_value() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "DB_URL", b"v1", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let versions = version::list(&db, &s.id).unwrap();
    version::rollback(&db, &s.id, &versions[0].id, &proj_key, "owner").unwrap();
    let current = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(current.as_slice(), b"v1");
}

#[test]
fn audit_entries_recorded() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "K", b"v", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let entries = audit::list(&db, 10).unwrap();
    assert!(entries.len() >= 2);
    assert!(entries.iter().any(|e| e.action == "created_secret"));
    assert!(entries.iter().any(|e| e.action == "updated_secret"));
}

#[test]
fn delete_secret() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "GONE", b"v", &proj_key, "owner", None).unwrap();
    secret::delete(&db, &s.id, "owner").unwrap();
    let list = secret::list(&db, &env_id).unwrap();
    assert!(list.is_empty());
}

#[test]
fn list_secrets_sorted_by_key() {
    let (_dir, db, proj_key, env_id, _) = setup();
    secret::create(&db, &env_id, "ZZZ", b"z", &proj_key, "owner", None).unwrap();
    secret::create(&db, &env_id, "AAA", b"a", &proj_key, "owner", None).unwrap();
    let list = secret::list(&db, &env_id).unwrap();
    assert_eq!(list[0].key, "AAA");
    assert_eq!(list[1].key, "ZZZ");
}

#[test]
fn expires_at_stored() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let future = yasecret_core::models::now() + 86400;
    let s = secret::create(&db, &env_id, "EXPIRING", b"v", &proj_key, "owner", Some(future)).unwrap();
    assert_eq!(s.expires_at, Some(future));
}
