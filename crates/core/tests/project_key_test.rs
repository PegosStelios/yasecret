use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, project, project_key};

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    (dir, db)
}

fn db_key() -> zeroize::Zeroizing<[u8; 32]> {
    let salt = crypto::generate_salt();
    crypto::derive_db_key("pw", &salt)
}

#[test]
fn store_and_load_project_key() {
    let (_dir, db) = open_db();
    let key = db_key();
    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &key).unwrap();
    let loaded1 = project_key::load(&db, &p.id, &key).unwrap();
    let loaded2 = project_key::load(&db, &p.id, &key).unwrap();
    assert_eq!(loaded1.as_ref(), loaded2.as_ref());
}

#[test]
fn wrong_db_key_fails_decrypt() {
    let (_dir, db) = open_db();
    let salt = crypto::generate_salt();
    let good_key = crypto::derive_db_key("pw", &salt);
    let bad_key = crypto::derive_db_key("wrong", &salt);
    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &good_key).unwrap();
    assert!(project_key::load(&db, &p.id, &bad_key).is_err());
}

#[test]
fn missing_project_key_returns_not_found() {
    let (_dir, db) = open_db();
    let key = db_key();
    assert!(project_key::load(&db, "nonexistent-project", &key).is_err());
}
