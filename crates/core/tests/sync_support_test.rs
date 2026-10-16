use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret, version};

fn setup() -> (tempfile::TempDir, Db, [u8; 32], String, String) {
    let dir = tempdir().unwrap();
    let db = Db::open(&dir.path().join("t.sqlite"), "pw").unwrap();
    let db_key = crypto::derive_db_key("pw", &crypto::generate_salt());
    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    (dir, db, *db_key, p.id, e.id)
}

#[test]
fn deleting_secret_records_tombstone_with_project() {
    let (_d, db, db_key, pid, env) = setup();
    let k = project_key::load(&db, &pid, &db_key).unwrap();
    let s = secret::create(&db, &env, "A", b"1", &k, "owner", None).unwrap();
    secret::delete(&db, &s.id, "owner").unwrap();
    let t = yasecret_core::tombstone::list(&db, &pid).unwrap();
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].id, s.id);
    assert_eq!(t[0].kind, "secret");
}

#[test]
fn deleting_environment_records_tombstone() {
    let (_d, db, _k, pid, env) = setup();
    environment::delete(&db, &env).unwrap();
    let t = yasecret_core::tombstone::list(&db, &pid).unwrap();
    assert!(t.iter().any(|t| t.id == env && t.kind == "env"));
}

#[test]
fn environment_has_updated_at_that_moves_on_rename() {
    let (_d, db, _k, _pid, env) = setup();
    let before = environment::get(&db, &env).unwrap().updated_at;
    std::thread::sleep(std::time::Duration::from_millis(1100));
    environment::rename(&db, &env, "development").unwrap();
    assert!(environment::get(&db, &env).unwrap().updated_at > before);
}

#[test]
fn store_existing_project_key_roundtrips() {
    let (_d, db, db_key, _pid, _env) = setup();
    let p2 = project::create(&db, "joined", None, "someone").unwrap();
    let key = [7u8; 32];
    project_key::store(&db, &p2.id, &key, &db_key).unwrap();
    assert_eq!(*project_key::load(&db, &p2.id, &db_key).unwrap(), key);
}

#[test]
fn rotate_reencrypts_values_and_history() {
    let (_d, db, db_key, pid, env) = setup();
    let old = project_key::load(&db, &pid, &db_key).unwrap();
    let s = secret::create(&db, &env, "A", b"v1", &old, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &old, "owner", None).unwrap();

    project_key::rotate(&db, &pid, &db_key).unwrap();
    let new = project_key::load(&db, &pid, &db_key).unwrap();
    assert_ne!(*new, *old);
    assert_eq!(secret::get_plaintext(&db, &s.id, &new).unwrap().as_slice(), b"v2");
    let v = &version::list(&db, &s.id).unwrap()[0];
    let nonce: [u8; 12] = v.nonce.clone().try_into().unwrap();
    assert_eq!(crypto::decrypt(&v.encrypted_value, &nonce, &new).unwrap().as_slice(), b"v1");
}
