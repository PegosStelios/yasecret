use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, env_file, environment, project, project_key, secret};

fn setup() -> (tempfile::TempDir, Db, [u8; 32], String, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);
    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key: [u8; 32] = *project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    (dir, db, proj_key, e.id, p.id)
}

#[test]
fn new_secret_defaults_to_secret_kind() {
    let (_d, db, k, env, _) = setup();
    let s = secret::create(&db, &env, "API_KEY", b"v", &k, "owner", None).unwrap();
    assert!(s.is_secret);
    assert!(secret::list(&db, &env).unwrap()[0].is_secret);
}

#[test]
fn set_kind_marks_variable_plain() {
    let (_d, db, k, env, _) = setup();
    let s = secret::create(&db, &env, "PORT", b"3000", &k, "owner", None).unwrap();
    secret::set_kind(&db, &s.id, false, "owner").unwrap();
    assert!(!secret::list(&db, &env).unwrap()[0].is_secret);
}

#[test]
fn rename_key_changes_key_and_keeps_value() {
    let (_d, db, k, env, _) = setup();
    let s = secret::create(&db, &env, "OLD", b"val", &k, "owner", None).unwrap();
    secret::rename_key(&db, &s.id, "NEW", "owner").unwrap();
    let all = secret::list(&db, &env).unwrap();
    assert_eq!(all[0].key, "NEW");
    assert_eq!(secret::get_plaintext(&db, &s.id, &k).unwrap().as_slice(), b"val");
}

#[test]
fn rename_key_to_existing_key_fails() {
    let (_d, db, k, env, _) = setup();
    secret::create(&db, &env, "A", b"1", &k, "owner", None).unwrap();
    let b = secret::create(&db, &env, "B", b"2", &k, "owner", None).unwrap();
    assert!(secret::rename_key(&db, &b.id, "A", "owner").is_err());
}

#[test]
fn clone_environment_copies_values_and_kinds() {
    let (_d, db, k, env, pid) = setup();
    let a = secret::create(&db, &env, "DB_URL", b"postgres://x", &k, "owner", None).unwrap();
    let p = secret::create(&db, &env, "PORT", b"3000", &k, "owner", None).unwrap();
    secret::set_kind(&db, &p.id, false, "owner").unwrap();

    let clone = environment::clone(&db, &env, "staging").unwrap();
    assert_eq!(clone.project_id, pid);
    assert_eq!(clone.name, "staging");
    let copied = secret::list(&db, &clone.id).unwrap();
    assert_eq!(copied.len(), 2);
    let db_url = copied.iter().find(|s| s.key == "DB_URL").unwrap();
    assert_ne!(db_url.id, a.id);
    assert!(db_url.is_secret);
    assert_eq!(secret::get_plaintext(&db, &db_url.id, &k).unwrap().as_slice(), b"postgres://x");
    assert!(!copied.iter().find(|s| s.key == "PORT").unwrap().is_secret);
}

#[test]
fn secret_count_counts_per_environment() {
    let (_d, db, k, env, pid) = setup();
    let other = environment::create(&db, &pid, "prod").unwrap();
    secret::create(&db, &env, "A", b"1", &k, "owner", None).unwrap();
    secret::create(&db, &env, "B", b"2", &k, "owner", None).unwrap();
    assert_eq!(environment::secret_count(&db, &env).unwrap(), 2);
    assert_eq!(environment::secret_count(&db, &other.id).unwrap(), 0);
}

#[test]
fn existing_vault_without_is_secret_column_still_opens() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("old.sqlite");
    {
        let db = Db::open(&path, "pw").unwrap();
        db.conn().execute_batch("ALTER TABLE secret DROP COLUMN is_secret;").unwrap();
    }
    let db = Db::open(&path, "pw").unwrap();
    let cols: Vec<String> = db.conn()
        .prepare("SELECT name FROM pragma_table_info('secret')").unwrap()
        .query_map([], |r| r.get(0)).unwrap()
        .collect::<Result<_, _>>().unwrap();
    assert!(cols.contains(&"is_secret".to_string()));
}

#[test]
fn parse_any_accepts_export_prefix() {
    let pairs = env_file::parse_any("export A=1\nB=2\n").unwrap();
    assert_eq!(pairs, vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
}

#[test]
fn parse_any_accepts_json_object() {
    let pairs = env_file::parse_any(r#"{"PORT": 3000, "NAME": "app", "DEBUG": true}"#).unwrap();
    assert!(pairs.contains(&("PORT".into(), "3000".into())));
    assert!(pairs.contains(&("NAME".into(), "app".into())));
    assert!(pairs.contains(&("DEBUG".into(), "true".into())));
}

#[test]
fn parse_any_rejects_nested_json() {
    assert!(env_file::parse_any(r#"{"A": {"b": 1}}"#).is_err());
}

#[test]
fn looks_secret_flags_sensitive_names() {
    for k in ["STRIPE_SECRET_KEY", "API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "PRIVATE_PEM", "AUTH_HEADER", "AWS_CREDENTIALS", "DATABASE_URL"] {
        assert!(env_file::looks_secret(k), "{k} should look secret");
    }
    for k in ["PORT", "NODE_ENV", "LOG_LEVEL", "DEBUG"] {
        assert!(!env_file::looks_secret(k), "{k} should look plain");
    }
}
