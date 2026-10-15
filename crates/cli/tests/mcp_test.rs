use std::process::Command;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, identity, project};

fn yasecret_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("yasecret");
    p
}

fn seed_db(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("db.sqlite");
    let salt = crypto::generate_salt();
    std::fs::write(dir.path().join("db.salt"), salt).unwrap();
    let db = Db::open(&db_path, "testpw").unwrap();
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let _ = project::create(&db, "web", None, &owner.id).unwrap();
    db_path
}

fn seed_db_with_secrets(dir: &tempfile::TempDir) -> std::path::PathBuf {
    use yasecret_core::{environment, project_key, secret};
    let db_path = dir.path().join("db.sqlite");
    let salt = crypto::generate_salt();
    std::fs::write(dir.path().join("db.salt"), salt).unwrap();
    let db_key = crypto::derive_db_key("testpw", &salt);
    let db = Db::open(&db_path, "testpw").unwrap();
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let p = project::create(&db, "web", None, &owner.id).unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "prod").unwrap();
    secret::create(&db, &e.id, "DB_URL", b"postgres://localhost/mydb", &proj_key, &owner.id, None).unwrap();
    secret::create(&db, &e.id, "API_KEY", b"sk-abc123", &proj_key, &owner.id, None).unwrap();
    db_path
}

#[test]
fn mcp_help_exits_cleanly() {
    let output = Command::new(yasecret_bin())
        .args(["mcp", "--help"])
        .output()
        .expect("failed to run yasecret mcp --help");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("mcp"),
        "output: {stdout}"
    );
}
