use std::process::Command;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret};

fn yasecret_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    // target/debug/deps/pull_test-xxx -> target/debug/yasecret
    p.pop(); p.pop();
    p.push("yasecret");
    p
}

fn seed_db(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("db.sqlite");
    let salt_path = dir.path().join("db.salt");
    let password = "testpw";
    let salt = crypto::generate_salt();
    std::fs::write(&salt_path, salt).unwrap();
    let db_key = crypto::derive_db_key(password, &salt);

    let db = Db::open(&db_path, password).unwrap();
    let p = project::create(&db, "my-app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    secret::create(&db, &e.id, "API_KEY", b"secret-value-123", &proj_key, "owner", None).unwrap();
    secret::create(&db, &e.id, "DB_URL", b"postgres://localhost/test", &proj_key, "owner", None).unwrap();
    db_path
}

#[test]
fn pull_outputs_env_format() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir);

    let output = Command::new(yasecret_bin())
        .args([
            "pull",
            "--project", "my-app",
            "--env", "dev",
            "--db", db_path.to_str().unwrap(),
            "--password", "testpw",
        ])
        .output()
        .expect("failed to run yasecret");

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("API_KEY=secret-value-123"), "got: {stdout}");
    assert!(stdout.contains("DB_URL=postgres://localhost/test"), "got: {stdout}");
}

#[test]
fn pull_unknown_project_exits_nonzero() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir);

    let output = Command::new(yasecret_bin())
        .args([
            "pull",
            "--project", "nonexistent",
            "--env", "dev",
            "--db", db_path.to_str().unwrap(),
            "--password", "testpw",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
}
