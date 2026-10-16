use std::process::Command;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, identity, project, project_key, secret};

fn yasecret_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("yasecret");
    p
}

fn seed_db(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let db_path = dir.path().join("db.sqlite");
    let salt_path = dir.path().join("db.salt");
    let salt = crypto::generate_salt();
    std::fs::write(&salt_path, salt).unwrap();
    let db_key = crypto::derive_db_key("testpw", &salt);
    let db = Db::open(&db_path, "testpw").unwrap();
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let p = project::create(&db, "shared-app", None, &owner.id).unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    secret::create(&db, &e.id, "API_KEY", b"val1", &proj_key, &owner.id, None).unwrap();
    db_path
}

#[test]
fn peers_self_prints_64_char_hex() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir);

    let output = Command::new(yasecret_bin())
        .args(["peers", "self", "--db", db_path.to_str().unwrap(), "--password", "testpw"])
        .output()
        .expect("failed to run peers self");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(stdout.len(), 64, "X25519 pubkey must be 64 hex chars, got: {stdout}");
    assert!(stdout.chars().all(|c| c.is_ascii_hexdigit()), "must be hex: {stdout}");
}

#[test]
fn share_prints_nonempty_ticket() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir);

    let fake_peer_key = "aa".repeat(32); // 64 hex chars

    let output = Command::new(yasecret_bin())
        .args([
            "share",
            "--project", "shared-app",
            "--peer-key", &fake_peer_key,
            "--no-wait",
            "--db", db_path.to_str().unwrap(),
            "--password", "testpw",
        ])
        .output()
        .expect("failed to run share");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(stdout.starts_with("yasecret://join?"), "expected an invite link, got: {stdout}");
    assert!(stdout.contains("m=device"), "peer key makes a device-bound invite: {stdout}");
}
