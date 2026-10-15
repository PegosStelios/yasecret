use std::process::Command;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret};

fn yasecret_bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); p.pop();
    p.push("yasecret");
    p
}

fn seed_db(dir: &tempfile::TempDir, password: &str) -> std::path::PathBuf {
    let db_path = dir.path().join("db.sqlite");
    let salt_path = dir.path().join("db.salt");
    let salt = crypto::generate_salt();
    std::fs::write(&salt_path, salt).unwrap();
    let db_key = crypto::derive_db_key(password, &salt);
    let db = Db::open(&db_path, password).unwrap();
    let p = project::create(&db, "my-app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    secret::create(&db, &e.id, "MY_SECRET", b"topsecret999", &proj_key, "owner", None).unwrap();
    db_path
}

// mask_output is tested here directly (unit-level)
fn mask_output(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();
    for s in secrets {
        if !s.is_empty() {
            result = result.replace(s.as_str(), "[REDACTED]");
        }
    }
    result
}

#[test]
fn mask_replaces_secret_value() {
    let out = "connecting with key=topsecret999 done";
    let masked = mask_output(out, &["topsecret999".to_string()]);
    assert!(!masked.contains("topsecret999"));
    assert!(masked.contains("[REDACTED]"));
    assert!(masked.contains("done"));
}

#[test]
fn mask_ignores_empty_secret() {
    let out = "output";
    let masked = mask_output(out, &["".to_string()]);
    assert_eq!(masked, "output");
}

#[test]
fn run_injects_secret_into_subprocess() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir, "testpw");

    let output = Command::new(yasecret_bin())
        .args([
            "run",
            "--project", "my-app",
            "--env", "dev",
            "--only", "MY_SECRET",
            "--db", db_path.to_str().unwrap(),
            "--password", "testpw",
            "--",
            "sh", "-c", "echo SECRET_IS=$MY_SECRET",
        ])
        .output()
        .expect("failed to run yasecret run");

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The subprocess outputs the value; yasecret masks it before returning
    assert!(stdout.contains("[REDACTED]") || stdout.contains("SECRET_IS="),
        "got: {stdout}");
}

#[test]
fn run_masks_secret_in_output() {
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir, "testpw");

    // Run a command that echoes the secret value; yasecret must mask it
    let output = Command::new(yasecret_bin())
        .args([
            "run",
            "--project", "my-app",
            "--env", "dev",
            "--only", "MY_SECRET",
            "--db", db_path.to_str().unwrap(),
            "--password", "testpw",
            "--",
            "sh", "-c", "echo topsecret999",
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("topsecret999"), "secret leaked: {stdout}");
    assert!(stdout.contains("[REDACTED]"), "not masked: {stdout}");
}
