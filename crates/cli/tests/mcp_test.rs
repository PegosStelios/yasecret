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

// ── Final review fix: TOFU test ───────────────────────────────────────────────

#[test]
fn mcp_run_inserts_tofu_token_on_first_start() {
    use std::process::Stdio;
    let dir = tempdir().unwrap();
    let db_path = seed_db(&dir);
    // Run `yasecret mcp` with stdin=null so the MCP server reads EOF and exits.
    // TOFU insert happens before serve(), so the row must be present after exit.
    let _ = Command::new(yasecret_bin())
        .args(["mcp", "--db", &db_path.to_string_lossy(), "--password", "testpw"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .expect("failed to run yasecret mcp");

    let db = Db::open(&db_path, "testpw").unwrap();
    let count: i64 = db.conn()
        .query_row("SELECT count(*) FROM mcp_session", [], |r| r.get(0))
        .unwrap_or(0);
    assert_eq!(count, 1, "mcp_session must have exactly 1 TOFU row after first start");
}

// ── Task 1 test ───────────────────────────────────────────────────────────────

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

// ── Task 2 tests ──────────────────────────────────────────────────────────────

#[test]
fn list_projects_returns_project_name() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.list_projects_impl();
    assert!(result.contains("web"), "expected 'web' in: {result}");
    assert!(result.contains("prod"), "expected 'prod' in: {result}");
}

#[test]
fn list_secret_keys_returns_key_names_not_values() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.list_secret_keys_impl("web", "prod");
    assert!(result.contains("DB_URL"), "expected 'DB_URL' in: {result}");
    assert!(result.contains("API_KEY"), "expected 'API_KEY' in: {result}");
    assert!(!result.contains("postgres://"), "must not contain plaintext value");
    assert!(!result.contains("sk-abc123"), "must not contain plaintext value");
}

#[test]
fn list_secret_keys_nonexistent_project_returns_error() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.list_secret_keys_impl("nonexistent", "prod");
    assert!(result.contains("error"), "expected error string, got: {result}");
    assert!(!result.contains("postgres://"), "must not leak values");
}

// ── Task 3 tests ──────────────────────────────────────────────────────────────

#[test]
fn run_with_secrets_masks_secret_value_in_output() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.run_with_secrets_impl(
        "web",
        "prod",
        &["DB_URL".to_string()],
        &["sh".to_string(), "-c".to_string(), "echo $DB_URL".to_string()],
    );
    assert!(!result.contains("postgres://"), "secret must be masked, got: {result}");
    assert!(result.contains("[REDACTED]"), "expected [REDACTED] in: {result}");
}

#[test]
fn run_with_secrets_captures_exit_status() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.run_with_secrets_impl(
        "web",
        "prod",
        &[],
        &["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
    );
    assert!(result.contains("42"), "should include exit code 42: {result}");
}

// ── Task 4 tests ──────────────────────────────────────────────────────────────

#[test]
fn get_secret_blocked_without_allow_plaintext() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.get_secret_impl("web", "prod", "DB_URL");
    assert!(
        result.contains("error") || result.contains("disabled"),
        "must be blocked when allow_plaintext=false, got: {result}"
    );
    assert!(!result.contains("postgres://"), "must not reveal value: {result}");
}

#[test]
fn get_secret_returns_value_when_allowed() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), true);
    let result = server.get_secret_impl("web", "prod", "DB_URL");
    assert!(result.contains("postgres://"), "expected plaintext value, got: {result}");
}

#[test]
fn import_env_creates_secrets() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let content = "NEW_KEY=new_value\nANOTHER=abc123\n";
    let result = server.import_env_impl("web", "prod", content);
    assert!(
        result.contains("2") || result.contains("imported"),
        "expected import count, got: {result}"
    );
}

#[test]
fn import_env_malformed_line_returns_error() {
    use yasecret_cli::mcp_server::YasecretServer;
    let dir = tempdir().unwrap();
    let db_path = seed_db_with_secrets(&dir);
    let server = YasecretServer::new(&db_path, "testpw".to_string(), false);
    let result = server.import_env_impl("web", "prod", "NOEQUALS\n");
    assert!(result.contains("error"), "expected error for malformed line, got: {result}");
}
