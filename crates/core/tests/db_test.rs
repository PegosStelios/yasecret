use std::path::PathBuf;
use tempfile::tempdir;
use yasecret_core::db::Db;

fn tmp_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    (dir, path)
}

#[test]
fn open_creates_db() {
    let (_dir, path) = tmp_db();
    let db = Db::open(&path, "password123").unwrap();
    assert!(path.exists());
    drop(db);
}

#[test]
fn wrong_password_fails() {
    let (_dir, path) = tmp_db();
    let _db = Db::open(&path, "correct").unwrap();
    drop(_db);
    let result = Db::open(&path, "wrong");
    assert!(result.is_err());
}

#[test]
fn db_has_expected_tables() {
    let (_dir, path) = tmp_db();
    let db = Db::open(&path, "pw").unwrap();
    let conn = db.conn();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='project'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn wal_mode_enabled() {
    let (_dir, path) = tmp_db();
    let db = Db::open(&path, "pw").unwrap();
    let mode: String = db.conn()
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}
