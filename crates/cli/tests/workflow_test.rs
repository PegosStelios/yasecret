//! push / diff / dev against a throwaway vault, via the real binary.

use std::{process::Command, time::{Duration, Instant}};
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret};

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("yasecret");
    p
}

struct Vault {
    dir: tempfile::TempDir,
    db_key: [u8; 32],
    env_id: String,
    project_id: String,
}

impl Vault {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let salt = crypto::generate_salt();
        std::fs::write(dir.path().join("db.salt"), salt).unwrap();
        let db_key = *crypto::derive_db_key("testpw", &salt);
        let db = Db::open(&dir.path().join("db.sqlite"), "testpw").unwrap();
        let p = project::create(&db, "shop", None, "owner").unwrap();
        project_key::create(&db, &p.id, &db_key).unwrap();
        let k = project_key::load(&db, &p.id, &db_key).unwrap();
        let e = environment::create(&db, &p.id, "dev").unwrap();
        secret::create(&db, &e.id, "API_KEY", b"old-key", &k, "owner", None).unwrap();
        let port = secret::create(&db, &e.id, "PORT", b"3000", &k, "owner", None).unwrap();
        secret::set_kind(&db, &port.id, false, "owner").unwrap();
        Self { dir, db_key, env_id: e.id, project_id: p.id }
    }

    fn db_path(&self) -> String {
        self.dir.path().join("db.sqlite").to_string_lossy().into_owned()
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn cmd(&self, args: &[&str]) -> std::process::Output {
        Command::new(bin())
            .args(args)
            .args(["--db", &self.db_path(), "--password", "testpw"])
            .output()
            .unwrap()
    }

    fn value(&self, key: &str) -> Option<(String, bool)> {
        let db = Db::open(&self.dir.path().join("db.sqlite"), "testpw").unwrap();
        let k = project_key::load(&db, &self.project_id, &self.db_key).unwrap();
        let s = secret::list(&db, &self.env_id).unwrap().into_iter().find(|s| s.key == key)?;
        let v = secret::get_plaintext(&db, &s.id, &k).unwrap();
        Some((String::from_utf8(v.to_vec()).unwrap(), s.is_secret))
    }
}

fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn push_adds_new_keys_and_skips_existing_by_default() {
    let v = Vault::new();
    let f = v.file(".env", "API_KEY=new-key\nPORT=3000\nDB_PASSWORD=pw\nLOG_LEVEL=debug\n");
    let out = v.cmd(&["push", "-p", "shop", "-e", "dev", "-i", &f]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = stdout(&out);
    assert!(text.contains("2 added"), "{text}");
    assert!(text.contains("1 unchanged"), "{text}");
    assert!(text.contains("1 skipped"), "{text}");
    assert_eq!(v.value("API_KEY").unwrap().0, "old-key");
    assert_eq!(v.value("DB_PASSWORD").unwrap(), ("pw".into(), true), "names like *PASSWORD* are stored as secrets");
    assert_eq!(v.value("LOG_LEVEL").unwrap(), ("debug".into(), false));
}

#[test]
fn push_overwrite_updates_and_dry_run_changes_nothing() {
    let v = Vault::new();
    let f = v.file(".env", "API_KEY=new-key\nEXTRA=1\n");
    let dry = v.cmd(&["push", "-p", "shop", "-e", "dev", "-i", &f, "--overwrite", "--dry-run"]);
    assert!(dry.status.success());
    assert!(stdout(&dry).contains("1 updated"), "{}", stdout(&dry));
    assert_eq!(v.value("API_KEY").unwrap().0, "old-key", "dry run must not write");
    assert!(v.value("EXTRA").is_none());

    let real = v.cmd(&["push", "-p", "shop", "-e", "dev", "-i", &f, "--overwrite"]);
    assert!(real.status.success());
    assert_eq!(v.value("API_KEY").unwrap().0, "new-key");
    assert_eq!(v.value("EXTRA").unwrap().0, "1");
}

#[test]
fn diff_reports_differences_without_values_and_exits_nonzero() {
    let v = Vault::new();
    let f = v.file(".env", "API_KEY=changed\nONLY_LOCAL=x\n");
    let out = v.cmd(&["diff", "-p", "shop", "-e", "dev", "-i", &f]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    assert!(text.contains("~ API_KEY"), "{text}");
    assert!(text.contains("- ONLY_LOCAL"), "{text}");
    assert!(text.contains("+ PORT"), "{text}");
    assert!(!text.contains("changed") && !text.contains("old-key") && !text.contains("3000"), "values leaked: {text}");

    let same = v.file("same.env", "API_KEY=old-key\nPORT=3000\n");
    let out = v.cmd(&["diff", "-p", "shop", "-e", "dev", "-i", &same]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

#[test]
fn dev_rewrites_the_file_when_the_vault_changes() {
    let v = Vault::new();
    let target = v.dir.path().join("watched.env");
    let mut child = Command::new(bin())
        .args(["dev", "-p", "shop", "-e", "dev", "-o", target.to_str().unwrap(), "--interval", "1"])
        .args(["--db", &v.db_path(), "--password", "testpw"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let wait_for = |needle: &str| {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if std::fs::read_to_string(&target).map(|t| t.contains(needle)).unwrap_or(false) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    };
    let first = wait_for("API_KEY=old-key");
    {
        let db = Db::open(&v.dir.path().join("db.sqlite"), "testpw").unwrap();
        let k = project_key::load(&db, &v.project_id, &v.db_key).unwrap();
        secret::create(&db, &v.env_id, "NEW_VAR", b"hello", &k, "owner", None).unwrap();
    }
    let second = wait_for("NEW_VAR=hello");
    let _ = child.kill();
    let _ = child.wait();
    assert!(first, "initial write never happened");
    assert!(second, "file was not updated after the vault changed");
}
