//! Throwaway vault + the real binary, shared by the CLI integration tests.
#![allow(dead_code)]

use std::process::Command;
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret};

pub fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("yasecret");
    p
}

pub struct Vault {
    pub dir: tempfile::TempDir,
    pub db_key: [u8; 32],
    pub env_id: String,
    pub project_id: String,
}

impl Vault {
    pub fn new() -> Self {
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

    pub fn db_path(&self) -> String {
        self.dir.path().join("db.sqlite").to_string_lossy().into_owned()
    }

    pub fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    pub fn cmd(&self, args: &[&str]) -> std::process::Output {
        Command::new(bin())
            .args(args)
            .args(["--db", &self.db_path(), "--password", "testpw"])
            .output()
            .unwrap()
    }

    pub fn value(&self, key: &str) -> Option<(String, bool)> {
        let db = Db::open(&self.dir.path().join("db.sqlite"), "testpw").unwrap();
        let k = project_key::load(&db, &self.project_id, &self.db_key).unwrap();
        let s = secret::list(&db, &self.env_id).unwrap().into_iter().find(|s| s.key == key)?;
        let v = secret::get_plaintext(&db, &s.id, &k).unwrap();
        Some((String::from_utf8(v.to_vec()).unwrap(), s.is_secret))
    }
}

pub fn stdout(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}


impl Vault {
    pub fn db(&self) -> Db {
        Db::open(&self.dir.path().join("db.sqlite"), "testpw").unwrap()
    }

    /// Adds a variable to the test environment.
    pub fn add(&self, key: &str, value: &str, is_secret: bool) {
        let db = self.db();
        let k = project_key::load(&db, &self.project_id, &self.db_key).unwrap();
        secret::create_with_kind(&db, &self.env_id, key, value.as_bytes(), &k, "owner", None, is_secret).unwrap();
    }
}
