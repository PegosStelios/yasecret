//! End-to-end: two (or three) devices, each with its own vault and sync service, on localhost.

use std::{path::PathBuf, time::{Duration, Instant}};

use tempfile::TempDir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret};
use yasecret_sync::{
    live::{SyncConfig, SyncService},
    SyncError,
};

struct Device {
    _dir: TempDir,
    db_path: PathBuf,
    db_key: [u8; 32],
    svc: Option<SyncService>,
}

impl Device {
    fn new(name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite");
        Db::open(&db_path, "pw").unwrap();
        let db_key = *crypto::derive_db_key("pw", &crypto::generate_salt());
        let svc = SyncService::start(SyncConfig {
            db_path: db_path.clone(),
            db_password: "pw".into(),
            db_key,
            data_dir: dir.path().join("sync"),
            device_name: name.into(),
        })
        .unwrap();
        Self { _dir: dir, db_path, db_key, svc: Some(svc) }
    }

    fn svc(&self) -> &SyncService {
        self.svc.as_ref().unwrap()
    }

    fn db(&self) -> Db {
        Db::open(&self.db_path, "pw").unwrap()
    }

    fn value(&self, project_id: &str, env_id: &str, key: &str) -> Option<String> {
        let db = self.db();
        let pk = project_key::load(&db, project_id, &self.db_key).ok()?;
        let s = secret::list(&db, env_id).ok()?.into_iter().find(|s| s.key == key)?;
        let v = secret::get_plaintext(&db, &s.id, &pk).ok()?;
        Some(String::from_utf8(v.to_vec()).unwrap())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Some(svc) = self.svc.take() {
            svc.shutdown();
        }
    }
}

fn eventually(what: &str, secs: u64, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if check() {
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("timed out waiting for: {what}");
}

#[test]
fn share_join_edit_delete_roundtrip() {
    let owner = Device::new("owner-mac");
    let (pid, dev_id) = {
        let db = owner.db();
        let p = project::create(&db, "shop", None, "owner").unwrap();
        project_key::create(&db, &p.id, &owner.db_key).unwrap();
        let pk = project_key::load(&db, &p.id, &owner.db_key).unwrap();
        let dev = environment::create(&db, &p.id, "development").unwrap();
        secret::create(&db, &dev.id, "API_KEY", b"v1", &pk, "owner", None).unwrap();
        let port = secret::create(&db, &dev.id, "PORT", b"3000", &pk, "owner", None).unwrap();
        secret::set_kind(&db, &port.id, false, "owner").unwrap();
        (p.id, dev.id)
    };

    let link = owner.svc().create_invite(&pid, None, "editor").unwrap();
    assert!(link.starts_with("yasecret://join?"));

    let member = Device::new("member-mac");
    let joined = member.svc().join(&link).unwrap();
    assert_eq!(joined, pid);

    eventually("member receives values", 30, || member.value(&pid, &dev_id, "API_KEY").as_deref() == Some("v1"));
    eventually("member receives plain flag", 10, || {
        secret::list(&member.db(), &dev_id).unwrap().iter().any(|s| s.key == "PORT" && !s.is_secret)
    });
    eventually("owner admits member", 30, || {
        owner.svc().members(&pid).unwrap().iter().any(|m| m.name == "member-mac" && m.level == "editor")
    });
    assert_eq!(member.svc().status(&pid).unwrap().my_level, "editor");

    // Member edits a value → owner sees it.
    {
        let db = member.db();
        let pk = project_key::load(&db, &pid, &member.db_key).unwrap();
        let s = secret::list(&db, &dev_id).unwrap().into_iter().find(|s| s.key == "API_KEY").unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        secret::update(&db, &s.id, b"v2", &pk, "member", None).unwrap();
    }
    member.svc().notify_local_change(&pid);
    eventually("owner sees member's edit", 30, || owner.value(&pid, &dev_id, "API_KEY").as_deref() == Some("v2"));

    // Owner deletes a variable and adds an environment → member follows.
    let staging_id = {
        let db = owner.db();
        let s = secret::list(&db, &dev_id).unwrap().into_iter().find(|s| s.key == "PORT").unwrap();
        secret::delete(&db, &s.id, "owner").unwrap();
        environment::create(&db, &pid, "staging").unwrap().id
    };
    owner.svc().notify_local_change(&pid);
    eventually("member loses deleted variable", 30, || member.value(&pid, &dev_id, "PORT").is_none());
    eventually("member gets new environment", 30, || {
        environment::list(&member.db(), &pid).unwrap().iter().any(|e| e.id == staging_id)
    });

    // The link was single use.
    let stranger = Device::new("stranger");
    match stranger.svc().join(&link) {
        Err(SyncError::InviteUsed) => {}
        other => panic!("expected InviteUsed, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn device_bound_invite_only_works_for_that_device() {
    let owner = Device::new("owner");
    let pid = {
        let db = owner.db();
        let p = project::create(&db, "api", None, "owner").unwrap();
        project_key::create(&db, &p.id, &owner.db_key).unwrap();
        let pk = project_key::load(&db, &p.id, &owner.db_key).unwrap();
        let env = environment::create(&db, &p.id, "production").unwrap();
        secret::create(&db, &env.id, "DB_URL", b"postgres://prod", &pk, "owner", None).unwrap();
        p.id
    };
    let viewer = Device::new("viewer");
    let link = owner
        .svc()
        .create_invite(&pid, Some(&viewer.svc().device_code()), "viewer")
        .unwrap();
    assert!(link.contains("m=device"));

    assert_eq!(viewer.svc().join(&link).unwrap(), pid);
    eventually("viewer is admitted as viewer", 30, || viewer.svc().status(&pid).unwrap().my_level == "viewer");
    let env_id = environment::list(&viewer.db(), &pid).unwrap()[0].id.clone();
    eventually("viewer reads value", 30, || viewer.value(&pid, &env_id, "DB_URL").as_deref() == Some("postgres://prod"));
}
