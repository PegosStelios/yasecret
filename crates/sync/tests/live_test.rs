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
    name: String,
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
        Self { _dir: dir, name: name.into(), db_path, db_key, svc: Some(svc) }
    }

    /// Starts the sync service again on the same vault, like reopening the app.
    fn restart(&mut self) {
        if let Some(svc) = self.svc.take() {
            svc.shutdown();
        }
        self.svc = Some(
            SyncService::start(SyncConfig {
                db_path: self.db_path.clone(),
                db_password: "pw".into(),
                db_key: self.db_key,
                data_dir: self._dir.path().join("sync"),
                device_name: self.name.clone(),
            })
            .unwrap(),
        );
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
    eventually("member sees its editor access", 15, || member.svc().status(&pid).unwrap().my_level == "editor");
    let cached: Option<String> = member
        .db()
        .conn()
        .query_row("SELECT my_level FROM sync_doc WHERE project_id = ?1", [&pid], |r| r.get(0))
        .unwrap();
    assert_eq!(cached.as_deref(), Some("editor"), "level is cached for the CLI");

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

    // Inheritance travels too.
    environment::set_parent(&owner.db(), &staging_id, Some(&dev_id)).unwrap();
    owner.svc().notify_local_change(&pid);
    eventually("member sees staging inherit from development", 30, || {
        environment::get(&member.db(), &staging_id).unwrap().inherits_from.as_deref() == Some(dev_id.as_str())
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

#[test]
fn removing_a_member_rotates_the_key_for_everyone_else() {
    let owner = Device::new("owner");
    let (pid, env_id) = {
        let db = owner.db();
        let p = project::create(&db, "team", None, "owner").unwrap();
        project_key::create(&db, &p.id, &owner.db_key).unwrap();
        let pk = project_key::load(&db, &p.id, &owner.db_key).unwrap();
        let env = environment::create(&db, &p.id, "prod").unwrap();
        secret::create(&db, &env.id, "TOKEN", b"before", &pk, "owner", None).unwrap();
        (p.id, env.id)
    };
    let stays = Device::new("stays");
    let leaves = Device::new("leaves");
    stays.svc().join(&owner.svc().create_invite(&pid, None, "editor").unwrap()).unwrap();
    leaves.svc().join(&owner.svc().create_invite(&pid, None, "editor").unwrap()).unwrap();
    for d in [&stays, &leaves] {
        eventually("member has the value", 30, || d.value(&pid, &env_id, "TOKEN").as_deref() == Some("before"));
    }
    eventually("both admitted", 30, || {
        owner.svc().members(&pid).unwrap().iter().filter(|m| m.level == "editor").count() == 2
    });
    let leaves_peer = leaves.svc().device_code();
    owner.svc().set_member_level(&pid, &leaves_peer, "removed").unwrap();

    {
        let db = owner.db();
        let pk = project_key::load(&db, &pid, &owner.db_key).unwrap();
        let s = secret::list(&db, &env_id).unwrap().into_iter().find(|s| s.key == "TOKEN").unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        secret::update(&db, &s.id, b"after", &pk, "owner", None).unwrap();
    }
    owner.svc().notify_local_change(&pid);

    eventually("remaining member reads the new value", 40, || stays.value(&pid, &env_id, "TOKEN").as_deref() == Some("after"));
    std::thread::sleep(Duration::from_secs(5));
    assert_ne!(leaves.value(&pid, &env_id, "TOKEN").as_deref(), Some("after"), "removed member must not read new values");
}

#[test]
fn relay_lets_members_join_and_sync_while_the_owner_is_offline() {
    // Goes through iroh's public discovery and relay servers, so waits are generous.
    use yasecret_sync::relay::Relay;

    let mut owner = Device::new("alice-laptop");
    let (pid, env_id) = {
        let db = owner.db();
        let p = project::create(&db, "always-on", Some("billing stack"), "owner").unwrap();
        project_key::create(&db, &p.id, &owner.db_key).unwrap();
        let pk = project_key::load(&db, &p.id, &owner.db_key).unwrap();
        let env = environment::create(&db, &p.id, "staging-eu").unwrap();
        secret::create(&db, &env.id, "SECRET", b"from-owner", &pk, "owner", None).unwrap();
        (p.id, env.id)
    };

    let rt = tokio::runtime::Runtime::new().unwrap();
    let relay_dir = tempfile::tempdir().unwrap();
    let relay = rt.block_on(Relay::start(relay_dir.path())).unwrap();
    assert_eq!(relay.code().len(), 64);

    // Only the owner can add a relay; the link it returns is what the relay imports.
    let relay_link = owner.svc().add_relay(&pid, &relay.code(), "office server").unwrap();
    assert!(relay_link.starts_with("yasecret://relay?"));
    let added = rt.block_on(relay.add(&relay_link)).unwrap();
    assert_eq!(added.name, "always-on");
    eventually("owner sees the relay online", 90, || {
        owner.svc().relays(&pid).unwrap().iter().any(|r| r.code == relay.code() && r.name == "office server" && r.online)
    });

    let have = |rt: &tokio::runtime::Runtime| rt.block_on(relay.projects()).unwrap().first().map(|p| p.entries).unwrap_or(0);
    // Let the relay settle on everything written so far, then count the invite on top of it.
    let mut settled = 0;
    eventually("relay stores the project", 90, || {
        let n = have(&rt);
        let stable = n > 0 && n == settled;
        settled = n;
        stable
    });
    let invite = owner.svc().create_invite(&pid, None, "editor").unwrap();
    eventually("relay stores the invite before the owner leaves", 90, || have(&rt) > settled);
    owner.svc.take().unwrap().shutdown();

    // The relay only ever holds sealed records: no project, environment, variable or device names.
    let stored = rt.block_on(relay.entry_contents()).unwrap();
    assert!(!stored.is_empty());
    for needle in ["always-on", "billing stack", "staging-eu", "SECRET", "alice-laptop", "from-owner"] {
        assert!(
            !stored.iter().any(|c| c.windows(needle.len()).any(|w| w == needle.as_bytes())),
            "relay can read {needle:?}"
        );
    }

    let member = Device::new("member");
    assert_eq!(member.svc().join(&invite).unwrap(), pid, "join must succeed through the relay alone");
    eventually("member reads the value via the relay", 90, || {
        member.value(&pid, &env_id, "SECRET").as_deref() == Some("from-owner")
    });
    assert_eq!(member.svc().status(&pid).unwrap().my_level, "pending", "only the owner can admit");

    // A relay can't be added by anyone but the owner.
    assert!(matches!(member.svc().add_relay(&pid, &relay.code(), "x"), Err(SyncError::NotOwner)));

    // The owner comes back, learns about the new member through the relay and admits them.
    owner.restart();
    eventually("owner admits the member who joined via the relay", 90, || {
        member.svc().status(&pid).unwrap().my_level == "editor"
    });
    rt.block_on(relay.shutdown());
}

#[test]
fn a_co_owner_runs_the_project_while_the_owner_is_away() {
    let mut owner = Device::new("owner");
    let (pid, env_id) = {
        let db = owner.db();
        let p = project::create(&db, "team-two", None, "owner").unwrap();
        project_key::create(&db, &p.id, &owner.db_key).unwrap();
        let pk = project_key::load(&db, &p.id, &owner.db_key).unwrap();
        let env = environment::create(&db, &p.id, "prod").unwrap();
        secret::create(&db, &env.id, "TOKEN", b"t1", &pk, "owner", None).unwrap();
        (p.id, env.id)
    };
    let co = Device::new("co");
    co.svc().join(&owner.svc().create_invite(&pid, None, "editor").unwrap()).unwrap();
    let co_peer = co.svc().device_code();
    eventually("owner makes them a co-owner", 60, || owner.svc().set_member_level(&pid, &co_peer, "owner").is_ok());
    eventually("co sees it can manage the project", 60, || {
        let st = co.svc().status(&pid).unwrap();
        st.is_owner && !st.is_root
    });
    owner.svc.take().unwrap().shutdown();

    // With the owner offline, the co-owner invites and admits someone.
    let newbie = Device::new("newbie");
    newbie.svc().join(&co.svc().create_invite(&pid, None, "editor").unwrap()).unwrap();
    let newbie_peer = newbie.svc().device_code();
    eventually("co-owner admits the newcomer", 60, || newbie.svc().status(&pid).unwrap().my_level == "editor");
    eventually("newcomer reads values", 60, || newbie.value(&pid, &env_id, "TOKEN").as_deref() == Some("t1"));
    assert!(matches!(co.svc().set_member_level(&pid, &newbie_peer, "owner"), Err(SyncError::NotOwner)), "only the root owner appoints owners");

    // The owner comes back, accepts the co-owner's grant, then demotes the co-owner: the
    // newcomer keeps access because the owner re-signs what the co-owner granted.
    owner.restart();
    eventually("owner sees the newcomer", 60, || {
        owner.svc().members(&pid).unwrap().iter().any(|m| m.peer_id == newbie_peer && m.level == "editor")
    });

    // A co-owner removing someone rotates the key; the owner switches to it too.
    let temp = Device::new("temp");
    temp.svc().join(&owner.svc().create_invite(&pid, None, "viewer").unwrap()).unwrap();
    let temp_peer = temp.svc().device_code();
    eventually("temp admitted", 60, || temp.svc().status(&pid).unwrap().my_level == "viewer");
    eventually("co-owner removes temp", 60, || co.svc().set_member_level(&pid, &temp_peer, "removed").is_ok());
    eventually("owner switches to the co-owner's new key", 60, || {
        let db = owner.db();
        let pk = project_key::load(&db, &pid, &owner.db_key).unwrap();
        let cdb = co.db();
        let ck = project_key::load(&cdb, &pid, &co.db_key).unwrap();
        *pk == *ck && owner.value(&pid, &env_id, "TOKEN").as_deref() == Some("t1")
    });
    {
        let db = owner.db();
        let pk = project_key::load(&db, &pid, &owner.db_key).unwrap();
        let s = secret::list(&db, &env_id).unwrap().into_iter().find(|s| s.key == "TOKEN").unwrap();
        std::thread::sleep(Duration::from_millis(1100));
        secret::update(&db, &s.id, b"t2", &pk, "owner", None).unwrap();
    }
    owner.svc().notify_local_change(&pid);
    eventually("co-owner reads the owner's edit under the new key", 60, || co.value(&pid, &env_id, "TOKEN").as_deref() == Some("t2"));
    assert_ne!(temp.value(&pid, &env_id, "TOKEN").as_deref(), Some("t2"), "removed device can't read it");

    owner.svc().set_member_level(&pid, &co_peer, "editor").unwrap();
    eventually("co is no longer an owner", 60, || !co.svc().status(&pid).unwrap().is_owner);
    assert!(matches!(co.svc().create_invite(&pid, None, "editor"), Err(SyncError::NotOwner)));
    std::thread::sleep(Duration::from_secs(5));
    assert_eq!(newbie.svc().status(&pid).unwrap().my_level, "editor", "demoting a co-owner keeps the people they admitted");
}
