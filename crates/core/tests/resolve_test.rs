//! Environment inheritance and ${KEY} references, as tools that use the values see them.

use yasecret_core::{crypto, db::Db, environment, project, project_key, resolve, secret, YasecretError};

struct P {
    _dir: tempfile::TempDir,
    db: Db,
    key: zeroize::Zeroizing<[u8; 32]>,
    pid: String,
}

fn setup() -> P {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db.sqlite"), "pw").unwrap();
    let db_key = crypto::derive_db_key("pw", &crypto::generate_salt());
    let p = project::create(&db, "app", None, "me").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let key = project_key::load(&db, &p.id, &db_key).unwrap();
    P { _dir: dir, db, key, pid: p.id }
}

impl P {
    fn env(&self, name: &str, vars: &[(&str, &str)]) -> String {
        let e = environment::create(&self.db, &self.pid, name).unwrap();
        for (k, v) in vars {
            secret::create(&self.db, &e.id, k, v.as_bytes(), &self.key, "me", None).unwrap();
        }
        e.id
    }

    fn resolved(&self, env_id: &str) -> Vec<(String, String, Option<String>)> {
        resolve::resolved(&self.db, env_id, &self.key)
            .unwrap()
            .into_iter()
            .map(|v| (v.key, v.value, v.inherited_from))
            .collect()
    }
}

#[test]
fn an_environment_inherits_its_parents_variables_and_overrides_them() {
    let p = setup();
    let dev = p.env("dev", &[("A", "1"), ("B", "2")]);
    let staging = p.env("staging", &[("B", "3"), ("C", "4")]);
    let prod = p.env("prod", &[("C", "5")]);
    environment::set_parent(&p.db, &staging, Some(&dev)).unwrap();
    environment::set_parent(&p.db, &prod, Some(&staging)).unwrap();
    assert_eq!(environment::get(&p.db, &prod).unwrap().inherits_from.as_deref(), Some(staging.as_str()));

    assert_eq!(
        p.resolved(&prod),
        vec![
            ("A".into(), "1".into(), Some("dev".into())),
            ("B".into(), "3".into(), Some("staging".into())),
            ("C".into(), "5".into(), None),
        ]
    );
    environment::set_parent(&p.db, &prod, None).unwrap();
    assert_eq!(p.resolved(&prod), vec![("C".into(), "5".into(), None)]);
}

#[test]
fn references_expand_from_the_resolved_environment() {
    let p = setup();
    let base = p.env("base", &[("HOST", "db.internal"), ("PORT", "5432")]);
    let app = p.env(
        "app",
        &[
            ("URL", "postgres://${HOST}:${PORT}/app"),
            ("NESTED", "${URL}?ssl=1"),
            ("LITERAL", "$${HOST} stays"),
            ("SHELL", "${HOME}/bin"),
        ],
    );
    environment::set_parent(&p.db, &app, Some(&base)).unwrap();
    let got = p.resolved(&app);
    let value = |k: &str| got.iter().find(|(key, _, _)| key == k).unwrap().1.clone();
    assert_eq!(value("URL"), "postgres://db.internal:5432/app");
    assert_eq!(value("NESTED"), "postgres://db.internal:5432/app?ssl=1");
    assert_eq!(value("LITERAL"), "${HOST} stays");
    assert_eq!(value("SHELL"), "${HOME}/bin", "names that aren't variables here stay as written");
}

#[test]
fn reference_cycles_are_reported() {
    let p = setup();
    let e = p.env("loop", &[("X", "${Y}"), ("Y", "a${X}")]);
    match resolve::resolved(&p.db, &e, &p.key) {
        Err(YasecretError::EnvParse(msg)) => assert!(msg.contains('X') && msg.contains('Y'), "{msg}"),
        other => panic!("expected a cycle error, got {:?}", other.map(|v| v.len())),
    }
}

#[test]
fn a_parent_must_be_in_the_same_project_and_not_create_a_loop() {
    let p = setup();
    let a = p.env("a", &[]);
    let b = p.env("b", &[]);
    environment::set_parent(&p.db, &b, Some(&a)).unwrap();
    assert!(environment::set_parent(&p.db, &a, Some(&b)).is_err(), "a → b → a");
    assert!(environment::set_parent(&p.db, &a, Some(&a)).is_err());
    let other = project::create(&p.db, "other", None, "me").unwrap();
    let foreign = environment::create(&p.db, &other.id, "x").unwrap();
    assert!(environment::set_parent(&p.db, &a, Some(&foreign.id)).is_err());
}

#[test]
fn deleting_a_parent_leaves_children_standing_alone() {
    let p = setup();
    let dev = p.env("dev", &[("A", "1")]);
    let staging = p.env("staging", &[("B", "2")]);
    environment::set_parent(&p.db, &staging, Some(&dev)).unwrap();
    let copy = environment::clone(&p.db, &staging, "staging-2").unwrap();
    assert_eq!(copy.inherits_from.as_deref(), Some(dev.as_str()), "a copy inherits from the same parent");
    environment::delete(&p.db, &dev).unwrap();
    assert_eq!(environment::get(&p.db, &staging).unwrap().inherits_from, None);
    assert_eq!(p.resolved(&staging), vec![("B".into(), "2".into(), None)]);
}
