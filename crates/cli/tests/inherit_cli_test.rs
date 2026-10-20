//! Inherited variables and ${KEY} references reach the tools that use them.

mod common;

use common::{stdout, Vault};
use yasecret_core::{environment, project_key, secret};

fn staging(v: &Vault) {
    let db = v.db();
    let k = project_key::load(&db, &v.project_id, &v.db_key).unwrap();
    let st = environment::create(&db, &v.project_id, "staging").unwrap();
    environment::set_parent(&db, &st.id, Some(&v.env_id)).unwrap();
    secret::create_with_kind(&db, &st.id, "PORT", b"8080", &k, "me", None, false).unwrap();
    secret::create_with_kind(&db, &st.id, "URL", b"http://localhost:${PORT}/?k=${API_KEY}", &k, "me", None, false).unwrap();
}

#[test]
fn pull_and_env_see_inherited_and_expanded_values() {
    let v = Vault::new();
    staging(&v);
    let out = stdout(&v.cmd(&["pull", "-p", "shop", "-e", "staging"]));
    assert!(out.contains("API_KEY=old-key"), "inherited from dev: {out}");
    assert!(out.contains("PORT=8080"), "own value wins: {out}");
    assert!(out.contains("URL='http://localhost:8080/?k=old-key'"), "references expand: {out}");
    let sh = stdout(&v.cmd(&["env", "-p", "shop", "-e", "staging", "--only", "API_KEY"]));
    assert_eq!(sh.trim(), "export API_KEY='old-key'");
}

#[test]
fn run_injects_inherited_variables() {
    let v = Vault::new();
    staging(&v);
    // Vault::cmd appends --db/--password, which `run` would pass on to the command after `--`.
    let out = std::process::Command::new(common::bin())
        .args(["run", "-p", "shop", "-e", "staging", "--only", "URL", "--db", &v.db_path(), "--password", "testpw", "--"])
        .args(["sh", "-c", "test \"$URL\" = 'http://localhost:8080/?k=old-key' && echo matched"])
        .output()
        .unwrap();
    assert!(stdout(&out).contains("matched"), "{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
}
