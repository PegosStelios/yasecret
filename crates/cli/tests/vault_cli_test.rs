//! yasecret vault passwd / recovery-key / recover / backup / restore.

mod common;

use common::{bin, stdout, Vault};
use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn pull(db: &str, password: &str) -> std::process::Output {
    run(&["pull", "-p", "shop", "-e", "dev", "--db", db, "--password", password])
}

#[test]
fn passwd_then_recover_with_the_recovery_key() {
    let v = Vault::new();
    let db = v.db_path();
    let key = run(&["vault", "recovery-key", "--db", &db, "--password", "testpw"]);
    assert!(key.status.success(), "{}", String::from_utf8_lossy(&key.stderr));
    let key = stdout(&key).lines().find(|l| l.matches('-').count() == 12).unwrap().trim().to_string();

    let changed = run(&["vault", "passwd", "--db", &db, "--password", "testpw", "--new-password", "second"]);
    assert!(changed.status.success(), "{}", String::from_utf8_lossy(&changed.stderr));
    assert!(stdout(&pull(&db, "second")).contains("API_KEY=old-key"));

    let recovered = run(&["vault", "recover", "--db", &db, "--key", &key, "--new-password", "third"]);
    assert!(recovered.status.success(), "{}", String::from_utf8_lossy(&recovered.stderr));
    assert!(stdout(&pull(&db, "third")).contains("API_KEY=old-key"));
    assert!(!pull(&db, "second").status.success());
}

#[test]
fn backup_and_restore_to_another_location() {
    let v = Vault::new();
    let db = v.db_path();
    let file = v.dir.path().join("vault.yasecret-backup");
    let made = run(&["vault", "backup", file.to_str().unwrap(), "--db", &db, "--password", "testpw"]);
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));

    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("db.sqlite");
    let target = target.to_str().unwrap();
    let wrong = run(&["vault", "restore", file.to_str().unwrap(), "--db", target, "--password", "nope"]);
    assert!(!wrong.status.success());
    let ok = run(&["vault", "restore", file.to_str().unwrap(), "--db", target, "--password", "testpw"]);
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    assert!(stdout(&pull(target, "testpw")).contains("API_KEY=old-key"));

    // An existing vault is only replaced when asked to.
    let again = run(&["vault", "restore", file.to_str().unwrap(), "--db", target, "--password", "testpw"]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("--replace"));
    let replaced = run(&["vault", "restore", file.to_str().unwrap(), "--db", target, "--password", "testpw", "--replace"]);
    assert!(replaced.status.success());
}
