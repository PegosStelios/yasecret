//! `yasecret relay code` / `relay add` without network.

use std::process::Command;

fn bin() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("yasecret");
    p
}

fn relay(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(bin()).arg("relay").args(args).arg("--dir").arg(dir).output().unwrap()
}

#[test]
fn relay_code_is_stable_hex() {
    let dir = tempfile::tempdir().unwrap();
    let a = relay(dir.path(), &["code"]);
    assert!(a.status.success(), "{}", String::from_utf8_lossy(&a.stderr));
    let code = String::from_utf8(a.stdout).unwrap().trim().to_string();
    assert_eq!(code.len(), 64);
    assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
    let b = relay(dir.path(), &["code"]);
    assert_eq!(String::from_utf8(b.stdout).unwrap().trim(), code, "same dir, same code");
}

#[test]
fn relay_add_rejects_garbage_and_queues_valid_links() {
    let dir = tempfile::tempdir().unwrap();
    let bad = relay(dir.path(), &["add", "yasecret://join?v=2&p=x"]);
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("yasecret://relay"));

    let ok = relay(dir.path(), &["add", "yasecret://relay?v=1&n=shop&t=docaaaa"]);
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    let queued: Vec<_> = std::fs::read_dir(dir.path().join("inbox")).unwrap().collect();
    assert_eq!(queued.len(), 1);
    assert!(String::from_utf8_lossy(&ok.stdout).contains("yasecret relay"), "tells you to start the relay");
}
