//! yasecret ls --json and --password-stdin, used by the VS Code extension.

mod common;

use common::{bin, Vault};
use std::{io::Write, process::{Command, Stdio}};

fn with_stdin_password(args: &[&str], db: &str, password: &str) -> std::process::Output {
    let mut child = Command::new(bin())
        .args(args)
        .args(["--db", db, "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn ls_json_lists_keys_without_values() {
    let v = Vault::new();
    let out = with_stdin_password(&["ls", "--json"], &v.db_path(), "testpw");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let project = &json["projects"][0];
    assert_eq!(project["name"], "shop");
    let vars = &project["environments"][0]["variables"];
    assert_eq!(project["environments"][0]["name"], "dev");
    let api = vars.as_array().unwrap().iter().find(|v| v["key"] == "API_KEY").unwrap();
    assert_eq!(api["secret"], true);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("old-key") && !text.contains("3000"), "no values in the listing: {text}");
}

#[test]
fn password_stdin_works_for_value_commands_and_rejects_a_wrong_one() {
    let v = Vault::new();
    let ok = with_stdin_password(&["pull", "-p", "shop", "-e", "dev"], &v.db_path(), "testpw");
    assert!(String::from_utf8_lossy(&ok.stdout).contains("API_KEY=old-key"));
    let bad = with_stdin_password(&["pull", "-p", "shop", "-e", "dev"], &v.db_path(), "nope");
    assert!(!bad.status.success());
}
