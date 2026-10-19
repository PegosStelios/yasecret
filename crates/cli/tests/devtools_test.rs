//! env / example / check / scan / share --relay, via the real binary.

mod common;

use common::{stdout, Vault};
use std::process::Command;

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn env_output_evaluates_to_the_exact_values_in_a_posix_shell() {
    let v = Vault::new();
    v.add("TRICKY", "it's $HOME \"quoted\"\nline2", true);
    let out = v.cmd(&["env", "-p", "shop", "-e", "dev"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let script = format!("{}\nprintf '%s|%s|%s' \"$API_KEY\" \"$PORT\" \"$TRICKY\"", stdout(&out));
    let shell = Command::new("sh").arg("-c").arg(&script).output().unwrap();
    assert_eq!(String::from_utf8_lossy(&shell.stdout), "old-key|3000|it's $HOME \"quoted\"\nline2");
}

#[test]
fn env_supports_other_shells_and_a_subset_of_keys() {
    let v = Vault::new();
    let fish = stdout(&v.cmd(&["env", "-p", "shop", "-e", "dev", "--shell", "fish", "--only", "PORT"]));
    assert_eq!(fish.trim(), "set -gx PORT '3000'");
    let ps = stdout(&v.cmd(&["env", "-p", "shop", "-e", "dev", "--shell", "powershell", "--only", "API_KEY"]));
    assert_eq!(ps.trim(), "$env:API_KEY = 'old-key'");
    let missing = v.cmd(&["env", "-p", "shop", "-e", "dev", "--only", "NOPE"]);
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("NOPE"));
}

#[test]
fn example_lists_keys_without_values() {
    let v = Vault::new();
    let path = v.dir.path().join(".env.example");
    let out = v.cmd(&["example", "-p", "shop", "-e", "dev", "-o", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("API_KEY=") && text.contains("PORT="), "{text}");
    assert!(!text.contains("old-key") && !text.contains("3000"), "no values: {text}");
}

#[test]
fn check_fails_on_missing_keys_against_the_vault_or_a_file() {
    let v = Vault::new();
    let example = v.file(".env.example", "API_KEY=\nPORT=\nSENTRY_DSN=  # secret\n");
    let out = v.cmd(&["check", "-p", "shop", "-e", "dev", "-i", &example]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("SENTRY_DSN"), "{}", stdout(&out));

    let local = v.file(".env", "API_KEY=x\nPORT=1\nSENTRY_DSN=y\n");
    let ok = v.cmd(&["check", "-i", &example, "--file", &local]);
    assert_eq!(ok.status.code(), Some(0), "{}{}", stdout(&ok), stderr(&ok));

    let empty = v.file("empty.env", "API_KEY=x\nPORT=\nSENTRY_DSN=y\n");
    let out = v.cmd(&["check", "-i", &example, "--file", &empty]);
    assert_eq!(out.status.code(), Some(1), "empty values count as missing");
    assert!(stdout(&out).contains("PORT"));

    let broken = v.cmd(&["check", "-i", "/nonexistent/.env.example", "--file", &local]);
    assert_eq!(broken.status.code(), Some(2));
}

fn git(dir: &std::path::Path, args: &[&str]) {
    let ok = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
        .status
        .success();
    assert!(ok, "git {args:?}");
}

#[test]
fn scan_reports_leaked_secrets_by_name_only() {
    let v = Vault::new();
    v.add("STRIPE_KEY", "sk_live_51Habcdef0123456789", true);
    v.add("APP_NAME", "storefront-production", false);
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    std::fs::write(repo.path().join("clean.txt"), "nothing here\n").unwrap();
    git(repo.path(), &["add", "."]);
    git(repo.path(), &["commit", "-qm", "init"]);

    let clean = v.cmd(&["scan", "--path", repo.path().to_str().unwrap()]);
    assert_eq!(clean.status.code(), Some(0), "{}{}", stdout(&clean), stderr(&clean));

    std::fs::write(repo.path().join("config.js"), "const name = 'storefront-production';\nconst k = 'sk_live_51Habcdef0123456789';\n").unwrap();
    let dirty = v.cmd(&["scan", "--path", repo.path().to_str().unwrap()]);
    assert_eq!(dirty.status.code(), Some(1));
    let report = stdout(&dirty);
    assert!(report.contains("config.js:2") && report.contains("STRIPE_KEY"), "{report}");
    assert!(!report.contains("sk_live"), "never print the value: {report}");
    assert!(!report.contains("APP_NAME"), "plain variables aren't secrets: {report}");

    // --staged looks only at what's about to be committed; --history at past commits.
    let staged = v.cmd(&["scan", "--path", repo.path().to_str().unwrap(), "--staged"]);
    assert_eq!(staged.status.code(), Some(0), "nothing staged yet");
    git(repo.path(), &["add", "config.js"]);
    let staged = v.cmd(&["scan", "--path", repo.path().to_str().unwrap(), "--staged"]);
    assert_eq!(staged.status.code(), Some(1));
    git(repo.path(), &["commit", "-qm", "oops"]);
    std::fs::remove_file(repo.path().join("config.js")).unwrap();
    git(repo.path(), &["commit", "-qam", "remove"]);
    let now = v.cmd(&["scan", "--path", repo.path().to_str().unwrap()]);
    assert_eq!(now.status.code(), Some(0), "gone from the working tree");
    let history = v.cmd(&["scan", "--path", repo.path().to_str().unwrap(), "--history"]);
    assert_eq!(history.status.code(), Some(1));
    assert!(stdout(&history).contains("STRIPE_KEY"));
}

#[test]
fn share_can_add_a_relay_from_the_cli() {
    let v = Vault::new();
    let relay_dir = tempfile::tempdir().unwrap();
    let code = Command::new(common::bin()).args(["relay", "code", "--dir"]).arg(relay_dir.path()).output().unwrap();
    let code = String::from_utf8(code.stdout).unwrap().trim().to_string();
    let out = v.cmd(&["share", "-p", "shop", "--relay", &code, "--name", "office box"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("yasecret relay add 'yasecret://relay?"), "{text}");
}
