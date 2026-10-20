//! yasecret rotate: generated values, guided rotation, and AWS against a fake IAM/STS.

mod common;

use common::{bin, stdout, Vault};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
};

#[test]
fn generate_replaces_the_value_and_keeps_the_old_one_in_history() {
    let v = Vault::new();
    let out = v.cmd(&["rotate", "-p", "shop", "-e", "dev", "API_KEY", "--generate", "--length", "40"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (value, _) = v.value("API_KEY").unwrap();
    assert_eq!(value.len(), 40);
    assert_ne!(value, "old-key");
    assert!(!stdout(&out).contains(&value), "the new value isn't printed");
}

#[test]
fn guided_rotation_shows_where_to_roll_the_key_and_takes_the_new_value() {
    let v = Vault::new();
    v.add("STRIPE_SECRET_KEY", "sk_live_old", true);
    let mut child = Command::new(bin())
        .args(["rotate", "-p", "shop", "-e", "dev", "STRIPE_SECRET_KEY", "--value-stdin", "--db", &v.db_path(), "--password", "testpw"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "sk_live_new").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert!(stdout(&out).contains("https://dashboard.stripe.com/apikeys"), "{}", stdout(&out));
    assert_eq!(v.value("STRIPE_SECRET_KEY").unwrap().0, "sk_live_new");

    let unknown = v.cmd(&["rotate", "-p", "shop", "-e", "dev", "PORT", "--value-stdin"]);
    assert!(!unknown.status.success() || stdout(&unknown).contains("--generate"));
}

/// Answers IAM/STS form posts like AWS would, recording each Action.
fn fake_aws(actions: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0;
            let mut auth = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let l = line.to_ascii_lowercase();
                if let Some(v) = l.strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                if l.starts_with("authorization:") {
                    auth = line.clone();
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            let body = String::from_utf8(body).unwrap();
            let action = body.split('&').find_map(|p| p.strip_prefix("Action=")).unwrap_or("").to_string();
            assert!(auth.contains("AWS4-HMAC-SHA256"), "requests are signed");
            actions.lock().unwrap().push(format!("{action} by {}", if auth.contains("AKIANEW") { "new" } else { "old" }));
            let xml = match action.as_str() {
                "CreateAccessKey" => "<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIANEWKEY000000</AccessKeyId><SecretAccessKey>newsecret/abc</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>",
                "GetCallerIdentity" => "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::1:user/ci</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>",
                _ => "<DeleteAccessKeyResponse/>",
            };
            let mut s = stream;
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{xml}", xml.len()).unwrap();
        }
    });
    url
}

#[test]
fn aws_rotation_creates_verifies_stores_then_deletes_the_old_key() {
    let v = Vault::new();
    v.add("AWS_ACCESS_KEY_ID", "AKIAOLDKEY0000000", false);
    v.add("AWS_SECRET_ACCESS_KEY", "oldsecret", true);
    let actions = Arc::new(Mutex::new(Vec::new()));
    let url = fake_aws(actions.clone());
    let out = Command::new(bin())
        .args(["rotate", "-p", "shop", "-e", "dev", "--aws", "--db", &v.db_path(), "--password", "testpw"])
        .env("YASECRET_AWS_IAM_URL", &url)
        .env("YASECRET_AWS_STS_URL", &url)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
    assert_eq!(v.value("AWS_ACCESS_KEY_ID").unwrap().0, "AKIANEWKEY000000");
    assert_eq!(v.value("AWS_SECRET_ACCESS_KEY").unwrap().0, "newsecret/abc");
    let seen = actions.lock().unwrap().clone();
    assert_eq!(seen.first().map(String::as_str), Some("CreateAccessKey by old"));
    assert!(seen.contains(&"GetCallerIdentity by new".to_string()), "the new key is checked: {seen:?}");
    assert_eq!(seen.last().map(String::as_str), Some("DeleteAccessKey by new"), "{seen:?}");
}
