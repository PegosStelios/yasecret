use std::time::{Duration, Instant};

use clap::{Args, ValueEnum};
use yasecret_core::{
    rotate::{self, aws, Charset},
    secret, YasecretError,
};

use super::target::Target;

#[derive(Clone, Copy, ValueEnum)]
pub enum CharsetArg {
    Urlsafe,
    Alnum,
    Hex,
}

#[derive(Args)]
pub struct RotateArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// The variable to replace
    #[arg(required_unless_present = "aws")]
    pub key: Option<String>,
    /// Replace it with a new random value
    #[arg(long, conflicts_with_all = ["value_stdin", "aws"])]
    pub generate: bool,
    #[arg(long, default_value_t = 48, requires = "generate")]
    pub length: usize,
    #[arg(long, value_enum, default_value_t = CharsetArg::Urlsafe, requires = "generate")]
    pub charset: CharsetArg,
    /// Read the new value from standard input instead of prompting
    #[arg(long, conflicts_with = "aws")]
    pub value_stdin: bool,
    /// Rotate an AWS access key pair through IAM: create a new key, check it, store it, delete the old one
    #[arg(long, conflicts_with = "key")]
    pub aws: bool,
    /// Keep the old AWS key instead of deleting it
    #[arg(long, requires = "aws")]
    pub keep_old: bool,
    #[arg(long, default_value = "AWS_ACCESS_KEY_ID", requires = "aws")]
    pub aws_id_key: String,
    #[arg(long, default_value = "AWS_SECRET_ACCESS_KEY", requires = "aws")]
    pub aws_secret_key: String,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub fn run(args: RotateArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    yasecret_core::access::ensure_can_write(&t.session.db, &t.project.id)?;
    if args.aws {
        return rotate_aws(&mut t, &args);
    }
    let key = args.key.clone().unwrap_or_default();
    let (id, old) = own_variable(&mut t, &key)?;
    let new = if args.generate {
        let charset = match args.charset {
            CharsetArg::Urlsafe => Charset::UrlSafe,
            CharsetArg::Alnum => Charset::Alphanumeric,
            CharsetArg::Hex => Charset::Hex,
        };
        rotate::generate(args.length, charset)
    } else {
        match rotate::provider(&key, &old) {
            Some(p) => {
                println!("{key} is a {} key. Roll it at:\n  {}\n{}", p.name, p.dashboard, p.steps);
            }
            None => println!("Paste the new value for {key}. (For a random value, use --generate.)"),
        }
        let value = if args.value_stdin {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim_end_matches(['\r', '\n']).to_string()
        } else {
            rpassword::prompt_password("New value: ")?
        };
        if value.is_empty() {
            return Err(YasecretError::InvalidValue("no new value given; nothing changed".into()));
        }
        value
    };
    secret::update(&t.session.db, &id, new.as_bytes(), &t.key, &t.session.identity.id, Some("rotated"))?;
    println!("Rotated {key} in {}/{}. The old value is in its history.", t.project.name, t.env.name);
    Ok(())
}

/// The id and current value of a variable the environment itself defines.
fn own_variable(t: &mut Target, key: &str) -> yasecret_core::Result<(String, String)> {
    match secret::list(&t.session.db, &t.env.id)?.into_iter().find(|s| s.key == key) {
        Some(s) => {
            let value = String::from_utf8_lossy(&secret::get_plaintext(&t.session.db, &s.id, &t.key)?).into_owned();
            Ok((s.id, value))
        }
        None if t.pairs()?.iter().any(|(k, _)| k == key) => Err(YasecretError::NotFound(format!(
            "{key} is inherited by {}; rotate it in the environment it comes from",
            t.env.name
        ))),
        None => Err(YasecretError::NotFound(format!("variable '{key}' in {}/{}", t.project.name, t.env.name))),
    }
}

fn aws_error(xml: &str) -> String {
    match (aws::xml_value(xml, "Code"), aws::xml_value(xml, "Message")) {
        (Some("LimitExceeded"), _) => "this IAM user already has two access keys; delete the unused one in IAM first".into(),
        (Some(code), Some(msg)) => format!("{code}: {msg}"),
        _ => xml.chars().take(300).collect(),
    }
}

/// A signed form POST to IAM or STS. Endpoints can be overridden for testing.
fn call(env_var: &str, default_url: &str, service: &str, creds: &aws::Credentials, body: &str) -> yasecret_core::Result<String> {
    let url = std::env::var(env_var).unwrap_or_else(|_| default_url.to_string());
    let host = url.split("://").nth(1).unwrap_or(&url).split('/').next().unwrap_or_default().to_string();
    let content_type = "application/x-www-form-urlencoded; charset=utf-8";
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let signed = aws::sign(creds, "POST", &host, "/", "", &[("content-type", content_type)], body.as_bytes(), "us-east-1", service, &aws::amz_date(now));
    let response = reqwest::blocking::Client::new()
        .post(&url)
        .header("content-type", content_type)
        .header("x-amz-date", &signed.amz_date)
        .header("authorization", &signed.authorization)
        .body(body.to_string())
        .timeout(Duration::from_secs(30))
        .send()
        .map_err(|e| YasecretError::Io(std::io::Error::other(format!("couldn't reach AWS: {e}"))))?;
    let ok = response.status().is_success();
    let text = response.text().map_err(|e| YasecretError::Io(std::io::Error::other(e.to_string())))?;
    if ok {
        Ok(text)
    } else {
        Err(YasecretError::Io(std::io::Error::other(format!("AWS refused the request — {}", aws_error(&text)))))
    }
}

fn rotate_aws(t: &mut Target, args: &RotateArgs) -> yasecret_core::Result<()> {
    let (id_secret, old_id) = own_variable(t, &args.aws_id_key)?;
    let (secret_secret, old_secret) = own_variable(t, &args.aws_secret_key)?;
    let old = aws::Credentials { access_key: old_id.clone(), secret_key: old_secret };

    println!("Creating a new access key for the IAM user that owns {old_id}…");
    let created = call("YASECRET_AWS_IAM_URL", "https://iam.amazonaws.com", "iam", &old, "Action=CreateAccessKey&Version=2010-05-08")?;
    let (Some(new_id), Some(new_secret)) = (aws::xml_value(&created, "AccessKeyId"), aws::xml_value(&created, "SecretAccessKey")) else {
        return Err(YasecretError::Io(std::io::Error::other("AWS didn't return a new access key")));
    };
    let new = aws::Credentials { access_key: new_id.to_string(), secret_key: new_secret.to_string() };

    // New IAM keys take a few seconds to work everywhere.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match call("YASECRET_AWS_STS_URL", "https://sts.amazonaws.com", "sts", &new, "Action=GetCallerIdentity&Version=2011-06-15") {
            Ok(_) => break,
            Err(e) if Instant::now() > deadline => {
                return Err(YasecretError::Io(std::io::Error::other(format!(
                    "the new key {} didn't start working ({e}); nothing was changed in the vault, and both keys still exist in IAM",
                    new.access_key
                ))))
            }
            Err(_) => std::thread::sleep(Duration::from_secs(3)),
        }
    }

    let me = t.session.identity.id.clone();
    let tx = t.session.db.conn().unchecked_transaction()?;
    secret::update(&t.session.db, &id_secret, new.access_key.as_bytes(), &t.key, &me, Some("rotated (AWS)"))?;
    secret::update(&t.session.db, &secret_secret, new.secret_key.as_bytes(), &t.key, &me, Some("rotated (AWS)"))?;
    tx.commit()?;
    println!("Stored the new key {} in {}/{}.", new.access_key, t.project.name, t.env.name);

    if args.keep_old {
        println!("Kept the old key {old_id}. Delete it in IAM once nothing uses it.");
        return Ok(());
    }
    let body = format!("Action=DeleteAccessKey&Version=2010-05-08&AccessKeyId={}", aws::encode(&old_id));
    match call("YASECRET_AWS_IAM_URL", "https://iam.amazonaws.com", "iam", &new, &body) {
        Ok(_) => println!("Deleted the old key {old_id}."),
        Err(e) => println!("Couldn't delete the old key {old_id} ({e}). Delete it in IAM yourself."),
    }
    Ok(())
}
