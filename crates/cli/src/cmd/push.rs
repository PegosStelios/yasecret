use clap::Args;
use std::collections::HashMap;
use yasecret_core::{env_file, secret, YasecretError};

use super::target::Target;

#[derive(Args)]
pub struct PushArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// .env or JSON file to read
    #[arg(short, long, default_value = ".env")]
    pub input: String,
    /// Replace values of keys that already exist (otherwise they're skipped)
    #[arg(long)]
    pub overwrite: bool,
    /// Show what would change without writing anything
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub fn run(args: PushArgs) -> yasecret_core::Result<()> {
    let content = std::fs::read_to_string(&args.input)
        .map_err(|e| YasecretError::NotFound(format!("{}: {e}", args.input)))?;
    let parsed = env_file::parse_any(&content)?;
    // Later lines win, like dotenv loaders.
    let mut incoming: Vec<(String, String)> = Vec::new();
    for (k, v) in parsed {
        if !env_file::valid_key(&k) {
            return Err(YasecretError::EnvParse(format!("'{k}' is not a valid variable name")));
        }
        incoming.retain(|(existing, _)| existing != &k);
        incoming.push((k, v));
    }

    let t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let current: HashMap<String, (String, String)> = secret::list(&t.session.db, &t.env.id)?
        .into_iter()
        .map(|s| {
            let nonce: [u8; 12] = s.nonce.clone().try_into().map_err(|_| YasecretError::Crypto)?;
            let v = yasecret_core::crypto::decrypt(&s.encrypted_value, &nonce, &t.key)?;
            Ok((s.key, (s.id, String::from_utf8_lossy(&v).into_owned())))
        })
        .collect::<yasecret_core::Result<_>>()?;

    let me = t.session.identity.id.clone();
    let (mut added, mut updated, mut unchanged, mut skipped) = (0, 0, 0, Vec::new());
    let tx = t.session.db.conn().unchecked_transaction()?;
    for (key, value) in &incoming {
        match current.get(key) {
            Some((_, old)) if old == value => unchanged += 1,
            Some((id, _)) if args.overwrite => {
                if !args.dry_run {
                    secret::update(&t.session.db, id, value.as_bytes(), &t.key, &me, Some("cli push"))?;
                }
                updated += 1;
            }
            Some(_) => skipped.push(key.clone()),
            None => {
                if !args.dry_run {
                    secret::create_with_kind(
                        &t.session.db, &t.env.id, key, value.as_bytes(), &t.key, &me, None, env_file::looks_secret(key),
                    )?;
                }
                added += 1;
            }
        }
    }
    tx.commit()?;

    let prefix = if args.dry_run { "Would push" } else { "Pushed" };
    println!(
        "{prefix} to {}/{}: {added} added, {updated} updated, {unchanged} unchanged, {} skipped",
        t.project.name,
        t.env.name,
        skipped.len()
    );
    if !skipped.is_empty() {
        println!("Skipped (already exist with a different value; use --overwrite): {}", skipped.join(", "));
    }
    Ok(())
}
