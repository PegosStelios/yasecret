use clap::Args;
use std::time::Duration;
use yasecret_core::{env_file, secret};

use super::target::{write_private, Target};

#[derive(Args)]
pub struct DevArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// File to keep up to date
    #[arg(short, long, default_value = ".env")]
    pub output: String,
    /// Seconds between checks
    #[arg(long, default_value_t = 2)]
    pub interval: u64,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Writes the .env, then rewrites it whenever the environment changes (including changes the
/// desktop app syncs in from teammates). Runs until interrupted.
pub fn run(args: DevArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let mut last_fingerprint = None;
    let mut last_keys: Vec<String> = Vec::new();
    eprintln!("Keeping {} in sync with {}/{}. Press Ctrl-C to stop.", args.output, t.project.name, t.env.name);
    loop {
        let fingerprint: Vec<(String, String, i64)> = secret::list(&t.session.db, &t.env.id)?
            .into_iter()
            .map(|s| (s.id, s.key, s.updated_at))
            .collect();
        if last_fingerprint.as_ref() != Some(&fingerprint) {
            let pairs = t.pairs()?;
            write_private(&args.output, &env_file::serialize(&pairs))?;
            let keys: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
            if last_fingerprint.is_some() {
                let added = keys.iter().filter(|k| !last_keys.contains(k)).count();
                let removed = last_keys.iter().filter(|k| !keys.contains(k)).count();
                eprintln!("Updated {} ({} variables, +{added} -{removed})", args.output, keys.len());
            } else {
                eprintln!("Wrote {} ({} variables)", args.output, keys.len());
            }
            last_keys = keys;
            last_fingerprint = Some(fingerprint);
        }
        std::thread::sleep(Duration::from_secs(args.interval.max(1)));
    }
}
