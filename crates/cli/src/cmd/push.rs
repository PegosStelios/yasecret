use clap::Args;
use yasecret_core::{access, env_file, secret, YasecretError};

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
    let pairs = env_file::parse_any(&content)?;
    let t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    access::ensure_can_write(&t.session.db, &t.project.id)?;
    let r = secret::merge(
        &t.session.db,
        &t.env.id,
        &pairs,
        &t.key,
        &t.session.identity.id,
        Some("cli push"),
        args.overwrite,
        args.dry_run,
    )?;

    let prefix = if args.dry_run { "Would push" } else { "Pushed" };
    println!(
        "{prefix} to {}/{}: {} added, {} updated, {} unchanged, {} skipped",
        t.project.name,
        t.env.name,
        r.added,
        r.updated,
        r.unchanged,
        r.skipped.len()
    );
    if !r.skipped.is_empty() {
        println!("Skipped (already exist with a different value; use --overwrite): {}", r.skipped.join(", "));
    }
    Ok(())
}
