use clap::Args;
use std::collections::BTreeMap;
use yasecret_core::{env_file, YasecretError};

use super::target::Target;

#[derive(Args)]
pub struct DiffArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// Local .env or JSON file to compare
    #[arg(short, long, default_value = ".env")]
    pub input: String,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Prints key-level differences (never values). Returns true when anything differs.
pub fn run(args: DiffArgs) -> yasecret_core::Result<bool> {
    let content = std::fs::read_to_string(&args.input)
        .map_err(|e| YasecretError::NotFound(format!("{}: {e}", args.input)))?;
    let local: BTreeMap<String, String> = env_file::parse_any(&content)?.into_iter().collect();
    let t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let vault: BTreeMap<String, String> = t.pairs()?.into_iter().collect();

    let mut lines = Vec::new();
    for key in vault.keys().chain(local.keys()).collect::<std::collections::BTreeSet<_>>() {
        match (vault.get(key), local.get(key)) {
            (Some(a), Some(b)) if a != b => lines.push(format!("~ {key}  (value differs)")),
            (Some(_), None) => lines.push(format!("+ {key}  (only in vault)")),
            (None, Some(_)) => lines.push(format!("- {key}  (only in {})", args.input)),
            _ => {}
        }
    }
    if lines.is_empty() {
        println!("{} matches {}/{} ({} variables)", args.input, t.project.name, t.env.name, vault.len());
        Ok(false)
    } else {
        println!("{} vs {}/{}:", args.input, t.project.name, t.env.name);
        for l in &lines {
            println!("  {l}");
        }
        Ok(true)
    }
}
