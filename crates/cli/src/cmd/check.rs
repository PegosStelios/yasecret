use clap::Args;
use yasecret_core::{env_file, YasecretError};

use super::target::Target;

#[derive(Args)]
pub struct CheckArgs {
    /// The keys that must be set, e.g. a committed .env.example
    #[arg(short, long, default_value = ".env.example")]
    pub input: String,
    /// Check this local file instead of an environment in the vault
    #[arg(long, conflicts_with_all = ["project", "env"])]
    pub file: Option<String>,
    #[arg(short, long, requires = "env")]
    pub project: Option<String>,
    #[arg(short, long, requires = "project")]
    pub env: Option<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Returns true when a required key is missing or empty.
pub fn run(args: CheckArgs) -> yasecret_core::Result<bool> {
    let read = |path: &str| std::fs::read_to_string(path).map_err(|e| YasecretError::NotFound(format!("{path}: {e}")));
    let required = env_file::parse_example(&read(&args.input)?)?;
    let (have, source): (Vec<(String, String)>, String) = match (&args.file, &args.project, &args.env) {
        (Some(file), _, _) => (env_file::parse_any(&read(file)?)?, file.clone()),
        (None, Some(p), Some(e)) => {
            let mut t = Target::open(p, e, args.db.as_deref(), args.password.as_deref())?;
            (t.pairs()?, format!("{}/{}", t.project.name, t.env.name))
        }
        _ => {
            return Err(YasecretError::NotFound(
                "nothing to check: pass --file .env, or --project and --env".into(),
            ))
        }
    };
    let missing: Vec<&String> = required
        .iter()
        .filter(|k| !have.iter().any(|(h, v)| h == *k && !v.is_empty()))
        .collect();
    if missing.is_empty() {
        println!("{source} has all {} keys from {}", required.len(), args.input);
        Ok(false)
    } else {
        println!("{source} is missing {} of {} keys from {}:", missing.len(), required.len(), args.input);
        for k in missing {
            println!("  {k}");
        }
        Ok(true)
    }
}
