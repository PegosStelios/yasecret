use clap::Args;
use yasecret_core::env_file::{self, ExportFormat};

use super::target::{write_private, Target};

#[derive(Args)]
pub struct ExampleArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// File to write (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Writes a `.env.example`: every key, no values, secrets marked.
pub fn run(args: ExampleArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let text = env_file::export(&t.items()?, ExportFormat::Example, &t.env.name)?;
    match args.output {
        Some(path) => {
            write_private(&path, &text)?;
            eprintln!("Wrote {path}");
        }
        None => print!("{text}"),
    }
    Ok(())
}
