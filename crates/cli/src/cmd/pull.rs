use clap::Args;
use yasecret_core::env_file;

use super::target::{write_private, Target};

#[derive(Args)]
pub struct PullArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    #[arg(short, long, help = "Output file (default: stdout)")]
    pub output: Option<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub fn run(args: PullArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let output = env_file::serialize(&t.pairs()?);
    match args.output.as_deref() {
        Some(path) => write_private(path, &output)?,
        None => print!("{output}"),
    }
    Ok(())
}
