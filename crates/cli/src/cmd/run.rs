use clap::Args;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

use super::target::Target;

#[derive(Args)]
pub struct RunArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    #[arg(long, value_delimiter = ',', help = "Comma-separated secret keys to inject")]
    pub only: Vec<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let env_vars: Vec<(String, Zeroizing<Vec<u8>>)> = t
        .pairs()?
        .into_iter()
        .filter(|(k, _)| args.only.is_empty() || args.only.contains(k))
        .map(|(k, v)| (k, Zeroizing::new(v.into_bytes())))
        .collect();

    let secret_values: Vec<String> = env_vars
        .iter()
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .collect();

    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    for (key, value) in &env_vars {
        cmd.env(key, String::from_utf8_lossy(value).as_ref());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .map_err(yasecret_core::YasecretError::Io)?;

    let stdout = mask(&String::from_utf8_lossy(&output.stdout), &secret_values);
    let stderr = mask(&String::from_utf8_lossy(&output.stderr), &secret_values);

    print!("{stdout}");
    eprint!("{stderr}");

    std::process::exit(output.status.code().unwrap_or(1));
}

fn mask(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();
    for s in secrets {
        if !s.is_empty() {
            result = result.replace(s.as_str(), "[REDACTED]");
        }
    }
    result
}
