use clap::{Args, ValueEnum};
use yasecret_core::{env_file, YasecretError};

use super::target::Target;

#[derive(Clone, Copy, ValueEnum)]
pub enum Shell {
    /// bash, zsh, sh: `export KEY='value'`
    Posix,
    Fish,
    Powershell,
    /// Plain .env text
    Dotenv,
}

#[derive(Args)]
pub struct EnvArgs {
    #[arg(short, long)]
    pub project: String,
    #[arg(short, long)]
    pub env: String,
    /// Output syntax
    #[arg(long, value_enum, default_value_t = Shell::Posix)]
    pub shell: Shell,
    /// Only these keys (comma-separated or repeated)
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Prints shell statements that set the environment's variables, for
/// `eval "$(yasecret env -p app -e dev)"` or a direnv `.envrc`.
pub fn run(args: EnvArgs) -> yasecret_core::Result<()> {
    let mut t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    let mut pairs = t.pairs()?;
    if !args.only.is_empty() {
        if let Some(missing) = args.only.iter().find(|k| !pairs.iter().any(|(p, _)| p == *k)) {
            return Err(YasecretError::NotFound(format!("variable '{missing}' in {}/{}", t.project.name, t.env.name)));
        }
        pairs.retain(|(k, _)| args.only.contains(k));
    }
    let out = match args.shell {
        Shell::Dotenv => env_file::serialize(&pairs),
        shell => pairs.iter().map(|(k, v)| format!("{}\n", statement(shell, k, v))).collect(),
    };
    print!("{out}");
    Ok(())
}

fn statement(shell: Shell, key: &str, value: &str) -> String {
    match shell {
        // Single quotes are literal in POSIX shells; a quote is closed, escaped and reopened.
        Shell::Posix => format!("export {key}='{}'", value.replace('\'', r"'\''")),
        // In fish single quotes, only \\ and \' are escapes.
        Shell::Fish => format!("set -gx {key} '{}'", value.replace('\\', r"\\").replace('\'', r"\'")),
        // PowerShell single quotes are literal; a quote is doubled.
        Shell::Powershell => format!("$env:{key} = '{}'", value.replace('\'', "''")),
        Shell::Dotenv => unreachable!(),
    }
}
