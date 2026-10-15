use clap::Args;
use std::process::{Command, Stdio};
use yasecret_core::{crypto, environment, project, project_key, secret};
use zeroize::Zeroizing;

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
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    let projects = project::list(&session.db)?;
    let proj = projects
        .iter()
        .find(|p| p.name == args.project)
        .ok_or_else(|| {
            yasecret_core::YasecretError::NotFound(format!("project '{}'", args.project))
        })?;

    let envs = environment::list(&session.db, &proj.id)?;
    let env = envs
        .iter()
        .find(|e| e.name == args.env)
        .ok_or_else(|| {
            yasecret_core::YasecretError::NotFound(format!("environment '{}'", args.env))
        })?;

    let proj_key = project_key::load(&session.db, &proj.id, &session.db_key)?;
    let all_secrets = secret::list(&session.db, &env.id)?;

    let mut env_vars: Vec<(String, Zeroizing<Vec<u8>>)> = vec![];
    for s in &all_secrets {
        if args.only.is_empty() || args.only.contains(&s.key) {
            let nonce: [u8; 12] = s
                .nonce
                .clone()
                .try_into()
                .map_err(|_| yasecret_core::YasecretError::Crypto)?;
            let value = crypto::decrypt(&s.encrypted_value, &nonce, &proj_key)?;
            env_vars.push((s.key.clone(), value));
        }
    }

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
