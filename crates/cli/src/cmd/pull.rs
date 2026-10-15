use clap::Args;
use yasecret_core::{crypto, environment, env_file, project, project_key, secret};

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
    let secrets = secret::list(&session.db, &env.id)?;

    let mut pairs = vec![];
    for s in &secrets {
        let nonce: [u8; 12] = s
            .nonce
            .clone()
            .try_into()
            .map_err(|_| yasecret_core::YasecretError::Crypto)?;
        let value = crypto::decrypt(&s.encrypted_value, &nonce, &proj_key)?;
        let value_str = String::from_utf8_lossy(&value).into_owned();
        pairs.push((s.key.clone(), value_str));
    }

    let output = env_file::serialize(&pairs);

    match args.output.as_deref() {
        Some(path) => std::fs::write(path, &output)?,
        None => print!("{output}"),
    }

    Ok(())
}
