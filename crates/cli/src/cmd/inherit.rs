use clap::Args;
use yasecret_core::{environment, YasecretError};

use super::target::Target;

#[derive(Args)]
pub struct InheritArgs {
    #[arg(short, long)]
    pub project: String,
    /// The environment that inherits
    #[arg(short, long)]
    pub env: String,
    /// Environment to inherit variables from (its own variables still win)
    #[arg(long, conflicts_with = "none", required_unless_present = "none")]
    pub from: Option<String>,
    /// Stop inheriting
    #[arg(long)]
    pub none: bool,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub fn run(args: InheritArgs) -> yasecret_core::Result<()> {
    let t = Target::open(&args.project, &args.env, args.db.as_deref(), args.password.as_deref())?;
    yasecret_core::access::ensure_can_write(&t.session.db, &t.project.id)?;
    let parent = match &args.from {
        Some(name) => Some(
            environment::list(&t.session.db, &t.project.id)?
                .into_iter()
                .find(|e| &e.name == name)
                .ok_or_else(|| YasecretError::NotFound(format!("environment '{name}' in '{}'", t.project.name)))?,
        ),
        None => None,
    };
    environment::set_parent(&t.session.db, &t.env.id, parent.as_ref().map(|p| p.id.as_str()))?;
    match parent {
        Some(p) => println!("{} now inherits from {}.", t.env.name, p.name),
        None => println!("{} no longer inherits from another environment.", t.env.name),
    }
    Ok(())
}
