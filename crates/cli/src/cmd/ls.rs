use clap::Args;
use serde_json::json;
use yasecret_core::{environment, project, secret};

#[derive(Args)]
pub struct LsArgs {
    /// Print JSON (for editors and scripts)
    #[arg(long)]
    pub json: bool,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Lists projects, environments and variable names. Never prints values.
pub fn run(args: LsArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;
    let mut projects = Vec::new();
    for p in project::list(&session.db)? {
        let envs = environment::list(&session.db, &p.id)?;
        let mut out_envs = Vec::new();
        for e in &envs {
            let vars: Vec<_> = secret::list(&session.db, &e.id)?
                .into_iter()
                .map(|s| json!({ "key": s.key, "secret": s.is_secret, "type": s.value_type }))
                .collect();
            let parent = e.inherits_from.as_ref().and_then(|id| envs.iter().find(|x| &x.id == id)).map(|x| x.name.clone());
            out_envs.push(json!({ "name": e.name, "inherits": parent, "variables": vars }));
        }
        projects.push(json!({ "name": p.name, "environments": out_envs }));
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&json!({ "projects": projects }))?);
    } else {
        for p in &projects {
            println!("{}", p["name"].as_str().unwrap_or_default());
            for e in p["environments"].as_array().into_iter().flatten() {
                let inherits = e["inherits"].as_str().map(|i| format!(" (inherits {i})")).unwrap_or_default();
                let n = e["variables"].as_array().map(Vec::len).unwrap_or(0);
                println!("  {}{inherits}: {n} variables", e["name"].as_str().unwrap_or_default());
            }
        }
    }
    Ok(())
}
