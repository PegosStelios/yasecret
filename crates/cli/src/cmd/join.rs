use clap::Args;
use yasecret_core::YasecretError;

#[derive(Args)]
pub struct JoinArgs {
    /// The yasecret://join link you were sent
    #[arg(alias = "ticket")]
    pub link: String,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub async fn run(args: JoinArgs) -> yasecret_core::Result<()> {
    tokio::task::spawn_blocking(move || {
        let path = crate::unlock::db_path(args.db.as_deref());
        let session = crate::unlock::unlock(&path, args.password.as_deref())?;
        let svc = super::share::start(&path, &session)?;
        eprintln!("Connecting to the person who shared this…");
        let project_id = svc.join(&args.link).map_err(super::share::sync_err)?;
        // Give the first sync pass a moment to land variables locally.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let name = yasecret_core::project::get(&session.db, &project_id)?.name;
        println!("Joined '{name}'. Run `yasecret pull` to write a .env.");
        svc.shutdown();
        Ok(())
    })
    .await
    .map_err(|e| YasecretError::Io(std::io::Error::other(e.to_string())))?
}
