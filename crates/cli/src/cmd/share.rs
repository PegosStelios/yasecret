use clap::Args;
use yasecret_core::{project, YasecretError};
use yasecret_sync::live::{SyncConfig, SyncService, LEVEL_EDITOR, LEVEL_VIEWER};

#[derive(Args)]
pub struct ShareArgs {
    #[arg(short, long)]
    pub project: String,
    /// Bind the invite to one device: the code shown by `yasecret peers self` on their machine
    #[arg(long, alias = "peer-key")]
    pub device_code: Option<String>,
    /// Give read-only access instead of edit access
    #[arg(long)]
    pub viewer: bool,
    /// Print the link and exit instead of staying online for the invitee
    #[arg(long)]
    pub no_wait: bool,
    /// Add an always-on peer instead of creating an invite: the code from `yasecret relay code`
    #[arg(long, conflicts_with_all = ["device_code", "viewer"])]
    pub relay: Option<String>,
    /// Name shown for the relay
    #[arg(long, requires = "relay")]
    pub name: Option<String>,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub async fn run(args: ShareArgs) -> yasecret_core::Result<()> {
    tokio::task::spawn_blocking(move || run_blocking(args))
        .await
        .map_err(|e| YasecretError::Io(std::io::Error::other(e.to_string())))?
}

fn run_blocking(args: ShareArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;
    let proj = project::list(&session.db)?
        .into_iter()
        .find(|p| p.name == args.project)
        .ok_or_else(|| YasecretError::NotFound(format!("project '{}'", args.project)))?;

    let svc = start(&path, &session)?;
    if let Some(code) = &args.relay {
        let link = svc.add_relay(&proj.id, code, args.name.as_deref().unwrap_or("")).map_err(sync_err);
        svc.shutdown();
        println!("Run this on the relay machine:\n  yasecret relay add '{}'", link?);
        return Ok(());
    }
    let level = if args.viewer { LEVEL_VIEWER } else { LEVEL_EDITOR };
    let link = svc
        .create_invite(&proj.id, args.device_code.as_deref(), level)
        .map_err(sync_err)?;
    println!("{link}");
    if args.no_wait {
        svc.shutdown();
        return Ok(());
    }
    eprintln!("Keep this running until your teammate has joined. Press Ctrl-C to stop.");
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc_wait(tx);
    let _ = rx.recv();
    svc.shutdown();
    Ok(())
}

pub(crate) fn start(path: &std::path::Path, session: &crate::unlock::Session) -> yasecret_core::Result<SyncService> {
    let data_dir = path.parent().unwrap_or_else(|| std::path::Path::new(".")).join("sync");
    SyncService::start(SyncConfig {
        db_path: path.to_path_buf(),
        db_password: session.password.clone(),
        db_key: *session.db_key,
        data_dir,
        device_name: hostname(),
    })
    .map_err(|e| match e {
        yasecret_sync::SyncError::InUse => YasecretError::Io(std::io::Error::other(
            "the Yasecret app (or another `yasecret share`) is running for this vault — share or join from there instead",
        )),
        other => sync_err(other),
    })
}

pub(crate) fn sync_err(e: yasecret_sync::SyncError) -> YasecretError {
    match e {
        yasecret_sync::SyncError::Core(c) => c,
        other => YasecretError::Io(std::io::Error::other(other.to_string())),
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "yasecret-cli".into())
}

fn ctrlc_wait(tx: std::sync::mpsc::Sender<()>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        let _ = tx.send(());
    });
}
