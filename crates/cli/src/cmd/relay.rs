use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Args, Subcommand};
use yasecret_core::YasecretError;
use yasecret_sync::{live::RelayLink, relay, SyncError};

use super::share::sync_err;

#[derive(Args)]
pub struct RelayArgs {
    #[command(subcommand)]
    pub action: Option<RelayAction>,
    /// Where the relay keeps its data (default: the local data dir, or $YASECRET_RELAY_DIR)
    #[arg(long, global = true)]
    pub dir: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum RelayAction {
    /// Print this relay's code. Paste it in Yasecret: Share → Always-on peer
    Code,
    /// Add a project using the relay link Yasecret gave you
    Add { link: String },
}

fn relay_dir(dir: Option<PathBuf>) -> PathBuf {
    dir.or_else(|| std::env::var_os("YASECRET_RELAY_DIR").map(PathBuf::from))
        .unwrap_or_else(|| dirs::data_local_dir().unwrap_or_else(|| PathBuf::from(".")).join("yasecret-relay"))
}

pub async fn run(args: RelayArgs) -> yasecret_core::Result<()> {
    let dir = relay_dir(args.dir);
    match args.action {
        Some(RelayAction::Code) => {
            println!("{}", relay::code_for_dir(&dir).map_err(sync_err)?);
            Ok(())
        }
        Some(RelayAction::Add { link }) => queue(&dir, &link),
        None => serve(&dir).await,
    }
}

/// Links go through an inbox so `add` works while the relay holds its data dir.
fn queue(dir: &Path, link: &str) -> yasecret_core::Result<()> {
    let parsed = RelayLink::parse(link).map_err(sync_err)?;
    let inbox = dir.join("inbox");
    std::fs::create_dir_all(&inbox)?;
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    std::fs::write(inbox.join(format!("{nanos}.link")), link.trim())?;
    if relay::is_running(dir) {
        println!("Queued “{}”. The running relay picks it up within a few seconds.", parsed.project_name);
    } else {
        println!("Queued “{}”. Start the relay with `yasecret relay` to begin syncing it.", parsed.project_name);
    }
    Ok(())
}

async fn take_inbox(r: &relay::Relay, dir: &Path) {
    let Ok(files) = std::fs::read_dir(dir.join("inbox")) else { return };
    let mut paths: Vec<PathBuf> = files.flatten().map(|f| f.path()).filter(|p| p.extension().is_some_and(|e| e == "link")).collect();
    paths.sort();
    for path in paths {
        let link = std::fs::read_to_string(&path).unwrap_or_default();
        match r.add(&link).await {
            Ok(p) => eprintln!("Added “{}”.", p.name),
            Err(e) => eprintln!("Couldn't add {}: {e}", path.display()),
        }
        let _ = std::fs::remove_file(&path);
    }
}

async fn serve(dir: &Path) -> yasecret_core::Result<()> {
    let r = relay::Relay::start(dir).await.map_err(|e| match e {
        SyncError::InUse => YasecretError::Io(std::io::Error::other(format!(
            "a relay is already running with {}",
            dir.display()
        ))),
        other => sync_err(other),
    })?;
    eprintln!("Relay code: {}", r.code());
    eprintln!("Data: {}", dir.display());
    take_inbox(&r, dir).await;
    let mut last = String::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    let mut redial = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = redial.tick() => { let _ = r.resume().await; }
            _ = tick.tick() => {
                take_inbox(&r, dir).await;
                let projects = r.projects().await.map_err(sync_err)?;
                let summary = if projects.is_empty() {
                    "No projects yet. In Yasecret: Share → Always-on peer, paste the relay code, then run `yasecret relay add '<link>'`.".to_string()
                } else {
                    projects.iter().map(|p| format!("{} ({} entries)", p.name, p.entries)).collect::<Vec<_>>().join(", ")
                };
                if summary != last {
                    eprintln!("Keeping: {summary}");
                    last = summary;
                }
            }
        }
    }
    r.shutdown().await;
    Ok(())
}
