use clap::Args;
use sha2::{Digest, Sha256};
use yasecret_sync::{doc_manager, node::SyncNode};

#[derive(Args)]
pub struct JoinArgs {
    #[arg(long)]
    pub ticket: String,
    #[arg(short, long)]
    pub project: String,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub async fn run(args: JoinArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    let data_dir = path.parent().unwrap_or_else(|| std::path::Path::new(".")).join("sync");
    let sync_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"yasecret-sync-key-v1");
        h.update(&session.identity.secret_key);
        h.finalize().into()
    };
    let node = SyncNode::start(&data_dir, &sync_key)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    let doc_id = doc_manager::join_project_doc(&session.db, &node, &args.ticket, &args.project)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    // Brief wait for initial sync to deliver content.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    println!("joined doc: {doc_id}. Run `yasecret pull` once sync settles.");
    node.stop().await;
    Ok(())
}
