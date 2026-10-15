use clap::Args;
use sha2::{Digest, Sha256};
use yasecret_core::{environment, project, project_key, secret};
use yasecret_sync::{
    applier::{push_env_meta, push_peer_key, push_project_meta, push_secret},
    doc_manager,
    node::SyncNode,
    peer_key::store_peer_key,
    types::{SyncEnvMeta, SyncProjectMeta, SyncSecret},
};

#[derive(Args)]
pub struct ShareArgs {
    #[arg(short, long)]
    pub project: String,
    /// Invitee's X25519 public key as 64-char hex (`yasecret peers self` on their machine)
    #[arg(long)]
    pub peer_key: String,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

pub async fn run(args: ShareArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    let peer_key_bytes =
        hex::decode(&args.peer_key).map_err(|_| yasecret_core::YasecretError::NotFound("invalid peer-key hex".into()))?;
    if peer_key_bytes.len() != 32 {
        return Err(yasecret_core::YasecretError::NotFound("peer-key must be 64 hex chars (32 bytes)".into()));
    }
    let peer_pub: [u8; 32] = peer_key_bytes.try_into().unwrap();
    let peer_id = hex::encode(peer_pub);

    let proj = project::list(&session.db)?
        .into_iter()
        .find(|p| p.name == args.project)
        .ok_or_else(|| yasecret_core::YasecretError::NotFound(format!("project '{}'", args.project)))?;

    let proj_key = project_key::load(&session.db, &proj.id, &session.db_key)?;

    let data_dir = path.parent().unwrap_or_else(|| std::path::Path::new(".")).join("sync");
    // Derive iroh node key from identity secret key, domain-separated from db_key.
    let sync_key: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"yasecret-sync-key-v1");
        h.update(&session.identity.secret_key);
        h.finalize().into()
    };
    let node = SyncNode::start(&data_dir, &sync_key)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    let ticket_str = doc_manager::create_project_doc(&session.db, &node, &proj.id)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    let doc_id = doc_manager::get_doc_id(&session.db, &proj.id)
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    store_peer_key(&session.db, &proj.id, &peer_id, &peer_pub, &proj_key)
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    let author = node
        .client()
        .author_create()
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    let meta = SyncProjectMeta {
        id: proj.id.clone(),
        name: proj.name.clone(),
        description: proj.description.clone(),
        owner_id: proj.owner_id.clone(),
        owner_signing_pub_key: hex::encode(session.identity.signing_key().verifying_key().as_bytes()),
        created_at: proj.created_at,
    };
    push_project_meta(&node, &doc_id, &meta, author)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    for env in environment::list(&session.db, &proj.id)? {
        let env_meta = SyncEnvMeta {
            id: env.id.clone(),
            project_id: proj.id.clone(),
            name: env.name.clone(),
            created_at: env.created_at,
        };
        push_env_meta(&node, &doc_id, &env_meta, author)
            .await
            .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

        for s in secret::list(&session.db, &env.id)? {
            // Send the DB's already-encrypted bytes directly — no re-encryption.
            let sync_secret = SyncSecret {
                id: s.id.clone(),
                key: s.key.clone(),
                encrypted_value: s.encrypted_value.clone(),
                nonce: s.nonce.clone(),
                created_at: s.created_at,
                updated_at: s.updated_at,
                created_by: s.created_by.clone(),
                expires_at: s.expires_at,
            };
            push_secret(&node, &doc_id, &env.id, &sync_secret, author)
                .await
                .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;
        }
    }

    // Write the encrypted project key for the peer so they can load it with peer_key::load_my_peer_key.
    let encrypted_blob = {
        let stored: Vec<u8> = session.db.conn().query_row(
            "SELECT encrypted_key FROM peer_project_key WHERE project_id=?1 AND peer_id=?2",
            rusqlite::params![&proj.id, &peer_id],
            |r| r.get(0),
        ).map_err(|e| yasecret_core::YasecretError::Db(e))?;
        stored
    };
    push_peer_key(&node, &doc_id, &peer_id, &encrypted_blob, author)
        .await
        .map_err(|e| yasecret_core::YasecretError::Io(std::io::Error::other(e.to_string())))?;

    println!("{ticket_str}");
    node.stop().await;
    Ok(())
}
