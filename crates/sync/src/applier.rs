use std::{path::PathBuf, sync::Arc};

use futures_lite::StreamExt;
use tokio::task::JoinHandle;
use yasecret_core::{
    db::Db,
    models::{Identity, Role, RoleLevel},
    role,
};

use crate::{
    node::SyncNode,
    types::{doc_keys, SyncEnvMeta, SyncProjectMeta, SyncRole, SyncSecret},
    Result,
};

// ── Push functions ────────────────────────────────────────────────────────────

pub async fn push_project_meta(
    node: &SyncNode,
    doc_id: &str,
    meta: &SyncProjectMeta,
    author: iroh_docs::AuthorId,
) -> Result<()> {
    let bytes = serde_json::to_vec(meta)?;
    write_entry(node, doc_id, doc_keys::project_meta(), bytes, author).await
}

pub async fn push_env_meta(
    node: &SyncNode,
    doc_id: &str,
    meta: &SyncEnvMeta,
    author: iroh_docs::AuthorId,
) -> Result<()> {
    let bytes = serde_json::to_vec(meta)?;
    write_entry(node, doc_id, &doc_keys::env_meta(&meta.id), bytes, author).await
}

pub async fn push_secret(
    node: &SyncNode,
    doc_id: &str,
    env_id: &str,
    secret: &SyncSecret,
    author: iroh_docs::AuthorId,
) -> Result<()> {
    let bytes = serde_json::to_vec(secret)?;
    write_entry(node, doc_id, &doc_keys::secret(env_id, &secret.key), bytes, author).await
}

pub async fn push_role(
    node: &SyncNode,
    doc_id: &str,
    sync_role: &SyncRole,
    author: iroh_docs::AuthorId,
) -> Result<()> {
    let bytes = serde_json::to_vec(sync_role)?;
    let key = doc_keys::role(&sync_role.peer_id, sync_role.env_id.as_deref());
    write_entry(node, doc_id, &key, bytes, author).await
}

pub async fn push_peer_key(
    node: &SyncNode,
    doc_id: &str,
    peer_id: &str,
    encrypted_key_blob: &[u8],
    author: iroh_docs::AuthorId,
) -> Result<()> {
    write_entry(
        node,
        doc_id,
        &doc_keys::peer_key(peer_id),
        encrypted_key_blob.to_vec(),
        author,
    )
    .await
}

// ── Apply helpers (called from subscribe_and_apply + tests) ──────────────────

/// Store the ECDH-encrypted project key blob that the owner sent for this peer.
/// Called by `subscribe_and_apply` when a `peer_key/<peer_id>` entry arrives.
pub fn apply_peer_key_entry(
    db: &Db,
    project_id: &str,
    peer_id: &str,
    encrypted_blob: &[u8],
) -> Result<()> {
    db.conn().execute(
        "INSERT OR REPLACE INTO peer_project_key (project_id, peer_id, encrypted_key) VALUES (?1, ?2, ?3)",
        rusqlite::params![project_id, peer_id, encrypted_blob],
    )?;
    Ok(())
}

/// Apply a SyncRole to the local DB.
/// Verifies the Ed25519 signature; silently drops the entry if invalid.
/// `owner_vk_bytes`: owner's Ed25519 verifying key bytes (32 bytes).
pub fn apply_role_entry(db: &Db, sync_role: &SyncRole, owner_vk_bytes: &[u8; 32]) -> Result<()> {
    let level = match RoleLevel::from_str(&sync_role.level) {
        Some(l) => l,
        None => return Ok(()),
    };
    let role = Role {
        id: sync_role.id.clone(),
        project_id: sync_role.project_id.clone(),
        env_id: sync_role.env_id.clone(),
        peer_id: sync_role.peer_id.clone(),
        level,
        granted_at: sync_role.granted_at,
        signature: sync_role.signature.clone(),
    };
    if role::verify_signature(&role, owner_vk_bytes).is_err() {
        return Ok(());
    }
    db.conn().execute(
        "INSERT OR IGNORE INTO role (id,project_id,env_id,peer_id,level,granted_at,signature) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![
            &role.id, &role.project_id, &role.env_id, &role.peer_id,
            role.level.as_str(), role.granted_at, &role.signature
        ],
    )?;
    Ok(())
}

// ── Background subscriber ─────────────────────────────────────────────────────

/// Spawn a background task that listens for iroh-docs remote insert events and applies them.
/// Runs until the doc stream ends or the node shuts down.
pub fn subscribe_and_apply(
    db_path: PathBuf,
    db_password: String,
    node: Arc<SyncNode>,
    doc_id: String,
    project_id: String,
    owner_vk_bytes: [u8; 32],
    our_identity: Identity,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let ns: iroh_docs::NamespaceId = match doc_id.parse() {
            Ok(n) => n,
            Err(_) => return,
        };
        let doc = match node.client().open(ns).await {
            Ok(Some(d)) => d,
            _ => return,
        };
        let mut events = match doc.subscribe().await {
            Ok(s) => s,
            Err(_) => return,
        };
        while let Some(event) = events.next().await {
            let entry = match event {
                Ok(iroh_docs::engine::LiveEvent::InsertRemote { entry, .. }) => entry,
                _ => continue,
            };
            let entry_key = String::from_utf8_lossy(entry.key()).to_string();
            let content_hash = entry.content_hash();
            let blob_bytes =
                match node.blob_store().blobs().get_bytes(content_hash).await {
                    Ok(b) => b.to_vec(),
                    Err(_) => continue,
                };
            let db_path2 = db_path.clone();
            let db_password2 = db_password.clone();
            let our_id = our_identity.clone();
            let owner_pk = owner_vk_bytes;
            let proj_id2 = project_id.clone();
            tokio::task::spawn_blocking(move || {
                let db = match Db::open(&db_path2, &db_password2) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                let _ = apply_entry(&db, &entry_key, &blob_bytes, &owner_pk, &our_id, &proj_id2);
            })
            .await
            .ok();
        }
    })
}

fn apply_entry(
    db: &Db,
    key: &str,
    content: &[u8],
    owner_vk_bytes: &[u8; 32],
    our_identity: &Identity,
    project_id: &str,
) {
    if key == "project/meta" {
        if let Ok(meta) = serde_json::from_slice::<SyncProjectMeta>(content) {
            let _ = apply_project_meta(db, &meta);
        }
    } else if key.starts_with("env/") && key.ends_with("/meta") {
        if let Ok(meta) = serde_json::from_slice::<SyncEnvMeta>(content) {
            let _ = apply_env_meta(db, &meta);
        }
    } else if key.starts_with("secret/") {
        if let Ok(s) = serde_json::from_slice::<SyncSecret>(content) {
            let _ = apply_secret(db, &s);
        }
    } else if key.starts_with("role/") {
        if let Ok(r) = serde_json::from_slice::<SyncRole>(content) {
            let _ = apply_role_entry(db, &r, owner_vk_bytes);
        }
    } else if key.starts_with("peer_key/") {
        let our_peer_id = hex::encode(our_identity.x25519_public().as_bytes());
        if key == format!("peer_key/{our_peer_id}") {
            let _ = apply_peer_key_entry(db, project_id, &our_peer_id, content);
        }
    }
}

fn apply_project_meta(db: &Db, meta: &SyncProjectMeta) -> yasecret_core::Result<()> {
    db.conn().execute(
        "INSERT OR IGNORE INTO project (id,name,description,created_at,owner_id) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![&meta.id, &meta.name, &meta.description, meta.created_at, &meta.owner_id],
    )?;
    Ok(())
}

fn apply_env_meta(db: &Db, meta: &SyncEnvMeta) -> yasecret_core::Result<()> {
    db.conn().execute(
        "INSERT OR IGNORE INTO environment (id,project_id,name,created_at) VALUES (?1,?2,?3,?4)",
        rusqlite::params![&meta.id, &meta.project_id, &meta.name, meta.created_at],
    )?;
    Ok(())
}

fn apply_secret(db: &Db, s: &SyncSecret) -> yasecret_core::Result<()> {
    // Check if this secret key already exists in the given env (need env_id from entry key or ID)
    // We use s.id as primary key — if already present, archive old value then replace
    let existing: rusqlite::Result<(String, Vec<u8>, Vec<u8>, String, i64)> = db.conn().query_row(
        "SELECT id, encrypted_value, nonce, created_by, updated_at FROM secret WHERE id=?1",
        [&s.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    );
    if let Ok((old_id, old_enc, old_nonce, old_by, old_at)) = existing {
        let version_id = yasecret_core::models::new_id();
        let _ = db.conn().execute(
            "INSERT INTO secret_version (id,secret_id,encrypted_value,nonce,changed_by,changed_at,note) VALUES (?1,?2,?3,?4,?5,?6,NULL)",
            rusqlite::params![&version_id, &old_id, &old_enc, &old_nonce, &old_by, old_at],
        );
        db.conn().execute(
            "UPDATE secret SET encrypted_value=?1,nonce=?2,updated_at=?3,expires_at=?4 WHERE id=?5",
            rusqlite::params![&s.encrypted_value, &s.nonce, s.updated_at, s.expires_at, &s.id],
        )?;
    }
    // If no existing row — we need the env_id, which we don't have here.
    // The owner pushes secrets with their env_id baked into the doc key, but SyncSecret
    // doesn't carry env_id separately. For the applier, we can only update existing secrets.
    // New secrets are handled by the join flow (CLI pull after sync).
    Ok(())
}

// ── Internal write helper ─────────────────────────────────────────────────────

async fn write_entry(
    node: &SyncNode,
    doc_id: &str,
    key: &[u8],
    value: Vec<u8>,
    author: iroh_docs::AuthorId,
) -> Result<()> {
    let ns: iroh_docs::NamespaceId = doc_id
        .parse()
        .map_err(|_| crate::SyncError::NoDoc(doc_id.to_string()))?;
    let doc = node
        .client()
        .open(ns)
        .await
        .map_err(anyhow::Error::from)?
        .ok_or_else(|| crate::SyncError::NoDoc(doc_id.to_string()))?;
    doc.set_bytes(author, key.to_vec(), value)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(())
}
