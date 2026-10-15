use yasecret_core::{crypto, db::Db, models::Identity};
use zeroize::Zeroizing;

use crate::{Result, SyncError};

/// Store the project key encrypted for a peer's X25519 public key.
/// `peer_pub_bytes`: 32-byte X25519 public key of the target peer.
/// `project_key`: the 32-byte symmetric project key.
pub fn store_peer_key(
    db: &Db,
    project_id: &str,
    peer_id: &str,
    peer_pub_bytes: &[u8; 32],
    project_key: &[u8; 32],
) -> Result<()> {
    let encrypted = crypto::encrypt_for_peer(project_key, peer_pub_bytes)?;
    db.conn().execute(
        "INSERT OR REPLACE INTO peer_project_key (project_id, peer_id, encrypted_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![project_id, peer_id, &encrypted],
    )?;
    Ok(())
}

/// Load the project key encrypted for our identity.
/// Looks up by `hex(identity.x25519_public())`, decrypts with our X25519 secret.
pub fn load_my_peer_key(
    db: &Db,
    project_id: &str,
    identity: &Identity,
) -> Result<Zeroizing<[u8; 32]>> {
    let my_peer_id = hex::encode(identity.x25519_public().as_bytes());
    let encrypted: Vec<u8> = db
        .conn()
        .query_row(
            "SELECT encrypted_key FROM peer_project_key WHERE project_id = ?1 AND peer_id = ?2",
            rusqlite::params![project_id, &my_peer_id],
            |r| r.get(0),
        )
        .map_err(|_| SyncError::NoPeerKey)?;

    let our_secret = identity.x25519_secret();
    let decrypted = crypto::decrypt_from_peer(&encrypted, &our_secret)?;
    let key_bytes: [u8; 32] = decrypted
        .as_slice()
        .try_into()
        .map_err(|_| SyncError::NoPeerKey)?;
    Ok(Zeroizing::new(key_bytes))
}
