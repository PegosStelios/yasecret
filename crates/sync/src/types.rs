use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProjectMeta {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    /// hex-encoded Ed25519 verifying key bytes (from identity.signing_key().verifying_key())
    /// Used by the applier to verify role signatures.
    pub owner_signing_pub_key: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEnvMeta {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub created_at: i64,
}

/// Secret entry synced in iroh-docs. Blob fields are raw bytes (serde encodes as base64 via Vec<u8>).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSecret {
    pub id: String,
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRole {
    pub id: String,
    pub project_id: String,
    pub env_id: Option<String>,
    pub peer_id: String,
    pub level: String,
    pub granted_at: i64,
    pub signature: Vec<u8>,
}

pub mod doc_keys {
    pub fn project_meta() -> &'static [u8] {
        b"project/meta"
    }
    pub fn env_meta(env_id: &str) -> Vec<u8> {
        format!("env/{env_id}/meta").into_bytes()
    }
    pub fn secret(env_id: &str, key: &str) -> Vec<u8> {
        format!("secret/{env_id}/{key}").into_bytes()
    }
    pub fn role(peer_id: &str, env_id: Option<&str>) -> Vec<u8> {
        format!("role/{peer_id}/{}", env_id.unwrap_or("*")).into_bytes()
    }
    pub fn peer_key(peer_id: &str) -> Vec<u8> {
        format!("peer_key/{peer_id}").into_bytes()
    }
}
