use std::path::Path;

use crate::{Result, SyncError};

pub struct SyncNode {
    router: iroh::protocol::Router,
    docs: iroh_docs::protocol::Docs,
    // Held so the on-disk blob store actor stays alive for the node's lifetime.
    blobs: iroh_blobs::store::fs::FsStore,
}

impl SyncNode {
    /// Start an iroh node using the key stored at `{data_dir}/sync.key`.
    /// If the file exists but is not exactly 32 bytes, returns Err.
    /// If the file doesn't exist, uses `key_bytes` and writes it.
    pub async fn start(data_dir: &Path, key_bytes: &[u8; 32]) -> Result<Self> {
        let key_path = data_dir.join("sync.key");

        let secret_bytes: [u8; 32] = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(SyncError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("sync.key must be 32 bytes, got {}", bytes.len()),
                )));
            }
            bytes.try_into().unwrap()
        } else {
            std::fs::create_dir_all(data_dir)?;
            std::fs::write(&key_path, key_bytes)?;
            *key_bytes
        };

        let sk = iroh::SecretKey::from_bytes(&secret_bytes);
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(sk)
            .bind()
            .await
            .map_err(|e| SyncError::Iroh(anyhow::anyhow!("{e}")))?;

        let blobs = iroh_blobs::store::fs::FsStore::load(data_dir.join("blobs"))
            .await
            .map_err(|e| SyncError::Iroh(anyhow::anyhow!("blob store: {e}")))?;
        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let docs = iroh_docs::protocol::Docs::persistent(data_dir.to_path_buf())
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await
            .map_err(|e| SyncError::Iroh(anyhow::anyhow!("docs: {e}")))?;

        // Without a router the node can dial out but rejects every incoming sync connection.
        let router = iroh::protocol::Router::builder(endpoint)
            .accept(iroh_blobs::ALPN, iroh_blobs::BlobsProtocol::new(&blobs, None))
            .accept(iroh_gossip::ALPN, gossip)
            .accept(iroh_docs::ALPN, docs.clone())
            .spawn();

        Ok(Self { router, docs, blobs })
    }

    /// Node ID as lowercase hex (stable for the same secret key).
    pub fn node_id(&self) -> String {
        hex::encode(self.router.endpoint().id().as_bytes())
    }

    /// Access the iroh-docs API (create, import, open docs; create authors).
    pub fn client(&self) -> &iroh_docs::api::DocsApi {
        self.docs.api()
    }

    pub fn blob_store(&self) -> &iroh_blobs::api::Store {
        &self.blobs
    }

    /// Stops all protocols and releases the on-disk stores so the same directory can be reopened.
    pub async fn shutdown(&self) {
        let _ = self.router.shutdown().await;
        let _ = self.blobs.shutdown().await;
    }

    pub async fn stop(self) {
        self.shutdown().await;
    }
}
