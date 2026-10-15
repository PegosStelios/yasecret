use std::{path::Path, sync::Arc};

use crate::{Result, SyncError};

pub struct SyncNode {
    endpoint: iroh::Endpoint,
    engine: Arc<iroh_docs::engine::Engine>,
    pub docs: iroh_docs::api::DocsApi,
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

        let gossip = iroh_gossip::net::Gossip::builder().spawn(endpoint.clone());
        let bao_store: iroh_blobs::api::Store =
            iroh_blobs::store::mem::MemStore::new().into();
        let replica_store = iroh_docs::store::fs::Store::memory();
        let downloader = bao_store.downloader(&endpoint);

        let engine = iroh_docs::engine::Engine::spawn(
            endpoint.clone(),
            gossip,
            replica_store,
            bao_store,
            downloader,
            iroh_docs::engine::DefaultAuthorStorage::Mem,
            None,
        )
        .await
        .map_err(anyhow::Error::from)?;

        let engine = Arc::new(engine);
        let docs = iroh_docs::api::DocsApi::spawn(engine.clone());

        Ok(Self { endpoint, engine, docs })
    }

    /// Node ID as lowercase hex (stable for the same secret key).
    pub fn node_id(&self) -> String {
        hex::encode(self.endpoint.id().as_bytes())
    }

    /// Access the iroh-docs API (create, import, open docs; create authors).
    pub fn client(&self) -> &iroh_docs::api::DocsApi {
        &self.docs
    }

    pub fn blob_store(&self) -> &iroh_blobs::api::Store {
        self.engine.blob_store()
    }

    pub async fn stop(self) {
        let _ = self.engine.shutdown().await;
        self.endpoint.close().await;
    }
}
