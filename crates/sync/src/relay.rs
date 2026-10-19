//! Always-on peer. Keeps a read-only copy of shared projects so members can join and pick up
//! changes while the owner's computer is off. It only ever holds what's in the doc: values are
//! encrypted with the project key, which a relay never receives.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use futures_lite::StreamExt;

use crate::{live::RelayLink, node::SyncNode, Result, SyncError};

pub struct Relay {
    node: SyncNode,
    dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelayProject {
    pub doc_id: String,
    pub name: String,
    /// Entries whose content is stored locally.
    pub entries: usize,
}

const NAMES: &str = "projects.json";

fn load_or_create_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join("sync.key");
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        return bytes.try_into().map_err(|_| {
            SyncError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, "sync.key must be 32 bytes"))
        });
    }
    std::fs::create_dir_all(dir)?;
    let key: [u8; 32] = rand::random();
    std::fs::write(&path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

/// The code an owner pastes into Yasecret to add this relay. Creates the relay's key if needed.
pub fn code_for_dir(dir: &Path) -> Result<String> {
    let key = load_or_create_key(dir)?;
    Ok(hex::encode(iroh::SecretKey::from_bytes(&key).public().as_bytes()))
}

/// True when a relay process currently holds `dir`.
pub fn is_running(dir: &Path) -> bool {
    let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("sync.lock")) else {
        return false;
    };
    matches!(f.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

impl Relay {
    /// Starts the relay node and resumes syncing every project it already holds.
    pub async fn start(dir: &Path) -> Result<Self> {
        let key = load_or_create_key(dir)?;
        let node = SyncNode::start(dir, &key).await?;
        let relay = Self { node, dir: dir.to_path_buf() };
        relay.resume().await?;
        Ok(relay)
    }

    pub fn code(&self) -> String {
        self.node.node_id()
    }

    /// Imports a project from a relay link (made by the owner in Share → Always-on peer).
    pub async fn add(&self, link: &str) -> Result<RelayProject> {
        let link = RelayLink::parse(link)?;
        let ticket: iroh_docs::DocTicket = link.ticket.parse().map_err(|_| SyncError::InvalidTicket)?;
        let doc = self.node.client().import(ticket).await.map_err(anyhow::Error::from)?;
        let doc_id = doc.id().to_string();
        let mut names = self.names();
        names.insert(doc_id.clone(), link.project_name.clone());
        std::fs::write(self.dir.join(NAMES), serde_json::to_vec_pretty(&names)?)?;
        Ok(RelayProject { entries: self.count(&doc).await?, doc_id, name: link.project_name })
    }

    pub async fn projects(&self) -> Result<Vec<RelayProject>> {
        let names = self.names();
        let mut ids = Vec::new();
        let mut list = self.node.client().list().await.map_err(anyhow::Error::from)?;
        while let Some(item) = list.next().await {
            ids.push(item.map_err(anyhow::Error::from)?.0);
        }
        let mut out = Vec::new();
        for id in ids {
            let Some(doc) = self.node.client().open(id).await.map_err(anyhow::Error::from)? else { continue };
            let doc_id = id.to_string();
            out.push(RelayProject {
                name: names.get(&doc_id).cloned().unwrap_or_else(|| "(unnamed)".into()),
                entries: self.count(&doc).await?,
                doc_id,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Reconnects every held project to the peers it has synced with before.
    pub async fn resume(&self) -> Result<()> {
        let mut list = self.node.client().list().await.map_err(anyhow::Error::from)?;
        let mut ids = Vec::new();
        while let Some(item) = list.next().await {
            ids.push(item.map_err(anyhow::Error::from)?.0);
        }
        for id in ids {
            if let Some(doc) = self.node.client().open(id).await.map_err(anyhow::Error::from)? {
                let _ = doc.start_sync(vec![]).await;
            }
        }
        Ok(())
    }

    /// Every stored entry's content, for checking what a relay can see.
    pub async fn entry_contents(&self) -> Result<Vec<Vec<u8>>> {
        let mut list = self.node.client().list().await.map_err(anyhow::Error::from)?;
        let mut ids = Vec::new();
        while let Some(item) = list.next().await {
            ids.push(item.map_err(anyhow::Error::from)?.0);
        }
        let mut out = Vec::new();
        for id in ids {
            let Some(doc) = self.node.client().open(id).await.map_err(anyhow::Error::from)? else { continue };
            let stream = doc.get_many(iroh_docs::store::Query::all()).await.map_err(anyhow::Error::from)?;
            tokio::pin!(stream);
            while let Some(entry) = stream.next().await {
                let entry = entry.map_err(anyhow::Error::from)?;
                if let Ok(bytes) = self.node.blob_store().blobs().get_bytes(entry.content_hash()).await {
                    out.push(bytes.to_vec());
                }
            }
        }
        Ok(out)
    }

    pub async fn shutdown(&self) {
        self.node.shutdown().await;
    }

    fn names(&self) -> BTreeMap<String, String> {
        std::fs::read(self.dir.join(NAMES))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    async fn count(&self, doc: &iroh_docs::api::Doc) -> Result<usize> {
        let stream = doc
            .get_many(iroh_docs::store::Query::all().key_prefix("v2/"))
            .await
            .map_err(anyhow::Error::from)?;
        tokio::pin!(stream);
        let mut n = 0;
        while let Some(entry) = stream.next().await {
            let entry = entry.map_err(anyhow::Error::from)?;
            if entry.content_len() > 0 && self.node.blob_store().blobs().get_bytes(entry.content_hash()).await.is_ok() {
                n += 1;
            }
        }
        Ok(n)
    }
}
