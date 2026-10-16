//! Long-running sync service used by the desktop app.
//!
//! Model: every project is one iroh doc. Environments and variables are stored under
//! `v2/env/{id}` and `v2/secret/{id}` and resolved last-write-wins on `updated_at`, with
//! deletions travelling as tombstones. Only entries written by authors holding an
//! owner-signed grant are accepted, and the owner's signing key is pinned from the invite
//! link, so holding the doc ticket alone is not enough to inject data.

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use futures_lite::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use yasecret_core::{
    crypto,
    db::Db,
    identity,
    models::{now, new_id, Identity},
    project_key, tombstone,
};
use zeroize::Zeroizing;

use crate::{node::SyncNode, Result, SyncError};

pub const INVITE_TTL_SECS: i64 = 24 * 3600;
/// Audit actor for changes that arrived from another device.
pub const SYNC_ACTOR: &str = "sync";
const JOIN_TIMEOUT: Duration = Duration::from_secs(45);
const RECONCILE_EVERY: Duration = Duration::from_secs(20);

pub const LEVEL_OWNER: &str = "owner";
pub const LEVEL_EDITOR: &str = "editor";
pub const LEVEL_VIEWER: &str = "viewer";
pub const LEVEL_REMOVED: &str = "removed";

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WProject {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WEnv {
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WSecret {
    pub id: String,
    pub env_id: String,
    pub key: String,
    pub enc: Vec<u8>,
    pub nonce: Vec<u8>,
    pub is_secret: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
    pub expires_at: Option<i64>,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WMember {
    pub peer_id: String,
    pub name: String,
    pub joined_at: i64,
    pub invite_id: Option<String>,
    /// HMAC proving the joiner holds the project key; see `join_proof`.
    #[serde(default)]
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WInvite {
    pub wrapped: Vec<u8>,
    pub nonce: Vec<u8>,
    pub expires_at: i64,
    pub redeemed_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WGrant {
    pub peer_id: String,
    pub author: String,
    pub level: String,
    pub granted_at: i64,
    pub signature: Vec<u8>,
}

mod keys {
    pub const PREFIX: &str = "v2/";
    pub const PROJECT: &str = "v2/project";
    pub fn env(id: &str) -> String { format!("v2/env/{id}") }
    pub fn secret(id: &str) -> String { format!("v2/secret/{id}") }
    pub fn member(peer: &str) -> String { format!("v2/member/{peer}") }
    pub fn peer_key(peer: &str) -> String { format!("v2/peer_key/{peer}") }
    pub fn invite(id: &str) -> String { format!("v2/invite/{id}") }
    pub fn grant(peer: &str) -> String { format!("v2/grant/{peer}") }
}

/// Binds a membership claim to the project key, so holding the doc ticket alone can't admit anyone.
pub fn join_proof(project_key: &[u8; 32], project_id: &str, peer_id: &str, author: &str) -> Vec<u8> {
    hmac_sha256(project_key, format!("yasecret-join-v2|{project_id}|{peer_id}|{author}").as_bytes()).to_vec()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<_>>());
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>());
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sign_grant(signer: &Identity, project_id: &str, peer: &str, author: &str, level: &str) -> WGrant {
    let granted_at = now();
    let msg = grant_msg(project_id, peer, author, level, granted_at);
    WGrant {
        peer_id: peer.to_string(),
        author: author.to_string(),
        level: level.to_string(),
        granted_at,
        signature: crypto::sign(msg.as_bytes(), &signer.signing_key()),
    }
}

fn grant_msg(project_id: &str, peer_id: &str, author: &str, level: &str, granted_at: i64) -> String {
    format!("yasecret-grant-v2|{project_id}|{peer_id}|{author}|{level}|{granted_at}")
}

// ── Invite links ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum InviteSecret {
    /// One-time key that unwraps the project key from `v2/invite/{id}`.
    Link { invite_id: String, key: [u8; 32] },
    /// Project key was encrypted to the joiner's device code.
    DeviceBound,
}

#[derive(Debug, Clone, PartialEq)]
pub struct InviteLink {
    pub project_id: String,
    pub project_name: String,
    pub owner_sign_pub: [u8; 32],
    pub ticket: String,
    pub secret: InviteSecret,
}

impl InviteLink {
    pub fn to_url(&self) -> String {
        let mut url = format!(
            "yasecret://join?v=2&p={}&n={}&o={}&t={}",
            self.project_id,
            percent_encode(&self.project_name),
            hex::encode(self.owner_sign_pub),
            self.ticket
        );
        match &self.secret {
            InviteSecret::Link { invite_id, key } => {
                url.push_str(&format!("&i={invite_id}&k={}", hex::encode(key)));
            }
            InviteSecret::DeviceBound => url.push_str("&m=device"),
        }
        url
    }

    pub fn parse(link: &str) -> Result<Self> {
        let bad = |why: &str| SyncError::InvalidLink(why.to_string());
        let link = link.trim();
        let query = link
            .strip_prefix("yasecret://join?")
            .ok_or_else(|| bad("it doesn't start with yasecret://join"))?;
        let params: HashMap<&str, &str> = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .collect();
        let get = |k: &str| params.get(k).copied().ok_or_else(|| bad("it is incomplete — copy the whole link"));
        if get("v")? != "2" {
            return Err(bad("it was made by a different version of Yasecret"));
        }
        let owner: [u8; 32] = hex::decode(get("o")?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| bad("the owner key is damaged"))?;
        let secret = if params.get("m") == Some(&"device") {
            InviteSecret::DeviceBound
        } else {
            let key: [u8; 32] = hex::decode(get("k")?)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| bad("the invite key is damaged"))?;
            InviteSecret::Link { invite_id: get("i")?.to_string(), key }
        };
        Ok(Self {
            project_id: get("p")?.to_string(),
            project_name: percent_decode(get("n")?),
            owner_sign_pub: owner,
            ticket: get("t")?.to_string(),
            secret,
        })
    }
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// iroh node key, derived from (and domain-separated from) the identity secret.
pub fn node_key(identity: &Identity) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"yasecret-sync-key-v1");
    h.update(&identity.secret_key);
    h.finalize().into()
}

pub fn peer_id(identity: &Identity) -> String {
    hex::encode(identity.x25519_public().as_bytes())
}

fn sign_pub(identity: &Identity) -> [u8; 32] {
    identity.signing_key().verifying_key().to_bytes()
}

// ── Public status types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Member {
    pub peer_id: String,
    pub name: String,
    pub level: String,
    pub joined_at: i64,
    pub is_me: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncStatus {
    pub shared: bool,
    pub is_owner: bool,
    pub my_level: String,
    pub peers_online: u32,
    pub last_synced_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Default)]
struct LiveState {
    neighbors: HashSet<String>,
    last_synced_at: Option<i64>,
    last_error: Option<String>,
}

// ── Service ───────────────────────────────────────────────────────────────────

pub struct SyncConfig {
    pub db_path: PathBuf,
    pub db_password: String,
    pub db_key: [u8; 32],
    pub data_dir: PathBuf,
    pub device_name: String,
}

pub struct SyncService {
    rt: tokio::runtime::Runtime,
    inner: Arc<Inner>,
}

struct Inner {
    handle: tokio::runtime::Handle,
    node: SyncNode,
    author: iroh_docs::AuthorId,
    db_path: PathBuf,
    db_password: Zeroizing<String>,
    db_key: Zeroizing<[u8; 32]>,
    identity: Identity,
    my_peer: String,
    device_name: String,
    revision: AtomicU64,
    watches: Mutex<HashMap<String, tokio::task::JoinHandle<()>>>,
    live: Mutex<HashMap<String, LiveState>>,
    pending: Mutex<HashMap<String, Arc<AtomicBool>>>,
    reconcile_lock: tokio::sync::Mutex<()>,
}

/// Facts about a shared project the service needs on every pass.
struct DocInfo {
    doc_id: String,
    owner_sign_pub: [u8; 32],
}

struct RawEntry {
    key: String,
    author: String,
    timestamp: u64,
    content: Vec<u8>,
}

impl SyncService {
    pub fn start(cfg: SyncConfig) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("yasecret-sync")
            .build()?;
        let db = Db::open(&cfg.db_path, &cfg.db_password)?;
        let identity = identity::load_or_create(&db, "local")?;
        let shared: Vec<String> = {
            let mut stmt = db.conn().prepare("SELECT project_id FROM sync_doc")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        drop(db);

        let key = node_key(&identity);
        let (node, author) = rt.block_on(async {
            let node = SyncNode::start(&cfg.data_dir, &key).await?;
            let author = node.client().author_default().await.map_err(anyhow::Error::from)?;
            Ok::<_, SyncError>((node, author))
        })?;

        let inner = Arc::new(Inner {
            handle: rt.handle().clone(),
            node,
            author,
            db_path: cfg.db_path,
            db_password: Zeroizing::new(cfg.db_password),
            db_key: Zeroizing::new(cfg.db_key),
            my_peer: peer_id(&identity),
            identity,
            device_name: cfg.device_name,
            revision: AtomicU64::new(0),
            watches: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            reconcile_lock: tokio::sync::Mutex::new(()),
        });
        let svc = Self { rt, inner };
        for project_id in shared {
            svc.watch(&project_id);
        }
        Ok(svc)
    }

    /// Stops syncing and releases the node's stores; the service is unusable afterwards.
    pub fn close(&self) {
        for (_, h) in self.inner.watches.lock().unwrap().drain() {
            h.abort();
        }
        let inner = self.inner.clone();
        self.rt.block_on(async move { inner.node.shutdown().await });
    }

    pub fn shutdown(self) {
        for (_, h) in self.inner.watches.lock().unwrap().drain() {
            h.abort();
        }
        let inner = self.inner.clone();
        self.rt.block_on(async move { inner.node.shutdown().await });
        self.rt.shutdown_timeout(Duration::from_secs(2));
    }

    /// Increments whenever remote changes were written into the local database.
    pub fn revision(&self) -> u64 {
        self.inner.revision.load(Ordering::SeqCst)
    }

    pub fn device_code(&self) -> String {
        self.inner.my_peer.clone()
    }

    /// Schedules a sync pass after a local edit. No-op for projects that aren't shared.
    pub fn notify_local_change(&self, project_id: &str) {
        if self.inner.watches.lock().unwrap().contains_key(project_id) {
            self.inner.schedule(project_id.to_string(), Duration::from_millis(150));
        }
    }

    /// Creates an invite. With `device_code`, only that device can use it.
    pub fn create_invite(&self, project_id: &str, device_code: Option<&str>, level: &str) -> Result<String> {
        if level != LEVEL_EDITOR && level != LEVEL_VIEWER {
            return Err(SyncError::InvalidLink(format!("unknown access level {level}")));
        }
        let inner = self.inner.clone();
        let project_id = project_id.to_string();
        let device_code = device_code.map(|c| c.chars().filter(|c| !c.is_whitespace()).collect::<String>());
        let level = level.to_string();
        let watch_id = project_id.clone();
        let url = self.rt.block_on(async move {
            let info = inner.ensure_doc(&project_id).await?;
            if info.owner_sign_pub != sign_pub(&inner.identity) {
                return Err(SyncError::NotOwner);
            }
            inner.reconcile(&project_id).await?;
            let doc = inner.open_doc(&info.doc_id).await?;
            let ticket = doc
                .share(
                    iroh_docs::api::protocol::ShareMode::Write,
                    iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
                )
                .await
                .map_err(anyhow::Error::from)?;
            let (name, project_key) = {
                let db = inner.db()?;
                let p = yasecret_core::project::get(&db, &project_id)?;
                (p.name, project_key::load(&db, &project_id, &inner.db_key)?)
            };
            let invite_id = new_id();
            let created = now();
            let secret = match device_code {
                Some(code) => {
                    let peer: [u8; 32] = hex::decode(&code)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or(SyncError::InvalidDeviceCode)?;
                    let blob = crypto::encrypt_for_peer(project_key.as_ref(), &peer)?;
                    inner.write(&doc, &keys::peer_key(&code), blob).await?;
                    inner.db()?.conn().execute(
                        "INSERT INTO sync_invite (id,project_id,kind,peer_id,level,created_at,expires_at) VALUES (?1,?2,'device',?3,?4,?5,?6)",
                        rusqlite::params![&invite_id, &project_id, &code, &level, created, created + 7 * INVITE_TTL_SECS],
                    )?;
                    InviteSecret::DeviceBound
                }
                None => {
                    let one_time = crypto::generate_project_key();
                    let (wrapped, nonce) = crypto::encrypt(project_key.as_ref(), &one_time)?;
                    let invite = WInvite { wrapped, nonce: nonce.to_vec(), expires_at: created + INVITE_TTL_SECS, redeemed_by: None };
                    inner.write(&doc, &keys::invite(&invite_id), serde_json::to_vec(&invite)?).await?;
                    inner.db()?.conn().execute(
                        "INSERT INTO sync_invite (id,project_id,kind,peer_id,level,created_at,expires_at) VALUES (?1,?2,'link',NULL,?3,?4,?5)",
                        rusqlite::params![&invite_id, &project_id, &level, created, invite.expires_at],
                    )?;
                    InviteSecret::Link { invite_id, key: *one_time }
                }
            };
            Ok::<_, SyncError>(InviteLink {
                project_id: project_id.clone(),
                project_name: name,
                owner_sign_pub: info.owner_sign_pub,
                ticket: ticket.to_string(),
                secret,
            }
            .to_url())
        })?;
        self.watch(&watch_id);
        Ok(url)
    }

    /// Joins a project from an invite link. Blocks until the owner's device answers.
    pub fn join(&self, link: &str) -> Result<String> {
        let invite = InviteLink::parse(link)?;
        let inner = self.inner.clone();
        let project_id = self.rt.block_on(async move { inner.join(invite).await })?;
        self.watch(&project_id);
        Ok(project_id)
    }

    pub fn members(&self, project_id: &str) -> Result<Vec<Member>> {
        let inner = self.inner.clone();
        let project_id = project_id.to_string();
        self.rt.block_on(async move { inner.members(&project_id).await })
    }

    pub fn set_member_level(&self, project_id: &str, peer: &str, level: &str) -> Result<()> {
        if ![LEVEL_EDITOR, LEVEL_VIEWER, LEVEL_REMOVED].contains(&level) {
            return Err(SyncError::InvalidLink(format!("unknown access level {level}")));
        }
        let inner = self.inner.clone();
        let (project_id, peer, level) = (project_id.to_string(), peer.to_string(), level.to_string());
        self.rt.block_on(async move {
            let info = inner.doc_info(&project_id)?.ok_or_else(|| SyncError::NoDoc(project_id.clone()))?;
            if info.owner_sign_pub != sign_pub(&inner.identity) {
                return Err(SyncError::NotOwner);
            }
            let doc = inner.open_doc(&info.doc_id).await?;
            let entries = inner.read_entries(&doc).await?;
            let grants = valid_grants(&project_id, &entries, &info.owner_sign_pub);
            let author = grants
                .get(&peer)
                .map(|g| g.author.clone())
                .ok_or_else(|| SyncError::InvalidLink("that member hasn't finished joining yet".into()))?;
            let g = inner.sign_grant(&project_id, &peer, &author, &level);
            inner.write(&doc, &keys::grant(&peer), serde_json::to_vec(&g)?).await?;
            if level == LEVEL_REMOVED {
                // The removed device still holds the old key; switch everyone else to a new one.
                let new_key = {
                    let db = inner.db()?;
                    let key = project_key::rotate(&db, &project_id, &inner.db_key)?;
                    db.conn().execute(
                        "UPDATE secret SET updated_at = updated_at + 1 WHERE env_id IN (SELECT id FROM environment WHERE project_id = ?1)",
                        [&project_id],
                    )?;
                    db.conn().execute(
                        "DELETE FROM sync_invite WHERE project_id = ?1 AND redeemed_by IS NULL",
                        [&project_id],
                    )?;
                    Zeroizing::new(key)
                };
                for g in grants.values().filter(|g| g.peer_id != peer && g.peer_id != inner.my_peer && g.level != LEVEL_REMOVED) {
                    let Some(pub_key) = hex::decode(&g.peer_id).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { continue };
                    let blob = crypto::encrypt_for_peer(new_key.as_ref(), &pub_key)?;
                    inner.write(&doc, &keys::peer_key(&g.peer_id), blob).await?;
                }
                inner.reconcile(&project_id).await?;
                inner.revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
    }

    pub fn status(&self, project_id: &str) -> Result<SyncStatus> {
        let info = self.inner.doc_info(project_id)?;
        let Some(info) = info else { return Ok(SyncStatus::default()) };
        let is_owner = info.owner_sign_pub == sign_pub(&self.inner.identity);
        let inner = self.inner.clone();
        let pid = project_id.to_string();
        let my_level = if is_owner {
            LEVEL_OWNER.to_string()
        } else {
            self.rt
                .block_on(async move {
                    let doc = inner.open_doc(&info.doc_id).await?;
                    let entries = inner.read_entries(&doc).await?;
                    let grants = valid_grants(&pid, &entries, &info.owner_sign_pub);
                    Ok::<_, SyncError>(grants.get(&inner.my_peer).map(|g| g.level.clone()))
                })?
                .unwrap_or_else(|| "pending".into())
        };
        let live = self.inner.live.lock().unwrap();
        let st = live.get(project_id);
        Ok(SyncStatus {
            shared: true,
            is_owner,
            my_level,
            peers_online: st.map(|s| s.neighbors.len() as u32).unwrap_or(0),
            last_synced_at: st.and_then(|s| s.last_synced_at),
            last_error: st.and_then(|s| s.last_error.clone()),
        })
    }

    /// Owner: stops sharing and rotates the project key so former members can't read new values.
    /// Member: leaves and removes the local copy.
    pub fn stop_sharing(&self, project_id: &str) -> Result<()> {
        let Some(info) = self.inner.doc_info(project_id)? else { return Ok(()) };
        let is_owner = info.owner_sign_pub == sign_pub(&self.inner.identity);
        if let Some(h) = self.inner.watches.lock().unwrap().remove(project_id) {
            h.abort();
        }
        let inner = self.inner.clone();
        let doc_id = info.doc_id.clone();
        self.rt.block_on(async move {
            if let Ok(doc) = inner.open_doc(&doc_id).await {
                let _ = doc.leave().await;
            }
            if let Ok(ns) = doc_id.parse::<iroh_docs::NamespaceId>() {
                let _ = inner.node.client().drop_doc(ns).await;
            }
        });
        let db = self.inner.db()?;
        db.conn().execute("DELETE FROM sync_doc WHERE project_id = ?1", [project_id])?;
        db.conn().execute("DELETE FROM sync_invite WHERE project_id = ?1", [project_id])?;
        if is_owner {
            project_key::rotate(&db, project_id, &self.inner.db_key)?;
        } else {
            yasecret_core::project::delete(&db, project_id)?;
        }
        self.inner.live.lock().unwrap().remove(project_id);
        self.inner.revision.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn watch(&self, project_id: &str) {
        let mut watches = self.inner.watches.lock().unwrap();
        if watches.contains_key(project_id) {
            return;
        }
        let inner = self.inner.clone();
        let pid = project_id.to_string();
        let handle = self.rt.spawn(async move { inner.watch_loop(pid).await });
        watches.insert(project_id.to_string(), handle);
    }
}

impl Inner {
    fn db(&self) -> Result<Db> {
        Ok(Db::open(&self.db_path, &self.db_password)?)
    }

    fn doc_info(&self, project_id: &str) -> Result<Option<DocInfo>> {
        let db = self.db()?;
        let row: Option<(String, Option<String>)> = db
            .conn()
            .query_row(
                "SELECT doc_id, owner_sign_pub FROM sync_doc WHERE project_id = ?1",
                [project_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        Ok(row.map(|(doc_id, owner)| DocInfo {
            doc_id,
            owner_sign_pub: owner
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| b.try_into().ok())
                .unwrap_or_else(|| sign_pub(&self.identity)),
        }))
    }

    async fn open_doc(&self, doc_id: &str) -> Result<iroh_docs::api::Doc> {
        let ns: iroh_docs::NamespaceId = doc_id.parse().map_err(|_| SyncError::NoDoc(doc_id.to_string()))?;
        self.node
            .client()
            .open(ns)
            .await
            .map_err(anyhow::Error::from)?
            .ok_or_else(|| SyncError::NoDoc(doc_id.to_string()))
    }

    async fn ensure_doc(&self, project_id: &str) -> Result<DocInfo> {
        if let Some(info) = self.doc_info(project_id)? {
            return Ok(info);
        }
        let doc = self.node.client().create().await.map_err(anyhow::Error::from)?;
        let doc_id = doc.id().to_string();
        self.db()?.conn().execute(
            "INSERT INTO sync_doc (project_id, doc_id, ticket, owner_sign_pub) VALUES (?1,?2,NULL,?3)",
            rusqlite::params![project_id, &doc_id, hex::encode(sign_pub(&self.identity))],
        )?;
        Ok(DocInfo { doc_id, owner_sign_pub: sign_pub(&self.identity) })
    }

    async fn write(&self, doc: &iroh_docs::api::Doc, key: &str, value: Vec<u8>) -> Result<()> {
        doc.set_bytes(self.author, key.as_bytes().to_vec(), value)
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }

    async fn read_entries(&self, doc: &iroh_docs::api::Doc) -> Result<Vec<RawEntry>> {
        let stream = doc
            .get_many(iroh_docs::store::Query::all().key_prefix(keys::PREFIX))
            .await
            .map_err(anyhow::Error::from)?;
        tokio::pin!(stream);
        let mut out = Vec::new();
        while let Some(entry) = stream.next().await {
            let entry = entry.map_err(anyhow::Error::from)?;
            if entry.content_len() == 0 {
                continue;
            }
            // Content may still be downloading; it is picked up on the next pass.
            let Ok(bytes) = self.node.blob_store().blobs().get_bytes(entry.content_hash()).await else {
                continue;
            };
            out.push(RawEntry {
                key: String::from_utf8_lossy(entry.key()).into_owned(),
                author: entry.author().to_string(),
                timestamp: entry.timestamp(),
                content: bytes.to_vec(),
            });
        }
        Ok(out)
    }

    fn sign_grant(&self, project_id: &str, peer: &str, author: &str, level: &str) -> WGrant {
        sign_grant(&self.identity, project_id, peer, author, level)
    }

    fn schedule(self: &Arc<Self>, project_id: String, delay: Duration) {
        let flag = self
            .pending
            .lock()
            .unwrap()
            .entry(project_id.clone())
            .or_insert_with(|| Arc::new(AtomicBool::new(false)))
            .clone();
        if flag.swap(true, Ordering::SeqCst) {
            return;
        }
        let inner = self.clone();
        self.handle.spawn(async move {
                tokio::time::sleep(delay).await;
                flag.store(false, Ordering::SeqCst);
                let result = inner.reconcile(&project_id).await;
                inner.record_result(&project_id, result.err().map(|e| e.to_string()));
            });
    }

    fn record_result(&self, project_id: &str, error: Option<String>) {
        let mut live = self.live.lock().unwrap();
        live.entry(project_id.to_string()).or_default().last_error = error;
    }

    async fn watch_loop(self: Arc<Self>, project_id: String) {
        let Ok(Some(info)) = self.doc_info(&project_id) else { return };
        let Ok(doc) = self.open_doc(&info.doc_id).await else { return };
        let _ = doc.start_sync(vec![]).await;
        let Ok(mut events) = doc.subscribe().await else { return };
        let result = self.reconcile(&project_id).await;
        self.record_result(&project_id, result.err().map(|e| e.to_string()));
        let mut tick = tokio::time::interval(RECONCILE_EVERY);
        loop {
            tokio::select! {
                ev = events.next() => {
                    let Some(Ok(ev)) = ev else { break };
                    use iroh_docs::engine::LiveEvent as E;
                    match ev {
                        E::NeighborUp(pk) => {
                            self.live.lock().unwrap().entry(project_id.clone()).or_default().neighbors.insert(pk.to_string());
                        }
                        E::NeighborDown(pk) => {
                            self.live.lock().unwrap().entry(project_id.clone()).or_default().neighbors.remove(&pk.to_string());
                        }
                        E::SyncFinished(_) => {
                            self.live.lock().unwrap().entry(project_id.clone()).or_default().last_synced_at = Some(now());
                            self.schedule(project_id.clone(), Duration::from_millis(200));
                        }
                        E::InsertRemote { .. } | E::ContentReady { .. } | E::PendingContentReady => {
                            self.schedule(project_id.clone(), Duration::from_millis(300));
                        }
                        E::InsertLocal { .. } => {}
                    }
                }
                _ = tick.tick() => {
                    self.schedule(project_id.clone(), Duration::from_millis(0));
                }
            }
        }
    }

    async fn join(self: &Arc<Self>, invite: InviteLink) -> Result<String> {
        if self.db()?.conn().query_row(
            "SELECT count(*) FROM project WHERE id = ?1",
            [&invite.project_id],
            |r| r.get::<_, i64>(0),
        )? > 0
        {
            return Err(SyncError::AlreadyJoined);
        }
        let ticket: iroh_docs::DocTicket = invite.ticket.parse().map_err(|_| SyncError::InvalidTicket)?;
        let doc = self.node.client().import(ticket).await.map_err(anyhow::Error::from)?;
        let doc_id = doc.id().to_string();

        let deadline = tokio::time::Instant::now() + JOIN_TIMEOUT;
        let (project, key) = loop {
            let entries = self.read_entries(&doc).await?;
            let grants = valid_grants(&invite.project_id, &entries, &invite.owner_sign_pub);
            let owner_authors: HashSet<&str> = grants
                .values()
                .filter(|g| g.level == LEVEL_OWNER)
                .map(|g| g.author.as_str())
                .collect();
            let by_owner = |key: &str| latest(&entries, key, |a| owner_authors.contains(a));
            let project = by_owner(keys::PROJECT).and_then(|e| serde_json::from_slice::<WProject>(&e.content).ok());
            let key = match &invite.secret {
                InviteSecret::Link { invite_id, key } => {
                    let k = keys::invite(invite_id);
                    // A redemption written by anyone means the link was already used.
                    if let Some(latest_any) = latest(&entries, &k, |_| true) {
                        if let Ok(inv) = serde_json::from_slice::<WInvite>(&latest_any.content) {
                            if inv.redeemed_by.is_some() {
                                return Err(SyncError::InviteUsed);
                            }
                        }
                    }
                    match by_owner(&k).and_then(|e| serde_json::from_slice::<WInvite>(&e.content).ok()) {
                        Some(inv) if inv.expires_at < now() => return Err(SyncError::InviteExpired),
                        Some(inv) => {
                            let nonce: [u8; 12] = inv.nonce.clone().try_into().map_err(|_| SyncError::InvalidTicket)?;
                            let plain = crypto::decrypt(&inv.wrapped, &nonce, key)?;
                            Some((plain.as_slice().try_into().map_err(|_| SyncError::InvalidTicket)?, Some(inv)))
                        }
                        None => None,
                    }
                }
                InviteSecret::DeviceBound => by_owner(&keys::peer_key(&self.my_peer)).map(|e| {
                    crypto::decrypt_from_peer(&e.content, &self.identity.x25519_secret())
                        .ok()
                        .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
                        .map(|k| (k, None))
                }).flatten(),
            };
            if std::env::var_os("YASECRET_SYNC_DEBUG").is_some() {
                eprintln!(
                    "[join] entries={} grants={} owner_authors={} project={} key={}",
                    entries.len(), grants.len(), owner_authors.len(), project.is_some(), key.is_some()
                );
            }
            if let (Some(p), Some(k)) = (project, key) {
                break (p, k);
            }
            if tokio::time::Instant::now() > deadline {
                let _ = doc.leave().await;
                let _ = self.node.client().drop_doc(doc.id()).await;
                return Err(SyncError::OwnerOffline);
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        };
        let (project_key_bytes, used_invite): ([u8; 32], Option<WInvite>) = key;

        {
            let db = self.db()?;
            db.conn().execute(
                "INSERT INTO project (id, name, description, created_at, owner_id, updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![&project.id, &project.name, &project.description, project.created_at, hex::encode(invite.owner_sign_pub), project.updated_at],
            )?;
            project_key::store(&db, &project.id, &project_key_bytes, &self.db_key)?;
            db.conn().execute(
                "INSERT OR REPLACE INTO sync_doc (project_id, doc_id, ticket, owner_sign_pub) VALUES (?1,?2,?3,?4)",
                rusqlite::params![&project.id, &doc_id, &invite.ticket, hex::encode(invite.owner_sign_pub)],
            )?;
        }

        let invite_id = match &invite.secret {
            InviteSecret::Link { invite_id, .. } => Some(invite_id.clone()),
            InviteSecret::DeviceBound => None,
        };
        if let (Some(id), Some(mut inv)) = (&invite_id, used_invite) {
            inv.redeemed_by = Some(self.my_peer.clone());
            self.write(&doc, &keys::invite(id), serde_json::to_vec(&inv)?).await?;
        }
        let proof = join_proof(&project_key_bytes, &project.id, &self.my_peer, &self.author.to_string());
        let member = WMember { peer_id: self.my_peer.clone(), name: self.device_name.clone(), joined_at: now(), invite_id, proof };
        self.write(&doc, &keys::member(&self.my_peer), serde_json::to_vec(&member)?).await?;
        self.reconcile(&project.id).await?;
        self.revision.fetch_add(1, Ordering::SeqCst);
        Ok(project.id)
    }

    async fn members(&self, project_id: &str) -> Result<Vec<Member>> {
        let Some(info) = self.doc_info(project_id)? else { return Ok(vec![]) };
        let doc = self.open_doc(&info.doc_id).await?;
        let entries = self.read_entries(&doc).await?;
        let grants = valid_grants(project_id, &entries, &info.owner_sign_pub);
        let mut out: Vec<Member> = Vec::new();
        let mut seen = HashSet::new();
        let mut member_entries: Vec<&RawEntry> = entries.iter().filter(|e| e.key.starts_with("v2/member/")).collect();
        member_entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        for e in member_entries {
            let Ok(m) = serde_json::from_slice::<WMember>(&e.content) else { continue };
            if e.key != keys::member(&m.peer_id) || !seen.insert(m.peer_id.clone()) {
                continue;
            }
            let level = grants.get(&m.peer_id).map(|g| g.level.clone()).unwrap_or_else(|| "pending".into());
            if level == LEVEL_REMOVED {
                continue;
            }
            out.push(Member {
                is_me: m.peer_id == self.my_peer,
                peer_id: m.peer_id,
                name: m.name,
                level,
                joined_at: m.joined_at,
            });
        }
        out.sort_by(|a, b| (a.level != LEVEL_OWNER, a.joined_at).cmp(&(b.level != LEVEL_OWNER, b.joined_at)));
        Ok(out)
    }

    /// One full sync pass: apply accepted remote changes, publish newer local ones,
    /// and (as owner) admit members who redeemed an invite.
    async fn reconcile(self: &Arc<Self>, project_id: &str) -> Result<()> {
        let _guard = self.reconcile_lock.lock().await;
        let Some(info) = self.doc_info(project_id)? else { return Ok(()) };
        let doc = self.open_doc(&info.doc_id).await?;
        let entries = self.read_entries(&doc).await?;
        let me = self.clone();
        let pid = project_id.to_string();
        let owner = info.owner_sign_pub;
        let author = self.author.to_string();
        let plan = tokio::task::spawn_blocking(move || -> Result<Plan> {
            let db = me.db()?;
            plan_reconcile(&db, &me, &pid, &entries, &owner, &author)
        })
        .await
        .map_err(|e| SyncError::Iroh(anyhow::anyhow!("{e}")))??;
        for (key, value) in plan.pushes {
            self.write(&doc, &key, value).await?;
        }
        if plan.changed_local {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

// ── Reconcile planning (pure DB + entries, no network) ────────────────────────

struct Plan {
    pushes: Vec<(String, Vec<u8>)>,
    changed_local: bool,
}

fn latest<'a>(entries: &'a [RawEntry], key: &str, accept: impl Fn(&str) -> bool) -> Option<&'a RawEntry> {
    entries
        .iter()
        .filter(|e| e.key == key && accept(&e.author))
        .max_by_key(|e| e.timestamp)
}

/// Latest owner-signed grant per peer.
fn valid_grants(project_id: &str, entries: &[RawEntry], owner: &[u8; 32]) -> HashMap<String, WGrant> {
    let mut out: HashMap<String, WGrant> = HashMap::new();
    for e in entries.iter().filter(|e| e.key.starts_with("v2/grant/")) {
        let Ok(g) = serde_json::from_slice::<WGrant>(&e.content) else { continue };
        if e.key != keys::grant(&g.peer_id) {
            continue;
        }
        let msg = grant_msg(project_id, &g.peer_id, &g.author, &g.level, g.granted_at);
        if crypto::verify(msg.as_bytes(), &g.signature, owner).is_err() {
            continue;
        }
        match out.get(&g.peer_id) {
            Some(prev) if prev.granted_at >= g.granted_at => {}
            _ => {
                out.insert(g.peer_id.clone(), g);
            }
        }
    }
    out
}

fn plan_reconcile(
    db: &Db,
    inner: &Inner,
    project_id: &str,
    entries: &[RawEntry],
    owner_sign_pub: &[u8; 32],
    my_author: &str,
) -> Result<Plan> {
    let mut plan = Plan { pushes: Vec::new(), changed_local: false };
    let am_owner = *owner_sign_pub == sign_pub(&inner.identity);
    let grants = valid_grants(project_id, entries, owner_sign_pub);

    if am_owner {
        let mine = grants.get(&inner.my_peer);
        if mine.map(|g| g.author != my_author || g.level != LEVEL_OWNER).unwrap_or(true) {
            let g = inner.sign_grant(project_id, &inner.my_peer, my_author, LEVEL_OWNER);
            plan.pushes.push((keys::grant(&inner.my_peer), serde_json::to_vec(&g)?));
        }
        if latest(entries, &keys::member(&inner.my_peer), |a| a == my_author).is_none() {
            let m = WMember { peer_id: inner.my_peer.clone(), name: inner.device_name.clone(), joined_at: now(), invite_id: None, proof: vec![] };
            plan.pushes.push((keys::member(&inner.my_peer), serde_json::to_vec(&m)?));
        }
        let project_key = project_key::load(db, project_id, &inner.db_key)?;
        plan.pushes.extend(admit_members(db, project_id, entries, &grants, &project_key, &inner.identity)?);
    }

    let writer_authors: HashSet<String> = grants
        .values()
        .filter(|g| g.level == LEVEL_OWNER || g.level == LEVEL_EDITOR)
        .map(|g| g.author.clone())
        .collect();
    let owner_authors: HashSet<String> = grants.values().filter(|g| g.level == LEVEL_OWNER).map(|g| g.author.clone()).collect();
    let i_can_write = am_owner || writer_authors.contains(my_author);

    // Pick up a rotated project key before touching values encrypted with it.
    if !am_owner {
        if let Some(e) = latest(entries, &keys::peer_key(&inner.my_peer), |a| owner_authors.contains(a)) {
            if let Some(key) = crypto::decrypt_from_peer(&e.content, &inner.identity.x25519_secret())
                .ok()
                .and_then(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
            {
                let current = project_key::load(db, project_id, &inner.db_key)?;
                if *current != key {
                    project_key::rekey(db, project_id, &inner.db_key, &key)?;
                    plan.changed_local = true;
                }
            }
        }
    }

    // Project name
    let local_project = yasecret_core::project::get(db, project_id)?;
    let remote_project = latest(entries, keys::PROJECT, |a| owner_authors.contains(a))
        .and_then(|e| serde_json::from_slice::<WProject>(&e.content).ok());
    match remote_project {
        Some(r) if r.updated_at > local_project.updated_at => {
            db.conn().execute(
                "UPDATE project SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
                rusqlite::params![&r.name, &r.description, r.updated_at, project_id],
            )?;
            plan.changed_local = true;
        }
        Some(r) if r.updated_at == local_project.updated_at => {}
        _ if am_owner => {
            let w = WProject {
                id: local_project.id.clone(),
                name: local_project.name.clone(),
                description: local_project.description.clone(),
                created_at: local_project.created_at,
                updated_at: local_project.updated_at,
            };
            plan.pushes.push((keys::PROJECT.to_string(), serde_json::to_vec(&w)?));
        }
        _ => {}
    }

    let mut env_tombs: HashMap<String, i64> = HashMap::new();
    let mut secret_tombs: HashMap<String, i64> = HashMap::new();
    for t in tombstone::list(db, project_id)? {
        match t.kind.as_str() {
            "env" => env_tombs.insert(t.id, t.deleted_at),
            _ => secret_tombs.insert(t.id, t.deleted_at),
        };
    }

    // Environments first, so variables always have a parent row.
    let remote_envs: HashMap<String, WEnv> = latest_per_prefix(entries, "v2/env/", &writer_authors);
    let local_envs: HashMap<String, yasecret_core::models::Environment> = yasecret_core::environment::list(db, project_id)?
        .into_iter()
        .map(|e| (e.id.clone(), e))
        .collect();
    let env_ids: HashSet<&String> = remote_envs.keys().chain(local_envs.keys()).chain(env_tombs.keys()).collect();
    for id in env_ids {
        let remote = remote_envs.get(id);
        let local = local_envs.get(id);
        let local_ts = local.map(|l| l.updated_at).or_else(|| env_tombs.get(id).copied());
        match (local_ts, remote) {
            (None, None) => {}
            (None, Some(r)) => {
                if !r.deleted {
                    upsert_env(db, project_id, r)?;
                    plan.changed_local = true;
                }
            }
            (Some(lt), Some(r)) if r.updated_at > lt => {
                if r.deleted {
                    if local.is_some() {
                        yasecret_core::environment::delete(db, id)?;
                        plan.changed_local = true;
                    }
                } else {
                    upsert_env(db, project_id, r)?;
                    db.conn().execute("DELETE FROM tombstone WHERE id = ?1", [id])?;
                    plan.changed_local = true;
                }
            }
            (Some(lt), r) => {
                let already_gone = local.is_none() && r.map(|r| r.deleted).unwrap_or(false);
                if i_can_write && !already_gone && r.map(|r| lt > r.updated_at).unwrap_or(true) {
                    let w = match local {
                        Some(l) => WEnv { id: l.id.clone(), name: l.name.clone(), created_at: l.created_at, updated_at: l.updated_at, deleted: false },
                        None => WEnv { id: id.clone(), name: String::new(), created_at: 0, updated_at: lt, deleted: true },
                    };
                    plan.pushes.push((keys::env(id), serde_json::to_vec(&w)?));
                }
            }
        }
    }

    // Variables
    let remote_secrets: HashMap<String, WSecret> = latest_per_prefix(entries, "v2/secret/", &writer_authors);
    let mut local_secrets: HashMap<String, yasecret_core::models::Secret> = HashMap::new();
    for env in yasecret_core::environment::list(db, project_id)? {
        for s in yasecret_core::secret::list(db, &env.id)? {
            local_secrets.insert(s.id.clone(), s);
        }
    }
    let ids: HashSet<&String> = remote_secrets.keys().chain(local_secrets.keys()).chain(secret_tombs.keys()).collect();
    for id in ids {
        let remote = remote_secrets.get(id);
        let local = local_secrets.get(id);
        let local_ts = local.map(|l| l.updated_at).or_else(|| secret_tombs.get(id).copied());
        match (local_ts, remote) {
            (None, None) => {}
            (None, Some(r)) => {
                if !r.deleted && apply_remote_secret(db, r, None)? {
                    plan.changed_local = true;
                }
            }
            (Some(lt), Some(r)) if r.updated_at > lt => {
                if r.deleted {
                    if local.is_some() {
                        yasecret_core::secret::delete(db, id, &r.created_by)?;
                        plan.changed_local = true;
                    }
                } else if apply_remote_secret(db, r, local)? {
                    db.conn().execute("DELETE FROM tombstone WHERE id = ?1", [id])?;
                    plan.changed_local = true;
                }
            }
            (Some(lt), r) => {
                let already_gone = local.is_none() && r.map(|r| r.deleted).unwrap_or(false);
                if i_can_write && !already_gone && r.map(|r| lt > r.updated_at).unwrap_or(true) {
                    let w = match local {
                        Some(l) => WSecret {
                            id: l.id.clone(),
                            env_id: l.env_id.clone(),
                            key: l.key.clone(),
                            enc: l.encrypted_value.clone(),
                            nonce: l.nonce.clone(),
                            is_secret: l.is_secret,
                            created_at: l.created_at,
                            updated_at: l.updated_at,
                            created_by: l.created_by.clone(),
                            expires_at: l.expires_at,
                            deleted: false,
                        },
                        None => WSecret {
                            id: id.clone(),
                            env_id: String::new(),
                            key: String::new(),
                            enc: vec![],
                            nonce: vec![],
                            is_secret: true,
                            created_at: 0,
                            updated_at: lt,
                            created_by: inner.my_peer.clone(),
                            expires_at: None,
                            deleted: true,
                        },
                    };
                    plan.pushes.push((keys::secret(id), serde_json::to_vec(&w)?));
                }
            }
        }
    }
    Ok(plan)
}

fn upsert_env(db: &Db, project_id: &str, r: &WEnv) -> Result<()> {
    db.conn().execute(
        "INSERT INTO environment (id, project_id, name, created_at, updated_at) VALUES (?1,?2,?3,?4,?5)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, updated_at = excluded.updated_at",
        rusqlite::params![&r.id, project_id, &r.name, r.created_at, r.updated_at],
    )?;
    Ok(())
}

fn latest_per_prefix<T: for<'de> Deserialize<'de>>(
    entries: &[RawEntry],
    prefix: &str,
    authors: &HashSet<String>,
) -> HashMap<String, T> {
    let mut best: HashMap<&str, &RawEntry> = HashMap::new();
    for e in entries.iter().filter(|e| e.key.starts_with(prefix) && authors.contains(&e.author)) {
        match best.get(e.key.as_str()) {
            Some(prev) if prev.timestamp >= e.timestamp => {}
            _ => {
                best.insert(e.key.as_str(), e);
            }
        }
    }
    best.into_iter()
        .filter_map(|(k, e)| {
            let id = k.strip_prefix(prefix)?.to_string();
            serde_json::from_slice(&e.content).ok().map(|v| (id, v))
        })
        .collect()
}

/// Writes a remote variable locally. Returns false if it had to be skipped (e.g. its
/// environment hasn't arrived yet).
fn apply_remote_secret(db: &Db, r: &WSecret, local: Option<&yasecret_core::models::Secret>) -> Result<bool> {
    let env_exists: i64 = db.conn().query_row("SELECT count(*) FROM environment WHERE id = ?1", [&r.env_id], |x| x.get(0))?;
    if env_exists == 0 {
        return Ok(false);
    }
    if let Some(l) = local {
        if l.encrypted_value != r.enc {
            db.conn().execute(
                "INSERT INTO secret_version (id,secret_id,encrypted_value,nonce,changed_by,changed_at,note) VALUES (?1,?2,?3,?4,?5,?6,'sync')",
                rusqlite::params![new_id(), &l.id, &l.encrypted_value, &l.nonce, &r.created_by, l.updated_at],
            )?;
        }
        db.conn().execute(
            "UPDATE secret SET key=?1, encrypted_value=?2, nonce=?3, is_secret=?4, updated_at=?5, expires_at=?6 WHERE id=?7",
            rusqlite::params![&r.key, &r.enc, &r.nonce, r.is_secret, r.updated_at, r.expires_at, &r.id],
        )?;
        yasecret_core::audit::append(db, SYNC_ACTOR, "synced_secret", "secret", &r.id, Some(&r.key))?;
        return Ok(true);
    }
    // Two people created the same name independently: the newer one wins.
    let clash: Option<(String, i64)> = db
        .conn()
        .query_row(
            "SELECT id, updated_at FROM secret WHERE env_id = ?1 AND key = ?2",
            rusqlite::params![&r.env_id, &r.key],
            |x| Ok((x.get(0)?, x.get(1)?)),
        )
        .ok();
    if let Some((other, other_ts)) = clash {
        if other_ts > r.updated_at {
            return Ok(false);
        }
        yasecret_core::secret::delete(db, &other, "sync")?;
    }
    db.conn().execute(
        "INSERT INTO secret (id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![&r.id, &r.env_id, &r.key, &r.enc, &r.nonce, r.created_at, r.updated_at, &r.created_by, r.expires_at, r.is_secret],
    )?;
    yasecret_core::audit::append(db, SYNC_ACTOR, "synced_secret", "secret", &r.id, Some(&r.key))?;
    Ok(true)
}

/// Owner side: grant access to members who proved they hold the project key and match a
/// pending invite. Returns the grant entries to publish.
fn admit_members(
    db: &Db,
    project_id: &str,
    entries: &[RawEntry],
    grants: &HashMap<String, WGrant>,
    project_key: &[u8; 32],
    signer: &Identity,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut pushes = Vec::new();
    for e in entries.iter().filter(|e| e.key.starts_with("v2/member/")) {
        let Ok(m) = serde_json::from_slice::<WMember>(&e.content) else { continue };
        if e.key != keys::member(&m.peer_id) || grants.contains_key(&m.peer_id) {
            continue;
        }
        if !constant_time_eq(&m.proof, &join_proof(project_key, project_id, &m.peer_id, &e.author)) {
            continue;
        }
        // An invite already redeemed by this same peer still qualifies, so a grant whose
        // publish failed earlier is re-issued instead of leaving the member stuck.
        let pending: Option<(String, String)> = match &m.invite_id {
            Some(invite_id) => db
                .conn()
                .query_row(
                    "SELECT id, level FROM sync_invite WHERE id = ?1 AND project_id = ?2 AND kind = 'link'
                       AND (redeemed_by IS NULL OR redeemed_by = ?4) AND expires_at >= ?3",
                    rusqlite::params![invite_id, project_id, now(), &m.peer_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok(),
            None => db
                .conn()
                .query_row(
                    "SELECT id, level FROM sync_invite WHERE project_id = ?1 AND kind = 'device' AND peer_id = ?2
                       AND (redeemed_by IS NULL OR redeemed_by = ?2) AND expires_at >= ?3",
                    rusqlite::params![project_id, &m.peer_id, now()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok(),
        };
        let Some((invite_row, level)) = pending else { continue };
        let g = sign_grant(signer, project_id, &m.peer_id, &e.author, &level);
        pushes.push((keys::grant(&m.peer_id), serde_json::to_vec(&g)?));
        db.conn().execute(
            "UPDATE sync_invite SET redeemed_by = ?1 WHERE id = ?2",
            rusqlite::params![&m.peer_id, &invite_row],
        )?;
    }
    Ok(pushes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_link_roundtrips() {
        let link = InviteLink {
            project_id: "p1".into(),
            project_name: "My App & Co".into(),
            owner_sign_pub: [9u8; 32],
            ticket: "docaaa".into(),
            secret: InviteSecret::Link { invite_id: "i1".into(), key: [3u8; 32] },
        };
        assert_eq!(InviteLink::parse(&link.to_url()).unwrap(), link);
        let device = InviteLink { secret: InviteSecret::DeviceBound, ..link };
        assert_eq!(InviteLink::parse(&device.to_url()).unwrap(), device);
    }

    fn owner_db() -> (tempfile::TempDir, Db, Identity, String, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("o.sqlite"), "pw").unwrap();
        let me = identity::load_or_create(&db, "local").unwrap();
        let p = yasecret_core::project::create(&db, "app", None, &me.id).unwrap();
        db.conn().execute(
            "INSERT INTO sync_invite (id,project_id,kind,peer_id,level,created_at,expires_at) VALUES ('inv1',?1,'link',NULL,'editor',0,?2)",
            rusqlite::params![&p.id, now() + 3600],
        ).unwrap();
        db.conn().execute(
            "INSERT INTO sync_invite (id,project_id,kind,peer_id,level,created_at,expires_at) VALUES ('dev1',?1,'device','victimpeer','viewer',0,?2)",
            rusqlite::params![&p.id, now() + 3600],
        ).unwrap();
        (dir, db, me, p.id, [7u8; 32])
    }

    fn member_entry(peer: &str, author: &str, invite: Option<&str>, proof: Vec<u8>) -> RawEntry {
        let m = WMember { peer_id: peer.into(), name: "x".into(), joined_at: 1, invite_id: invite.map(String::from), proof };
        RawEntry { key: keys::member(peer), author: author.into(), timestamp: 1, content: serde_json::to_vec(&m).unwrap() }
    }

    #[test]
    fn ticket_holder_without_project_key_cannot_claim_a_link_invite() {
        let (_d, db, me, pid, key) = owner_db();
        let forged = member_entry("attacker", "attacker-author", Some("inv1"), vec![0u8; 32]);
        let pushes = admit_members(&db, &pid, &[forged], &HashMap::new(), &key, &me).unwrap();
        assert!(pushes.is_empty(), "no grant without a valid proof");
    }

    #[test]
    fn ticket_holder_cannot_hijack_a_device_bound_invite() {
        let (_d, db, me, pid, key) = owner_db();
        let wrong_key = [9u8; 32];
        let forged = member_entry("victimpeer", "attacker-author", None, join_proof(&wrong_key, &pid, "victimpeer", "attacker-author"));
        assert!(admit_members(&db, &pid, &[forged], &HashMap::new(), &key, &me).unwrap().is_empty());
    }

    #[test]
    fn joiner_with_valid_proof_is_admitted_once_and_regranted_if_needed() {
        let (_d, db, me, pid, key) = owner_db();
        let good = member_entry("friend", "friend-author", Some("inv1"), join_proof(&key, &pid, "friend", "friend-author"));
        let pushes = admit_members(&db, &pid, &[good], &HashMap::new(), &key, &me).unwrap();
        assert_eq!(pushes.len(), 1);
        let g: WGrant = serde_json::from_slice(&pushes[0].1).unwrap();
        assert_eq!((g.peer_id.as_str(), g.author.as_str(), g.level.as_str()), ("friend", "friend-author", "editor"));
        // Grant never landed in the doc: the same member is granted again.
        let again = member_entry("friend", "friend-author", Some("inv1"), join_proof(&key, &pid, "friend", "friend-author"));
        assert_eq!(admit_members(&db, &pid, &[again], &HashMap::new(), &key, &me).unwrap().len(), 1);
        // A different peer can't reuse the redeemed invite.
        let other = member_entry("other", "other-author", Some("inv1"), join_proof(&key, &pid, "other", "other-author"));
        assert!(admit_members(&db, &pid, &[other], &HashMap::new(), &key, &me).unwrap().is_empty());
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex::encode(mac), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn garbage_links_are_rejected_with_reason() {
        assert!(matches!(InviteLink::parse("https://example.com"), Err(SyncError::InvalidLink(_))));
        assert!(matches!(InviteLink::parse("yasecret://join?v=2&p=x"), Err(SyncError::InvalidLink(_))));
    }
}
