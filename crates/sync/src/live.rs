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
/// How long after an invite expires the owner still admits someone who redeemed it in time
/// (they may have joined through an always-on peer while the owner was offline).
pub const ADMIT_GRACE_SECS: i64 = 7 * 24 * 3600;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherits_from: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
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
    /// The device's signing key, needed to make it a co-owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_pub: Option<String>,
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
    /// Signing key of the co-owner who signed this grant; absent when the root owner did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// For a co-owner: the signing key they sign grants with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_pub: Option<String>,
}

/// An always-on peer the owner added; members dial it so the project stays reachable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WRelay {
    pub code: String,
    pub name: String,
    pub added_at: i64,
    pub removed: bool,
    pub signature: Vec<u8>,
    /// Signing key of the co-owner who added it; absent when the root owner did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
}

fn relay_msg(project_id: &str, code: &str, name: &str, added_at: i64, removed: bool, signed_by: Option<&str>) -> String {
    let base = format!("yasecret-relay-v1|{project_id}|{code}|{name}|{added_at}|{removed}");
    match signed_by {
        Some(k) => format!("{base}|{k}"),
        None => base,
    }
}

/// Latest relay record per relay signed by the root owner or a co-owner, excluding removed ones.
fn valid_relays(project_id: &str, entries: &[RawEntry], owner: &[u8; 32]) -> Vec<WRelay> {
    let co_owner_keys: Vec<[u8; 32]> = grants_and_co_owners(project_id, entries, owner).1.into_values().collect();
    let mut latest_by_code: HashMap<String, WRelay> = HashMap::new();
    for e in entries.iter().filter(|e| e.key.starts_with("v2/relay/")) {
        let Ok(r) = serde_json::from_slice::<WRelay>(&e.content) else { continue };
        if e.key != keys::relay(&r.code) {
            continue;
        }
        let signer = match r.signed_by.as_deref() {
            None => *owner,
            Some(k) => match hex32(k).filter(|k| co_owner_keys.contains(k)) {
                Some(k) => k,
                None => continue,
            },
        };
        let msg = relay_msg(project_id, &r.code, &r.name, r.added_at, r.removed, r.signed_by.as_deref());
        if crypto::verify(msg.as_bytes(), &r.signature, &signer).is_err() {
            continue;
        }
        match latest_by_code.get(&r.code) {
            Some(prev) if (prev.added_at, prev.removed) >= (r.added_at, r.removed) => {}
            _ => {
                latest_by_code.insert(r.code.clone(), r);
            }
        }
    }
    let mut out: Vec<WRelay> = latest_by_code.into_values().filter(|r| !r.removed).collect();
    out.sort_by(|a, b| a.added_at.cmp(&b.added_at));
    out
}

fn relay_addr(code: &str) -> Option<iroh::EndpointAddr> {
    code.parse::<iroh::PublicKey>().ok().map(iroh::EndpointAddr::new)
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
    pub fn relay(code: &str) -> String { format!("v2/relay/{code}") }
}

// ── Sealed records ────────────────────────────────────────────────────────────
//
// Project, environment, variable and member records are encrypted whole with the project
// key, so a relay or anyone holding a doc ticket sees no names. Grants, invites, key
// handoffs and relay records stay readable: they're what a device needs before it has the key.

fn is_sealed_key(key: &str) -> bool {
    key == keys::PROJECT || key.starts_with("v2/env/") || key.starts_with("v2/secret/") || key.starts_with("v2/member/")
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    sealed: Vec<u8>,
    nonce: Vec<u8>,
}

fn seal(project_key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let (sealed, nonce) = crypto::encrypt(plain, project_key)?;
    Ok(serde_json::to_vec(&Sealed { sealed, nonce: nonce.to_vec() })?)
}

/// Opens sealed records. Ones this key can't open (sealed before a key rotation, or by a
/// device that hasn't caught up) are dropped, so they count as missing and get re-sealed.
fn open_entries(entries: Vec<RawEntry>, project_key: &[u8; 32]) -> Vec<RawEntry> {
    entries
        .into_iter()
        .filter_map(|mut e| {
            if !is_sealed_key(&e.key) {
                return Some(e);
            }
            match serde_json::from_slice::<Sealed>(&e.content) {
                Ok(s) => {
                    let nonce: [u8; 12] = s.nonce.try_into().ok()?;
                    e.content = crypto::decrypt(&s.sealed, &nonce, project_key).ok()?.to_vec();
                    Some(e)
                }
                Err(_) => {
                    e.legacy = true;
                    Some(e)
                }
            }
        })
        .collect()
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

fn sign_grant(
    signer: &Identity,
    project_id: &str,
    peer: &str,
    author: &str,
    level: &str,
    signed_by: Option<String>,
    sign_pub: Option<String>,
) -> WGrant {
    let mut g = WGrant {
        peer_id: peer.to_string(),
        author: author.to_string(),
        level: level.to_string(),
        granted_at: now(),
        signature: vec![],
        signed_by,
        sign_pub,
    };
    g.signature = crypto::sign(grant_msg(project_id, &g).as_bytes(), &signer.signing_key());
    g
}

fn grant_msg(project_id: &str, g: &WGrant) -> String {
    let base = format!("yasecret-grant-v2|{project_id}|{}|{}|{}|{}", g.peer_id, g.author, g.level, g.granted_at);
    if g.signed_by.is_none() && g.sign_pub.is_none() {
        // Grants from before co-owners existed.
        base
    } else {
        format!("{base}|{}|{}", g.signed_by.as_deref().unwrap_or(""), g.sign_pub.as_deref().unwrap_or(""))
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok().and_then(|b| b.try_into().ok())
}

/// Later grants win; at the same time, removal wins.
fn keep_latest(out: &mut HashMap<String, WGrant>, g: WGrant) {
    let rank = |l: &str| if l == LEVEL_REMOVED { 1 } else { 0 };
    match out.get(&g.peer_id) {
        Some(prev) if (prev.granted_at, rank(&prev.level)) >= (g.granted_at, rank(&g.level)) => {}
        _ => {
            out.insert(g.peer_id.clone(), g);
        }
    }
}

/// Valid grants, latest per peer, and the current co-owners (peer → signing key).
///
/// The root owner (pinned from the invite link) appoints and removes co-owners: only
/// root-signed grants decide who owns. Co-owners sign grants for everyone else. A grant
/// counts only while its signer is the root or a current co-owner, so grants a demoted
/// co-owner signs (whatever date they put on them) are ignored; when demoting, the root
/// re-signs the grants that co-owner issued.
fn grants_and_co_owners(project_id: &str, entries: &[RawEntry], root: &[u8; 32]) -> (HashMap<String, WGrant>, HashMap<String, [u8; 32]>) {
    let parsed: Vec<WGrant> = entries
        .iter()
        .filter(|e| e.key.starts_with("v2/grant/"))
        .filter_map(|e| serde_json::from_slice::<WGrant>(&e.content).ok().filter(|g| e.key == keys::grant(&g.peer_id)))
        .collect();
    let verifies = |g: &WGrant, key: &[u8; 32]| crypto::verify(grant_msg(project_id, g).as_bytes(), &g.signature, key).is_ok();

    let mut by_root: HashMap<String, WGrant> = HashMap::new();
    for g in parsed.iter().filter(|g| g.signed_by.is_none() && verifies(g, root)) {
        keep_latest(&mut by_root, g.clone());
    }
    let co_owners: HashMap<String, [u8; 32]> = by_root
        .values()
        .filter(|g| g.level == LEVEL_OWNER)
        .filter_map(|g| Some((g.peer_id.clone(), hex32(g.sign_pub.as_deref()?)?)))
        .filter(|(_, k)| k != root)
        .collect();
    let owners: HashSet<&String> = by_root.values().filter(|g| g.level == LEVEL_OWNER).map(|g| &g.peer_id).collect();

    let mut out = by_root.clone();
    for g in parsed.iter().filter(|g| g.signed_by.is_some()) {
        let Some(key) = g.signed_by.as_deref().and_then(hex32) else { continue };
        if !co_owners.values().any(|k| *k == key) || !verifies(g, &key) {
            continue;
        }
        if g.level == LEVEL_OWNER || g.sign_pub.is_some() || owners.contains(&g.peer_id) {
            continue;
        }
        keep_latest(&mut out, g.clone());
    }
    (out, co_owners)
}

// ── Key handoffs ──────────────────────────────────────────────────────────────

/// The project key for one device, with when it was rotated, so every device picks the same
/// key when two owners rotate at once.
fn handoff_blob(key: &[u8; 32], rotated_at: i64, peer_x25519: &[u8; 32]) -> Result<Vec<u8>> {
    let mut plain = key.to_vec();
    plain.extend_from_slice(&rotated_at.to_be_bytes());
    Ok(crypto::encrypt_for_peer(&plain, peer_x25519)?)
}

/// The key from the newest rotation among owner handoffs addressed to `my_peer`.
/// Handoffs from before rotation times were recorded read as rotated at 0.
fn chosen_handoff(entries: &[RawEntry], my_peer: &str, owner_authors: &HashSet<String>, secret: &x25519_dalek::StaticSecret) -> Option<[u8; 32]> {
    let key = keys::peer_key(my_peer);
    entries
        .iter()
        .filter(|e| e.key == key && owner_authors.contains(&e.author))
        .filter_map(|e| {
            let plain = crypto::decrypt_from_peer(&e.content, secret).ok()?;
            let k: [u8; 32] = plain.get(..32)?.try_into().ok()?;
            let at = match plain.get(32..40) {
                Some(b) => i64::from_be_bytes(b.try_into().ok()?),
                None => 0,
            };
            Some(((at, e.author.clone()), k))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, k)| k)
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

/// What the owner hands to `yasecret relay add`: a read-only doc ticket, no project key.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayLink {
    pub project_name: String,
    pub ticket: String,
}

impl RelayLink {
    pub fn to_url(&self) -> String {
        format!("yasecret://relay?v=1&n={}&t={}", percent_encode(&self.project_name), self.ticket)
    }

    pub fn parse(link: &str) -> Result<Self> {
        let bad = |why: &str| SyncError::InvalidLink(why.to_string());
        let query = link
            .trim()
            .strip_prefix("yasecret://relay?")
            .ok_or_else(|| bad("it doesn't start with yasecret://relay"))?;
        let params: HashMap<&str, &str> = query.split('&').filter_map(|kv| kv.split_once('=')).collect();
        let get = |k: &str| params.get(k).copied().ok_or_else(|| bad("it is incomplete — copy the whole link"));
        if get("v")? != "1" {
            return Err(bad("it was made by a different version of Yasecret"));
        }
        let ticket = get("t")?;
        if ticket.parse::<iroh_docs::DocTicket>().is_err() {
            return Err(bad("its ticket is damaged — copy the whole link again"));
        }
        Ok(Self { project_name: percent_decode(get("n")?), ticket: ticket.to_string() })
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
    /// The owner who shared the project (as opposed to a co-owner).
    pub is_root: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RelayPeer {
    pub code: String,
    pub name: String,
    pub added_at: i64,
    pub online: bool,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SyncStatus {
    pub shared: bool,
    /// Owner or co-owner: can invite people and change access.
    pub is_owner: bool,
    /// The owner who shared the project: can appoint co-owners and stop sharing.
    pub is_root: bool,
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
    // Refreshed on every sync pass so status and member lists never block the UI.
    is_owner: Option<bool>,
    is_root: Option<bool>,
    my_level: Option<String>,
    members: Option<Vec<Member>>,
    relays: Option<Vec<WRelay>>,
    last_relay_dial: Option<std::time::Instant>,
}

/// Connected devices, not counting always-on peers.
fn people_online(st: &LiveState) -> u32 {
    let relays: HashSet<&str> = st.relays.iter().flatten().map(|r| r.code.as_str()).collect();
    st.neighbors.iter().filter(|n| !relays.contains(n.as_str())).count() as u32
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

struct RawDocInfo {
    doc_id: String,
    owner_sign_pub: Option<String>,
}

struct RawEntry {
    key: String,
    author: String,
    timestamp: u64,
    content: Vec<u8>,
    /// A record that should be sealed but was written in plaintext by an older version.
    legacy: bool,
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
            let mut stmt = db.conn().prepare("SELECT project_id FROM sync_doc WHERE owner_sign_pub IS NOT NULL")?;
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
            inner.require_admin(&project_id, &info).await?;
            inner.reconcile(&project_id).await?;
            let doc = inner.open_doc(&info.doc_id).await?;
            let mut ticket = doc
                .share(
                    iroh_docs::api::protocol::ShareMode::Write,
                    iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
                )
                .await
                .map_err(anyhow::Error::from)?;
            // Always-on peers let the joiner get in while this computer is off.
            let entries = inner.read_entries(&doc).await?;
            for r in valid_relays(&project_id, &entries, &info.owner_sign_pub) {
                if let Ok(pk) = r.code.parse::<iroh::PublicKey>() {
                    ticket.nodes.push(inner.node.known_addr(pk).await);
                }
            }
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
                    let blob = handoff_blob(&project_key, 0, &peer)?;
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

    /// Owner: registers an always-on peer and returns the link to run on it
    /// (`yasecret relay add '<link>'`). The relay only gets read access to encrypted data.
    pub fn add_relay(&self, project_id: &str, code: &str, name: &str) -> Result<String> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
        let addr = relay_addr(&code).filter(|_| code.len() == 64).ok_or(SyncError::InvalidRelayCode)?;
        let name = match name.trim() {
            "" => "Always-on peer".to_string(),
            n => n.to_string(),
        };
        let inner = self.inner.clone();
        let pid = project_id.to_string();
        let url = self.rt.block_on(async move {
            // A project that isn't shared yet is this device's own; ensure_doc shares it.
            let info = inner.ensure_doc(&pid).await?;
            inner.require_admin(&pid, &info).await?;
            let doc = inner.open_doc(&info.doc_id).await?;
            let r = inner.sign_relay(&info.owner_sign_pub, &pid, &code, &name, false);
            inner.write(&doc, &keys::relay(&code), serde_json::to_vec(&r)?).await?;
            inner.reconcile(&pid).await?;
            let ticket = doc
                .share(
                    iroh_docs::api::protocol::ShareMode::Read,
                    iroh_docs::api::protocol::AddrInfoOptions::RelayAndAddresses,
                )
                .await
                .map_err(anyhow::Error::from)?;
            let _ = doc.start_sync(vec![addr]).await;
            let project_name = yasecret_core::project::get(&inner.db()?, &pid)?.name;
            Ok::<_, SyncError>(RelayLink { project_name, ticket: ticket.to_string() }.to_url())
        })?;
        self.watch(project_id);
        Ok(url)
    }

    /// Owner: members stop dialing this peer. A read-only doc capability can't be revoked, so
    /// the peer keeps what it stored and devices that remember it may still sync with it;
    /// stopping sharing (which rotates the key and leaves the doc) cuts it off completely.
    pub fn remove_relay(&self, project_id: &str, code: &str) -> Result<()> {
        let inner = self.inner.clone();
        let (pid, code) = (project_id.to_string(), code.to_string());
        self.rt.block_on(async move {
            let info = inner.doc_info(&pid)?.ok_or_else(|| SyncError::NoDoc(pid.clone()))?;
            inner.require_admin(&pid, &info).await?;
            let doc = inner.open_doc(&info.doc_id).await?;
            let name = valid_relays(&pid, &inner.read_entries(&doc).await?, &info.owner_sign_pub)
                .into_iter()
                .find(|r| r.code == code)
                .map(|r| r.name)
                .unwrap_or_default();
            let r = inner.sign_relay(&info.owner_sign_pub, &pid, &code, &name, true);
            inner.write(&doc, &keys::relay(&code), serde_json::to_vec(&r)?).await?;
            inner.reconcile(&pid).await
        })
    }

    pub fn relays(&self, project_id: &str) -> Result<Vec<RelayPeer>> {
        let cached = self.inner.live.lock().unwrap().get(project_id).and_then(|s| s.relays.clone());
        let list = match cached {
            Some(list) => list,
            None => {
                let Some(info) = self.inner.doc_info(project_id)? else { return Ok(vec![]) };
                let inner = self.inner.clone();
                let pid = project_id.to_string();
                self.rt.block_on(async move {
                    let doc = inner.open_doc(&info.doc_id).await?;
                    Ok::<_, SyncError>(valid_relays(&pid, &inner.read_entries(&doc).await?, &info.owner_sign_pub))
                })?
            }
        };
        let live = self.inner.live.lock().unwrap();
        let neighbors = live.get(project_id).map(|s| s.neighbors.clone()).unwrap_or_default();
        Ok(list
            .into_iter()
            .map(|r| RelayPeer { online: neighbors.contains(&r.code), code: r.code, name: r.name, added_at: r.added_at })
            .collect())
    }

    pub fn members(&self, project_id: &str) -> Result<Vec<Member>> {
        let inner = self.inner.clone();
        let project_id = project_id.to_string();
        self.rt.block_on(async move { inner.members(&project_id).await })
    }

    /// `level`: "owner" (co-owner; root owner only), "editor", "viewer" or "removed".
    /// Co-owners can change anyone's access except owners'.
    pub fn set_member_level(&self, project_id: &str, peer: &str, level: &str) -> Result<()> {
        if ![LEVEL_OWNER, LEVEL_EDITOR, LEVEL_VIEWER, LEVEL_REMOVED].contains(&level) {
            return Err(SyncError::InvalidLink(format!("unknown access level {level}")));
        }
        let inner = self.inner.clone();
        let (project_id, peer, level) = (project_id.to_string(), peer.to_string(), level.to_string());
        self.rt.block_on(async move {
            let info = inner.doc_info(&project_id)?.ok_or_else(|| SyncError::NoDoc(project_id.clone()))?;
            let root = info.owner_sign_pub;
            let doc = inner.open_doc(&info.doc_id).await?;
            let key = project_key::load(&inner.db()?, &project_id, &inner.db_key)?;
            let entries = open_entries(inner.read_entries(&doc).await?, &key);
            let (is_admin, is_root) = inner.roles(&project_id, &info, &entries);
            if !is_admin {
                return Err(SyncError::NotOwner);
            }
            if peer == inner.my_peer {
                return Err(SyncError::InvalidLink("you can't change your own access".into()));
            }
            let (grants, co_owners) = grants_and_co_owners(&project_id, &entries, &root);
            let current = grants
                .get(&peer)
                .ok_or_else(|| SyncError::InvalidLink("that member hasn't finished joining yet".into()))?
                .clone();
            if (level == LEVEL_OWNER || current.level == LEVEL_OWNER) && !is_root {
                return Err(SyncError::NotOwner);
            }
            let sign_pub_for = if level == LEVEL_OWNER {
                let record = latest(&entries, &keys::member(&peer), |a| a == current.author)
                    .and_then(|e| serde_json::from_slice::<WMember>(&e.content).ok());
                Some(record.and_then(|m| m.sign_pub).ok_or_else(|| {
                    SyncError::InvalidLink("that device needs to update Yasecret before it can be a co-owner".into())
                })?)
            } else {
                None
            };
            // Grants a co-owner issued stop counting once they're demoted: re-sign them so
            // the people they let in keep their access.
            if let (Some(co_key), true) = (co_owners.get(&peer), level != LEVEL_OWNER) {
                let co_hex = hex::encode(co_key);
                for g in grants.values().filter(|g| g.signed_by.as_deref() == Some(co_hex.as_str())) {
                    let again = inner.sign_grant(&root, &project_id, &g.peer_id, &g.author, &g.level, None);
                    inner.write(&doc, &keys::grant(&g.peer_id), serde_json::to_vec(&again)?).await?;
                }
            }
            let g = inner.sign_grant(&root, &project_id, &peer, &current.author, &level, sign_pub_for);
            inner.write(&doc, &keys::grant(&peer), serde_json::to_vec(&g)?).await?;
            if level == LEVEL_REMOVED {
                // The removed device still holds the old key; switch everyone else (this
                // device included, so every owner agrees which rotation is newest) to a new one.
                let rotated_at = now();
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
                for g in grants.values().filter(|g| g.peer_id != peer && g.level != LEVEL_REMOVED) {
                    let Some(pub_key) = hex32(&g.peer_id) else { continue };
                    let blob = handoff_blob(&new_key, rotated_at, &pub_key)?;
                    inner.write(&doc, &keys::peer_key(&g.peer_id), blob).await?;
                }
                inner.reconcile(&project_id).await?;
                inner.revision.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })
    }

    pub fn status(&self, project_id: &str) -> Result<SyncStatus> {
        if let Some(st) = self.inner.live.lock().unwrap().get(project_id) {
            if let (Some(is_owner), Some(is_root), Some(level)) = (st.is_owner, st.is_root, &st.my_level) {
                return Ok(SyncStatus {
                    shared: true,
                    is_owner,
                    is_root,
                    my_level: level.clone(),
                    peers_online: people_online(st),
                    last_synced_at: st.last_synced_at,
                    last_error: st.last_error.clone(),
                });
            }
        }
        let info = self.inner.doc_info(project_id)?;
        let Some(info) = info else { return Ok(SyncStatus::default()) };
        let is_root = info.owner_sign_pub == sign_pub(&self.inner.identity);
        let inner = self.inner.clone();
        let pid = project_id.to_string();
        let my_level = if is_root {
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
            is_owner: is_root || my_level == LEVEL_OWNER,
            is_root,
            my_level,
            peers_online: st.map(people_online).unwrap_or(0),
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
        Ok(row.map(|(doc_id, owner)| RawDocInfo {
            doc_id,
            owner_sign_pub: owner,
        })
        .and_then(|i| {
            // Legacy rows without a pinned owner key can't be verified; treat them as unshared
            // rather than guessing that this device is the owner.
            let key = i.owner_sign_pub.as_deref().and_then(|h| hex::decode(h).ok()).and_then(|b| b.try_into().ok())?;
            Some(DocInfo { doc_id: i.doc_id, owner_sign_pub: key })
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
                legacy: false,
            });
        }
        Ok(out)
    }

    /// How this device signs in a project: nothing extra as the root owner, its key as a co-owner.
    fn signed_by(&self, root: &[u8; 32]) -> Option<String> {
        let mine = sign_pub(&self.identity);
        (mine != *root).then(|| hex::encode(mine))
    }

    fn sign_grant(&self, root: &[u8; 32], project_id: &str, peer: &str, author: &str, level: &str, sign_pub_for: Option<String>) -> WGrant {
        sign_grant(&self.identity, project_id, peer, author, level, self.signed_by(root), sign_pub_for)
    }

    fn sign_relay(&self, root: &[u8; 32], project_id: &str, code: &str, name: &str, removed: bool) -> WRelay {
        let added_at = now();
        let signed_by = self.signed_by(root);
        let msg = relay_msg(project_id, code, name, added_at, removed, signed_by.as_deref());
        WRelay {
            code: code.to_string(),
            name: name.to_string(),
            added_at,
            removed,
            signature: crypto::sign(msg.as_bytes(), &self.identity.signing_key()),
            signed_by,
        }
    }

    /// (may manage people and relays, is the root owner)
    fn roles(&self, project_id: &str, info: &DocInfo, entries: &[RawEntry]) -> (bool, bool) {
        let mine = sign_pub(&self.identity);
        let is_root = info.owner_sign_pub == mine;
        let co_owner = grants_and_co_owners(project_id, entries, &info.owner_sign_pub).1.get(&self.my_peer) == Some(&mine);
        (is_root || co_owner, is_root)
    }

    async fn require_admin(&self, project_id: &str, info: &DocInfo) -> Result<()> {
        if info.owner_sign_pub == sign_pub(&self.identity) {
            return Ok(());
        }
        let doc = self.open_doc(&info.doc_id).await?;
        let entries = self.read_entries(&doc).await?;
        if self.roles(project_id, info, &entries).0 { Ok(()) } else { Err(SyncError::NotOwner) }
    }

    fn my_member_record(&self) -> WMember {
        WMember {
            peer_id: self.my_peer.clone(),
            name: self.device_name.clone(),
            joined_at: now(),
            invite_id: None,
            proof: vec![],
            sign_pub: Some(hex::encode(sign_pub(&self.identity))),
        }
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
                InviteSecret::DeviceBound => {
                    let authors: HashSet<String> = owner_authors.iter().map(|a| a.to_string()).collect();
                    chosen_handoff(&entries, &self.my_peer, &authors, &self.identity.x25519_secret()).map(|k| (k, None))
                }
            };
            // The project record is sealed: it can only be read once the key is known.
            let project = key.as_ref().and_then(|(k, _)| {
                let opened = open_entries(entries.iter().filter(|e| e.key == keys::PROJECT).map(|e| RawEntry {
                    key: e.key.clone(),
                    author: e.author.clone(),
                    timestamp: e.timestamp,
                    content: e.content.clone(),
                    legacy: false,
                }).collect(), k);
                latest(&opened, keys::PROJECT, |a| owner_authors.contains(a)).and_then(|e| serde_json::from_slice::<WProject>(&e.content).ok())
            });
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
        let member = WMember { invite_id, proof, ..self.my_member_record() };
        self.write(&doc, &keys::member(&self.my_peer), seal(&project_key_bytes, &serde_json::to_vec(&member)?)?).await?;
        self.reconcile(&project.id).await?;
        self.revision.fetch_add(1, Ordering::SeqCst);
        Ok(project.id)
    }

    async fn members(&self, project_id: &str) -> Result<Vec<Member>> {
        if let Some(cached) = self.live.lock().unwrap().get(project_id).and_then(|s| s.members.clone()) {
            return Ok(cached);
        }
        let Some(info) = self.doc_info(project_id)? else { return Ok(vec![]) };
        let doc = self.open_doc(&info.doc_id).await?;
        let key = project_key::load(&self.db()?, project_id, &self.db_key)?;
        let entries = open_entries(self.read_entries(&doc).await?, &key);
        let grants = valid_grants(project_id, &entries, &info.owner_sign_pub);
        Ok(members_from(&entries, &grants, &self.my_peer))
    }

    fn refresh_cache(&self, project_id: &str, info: &DocInfo, entries: &[RawEntry]) {
        let grants = valid_grants(project_id, entries, &info.owner_sign_pub);
        let is_root = info.owner_sign_pub == sign_pub(&self.identity);
        let level = if is_root {
            LEVEL_OWNER.to_string()
        } else {
            grants.get(&self.my_peer).map(|g| g.level.clone()).unwrap_or_else(|| "pending".into())
        };
        let members = members_from(entries, &grants, &self.my_peer);
        let mut live = self.live.lock().unwrap();
        let st = live.entry(project_id.to_string()).or_default();
        if st.my_level.as_deref() != Some(level.as_str()) {
            // Lets the CLI and MCP server refuse changes that would never sync.
            if let Ok(db) = self.db() {
                let _ = db.conn().execute("UPDATE sync_doc SET my_level = ?1 WHERE project_id = ?2", rusqlite::params![&level, project_id]);
            }
        }
        st.is_owner = Some(is_root || level == LEVEL_OWNER);
        st.is_root = Some(is_root);
        st.my_level = Some(level);
        st.members = Some(members);
        st.relays = Some(valid_relays(project_id, entries, &info.owner_sign_pub));
    }

    /// Dials always-on peers that aren't connected, at most every `RECONCILE_EVERY`.
    async fn dial_relays(&self, project_id: &str, doc: &iroh_docs::api::Doc) {
        let ids: Vec<iroh::PublicKey> = {
            let mut live = self.live.lock().unwrap();
            let st = live.entry(project_id.to_string()).or_default();
            if st.last_relay_dial.is_some_and(|t| t.elapsed() < RECONCILE_EVERY) {
                return;
            }
            let ids: Vec<_> = st
                .relays
                .iter()
                .flatten()
                .filter(|r| !st.neighbors.contains(&r.code))
                .filter_map(|r| r.code.parse().ok())
                .collect();
            if !ids.is_empty() {
                st.last_relay_dial = Some(std::time::Instant::now());
            }
            ids
        };
        if !ids.is_empty() {
            let mut addrs = Vec::new();
            for id in ids {
                addrs.push(self.node.known_addr(id).await);
            }
            let _ = doc.start_sync(addrs).await;
        }
    }

    /// One full sync pass: apply accepted remote changes, publish newer local ones,
    /// and (as owner) admit members who redeemed an invite.
    async fn reconcile(self: &Arc<Self>, project_id: &str) -> Result<()> {
        let _guard = self.reconcile_lock.lock().await;
        let Some(info) = self.doc_info(project_id)? else { return Ok(()) };
        let doc = self.open_doc(&info.doc_id).await?;
        let key_before = project_key::load(&self.db()?, project_id, &self.db_key)?;
        let entries = open_entries(self.read_entries(&doc).await?, &key_before);
        self.refresh_cache(project_id, &info, &entries);
        self.dial_relays(project_id, &doc).await;
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
        // The plan may have switched to a rotated key; seal with the one now in use.
        let key_now = project_key::load(&self.db()?, project_id, &self.db_key)?;
        let wrote = !plan.pushes.is_empty();
        for (key, value) in plan.pushes {
            let value = if is_sealed_key(&key) { seal(&key_now, &value)? } else { value };
            self.write(&doc, &key, value).await?;
        }
        if wrote {
            let entries = open_entries(self.read_entries(&doc).await?, &key_now);
            self.refresh_cache(project_id, &info, &entries);
        }
        if plan.changed_local {
            self.revision.fetch_add(1, Ordering::SeqCst);
        }
        if *key_now != *key_before {
            // Records sealed with the new key were skipped this pass.
            self.schedule(project_id.to_string(), Duration::from_millis(100));
        }
        Ok(())
    }
}

fn members_from(entries: &[RawEntry], grants: &HashMap<String, WGrant>, my_peer: &str) -> Vec<Member> {
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
        // The root owner's grant is the owner grant without a co-owner signing key.
        let is_root = grants.get(&m.peer_id).is_some_and(|g| g.level == LEVEL_OWNER && g.sign_pub.is_none());
        out.push(Member { is_me: m.peer_id == my_peer, peer_id: m.peer_id, name: m.name, level, joined_at: m.joined_at, is_root });
    }
    out.sort_by(|a, b| (a.level != LEVEL_OWNER, a.joined_at).cmp(&(b.level != LEVEL_OWNER, b.joined_at)));
    out
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

/// Latest valid grant per peer; see `grants_and_co_owners`.
fn valid_grants(project_id: &str, entries: &[RawEntry], root: &[u8; 32]) -> HashMap<String, WGrant> {
    grants_and_co_owners(project_id, entries, root).0
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
    // `am_owner`: the root owner, who publishes the project record and its own grant.
    let am_owner = *owner_sign_pub == sign_pub(&inner.identity);
    let (grants, co_owners) = grants_and_co_owners(project_id, entries, owner_sign_pub);
    let am_co_owner = co_owners.get(&inner.my_peer) == Some(&sign_pub(&inner.identity));

    if am_owner {
        let mine = grants.get(&inner.my_peer);
        if mine.map(|g| g.author != my_author || g.level != LEVEL_OWNER || g.sign_pub.is_some()).unwrap_or(true) {
            let g = inner.sign_grant(owner_sign_pub, project_id, &inner.my_peer, my_author, LEVEL_OWNER, None);
            plan.pushes.push((keys::grant(&inner.my_peer), serde_json::to_vec(&g)?));
        }
    }
    if am_owner || am_co_owner {
        let project_key = project_key::load(db, project_id, &inner.db_key)?;
        plan.pushes.extend(admit_members(db, project_id, entries, &grants, &project_key, &inner.identity, inner.signed_by(owner_sign_pub))?);
    }

    // Publish this device's member record when it's missing (sealed with a replaced key, or
    // the owner's first pass) or predates signing keys.
    let admitted = am_owner || grants.get(&inner.my_peer).is_some_and(|g| g.author == my_author && g.level != LEVEL_REMOVED);
    let my_record = latest(entries, &keys::member(&inner.my_peer), |a| a == my_author)
        .and_then(|e| serde_json::from_slice::<WMember>(&e.content).ok());
    if admitted && my_record.as_ref().is_none_or(|m| m.sign_pub.is_none()) {
        let mut m = inner.my_member_record();
        if let Some(old) = my_record {
            m.joined_at = old.joined_at;
            m.invite_id = old.invite_id;
        }
        plan.pushes.push((keys::member(&inner.my_peer), serde_json::to_vec(&m)?));
    }

    let writer_authors: HashSet<String> = grants
        .values()
        .filter(|g| g.level == LEVEL_OWNER || g.level == LEVEL_EDITOR)
        .map(|g| g.author.clone())
        .collect();
    let owner_authors: HashSet<String> = grants.values().filter(|g| g.level == LEVEL_OWNER).map(|g| g.author.clone()).collect();
    let i_can_write = am_owner || writer_authors.contains(my_author);

    // Pick up a rotated project key before touching values encrypted with it. Owners take
    // part too: a co-owner may have rotated it.
    if let Some(key) = chosen_handoff(entries, &inner.my_peer, &owner_authors, &inner.identity.x25519_secret()) {
        let current = project_key::load(db, project_id, &inner.db_key)?;
        if *current != key {
            project_key::rekey(db, project_id, &inner.db_key, &key)?;
            plan.changed_local = true;
        }
    }

    // Records written in plaintext by older versions: the owner publishes them again, sealed.
    if am_owner {
        let mut latest_by_key: HashMap<&str, &RawEntry> = HashMap::new();
        for e in entries.iter().filter(|e| is_sealed_key(&e.key)) {
            if latest_by_key.get(e.key.as_str()).is_none_or(|p| e.timestamp > p.timestamp) {
                latest_by_key.insert(&e.key, e);
            }
        }
        for e in latest_by_key.values().filter(|e| e.legacy && writer_authors.contains(&e.author)) {
            plan.pushes.push((e.key.clone(), e.content.clone()));
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
    let local_envs: HashMap<String, WEnv> = yasecret_core::environment::list(db, project_id)?
        .into_iter()
        .map(|l| (l.id.clone(), WEnv { id: l.id, name: l.name, created_at: l.created_at, updated_at: l.updated_at, deleted: false, inherits_from: l.inherits_from }))
        .chain(env_tombs.iter().map(|(id, at)| {
            (id.clone(), WEnv { id: id.clone(), name: String::new(), created_at: 0, updated_at: *at, deleted: true, inherits_from: None })
        }))
        .collect();
    let env_ids: HashSet<&String> = remote_envs.keys().chain(local_envs.keys()).collect();
    for id in env_ids {
        match decide(local_envs.get(id), remote_envs.get(id)) {
            Decision::Apply(r) => {
                let applied = if r.deleted {
                    yasecret_core::environment::delete(db, id).map(|_| true).map_err(SyncError::from)
                } else {
                    upsert_env(db, project_id, r)
                };
                if matches!(applied, Ok(true)) {
                    db.conn().execute("DELETE FROM tombstone WHERE id = ?1 AND ?2 = 0", rusqlite::params![id, r.deleted])?;
                    plan.changed_local = true;
                }
            }
            Decision::Push(l) if i_can_write => plan.pushes.push((keys::env(id), serde_json::to_vec(l)?)),
            _ => {}
        }
    }

    // Variables
    let remote_secrets: HashMap<String, WSecret> = latest_per_prefix(entries, "v2/secret/", &writer_authors);
    let mut local_secrets: HashMap<String, WSecret> = HashMap::new();
    for env in yasecret_core::environment::list(db, project_id)? {
        for l in yasecret_core::secret::list(db, &env.id)? {
            local_secrets.insert(l.id.clone(), WSecret {
                id: l.id,
                env_id: l.env_id,
                key: l.key,
                enc: l.encrypted_value,
                nonce: l.nonce,
                is_secret: l.is_secret,
                created_at: l.created_at,
                updated_at: l.updated_at,
                created_by: l.created_by,
                expires_at: l.expires_at,
                deleted: false,
                value_type: l.value_type,
            });
        }
    }
    for (id, at) in &secret_tombs {
        local_secrets.entry(id.clone()).or_insert_with(|| WSecret {
            id: id.clone(),
            env_id: String::new(),
            key: String::new(),
            enc: vec![],
            nonce: vec![],
            is_secret: true,
            created_at: 0,
            updated_at: *at,
            created_by: inner.my_peer.clone(),
            expires_at: None,
            deleted: true,
            value_type: None,
        });
    }
    let ids: HashSet<&String> = remote_secrets.keys().chain(local_secrets.keys()).collect();
    for id in ids {
        let local = local_secrets.get(id);
        match decide(local, remote_secrets.get(id)) {
            Decision::Apply(r) => {
                let local_live = local.filter(|l| !l.deleted);
                let applied = if r.deleted {
                    match local_live {
                        Some(_) => yasecret_core::secret::delete(db, id, SYNC_ACTOR).map(|_| true).map_err(SyncError::from),
                        None => Ok(false),
                    }
                } else {
                    apply_remote_secret(db, project_id, r, local_live)
                };
                // One bad item must not stop the rest of the project from syncing.
                if matches!(applied, Ok(true)) {
                    if !r.deleted {
                        db.conn().execute("DELETE FROM tombstone WHERE id = ?1", [id])?;
                    }
                    plan.changed_local = true;
                }
            }
            Decision::Push(l) if i_can_write => plan.pushes.push((keys::secret(id), serde_json::to_vec(l)?)),
            _ => {}
        }
    }
    Ok(plan)
}

enum Decision<'a, T> {
    Apply(&'a T),
    Push(&'a T),
    Nothing,
}

/// Last-write-wins on `updated_at`; equal timestamps are settled by content hash so every
/// device picks the same winner.
fn decide<'a, T: Serialize + PartialEq + HasUpdatedAt>(local: Option<&'a T>, remote: Option<&'a T>) -> Decision<'a, T> {
    match (local, remote) {
        (None, None) => Decision::Nothing,
        (None, Some(r)) if r.is_deleted() => Decision::Nothing,
        (None, Some(r)) => Decision::Apply(r),
        (Some(l), None) => Decision::Push(l),
        (Some(l), Some(r)) if l == r => Decision::Nothing,
        (Some(l), Some(r)) if l.is_deleted() && r.is_deleted() => Decision::Nothing,
        (Some(l), Some(r)) => {
            if order_key(r) > order_key(l) { Decision::Apply(r) } else { Decision::Push(l) }
        }
    }
}

trait HasUpdatedAt {
    fn updated_at(&self) -> i64;
    fn is_deleted(&self) -> bool;
}

impl HasUpdatedAt for WEnv {
    fn updated_at(&self) -> i64 { self.updated_at }
    fn is_deleted(&self) -> bool { self.deleted }
}

impl HasUpdatedAt for WSecret {
    fn updated_at(&self) -> i64 { self.updated_at }
    fn is_deleted(&self) -> bool { self.deleted }
}

fn order_key<T: Serialize + HasUpdatedAt>(x: &T) -> (i64, [u8; 32]) {
    let bytes = serde_json::to_vec(x).unwrap_or_default();
    (x.updated_at(), Sha256::digest(&bytes).into())
}

/// Returns false when the row belongs to another project and was left alone.
fn upsert_env(db: &Db, project_id: &str, r: &WEnv) -> Result<bool> {
    let n = db.conn().execute(
        "INSERT INTO environment (id, project_id, name, created_at, updated_at, inherits_from) VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, created_at = excluded.created_at, updated_at = excluded.updated_at,
           inherits_from = excluded.inherits_from
         WHERE environment.project_id = excluded.project_id",
        rusqlite::params![&r.id, project_id, &r.name, r.created_at, r.updated_at, &r.inherits_from],
    )?;
    Ok(n > 0)
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

/// Writes a remote variable locally. Returns false if it was skipped: its environment
/// hasn't arrived yet, or belongs to another project, or a newer local variable owns the name.
fn apply_remote_secret(db: &Db, project_id: &str, r: &WSecret, local: Option<&WSecret>) -> Result<bool> {
    let env_ok: i64 = db.conn().query_row(
        "SELECT count(*) FROM environment WHERE id = ?1 AND project_id = ?2",
        rusqlite::params![&r.env_id, project_id],
        |x| x.get(0),
    )?;
    if env_ok == 0 {
        return Ok(false);
    }
    // Same name held by a different variable (created or renamed independently): newer wins.
    let clash: Option<(String, i64)> = db
        .conn()
        .query_row(
            "SELECT id, updated_at FROM secret WHERE env_id = ?1 AND key = ?2 AND id != ?3",
            rusqlite::params![&r.env_id, &r.key, &r.id],
            |x| Ok((x.get(0)?, x.get(1)?)),
        )
        .ok();
    if let Some((other, other_ts)) = clash {
        if other_ts > r.updated_at {
            return Ok(false);
        }
        yasecret_core::secret::delete(db, &other, SYNC_ACTOR)?;
    }
    if let Some(l) = local {
        if l.enc != r.enc {
            db.conn().execute(
                "INSERT INTO secret_version (id,secret_id,encrypted_value,nonce,changed_by,changed_at,note) VALUES (?1,?2,?3,?4,?5,?6,'sync')",
                rusqlite::params![new_id(), &l.id, &l.enc, &l.nonce, SYNC_ACTOR, l.updated_at],
            )?;
        }
        db.conn().execute(
            "UPDATE secret SET env_id=?1, key=?2, encrypted_value=?3, nonce=?4, is_secret=?5, created_at=?6, updated_at=?7,
                               created_by=?8, expires_at=?9, value_type=?11 WHERE id=?10",
            rusqlite::params![&r.env_id, &r.key, &r.enc, &r.nonce, r.is_secret, r.created_at, r.updated_at, &r.created_by, r.expires_at, &r.id, &r.value_type],
        )?;
    } else {
        let inserted = db.conn().execute(
            "INSERT OR IGNORE INTO secret (id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at,is_secret,value_type) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![&r.id, &r.env_id, &r.key, &r.enc, &r.nonce, r.created_at, r.updated_at, &r.created_by, r.expires_at, r.is_secret, &r.value_type],
        )?;
        if inserted == 0 {
            // The id already exists elsewhere (another project); never touch it from here.
            return Ok(false);
        }
    }
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
    signed_by: Option<String>,
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
        // publish failed earlier is re-issued instead of leaving the member stuck. An expired
        // invite still admits someone who joined before it expired, within the grace period.
        let in_time = "(expires_at >= ?3 OR (expires_at >= ?5 AND expires_at + ?6 >= ?3))";
        let pending: Option<(String, String)> = match &m.invite_id {
            Some(invite_id) => db
                .conn()
                .query_row(
                    &format!(
                        "SELECT id, level FROM sync_invite WHERE id = ?1 AND project_id = ?2 AND kind = 'link'
                           AND (redeemed_by IS NULL OR redeemed_by = ?4) AND {in_time}"
                    ),
                    rusqlite::params![invite_id, project_id, now(), &m.peer_id, m.joined_at, ADMIT_GRACE_SECS],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok(),
            None => db
                .conn()
                .query_row(
                    &format!(
                        "SELECT id, level FROM sync_invite WHERE project_id = ?1 AND kind = 'device' AND peer_id = ?2
                           AND (redeemed_by IS NULL OR redeemed_by = ?2) AND {in_time}"
                    ),
                    rusqlite::params![project_id, &m.peer_id, now(), &m.peer_id, m.joined_at, ADMIT_GRACE_SECS],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .ok(),
        };
        let Some((invite_row, level)) = pending else { continue };
        let g = sign_grant(signer, project_id, &m.peer_id, &e.author, &level, signed_by.clone(), None);
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
        let m = WMember { peer_id: peer.into(), name: "x".into(), joined_at: 1, invite_id: invite.map(String::from), proof, sign_pub: None };
        RawEntry { key: keys::member(peer), author: author.into(), timestamp: 1, content: serde_json::to_vec(&m).unwrap(), legacy: false }
    }

    #[test]
    fn ticket_holder_without_project_key_cannot_claim_a_link_invite() {
        let (_d, db, me, pid, key) = owner_db();
        let forged = member_entry("attacker", "attacker-author", Some("inv1"), vec![0u8; 32]);
        let pushes = admit_members(&db, &pid, &[forged], &HashMap::new(), &key, &me, None).unwrap();
        assert!(pushes.is_empty(), "no grant without a valid proof");
    }

    #[test]
    fn ticket_holder_cannot_hijack_a_device_bound_invite() {
        let (_d, db, me, pid, key) = owner_db();
        let wrong_key = [9u8; 32];
        let forged = member_entry("victimpeer", "attacker-author", None, join_proof(&wrong_key, &pid, "victimpeer", "attacker-author"));
        assert!(admit_members(&db, &pid, &[forged], &HashMap::new(), &key, &me, None).unwrap().is_empty());
    }

    #[test]
    fn joiner_with_valid_proof_is_admitted_once_and_regranted_if_needed() {
        let (_d, db, me, pid, key) = owner_db();
        let good = member_entry("friend", "friend-author", Some("inv1"), join_proof(&key, &pid, "friend", "friend-author"));
        let pushes = admit_members(&db, &pid, &[good], &HashMap::new(), &key, &me, None).unwrap();
        assert_eq!(pushes.len(), 1);
        let g: WGrant = serde_json::from_slice(&pushes[0].1).unwrap();
        assert_eq!((g.peer_id.as_str(), g.author.as_str(), g.level.as_str()), ("friend", "friend-author", "editor"));
        // Grant never landed in the doc: the same member is granted again.
        let again = member_entry("friend", "friend-author", Some("inv1"), join_proof(&key, &pid, "friend", "friend-author"));
        assert_eq!(admit_members(&db, &pid, &[again], &HashMap::new(), &key, &me, None).unwrap().len(), 1);
        // A different peer can't reuse the redeemed invite.
        let other = member_entry("other", "other-author", Some("inv1"), join_proof(&key, &pid, "other", "other-author"));
        assert!(admit_members(&db, &pid, &[other], &HashMap::new(), &key, &me, None).unwrap().is_empty());
    }

    fn wsecret(id: &str, env: &str, key: &str, ts: i64, val: u8) -> WSecret {
        WSecret {
            id: id.into(), env_id: env.into(), key: key.into(), enc: vec![val], nonce: vec![0; 12],
            is_secret: true, created_at: 1, updated_at: ts, created_by: "x".into(), expires_at: None, deleted: false, value_type: None,
        }
    }

    #[test]
    fn same_second_conflicts_resolve_identically_on_both_devices() {
        let a = wsecret("s", "e", "K", 100, 1);
        let b = wsecret("s", "e", "K", 100, 2);
        let on_a = match decide(Some(&a), Some(&b)) { Decision::Apply(w) | Decision::Push(w) => w.enc.clone(), Decision::Nothing => vec![] };
        let on_b = match decide(Some(&b), Some(&a)) { Decision::Apply(w) | Decision::Push(w) => w.enc.clone(), Decision::Nothing => vec![] };
        assert_eq!(on_a, on_b, "both devices must converge on the same value");
        assert!(matches!(decide(Some(&a), Some(&a)), Decision::Nothing));
        let newer = wsecret("s", "e", "K", 101, 0);
        assert!(matches!(decide(Some(&a), Some(&newer)), Decision::Apply(_)));
        assert!(matches!(decide(Some(&newer), Some(&a)), Decision::Push(_)));
    }

    fn two_projects() -> (tempfile::TempDir, Db, String, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.sqlite"), "pw").unwrap();
        let p1 = yasecret_core::project::create(&db, "p1", None, "o").unwrap();
        let p2 = yasecret_core::project::create(&db, "p2", None, "o").unwrap();
        let e1 = yasecret_core::environment::create(&db, &p1.id, "dev").unwrap();
        let e2 = yasecret_core::environment::create(&db, &p2.id, "dev").unwrap();
        (dir, db, p1.id, e1.id, e2.id)
    }

    #[test]
    fn remote_data_cannot_reach_another_projects_environment() {
        let (_d, db, p1, _e1, e2) = two_projects();
        assert!(!apply_remote_secret(&db, &p1, &wsecret("s1", &e2, "INJECTED", 5, 1), None).unwrap());
        assert!(yasecret_core::secret::list(&db, &e2).unwrap().is_empty());
        let foreign_env = WEnv { id: e2.clone(), name: "pwned".into(), created_at: 0, updated_at: i64::MAX, deleted: false, inherits_from: None };
        assert!(!upsert_env(&db, &p1, &foreign_env).unwrap());
        assert_eq!(yasecret_core::environment::get(&db, &e2).unwrap().name, "dev");
    }

    #[test]
    fn remote_rename_onto_an_existing_name_resolves_instead_of_failing() {
        let (_d, db, p1, e1, _e2) = two_projects();
        let k = [1u8; 32];
        let older = yasecret_core::secret::create(&db, &e1, "TAKEN", b"old", &k, "o", None).unwrap();
        let renamed = wsecret("other-id", &e1, "TAKEN", older.updated_at + 10, 3);
        assert!(apply_remote_secret(&db, &p1, &renamed, None).unwrap());
        let list = yasecret_core::secret::list(&db, &e1).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "other-id");

        let stale = wsecret("stale-id", &e1, "TAKEN", 0, 4);
        assert!(!apply_remote_secret(&db, &p1, &stale, None).unwrap(), "older remote loses, without an error");
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

    #[test]
    fn relay_link_roundtrips() {
        let ns = iroh_docs::NamespaceSecret::from_bytes(&[3u8; 32]);
        let node = iroh::SecretKey::from_bytes(&[7u8; 32]).public();
        let ticket = iroh_docs::DocTicket::new(iroh_docs::Capability::Read(ns.id()), vec![iroh::EndpointAddr::new(node)]);
        let link = RelayLink { project_name: "Shop / prod".into(), ticket: ticket.to_string() };
        assert!(matches!(
            RelayLink::parse("yasecret://relay?v=1&n=x&t=docnotaticket"),
            Err(SyncError::InvalidLink(_))
        ));
        assert_eq!(RelayLink::parse(&link.to_url()).unwrap(), link);
        assert!(matches!(RelayLink::parse("yasecret://join?v=2"), Err(SyncError::InvalidLink(_))));
    }

    #[test]
    fn only_owner_signed_relays_are_dialed_and_removal_wins() {
        let (_a, _, owner, _, _) = owner_db();
        let (_b, _, intruder, _, _) = owner_db();
        let owner_pub = sign_pub(&owner);
        let entry = |signer: &Identity, code: &str, removed: bool, at: i64| {
            let msg = relay_msg("p1", code, "box", at, removed, None);
            let r = WRelay { code: code.into(), name: "box".into(), added_at: at, removed, signature: crypto::sign(msg.as_bytes(), &signer.signing_key()), signed_by: None };
            RawEntry { key: keys::relay(code), author: "a".into(), timestamp: at as u64, content: serde_json::to_vec(&r).unwrap(), legacy: false }
        };
        let good = "aa".repeat(32);
        let forged = "bb".repeat(32);
        let entries = vec![entry(&owner, &good, false, 10), entry(&intruder, &forged, false, 10)];
        let relays = valid_relays("p1", &entries, &owner_pub);
        assert_eq!(relays.iter().map(|r| r.code.as_str()).collect::<Vec<_>>(), vec![good.as_str()]);
        assert!(valid_relays("other-project", &entries, &owner_pub).is_empty(), "signature is bound to the project");

        let removed = vec![entry(&owner, &good, false, 10), entry(&owner, &good, true, 11)];
        assert!(valid_relays("p1", &removed, &owner_pub).is_empty());
    }

    fn expired_link_invite(db: &Db, pid: &str, expired_secs_ago: i64) {
        db.conn().execute(
            "INSERT INTO sync_invite (id,project_id,kind,peer_id,level,created_at,expires_at) VALUES ('old',?1,'link',NULL,'editor',0,?2)",
            rusqlite::params![pid, now() - expired_secs_ago],
        ).unwrap();
    }

    fn joined_member(pid: &str, key: &[u8; 32], joined_at: i64) -> RawEntry {
        let proof = join_proof(key, pid, "latecomer", "late-author");
        let m = WMember { peer_id: "latecomer".into(), name: "x".into(), joined_at, invite_id: Some("old".into()), proof, sign_pub: None };
        RawEntry { key: keys::member("latecomer"), author: "late-author".into(), timestamp: 1, content: serde_json::to_vec(&m).unwrap(), legacy: false }
    }

    #[test]
    fn member_who_joined_in_time_is_admitted_after_the_invite_expires() {
        // Joined through an always-on peer while the owner was offline past the invite's expiry.
        let (_d, db, me, pid, key) = owner_db();
        expired_link_invite(&db, &pid, 3600);
        let m = joined_member(&pid, &key, now() - 2 * 3600);
        assert_eq!(admit_members(&db, &pid, &[m], &HashMap::new(), &key, &me, None).unwrap().len(), 1);
    }

    #[test]
    fn expired_invites_still_reject_late_joins_and_stale_ones() {
        let (_d, db, me, pid, key) = owner_db();
        expired_link_invite(&db, &pid, 3600);
        let late = joined_member(&pid, &key, now());
        assert!(admit_members(&db, &pid, &[late], &HashMap::new(), &key, &me, None).unwrap().is_empty());

        let (_d2, db2, me2, pid2, key2) = owner_db();
        expired_link_invite(&db2, &pid2, ADMIT_GRACE_SECS + 3600);
        let in_time = joined_member(&pid2, &key2, now() - ADMIT_GRACE_SECS - 2 * 3600);
        assert!(admit_members(&db2, &pid2, &[in_time], &HashMap::new(), &key2, &me2, None).unwrap().is_empty());
    }

    #[test]
    fn sealed_records_open_with_the_right_key_only_and_legacy_plaintext_is_flagged() {
        let (k1, k2) = ([1u8; 32], [2u8; 32]);
        let env = br#"{"id":"e1","name":"prod","created_at":1,"updated_at":1,"deleted":false}"#;
        let raw = |key: &str, content: Vec<u8>| RawEntry { key: key.into(), author: "a".into(), timestamp: 1, content, legacy: false };
        let entries = vec![
            raw(&keys::env("e1"), seal(&k1, env).unwrap()),
            raw(&keys::env("e2"), seal(&k2, env).unwrap()),
            raw(&keys::env("e3"), env.to_vec()),
            raw(&keys::grant("p"), b"{}".to_vec()),
        ];
        assert!(!String::from_utf8_lossy(&entries[0].content).contains("prod"), "sealed content hides names");
        let opened = open_entries(entries, &k1);
        let keys_seen: Vec<&str> = opened.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys_seen, vec!["v2/env/e1", "v2/env/e3", "v2/grant/p"], "a record sealed with another key counts as missing");
        assert_eq!(opened[0].content, env.to_vec());
        assert!(!opened[0].legacy && opened[1].legacy && !opened[2].legacy);
    }

    fn grant_entry(signer: &Identity, root: &Identity, peer: &str, level: &str, at: i64, sign_pub_for: Option<&Identity>) -> RawEntry {
        let signed_by = (signer.id != root.id).then(|| hex::encode(super::sign_pub(signer)));
        let mut g = sign_grant(signer, "p1", peer, &format!("{peer}-author"), level, signed_by, sign_pub_for.map(|i| hex::encode(super::sign_pub(i))));
        g.granted_at = at;
        let msg = grant_msg("p1", &g);
        g.signature = crypto::sign(msg.as_bytes(), &signer.signing_key());
        RawEntry { key: keys::grant(peer), author: "x".into(), timestamp: at as u64, content: serde_json::to_vec(&g).unwrap(), legacy: false }
    }

    #[test]
    fn co_owners_manage_members_but_not_owners() {
        let (_a, _, root, _, _) = owner_db();
        let (_b, _, co, _, _) = owner_db();
        let root_pub = super::sign_pub(&root);
        let entries = vec![
            grant_entry(&root, &root, "root-peer", LEVEL_OWNER, 1, None),
            grant_entry(&root, &root, "co-peer", LEVEL_OWNER, 2, Some(&co)),
            grant_entry(&co, &root, "m1", LEVEL_EDITOR, 3, None),
            grant_entry(&co, &root, "m2", LEVEL_OWNER, 3, Some(&co)),
            grant_entry(&co, &root, "root-peer", LEVEL_REMOVED, 4, None),
        ];
        let (grants, co_owners) = grants_and_co_owners("p1", &entries, &root_pub);
        assert_eq!(co_owners.get("co-peer"), Some(&super::sign_pub(&co)));
        assert_eq!(grants.get("m1").map(|g| g.level.as_str()), Some(LEVEL_EDITOR), "co-owner admits members");
        assert!(!grants.contains_key("m2"), "only the root owner appoints owners");
        assert_eq!(grants.get("root-peer").map(|g| g.level.as_str()), Some(LEVEL_OWNER), "nobody but the root changes the root");
    }

    #[test]
    fn grants_signed_by_a_demoted_co_owner_stop_counting() {
        let (_a, _, root, _, _) = owner_db();
        let (_b, _, co, _, _) = owner_db();
        let entries = vec![
            grant_entry(&root, &root, "co-peer", LEVEL_OWNER, 2, Some(&co)),
            grant_entry(&co, &root, "m1", LEVEL_EDITOR, 3, None),
            grant_entry(&root, &root, "co-peer", LEVEL_EDITOR, 4, None),
            grant_entry(&co, &root, "m3", LEVEL_EDITOR, 5, None),
        ];
        let (grants, co_owners) = grants_and_co_owners("p1", &entries, &super::sign_pub(&root));
        assert!(co_owners.is_empty());
        assert!(!grants.contains_key("m1") && !grants.contains_key("m3"));
        assert_eq!(grants.get("co-peer").map(|g| g.level.as_str()), Some(LEVEL_EDITOR));
    }

    #[test]
    fn the_newest_key_rotation_wins_whoever_wrote_it() {
        let (_a, _, me, _, _) = owner_db();
        let my_pub = me.x25519_public().to_bytes();
        let handoff = |key: [u8; 32], at: i64, author: &str| RawEntry {
            key: keys::peer_key("me"),
            author: author.into(),
            timestamp: 1,
            content: handoff_blob(&key, at, &my_pub).unwrap(),
            legacy: false,
        };
        let legacy = RawEntry {
            key: keys::peer_key("me"),
            author: "a0".into(),
            timestamp: 9,
            content: crypto::encrypt_for_peer(&[9u8; 32], &my_pub).unwrap(),
            legacy: false,
        };
        let entries = vec![handoff([1u8; 32], 200, "a1"), legacy, handoff([2u8; 32], 100, "a2")];
        let authors: HashSet<String> = ["a0", "a1", "a2"].iter().map(|s| s.to_string()).collect();
        assert_eq!(chosen_handoff(&entries, "me", &authors, &me.x25519_secret()), Some([1u8; 32]));
        let only_a0: HashSet<String> = ["a0".to_string()].into_iter().collect();
        assert_eq!(chosen_handoff(&entries, "me", &only_a0, &me.x25519_secret()), Some([9u8; 32]), "older handoffs still read");
    }
}
