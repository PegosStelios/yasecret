uniffi::setup_scaffolding!();

use std::{path::Path, sync::Arc};
use yasecret_core::{db::Db, env_file, models::now};
use zeroize::Zeroizing;

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("Wrong password")]
    WrongPassword,
    #[error("Not found: {msg}")]
    NotFound { msg: String },
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Crypto error")]
    Crypto,
    #[error("IO: {msg}")]
    Io { msg: String },
    #[error("Database: {msg}")]
    Db { msg: String },
    #[error("Parse: {msg}")]
    Parse { msg: String },
    #[error("{msg}")]
    Sync { msg: String },
}

impl From<yasecret_sync::SyncError> for FfiError {
    fn from(e: yasecret_sync::SyncError) -> Self {
        match e {
            yasecret_sync::SyncError::Core(c) => FfiError::from(c),
            other => FfiError::Sync { msg: other.to_string() },
        }
    }
}

impl From<yasecret_core::error::YasecretError> for FfiError {
    fn from(e: yasecret_core::error::YasecretError) -> Self {
        use yasecret_core::error::YasecretError as E;
        match e {
            E::WrongPassword       => FfiError::WrongPassword,
            E::PermissionDenied    => FfiError::PermissionDenied,
            E::Crypto              => FfiError::Crypto,
            E::NotFound(m)         => FfiError::NotFound { msg: m },
            E::Db(e)               => FfiError::Db { msg: e.to_string() },
            E::Io(e)               => FfiError::Io { msg: e.to_string() },
            E::EnvParse(m)         => FfiError::Parse { msg: m },
            E::Serde(e)            => FfiError::Db { msg: e.to_string() },
        }
    }
}

// ── Records ───────────────────────────────────────────────────────────────────

#[derive(Clone, uniffi::Record)]
pub struct FfiProject {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Clone, uniffi::Record)]
pub struct FfiEnvironment {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub secret_count: u32,
}

#[derive(Clone, uniffi::Record)]
pub struct FfiSecret {
    pub id: String,
    pub env_id: String,
    pub key: String,
    pub expires_at: Option<i64>,
    pub is_secret: bool,
    pub updated_at: i64,
}

impl From<yasecret_core::models::Secret> for FfiSecret {
    fn from(s: yasecret_core::models::Secret) -> Self {
        FfiSecret {
            id: s.id,
            env_id: s.env_id,
            key: s.key,
            expires_at: s.expires_at,
            is_secret: s.is_secret,
            updated_at: s.updated_at,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct FfiImportRow {
    pub key: String,
    pub value: String,
    pub exists: bool,
    pub suggested_secret: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct FfiImportItem {
    pub key: String,
    pub value: String,
    pub is_secret: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct FfiImportSummary {
    pub added: u32,
    pub updated: u32,
    pub skipped: u32,
}

// ── Session ───────────────────────────────────────────────────────────────────

#[derive(Clone, uniffi::Record)]
pub struct FfiMember {
    pub peer_id: String,
    pub name: String,
    pub level: String,
    pub joined_at: i64,
    pub is_me: bool,
}

#[derive(Clone, uniffi::Record)]
pub struct FfiSyncStatus {
    pub shared: bool,
    pub is_owner: bool,
    pub my_level: String,
    pub peers_online: u32,
    pub last_synced_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(uniffi::Object)]
pub struct YasecretSession {
    db_path: String,
    password: String,
    db_key: Zeroizing<[u8; 32]>,
    sync: std::sync::Mutex<Option<Arc<yasecret_sync::live::SyncService>>>,
}

#[uniffi::export]
impl YasecretSession {
    #[uniffi::constructor]
    pub fn new(db_path: String, password: String) -> Result<Arc<Self>, FfiError> {
        let path = Path::new(&db_path);

        let salt_path = {
            let mut p = path.to_path_buf();
            p.set_extension("salt");
            p
        };
        let salt: [u8; 16] = if salt_path.exists() {
            std::fs::read(&salt_path)
                .map_err(|e| FfiError::Io { msg: e.to_string() })?
                .try_into()
                .map_err(|_| FfiError::Io { msg: "salt file corrupt (expected 16 bytes)".into() })?
        } else {
            let s = yasecret_core::crypto::generate_salt();
            std::fs::write(&salt_path, s)
                .map_err(|e| FfiError::Io { msg: e.to_string() })?;
            s
        };

        let db_key = yasecret_core::crypto::derive_db_key(&password, &salt);

        // Verify password — Db::open returns WrongPassword on bad SQLCipher key
        Db::open(path, &password).map_err(FfiError::from)?;

        Ok(Arc::new(Self { db_path, password, db_key, sync: std::sync::Mutex::new(None) }))
    }

    // ── Projects ──────────────────────────────────────────────────────────────

    pub fn list_projects(&self) -> Result<Vec<FfiProject>, FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::project::list(&db)?
            .into_iter()
            .map(|p| FfiProject { id: p.id, name: p.name, description: p.description })
            .collect())
    }

    pub fn create_project(&self, name: String, description: Option<String>) -> Result<FfiProject, FfiError> {
        let db = self.open()?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let p = yasecret_core::project::create(&db, &name, description.as_deref(), &id)?;
        yasecret_core::project_key::create(&db, &p.id, &self.db_key)?;
        Ok(FfiProject { id: p.id, name: p.name, description: p.description })
    }

    pub fn rename_project(&self, project_id: String, new_name: String) -> Result<(), FfiError> {
        let db = self.open()?;
        yasecret_core::project::rename(&db, &project_id, &new_name)?;
        self.touched(&project_id);
        Ok(())
    }

    pub fn delete_project(&self, project_id: String) -> Result<(), FfiError> {
        if let Some(svc) = self.sync_service() {
            svc.stop_sharing(&project_id)?;
        }
        let db = self.open()?;
        Ok(yasecret_core::project::delete(&db, &project_id)?)
    }

    // ── Environments ──────────────────────────────────────────────────────────

    pub fn list_environments(&self, project_id: String) -> Result<Vec<FfiEnvironment>, FfiError> {
        let db = self.open()?;
        yasecret_core::environment::list(&db, &project_id)?
            .into_iter()
            .map(|e| env_record(&db, e))
            .collect()
    }

    pub fn create_environment(&self, project_id: String, name: String) -> Result<FfiEnvironment, FfiError> {
        let db = self.open()?;
        let e = yasecret_core::environment::create(&db, &project_id, &name)?;
        self.touched(&project_id);
        env_record(&db, e)
    }

    pub fn clone_environment(&self, env_id: String, new_name: String) -> Result<FfiEnvironment, FfiError> {
        let db = self.open()?;
        db.conn().execute_batch("BEGIN").map_err(db_err)?;
        let result = yasecret_core::environment::clone(&db, &env_id, &new_name)
            .map_err(FfiError::from)
            .and_then(|e| env_record(&db, e));
        let result = finish_tx(&db, result)?;
        self.touched(&result.project_id);
        Ok(result)
    }

    pub fn rename_environment(&self, env_id: String, new_name: String) -> Result<(), FfiError> {
        let db = self.open()?;
        yasecret_core::environment::rename(&db, &env_id, &new_name)?;
        self.touched_env(&db, &env_id);
        Ok(())
    }

    pub fn delete_environment(&self, env_id: String) -> Result<(), FfiError> {
        let db = self.open()?;
        let project_id = yasecret_core::environment::get(&db, &env_id)?.project_id;
        yasecret_core::environment::delete(&db, &env_id)?;
        self.touched(&project_id);
        Ok(())
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    pub fn list_secrets(&self, env_id: String) -> Result<Vec<FfiSecret>, FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::secret::list(&db, &env_id)?
            .into_iter()
            .map(FfiSecret::from)
            .collect())
    }

    pub fn create_secret(
        &self,
        project_id: String,
        env_id: String,
        key: String,
        value: String,
        expires_at: Option<i64>,
        is_secret: bool,
    ) -> Result<FfiSecret, FfiError> {
        check_key(&key)?;
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        db.conn().execute_batch("BEGIN").map_err(db_err)?;
        let result = (|| {
            let s = yasecret_core::secret::create(
                &db, &env_id, &key, value.as_bytes(), &proj_key, &id, expires_at,
            ).map_err(duplicate_aware)?;
            if !is_secret {
                yasecret_core::secret::set_kind(&db, &s.id, false, &id)?;
            }
            Ok(FfiSecret { is_secret, ..FfiSecret::from(s) })
        })();
        let r = finish_tx(&db, result)?;
        self.touched(&project_id);
        Ok(r)
    }

    /// Changes any combination of key, value and kind in one transaction.
    pub fn edit_secret(
        &self,
        project_id: String,
        secret_id: String,
        new_key: Option<String>,
        new_value: Option<String>,
        is_secret: Option<bool>,
    ) -> Result<(), FfiError> {
        if let Some(k) = &new_key {
            check_key(k)?;
        }
        let db = self.open()?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let proj_key = match new_value {
            Some(_) => Some(yasecret_core::project_key::load(&db, &project_id, &self.db_key)?),
            None => None,
        };
        db.conn().execute_batch("BEGIN").map_err(db_err)?;
        let result = (|| {
            if let Some(k) = &new_key {
                yasecret_core::secret::rename_key(&db, &secret_id, k, &id).map_err(duplicate_aware)?;
            }
            if let (Some(v), Some(pk)) = (&new_value, &proj_key) {
                yasecret_core::secret::update(&db, &secret_id, v.as_bytes(), pk, &id, None)?;
            }
            if let Some(flag) = is_secret {
                yasecret_core::secret::set_kind(&db, &secret_id, flag, &id)?;
            }
            Ok(())
        })();
        let r = finish_tx(&db, result)?;
        self.touched(&project_id);
        Ok(r)
    }

    pub fn update_secret(
        &self,
        project_id: String,
        secret_id: String,
        new_value: String,
    ) -> Result<(), FfiError> {
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        yasecret_core::secret::update(&db, &secret_id, new_value.as_bytes(), &proj_key, &id, None)?;
        self.touched(&project_id);
        Ok(())
    }

    pub fn delete_secret(&self, secret_id: String) -> Result<(), FfiError> {
        let db = self.open()?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let project_id: Option<String> = db.conn().query_row(
            "SELECT e.project_id FROM secret s JOIN environment e ON e.id = s.env_id WHERE s.id = ?1",
            [&secret_id],
            |r| r.get(0),
        ).ok();
        yasecret_core::secret::delete(&db, &secret_id, &id)?;
        if let Some(pid) = project_id {
            self.touched(&pid);
        }
        Ok(())
    }

    pub fn get_secret_plaintext(
        &self,
        project_id: String,
        secret_id: String,
    ) -> Result<String, FfiError> {
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let bytes = yasecret_core::secret::get_plaintext(&db, &secret_id, &proj_key)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|e| FfiError::Parse { msg: e.to_string() })
    }

    // ── Import / Export ───────────────────────────────────────────────────────

    pub fn import_env(
        &self,
        project_id: String,
        env_id: String,
        content: String,
    ) -> Result<u32, FfiError> {
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let pairs = env_file::parse_any(&content)?;
        db.conn().execute_batch("BEGIN")
            .map_err(|e| FfiError::Db { msg: e.to_string() })?;
        let mut count = 0u32;
        let result: Result<u32, FfiError> = (|| {
            for (key, value) in &pairs {
                yasecret_core::secret::create(
                    &db, &env_id, key, value.as_bytes(), &proj_key, &id, None,
                )?;
                count += 1;
            }
            Ok(count)
        })();
        match &result {
            Ok(_) => db.conn().execute_batch("COMMIT")
                .map_err(|e| FfiError::Db { msg: e.to_string() })?,
            Err(_) => { db.conn().execute_batch("ROLLBACK").ok(); }
        }
        if result.is_ok() {
            self.touched(&project_id);
        }
        result
    }

    pub fn preview_import(&self, env_id: String, content: String) -> Result<Vec<FfiImportRow>, FfiError> {
        let db = self.open()?;
        let existing: std::collections::HashSet<String> = yasecret_core::secret::list(&db, &env_id)?
            .into_iter()
            .map(|s| s.key)
            .collect();
        Ok(env_file::parse_any(&content)?
            .into_iter()
            .map(|(key, value)| FfiImportRow {
                exists: existing.contains(&key),
                suggested_secret: env_file::looks_secret(&key),
                key,
                value,
            })
            .collect())
    }

    pub fn apply_import(
        &self,
        project_id: String,
        env_id: String,
        items: Vec<FfiImportItem>,
        overwrite: bool,
    ) -> Result<FfiImportSummary, FfiError> {
        for item in &items {
            check_key(&item.key)?;
        }
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let existing: std::collections::HashMap<String, String> = yasecret_core::secret::list(&db, &env_id)?
            .into_iter()
            .map(|s| (s.key, s.id))
            .collect();
        db.conn().execute_batch("BEGIN").map_err(db_err)?;
        let result = (|| {
            let mut summary = FfiImportSummary { added: 0, updated: 0, skipped: 0 };
            for item in &items {
                match existing.get(&item.key) {
                    Some(_) if !overwrite => summary.skipped += 1,
                    Some(sid) => {
                        yasecret_core::secret::update(&db, sid, item.value.as_bytes(), &proj_key, &id, Some("import"))?;
                        yasecret_core::secret::set_kind(&db, sid, item.is_secret, &id)?;
                        summary.updated += 1;
                    }
                    None => {
                        let s = yasecret_core::secret::create(
                            &db, &env_id, &item.key, item.value.as_bytes(), &proj_key, &id, None,
                        ).map_err(duplicate_aware)?;
                        if !item.is_secret {
                            yasecret_core::secret::set_kind(&db, &s.id, false, &id)?;
                        }
                        summary.added += 1;
                    }
                }
            }
            Ok(summary)
        })();
        let r = finish_tx(&db, result)?;
        self.touched(&project_id);
        Ok(r)
    }

    pub fn export_env(
        &self,
        project_id: String,
        env_id: String,
    ) -> Result<String, FfiError> {
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let secrets = yasecret_core::secret::list(&db, &env_id)?;
        let mut pairs: Vec<(String, String)> = vec![];
        for s in &secrets {
            let val = yasecret_core::secret::get_plaintext(&db, &s.id, &proj_key)?;
            pairs.push((s.key.clone(), String::from_utf8_lossy(&val).into_owned()));
        }
        Ok(env_file::serialize(&pairs))
    }

    // ── Sharing / sync ────────────────────────────────────────────────────────

    /// Starts the background sync node. Safe to call more than once.
    pub fn start_sync(&self, device_name: String) -> Result<(), FfiError> {
        let mut guard = self.sync.lock().unwrap();
        if guard.is_some() {
            return Ok(());
        }
        let data_dir = Path::new(&self.db_path)
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("sync");
        let svc = yasecret_sync::live::SyncService::start(yasecret_sync::live::SyncConfig {
            db_path: self.db_path.clone().into(),
            db_password: self.password.clone(),
            db_key: *self.db_key,
            data_dir,
            device_name,
        })?;
        *guard = Some(Arc::new(svc));
        Ok(())
    }

    pub fn stop_sync(&self) {
        let svc = self.sync.lock().unwrap().take();
        if let Some(svc) = svc {
            svc.close();
        }
    }

    /// This device's code for device-bound invites.
    pub fn device_code(&self) -> Result<String, FfiError> {
        let db = self.open()?;
        let identity = yasecret_core::identity::load_or_create(&db, "local")?;
        Ok(yasecret_sync::live::peer_id(&identity))
    }

    /// `level` is "editor" or "viewer". Pass `device_code` for a device-bound invite.
    pub fn create_invite(&self, project_id: String, device_code: Option<String>, level: String) -> Result<String, FfiError> {
        Ok(self.require_sync()?.create_invite(&project_id, device_code.as_deref(), &level)?)
    }

    /// Blocks up to ~45s while the owner's device answers. Returns the project id.
    pub fn join_project(&self, link: String) -> Result<String, FfiError> {
        Ok(self.require_sync()?.join(&link)?)
    }

    pub fn list_members(&self, project_id: String) -> Result<Vec<FfiMember>, FfiError> {
        let Some(svc) = self.sync_service() else { return Ok(vec![]) };
        Ok(svc
            .members(&project_id)?
            .into_iter()
            .map(|m| FfiMember { peer_id: m.peer_id, name: m.name, level: m.level, joined_at: m.joined_at, is_me: m.is_me })
            .collect())
    }

    /// `level` is "editor", "viewer" or "removed".
    pub fn set_member_level(&self, project_id: String, peer_id: String, level: String) -> Result<(), FfiError> {
        Ok(self.require_sync()?.set_member_level(&project_id, &peer_id, &level)?)
    }

    pub fn sync_status(&self, project_id: String) -> Result<FfiSyncStatus, FfiError> {
        let shared = {
            let db = self.open()?;
            db.conn().query_row("SELECT count(*) FROM sync_doc WHERE project_id = ?1", [&project_id], |r| r.get::<_, i64>(0))
                .map_err(db_err)? > 0
        };
        let st = match (shared, self.sync_service()) {
            (true, Some(svc)) => svc.status(&project_id)?,
            (true, None) => yasecret_sync::live::SyncStatus { shared: true, ..Default::default() },
            _ => yasecret_sync::live::SyncStatus::default(),
        };
        Ok(FfiSyncStatus {
            shared: st.shared,
            is_owner: st.is_owner,
            my_level: st.my_level,
            peers_online: st.peers_online,
            last_synced_at: st.last_synced_at,
            last_error: st.last_error,
        })
    }

    /// Changes whenever synced data from other devices landed in the vault.
    pub fn sync_revision(&self) -> u64 {
        self.sync_service().map(|s| s.revision()).unwrap_or(0)
    }

    /// Owner: stop sharing and rotate the key. Member: leave and remove the local copy.
    pub fn stop_sharing(&self, project_id: String) -> Result<(), FfiError> {
        Ok(self.require_sync()?.stop_sharing(&project_id)?)
    }

    // ── MCP session ───────────────────────────────────────────────────────────

    pub fn mcp_session_count(&self) -> Result<u32, FfiError> {
        let db = self.open()?;
        let count: i64 = db.conn()
            .query_row("SELECT count(*) FROM mcp_session", [], |r| r.get(0))
            .map_err(|e| FfiError::Db { msg: e.to_string() })?;
        Ok(count as u32)
    }

    pub fn grant_mcp_access(&self) -> Result<(), FfiError> {
        let db = self.open()?;
        // BEGIN IMMEDIATE acquires a write lock immediately, preventing a
        // concurrent caller from inserting between our count check and insert.
        db.conn().execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| FfiError::Db { msg: e.to_string() })?;
        let count: i64 = db.conn()
            .query_row("SELECT count(*) FROM mcp_session", [], |r| r.get(0))
            .unwrap_or(0);
        let result: Result<(), FfiError> = (|| {
            if count == 0 {
                let token = uuid::Uuid::new_v4().to_string();
                db.conn().execute(
                    "INSERT INTO mcp_session (token, granted_at, label) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&token, now(), "Claude Code"],
                ).map_err(|e| FfiError::Db { msg: e.to_string() })?;
            }
            Ok(())
        })();
        match &result {
            Ok(_) => db.conn().execute_batch("COMMIT")
                .map_err(|e| FfiError::Db { msg: e.to_string() })?,
            Err(_) => { db.conn().execute_batch("ROLLBACK").ok(); }
        }
        result
    }
}

// ── Free functions ────────────────────────────────────────────────────────────

#[uniffi::export]
pub fn default_db_path() -> String {
    let mut base = dirs::data_local_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    base.push("yasecret");
    std::fs::create_dir_all(&base).ok();
    base.push("db.sqlite");
    base.to_string_lossy().into_owned()
}

#[uniffi::export]
pub fn looks_secret(key: String) -> bool {
    env_file::looks_secret(&key)
}

#[uniffi::export]
pub fn is_valid_key(key: String) -> bool {
    env_file::valid_key(&key)
}

// ── Internals ─────────────────────────────────────────────────────────────────

fn db_err(e: rusqlite::Error) -> FfiError {
    FfiError::Db { msg: e.to_string() }
}

fn finish_tx<T>(db: &Db, result: Result<T, FfiError>) -> Result<T, FfiError> {
    match &result {
        Ok(_) => db.conn().execute_batch("COMMIT").map_err(db_err)?,
        Err(_) => {
            db.conn().execute_batch("ROLLBACK").ok();
        }
    }
    result
}

fn check_key(key: &str) -> Result<(), FfiError> {
    if env_file::valid_key(key) {
        Ok(())
    } else {
        Err(FfiError::Parse {
            msg: format!("'{key}' is not a valid variable name — use letters, digits and _ (must not start with a digit)"),
        })
    }
}

fn duplicate_aware(e: yasecret_core::YasecretError) -> FfiError {
    match &e {
        yasecret_core::YasecretError::Db(inner) if inner.to_string().contains("UNIQUE") => FfiError::Parse {
            msg: "A variable with this name already exists in this environment".into(),
        },
        _ => FfiError::from(e),
    }
}

fn env_record(db: &Db, e: yasecret_core::models::Environment) -> Result<FfiEnvironment, FfiError> {
    let secret_count = yasecret_core::environment::secret_count(db, &e.id)?;
    Ok(FfiEnvironment { id: e.id, project_id: e.project_id, name: e.name, secret_count })
}

impl YasecretSession {
    fn open(&self) -> Result<Db, FfiError> {
        Ok(Db::open(Path::new(&self.db_path), &self.password)?)
    }

    fn sync_service(&self) -> Option<Arc<yasecret_sync::live::SyncService>> {
        self.sync.lock().unwrap().clone()
    }

    fn require_sync(&self) -> Result<Arc<yasecret_sync::live::SyncService>, FfiError> {
        self.sync_service()
            .ok_or_else(|| FfiError::Sync { msg: "Sharing isn't running — unlock the vault and try again".into() })
    }

    fn touched(&self, project_id: &str) {
        if let Some(svc) = self.sync_service() {
            svc.notify_local_change(project_id);
        }
    }

    fn touched_env(&self, db: &Db, env_id: &str) {
        if let Ok(e) = yasecret_core::environment::get(db, env_id) {
            self.touched(&e.project_id);
        }
    }
}

impl Drop for YasecretSession {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn make_session(dir: &tempfile::TempDir) -> Arc<YasecretSession> {
        let db_path = dir.path().join("db.sqlite").to_string_lossy().into_owned();
        YasecretSession::new(db_path, "pw".to_string()).unwrap()
    }

    #[test]
    fn wrong_password_returns_error() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite").to_string_lossy().into_owned();
        let salt = yasecret_core::crypto::generate_salt();
        std::fs::write(dir.path().join("db.salt"), salt).unwrap();
        Db::open(std::path::Path::new(&db_path), "correct").unwrap();
        let result = YasecretSession::new(db_path, "wrong".to_string());
        assert!(result.is_err(), "wrong password must fail");
        let err = result.err().unwrap();
        assert!(matches!(err, FfiError::WrongPassword));
    }

    #[test]
    fn create_and_list_project() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        session.create_project("myapp".into(), None).unwrap();
        let projects = session.list_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "myapp");
    }

    #[test]
    fn create_secret_and_get_plaintext() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let proj = session.create_project("app".into(), None).unwrap();
        let env = session.create_environment(proj.id.clone(), "dev".into()).unwrap();
        let secret = session.create_secret(
            proj.id.clone(), env.id.clone(), "DB_URL".into(),
            "postgres://localhost".into(), None, true,
        ).unwrap();
        let val = session.get_secret_plaintext(proj.id.clone(), secret.id.clone()).unwrap();
        assert_eq!(val, "postgres://localhost");
    }

    #[test]
    fn import_env_returns_count() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let proj = session.create_project("app".into(), None).unwrap();
        let env = session.create_environment(proj.id.clone(), "prod".into()).unwrap();
        let count = session.import_env(proj.id.clone(), env.id, "A=1\nB=2\n".into()).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn missing_project_key_gives_error_on_plaintext() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let result = session.get_secret_plaintext("nonexistent-proj".into(), "any-secret".into());
        assert!(result.is_err());
    }

    fn proj_env(session: &YasecretSession) -> (String, String) {
        let proj = session.create_project("app".into(), None).unwrap();
        let env = session.create_environment(proj.id.clone(), "dev".into()).unwrap();
        (proj.id, env.id)
    }

    #[test]
    fn create_plain_variable_is_listed_as_plain() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        session.create_secret(p, e.clone(), "PORT".into(), "3000".into(), None, false).unwrap();
        let listed = session.list_secrets(e).unwrap();
        assert!(!listed[0].is_secret);
        assert!(listed[0].updated_at > 0);
    }

    #[test]
    fn edit_secret_changes_key_value_and_kind() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        let s = session.create_secret(p.clone(), e.clone(), "OLD".into(), "v1".into(), None, true).unwrap();
        session.edit_secret(p.clone(), s.id.clone(), Some("NEW".into()), Some("v2".into()), Some(false)).unwrap();
        let got = &session.list_secrets(e).unwrap()[0];
        assert_eq!(got.key, "NEW");
        assert!(!got.is_secret);
        assert_eq!(session.get_secret_plaintext(p, s.id).unwrap(), "v2");
    }

    #[test]
    fn invalid_key_is_rejected() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        assert!(session.create_secret(p, e, "BAD KEY".into(), "v".into(), None, true).is_err());
    }

    #[test]
    fn clone_environment_reports_count() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        session.create_secret(p.clone(), e.clone(), "A".into(), "1".into(), None, true).unwrap();
        let c = session.clone_environment(e, "staging".into()).unwrap();
        assert_eq!(c.secret_count, 1);
        let envs = session.list_environments(p).unwrap();
        assert_eq!(envs.iter().find(|x| x.name == "staging").unwrap().secret_count, 1);
    }

    #[test]
    fn preview_import_flags_existing_and_secret_like() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        session.create_secret(p, e.clone(), "PORT".into(), "1".into(), None, false).unwrap();
        let rows = session.preview_import(e, "PORT=3000\nAPI_TOKEN=abc\n".into()).unwrap();
        let port = rows.iter().find(|r| r.key == "PORT").unwrap();
        let tok = rows.iter().find(|r| r.key == "API_TOKEN").unwrap();
        assert!(port.exists && !port.suggested_secret);
        assert!(!tok.exists && tok.suggested_secret);
        assert_eq!(tok.value, "abc");
    }

    #[test]
    fn apply_import_skips_or_overwrites_existing() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        session.create_secret(p.clone(), e.clone(), "PORT".into(), "1".into(), None, false).unwrap();
        let items = vec![
            FfiImportItem { key: "PORT".into(), value: "2".into(), is_secret: false },
            FfiImportItem { key: "NEW_KEY".into(), value: "x".into(), is_secret: true },
        ];
        let skip = session.apply_import(p.clone(), e.clone(), items.clone(), false).unwrap();
        assert_eq!((skip.added, skip.updated, skip.skipped), (1, 0, 1));
        let port_id = session.list_secrets(e.clone()).unwrap().into_iter().find(|s| s.key == "PORT").unwrap().id;
        assert_eq!(session.get_secret_plaintext(p.clone(), port_id.clone()).unwrap(), "1");

        let over = session.apply_import(p.clone(), e.clone(), items, true).unwrap();
        assert_eq!((over.added, over.updated, over.skipped), (0, 2, 0));
        assert_eq!(session.get_secret_plaintext(p, port_id).unwrap(), "2");
    }

    #[test]
    fn sync_lifecycle_and_invite() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        let (p, e) = proj_env(&session);
        session.create_secret(p.clone(), e, "A".into(), "1".into(), None, true).unwrap();
        assert!(!session.sync_status(p.clone()).unwrap().shared);
        assert!(session.create_invite(p.clone(), None, "editor".into()).is_err(), "needs sync running");

        session.start_sync("test-mac".into()).unwrap();
        assert_eq!(session.device_code().unwrap().len(), 64);
        let link = session.create_invite(p.clone(), None, "editor".into()).unwrap();
        assert!(link.starts_with("yasecret://join?"));
        let st = session.sync_status(p.clone()).unwrap();
        assert!(st.shared && st.is_owner);
        assert_eq!(st.my_level, "owner");
        assert_eq!(session.list_members(p.clone()).unwrap().len(), 1);

        session.stop_sharing(p.clone()).unwrap();
        assert!(!session.sync_status(p).unwrap().shared);
        session.stop_sync();
        session.start_sync("test-mac".into()).unwrap();
    }

    #[test]
    fn grant_mcp_access_is_idempotent() {
        let dir = tempdir().unwrap();
        let session = make_session(&dir);
        assert_eq!(session.mcp_session_count().unwrap(), 0);
        session.grant_mcp_access().unwrap();
        session.grant_mcp_access().unwrap();
        assert_eq!(session.mcp_session_count().unwrap(), 1);
    }
}
