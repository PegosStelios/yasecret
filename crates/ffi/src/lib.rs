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
}

#[derive(Clone, uniffi::Record)]
pub struct FfiSecret {
    pub id: String,
    pub env_id: String,
    pub key: String,
    pub expires_at: Option<i64>,
}

// ── Session ───────────────────────────────────────────────────────────────────

#[derive(uniffi::Object)]
pub struct YasecretSession {
    db_path: String,
    password: String,
    db_key: Zeroizing<[u8; 32]>,
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

        Ok(Arc::new(Self { db_path, password, db_key }))
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

    pub fn delete_project(&self, project_id: String) -> Result<(), FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::project::delete(&db, &project_id)?)
    }

    // ── Environments ──────────────────────────────────────────────────────────

    pub fn list_environments(&self, project_id: String) -> Result<Vec<FfiEnvironment>, FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::environment::list(&db, &project_id)?
            .into_iter()
            .map(|e| FfiEnvironment { id: e.id, project_id: e.project_id, name: e.name })
            .collect())
    }

    pub fn create_environment(&self, project_id: String, name: String) -> Result<FfiEnvironment, FfiError> {
        let db = self.open()?;
        let e = yasecret_core::environment::create(&db, &project_id, &name)?;
        Ok(FfiEnvironment { id: e.id, project_id: e.project_id, name: e.name })
    }

    pub fn delete_environment(&self, env_id: String) -> Result<(), FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::environment::delete(&db, &env_id)?)
    }

    // ── Secrets ───────────────────────────────────────────────────────────────

    pub fn list_secrets(&self, env_id: String) -> Result<Vec<FfiSecret>, FfiError> {
        let db = self.open()?;
        Ok(yasecret_core::secret::list(&db, &env_id)?
            .into_iter()
            .map(|s| FfiSecret { id: s.id, env_id: s.env_id, key: s.key, expires_at: s.expires_at })
            .collect())
    }

    pub fn create_secret(
        &self,
        project_id: String,
        env_id: String,
        key: String,
        value: String,
        expires_at: Option<i64>,
    ) -> Result<FfiSecret, FfiError> {
        let db = self.open()?;
        let proj_key = yasecret_core::project_key::load(&db, &project_id, &self.db_key)?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        let s = yasecret_core::secret::create(
            &db, &env_id, &key, value.as_bytes(), &proj_key, &id, expires_at,
        )?;
        Ok(FfiSecret { id: s.id, env_id: s.env_id, key: s.key, expires_at: s.expires_at })
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
        Ok(())
    }

    pub fn delete_secret(&self, secret_id: String) -> Result<(), FfiError> {
        let db = self.open()?;
        let id = yasecret_core::identity::load_or_create(&db, "local")?.id;
        Ok(yasecret_core::secret::delete(&db, &secret_id, &id)?)
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
        let pairs = env_file::parse(&content)?;
        let mut count = 0u32;
        for (key, value) in &pairs {
            yasecret_core::secret::create(
                &db, &env_id, key, value.as_bytes(), &proj_key, &id, None,
            )?;
            count += 1;
        }
        Ok(count)
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
        let count: i64 = db.conn()
            .query_row("SELECT count(*) FROM mcp_session", [], |r| r.get(0))
            .unwrap_or(0);
        if count == 0 {
            let token = uuid::Uuid::new_v4().to_string();
            db.conn().execute(
                "INSERT INTO mcp_session (token, granted_at, label) VALUES (?1, ?2, ?3)",
                rusqlite::params![&token, now(), "Claude Code"],
            ).map_err(|e| FfiError::Db { msg: e.to_string() })?;
        }
        Ok(())
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

// ── Internals ─────────────────────────────────────────────────────────────────

impl YasecretSession {
    fn open(&self) -> Result<Db, FfiError> {
        Ok(Db::open(Path::new(&self.db_path), &self.password)?)
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
            "postgres://localhost".into(), None,
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
