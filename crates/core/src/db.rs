use std::path::Path;
use rusqlite::Connection;
use crate::error::{Result, YasecretError};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Set file permissions to 0600 (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(path, perms);
            }
        }

        // Unlock SQLCipher — escape single quotes in password
        let escaped = password.replace('\'', "''");
        conn.execute_batch(&format!("PRAGMA key = '{escaped}';"))?;

        // Verify key is correct by reading sqlite_master
        let result: rusqlite::Result<i64> =
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0));
        if result.is_err() {
            return Err(YasecretError::WrongPassword);
        }

        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;

        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS identity (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                public_key BLOB NOT NULL,
                secret_key BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peer (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                public_key BLOB NOT NULL,
                first_seen INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS project (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                description TEXT,
                created_at  INTEGER NOT NULL,
                owner_id    TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS environment (
                id         TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
                name       TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS secret (
                id              TEXT PRIMARY KEY,
                env_id          TEXT NOT NULL REFERENCES environment(id) ON DELETE CASCADE,
                key             TEXT NOT NULL,
                encrypted_value BLOB NOT NULL,
                nonce           BLOB NOT NULL,
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL,
                created_by      TEXT NOT NULL,
                expires_at      INTEGER
            );

            CREATE TABLE IF NOT EXISTS secret_version (
                id              TEXT PRIMARY KEY,
                secret_id       TEXT NOT NULL REFERENCES secret(id) ON DELETE CASCADE,
                encrypted_value BLOB NOT NULL,
                nonce           BLOB NOT NULL,
                changed_by      TEXT NOT NULL,
                changed_at      INTEGER NOT NULL,
                note            TEXT
            );

            CREATE TABLE IF NOT EXISTS project_key (
                project_id    TEXT PRIMARY KEY REFERENCES project(id) ON DELETE CASCADE,
                encrypted_key BLOB NOT NULL,
                key_nonce     BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peer_project_key (
                project_id    TEXT NOT NULL,
                peer_id       TEXT NOT NULL,
                encrypted_key BLOB NOT NULL,
                PRIMARY KEY (project_id, peer_id)
            );

            CREATE TABLE IF NOT EXISTS role (
                id         TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                env_id     TEXT,
                peer_id    TEXT NOT NULL,
                level      TEXT NOT NULL,
                granted_at INTEGER NOT NULL,
                signature  BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_entry (
                id          TEXT PRIMARY KEY,
                peer_id     TEXT NOT NULL,
                action      TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id   TEXT NOT NULL,
                timestamp   INTEGER NOT NULL,
                detail      TEXT
            );

            CREATE TABLE IF NOT EXISTS sync_doc (
                project_id TEXT PRIMARY KEY REFERENCES project(id) ON DELETE CASCADE,
                doc_id     TEXT NOT NULL,
                ticket     TEXT
            );

            CREATE TABLE IF NOT EXISTS mcp_session (
                token      TEXT PRIMARY KEY,
                granted_at INTEGER NOT NULL,
                label      TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_secret_env_key
                ON secret(env_id, key);
        ")?;
        Ok(())
    }
}
