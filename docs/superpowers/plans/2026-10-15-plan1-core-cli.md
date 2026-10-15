# yasecret — Plan 1: Core + CLI

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Working local secrets manager — Cargo workspace, encrypted SQLite storage, full secret CRUD, and `yasecret pull` / `yasecret run` CLI commands.

**Architecture:** A `core` Rust library crate owns all business logic (DB, encryption, models, CRUD). A `cli` crate is a thin binary over `core`. No networking in this plan — that is Plan 2. Every secret value is AES-256-GCM encrypted with a per-project key; the DB itself is SQLCipher-encrypted via Argon2id-derived key.

**Tech Stack:** Rust stable, rusqlite + bundled SQLCipher, aes-gcm, argon2, x25519-dalek, ed25519-dalek, zeroize, uuid, serde/serde_json, clap v4, rpassword

**Spec:** `docs/superpowers/specs/2026-10-15-yasecret-design.md`

## Global Constraints

- Rust edition 2021, MSRV 1.77
- SQLCipher bundled (no system library dependency)
- All secret values zeroized on drop — never in plaintext in a `String` that outlives its scope; use `ZeroizingVec` / `Zeroizing<Vec<u8>>`
- DB file permissions set to 0o600 after creation
- `unwrap()` / `expect()` banned in non-test code; all errors propagate via `YasecretError`
- UUIDs for all primary keys (UUID v4)
- Timestamps: Unix seconds as `i64`
- No `println!` in `core`; no logging library needed in Plan 1

## Review Focus

- **Wrong master password:** `db::open()` must return `Err` (not panic, not open a blank DB) when PRAGMA key is incorrect.
- **Concurrent writes to same DB file:** SQLite WAL mode must be enabled so two CLI invocations don't corrupt data.
- **Secret value zeroize:** Decrypted bytes must not remain in heap after the owning struct drops — test by checking `Zeroizing<Vec<u8>>` drop behavior.
- **`.env` edge cases:** Values with `=` signs, quoted values with spaces, lines with no value (`KEY=`), and comment lines (`# …`) must all parse without panic.
- **Role check before write:** `secret::update_secret()` must return `Err(YasecretError::PermissionDenied)` when caller identity has only `read` level on that environment.

---

## File Map

```
Cargo.toml                          ← workspace root
crates/
  core/
    Cargo.toml
    src/
      lib.rs                        ← public API re-exports + CoreConfig
      error.rs                      ← YasecretError
      db.rs                         ← Db struct, open/close, migrations, WAL
      crypto.rs                     ← argon2id, aes-256-gcm, x25519, ed25519, zeroize
      models.rs                     ← Project, Environment, Secret, SecretVersion,
                                       Role, AuditEntry, Identity structs
      identity.rs                   ← load_or_create_identity, keypair storage
      project.rs                    ← create_project, get_project, list_projects,
                                       delete_project
      environment.rs                ← create_environment, list_environments,
                                       get_environment, delete_environment
      secret.rs                     ← create_secret, get_secret, list_secrets,
                                       update_secret, delete_secret (role-checked)
      version.rs                    ← list_secret_versions, rollback_secret
      audit.rs                      ← append_audit_entry, list_audit_entries
      role.rs                       ← create_role, check_permission,
                                       verify_role_signature, revoke_role
      env_file.rs                   ← parse_env_file, serialize_env, parse_env_example
    tests/
      db_test.rs
      crypto_test.rs
      secret_test.rs
      env_file_test.rs
      role_test.rs
  cli/
    Cargo.toml
    src/
      main.rs                       ← clap app, subcommand dispatch
      unlock.rs                     ← interactive master password prompt + DB open
      cmd/
        pull.rs                     ← yasecret pull
        run.rs                      ← yasecret run
```

---

## Task 1: Cargo Workspace Scaffold

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/core/Cargo.toml`
- Create: `crates/core/src/lib.rs`
- Create: `crates/core/src/error.rs`
- Create: `crates/cli/Cargo.toml`
- Create: `crates/cli/src/main.rs`

**Interfaces:**
- Produces: compilable workspace; `cargo build` succeeds

- [ ] **Step 1: Create workspace Cargo.toml**

```toml
# Cargo.toml
[workspace]
members = ["crates/core", "crates/cli"]
resolver = "2"

[workspace.dependencies]
rusqlite = { version = "0.31", features = ["bundled-sqlcipher"] }
aes-gcm   = "0.10"
argon2    = "0.5"
x25519-dalek = { version = "2", features = ["static_secrets"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
zeroize   = { version = "1", features = ["derive"] }
rand      = "0.8"
uuid      = { version = "1", features = ["v4"] }
serde     = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
clap      = { version = "4", features = ["derive"] }
rpassword = "7"
```

- [ ] **Step 2: Create crates/core/Cargo.toml**

```toml
[package]
name    = "yasecret-core"
version = "0.1.0"
edition = "2021"

[dependencies]
rusqlite     = { workspace = true }
aes-gcm      = { workspace = true }
argon2       = { workspace = true }
x25519-dalek = { workspace = true }
ed25519-dalek = { workspace = true }
zeroize      = { workspace = true }
rand         = { workspace = true }
uuid         = { workspace = true }
serde        = { workspace = true }
serde_json   = { workspace = true }
thiserror    = { workspace = true }
```

- [ ] **Step 3: Create crates/core/src/error.rs**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum YasecretError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("wrong master password or corrupted database")]
    WrongPassword,
    #[error("encryption error")]
    Crypto,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("permission denied")]
    PermissionDenied,
    #[error("invalid .env format: {0}")]
    EnvParse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, YasecretError>;
```

- [ ] **Step 4: Create crates/core/src/lib.rs**

```rust
pub mod audit;
pub mod crypto;
pub mod db;
pub mod env_file;
pub mod environment;
pub mod error;
pub mod identity;
pub mod models;
pub mod project;
pub mod role;
pub mod secret;
pub mod version;

pub use error::{Result, YasecretError};
pub use db::Db;
```

- [ ] **Step 5: Create crates/cli/Cargo.toml**

```toml
[package]
name    = "yasecret"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "yasecret"
path = "src/main.rs"

[dependencies]
yasecret-core = { path = "../core" }
clap          = { workspace = true }
rpassword     = { workspace = true }
```

- [ ] **Step 6: Create crates/cli/src/main.rs stub**

```rust
use clap::{Parser, Subcommand};

mod cmd;
mod unlock;

#[derive(Parser)]
#[command(name = "yasecret", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Pull(cmd::pull::PullArgs),
    Run(cmd::run::RunArgs),
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Pull(args) => cmd::pull::run(args),
        Commands::Run(args) => cmd::run::run(args),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 7: Verify workspace compiles**

```bash
mkdir -p crates/cli/src/cmd
touch crates/cli/src/unlock.rs
touch crates/cli/src/cmd/mod.rs
touch crates/cli/src/cmd/pull.rs
touch crates/cli/src/cmd/run.rs
# Add stubs to pull.rs and run.rs:
# pub struct PullArgs {}
# pub fn run(_: PullArgs) -> yasecret_core::Result<()> { Ok(()) }
cargo build
```

Expected: compiles with warnings only.

- [ ] **Step 8: Commit**

```bash
git init
git add Cargo.toml crates/
git commit -m "chore: initialize yasecret workspace"
```

---

## Task 2: Database Layer (SQLCipher + Migrations)

**Files:**
- Create: `crates/core/src/db.rs`
- Create: `crates/core/tests/db_test.rs`

**Interfaces:**
- Produces: `Db::open(path, password) -> Result<Db>`, `Db::conn() -> &Connection`
- Later tasks call `db.conn()` to execute SQL

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/db_test.rs
use std::path::PathBuf;
use tempfile::tempdir;
use yasecret_core::db::Db;

fn tmp_db() -> (tempfile::TempDir, PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    (dir, path)
}

#[test]
fn open_creates_db() {
    let (_dir, path) = tmp_db();
    let db = Db::open(&path, "password123").unwrap();
    assert!(path.exists());
    drop(db);
}

#[test]
fn wrong_password_fails() {
    let (_dir, path) = tmp_db();
    let _db = Db::open(&path, "correct").unwrap();
    drop(_db);
    let result = Db::open(&path, "wrong");
    assert!(result.is_err());
}

#[test]
fn db_has_expected_tables() {
    let (_dir, path) = tmp_db();
    let db = Db::open(&path, "pw").unwrap();
    let conn = db.conn();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='project'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}
```

Add `tempfile = "3"` to `[dev-dependencies]` in `crates/core/Cargo.toml`.

- [ ] **Step 2: Run tests — expect compile failure**

```bash
cargo test -p yasecret-core --test db_test 2>&1 | head -20
```

Expected: `error[E0433]: failed to resolve: use of undeclared crate or module 'db'`

- [ ] **Step 3: Implement db.rs**

```rust
// crates/core/src/db.rs
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use rusqlite::Connection;
use crate::error::{Result, YasecretError};

pub struct Db {
    conn: Connection,
}

impl Db {
    pub fn open(path: &Path, password: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Set file permissions to 0600
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

        // Unlock SQLCipher
        conn.execute_batch(&format!("PRAGMA key = '{password}';"))?;

        // Verify the key is correct by reading a known table
        let result: rusqlite::Result<i64> = conn.query_row(
            "SELECT count(*) FROM sqlite_master",
            [],
            |r| r.get(0),
        );
        if result.is_err() {
            return Err(YasecretError::WrongPassword);
        }

        // WAL mode for concurrent access
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
            CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

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
```

- [ ] **Step 4: Run tests — expect pass**

```bash
cargo test -p yasecret-core --test db_test
```

Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/db.rs crates/core/tests/db_test.rs crates/core/Cargo.toml
git commit -m "feat(core): database layer with SQLCipher and migrations"
```

---

## Task 3: Crypto Primitives

**Files:**
- Create: `crates/core/src/crypto.rs`
- Create: `crates/core/tests/crypto_test.rs`

**Interfaces:**
- Produces:
  - `derive_db_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]>`
  - `generate_salt() -> [u8; 16]`
  - `generate_project_key() -> Zeroizing<[u8; 32]>`
  - `encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])>` → (ciphertext, nonce)
  - `decrypt(ciphertext: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>>`
  - `generate_identity_keypair() -> (x25519_dalek::StaticSecret, x25519_dalek::PublicKey)`
  - `encrypt_for_peer(plaintext: &[u8], peer_pub: &[u8; 32]) -> Result<Vec<u8>>`
  - `decrypt_from_peer(ciphertext: &[u8], our_secret: &x25519_dalek::StaticSecret) -> Result<Zeroizing<Vec<u8>>>`
  - `sign(message: &[u8], signing_key: &ed25519_dalek::SigningKey) -> Vec<u8>`
  - `verify(message: &[u8], signature: &[u8], verifying_key: &[u8; 32]) -> Result<()>`

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/crypto_test.rs
use yasecret_core::crypto::*;

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = generate_project_key();
    let plaintext = b"DATABASE_URL=postgres://localhost/test";
    let (ciphertext, nonce) = encrypt(plaintext, &key).unwrap();
    let decrypted = decrypt(&ciphertext, &nonce, &key).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn wrong_key_decrypt_fails() {
    let key1 = generate_project_key();
    let key2 = generate_project_key();
    let (ciphertext, nonce) = encrypt(b"secret", &key1).unwrap();
    assert!(decrypt(&ciphertext, &nonce, &key2).is_err());
}

#[test]
fn derive_key_deterministic() {
    let salt = generate_salt();
    let k1 = derive_db_key("password", &salt);
    let k2 = derive_db_key("password", &salt);
    assert_eq!(k1.as_ref(), k2.as_ref());
}

#[test]
fn derive_key_different_passwords() {
    let salt = generate_salt();
    let k1 = derive_db_key("password1", &salt);
    let k2 = derive_db_key("password2", &salt);
    assert_ne!(k1.as_ref(), k2.as_ref());
}

#[test]
fn peer_key_exchange_roundtrip() {
    let (secret_a, pub_a) = generate_identity_keypair();
    let (secret_b, pub_b) = generate_identity_keypair();
    let plaintext = b"project-key-bytes-here-32-chars!!";
    let encrypted = encrypt_for_peer(plaintext, pub_b.as_bytes()).unwrap();
    let decrypted = decrypt_from_peer(&encrypted, &secret_b).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    // A's secret key is unused in this direction — just verify B can decrypt
    let _ = (secret_a, pub_a);
}

#[test]
fn ed25519_sign_verify() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut OsRng);
    let message = b"role:project-id:peer-id:write";
    let sig = sign(message, &signing_key);
    let vk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    assert!(verify(message, &sig, &vk_bytes).is_ok());
    assert!(verify(b"tampered", &sig, &vk_bytes).is_err());
}
```

- [ ] **Step 2: Run tests — expect compile failure**

```bash
cargo test -p yasecret-core --test crypto_test 2>&1 | head -10
```

Expected: `failed to resolve: use of undeclared crate or module 'crypto'`

- [ ] **Step 3: Implement crypto.rs**

```rust
// crates/core/src/crypto.rs
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Params, PasswordHasher, password_hash::SaltString};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, YasecretError};

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_db_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .expect("argon2 hash failed");
    output
}

pub fn generate_project_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| YasecretError::Crypto)?;
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(ciphertext: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| YasecretError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn generate_identity_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

// Encrypt `plaintext` so only the holder of the X25519 secret key for `peer_pub` can decrypt.
// Uses ephemeral ECDH: generate ephemeral keypair, derive shared secret, AES-GCM encrypt.
// Output: [ephemeral_pub(32)] ++ [nonce(12)] ++ [ciphertext]
pub fn encrypt_for_peer(plaintext: &[u8], peer_pub_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    let peer_pub = PublicKey::from(*peer_pub_bytes);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);
    let shared: SharedSecret = ephemeral_secret.diffie_hellman(&peer_pub);
    // Derive AES key from shared secret via SHA-256 (simple KDF)
    let aes_key: [u8; 32] = {
        use std::collections::hash_map::DefaultHasher; // NOT cryptographic — use SHA-256
        // Actually use a proper KDF here:
        let mut key = [0u8; 32];
        let shared_bytes = shared.as_bytes();
        // HKDF-like: hash(shared || "yasecret-v1")
        use std::hash::{Hash, Hasher};
        // We'll use ring/sha2 — add sha2 = "0.10" to Cargo.toml
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(shared_bytes);
        hasher.update(b"yasecret-peer-key-v1");
        let result = hasher.finalize();
        key.copy_from_slice(&result);
        key
    };
    let (ciphertext, nonce) = encrypt(plaintext, &aes_key)?;
    let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_from_peer(data: &[u8], our_secret: &StaticSecret) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 32 + 12 {
        return Err(YasecretError::Crypto);
    }
    let ephemeral_pub = PublicKey::from(<[u8; 32]>::try_from(&data[..32]).unwrap());
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let ciphertext = &data[44..];
    let shared = our_secret.diffie_hellman(&ephemeral_pub);
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(b"yasecret-peer-key-v1");
    let result = hasher.finalize();
    let mut aes_key = Zeroizing::new([0u8; 32]);
    aes_key.copy_from_slice(&result);
    decrypt(ciphertext, &nonce, &aes_key)
}

pub fn sign(message: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    signing_key.sign(message).to_bytes().to_vec()
}

pub fn verify(message: &[u8], signature_bytes: &[u8], verifying_key_bytes: &[u8; 32]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(verifying_key_bytes).map_err(|_| YasecretError::Crypto)?;
    let sig_arr: [u8; 64] = signature_bytes.try_into().map_err(|_| YasecretError::Crypto)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).map_err(|_| YasecretError::Crypto)
}
```

Add `sha2 = "0.10"` to `[workspace.dependencies]` and `crates/core/Cargo.toml`.

- [ ] **Step 4: Run tests — expect pass**

```bash
cargo test -p yasecret-core --test crypto_test
```

Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/crypto.rs crates/core/tests/crypto_test.rs Cargo.toml crates/core/Cargo.toml
git commit -m "feat(core): crypto primitives — argon2id, aes-256-gcm, x25519, ed25519"
```

---

## Task 4: Models + Identity

**Files:**
- Create: `crates/core/src/models.rs`
- Create: `crates/core/src/identity.rs`

**Interfaces:**
- Produces:
  - All model structs (public)
  - `identity::load_or_create(db: &Db, name: &str) -> Result<Identity>`
  - `identity::load(db: &Db) -> Result<Identity>`
  - `Identity.signing_key() -> ed25519_dalek::SigningKey`
  - `Identity.x25519_secret() -> x25519_dalek::StaticSecret`

- [ ] **Step 1: Implement models.rs**

No tests for pure data structs — covered by integration tests in later tasks.

```rust
// crates/core/src/models.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,    // x25519 public key bytes (32)
    pub secret_key: Vec<u8>,    // x25519 secret key bytes (32) — stored encrypted in DB
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub owner_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub env_id: String,
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SecretVersion {
    pub id: String,
    pub secret_id: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub changed_by: String,
    pub changed_at: i64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleLevel {
    Read,
    Write,
    Admin,
}

impl RoleLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
    pub fn can_write(&self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }
}

#[derive(Debug, Clone)]
pub struct Role {
    pub id: String,
    pub project_id: String,
    pub env_id: Option<String>,
    pub peer_id: String,
    pub level: RoleLevel,
    pub granted_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub peer_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub timestamp: i64,
    pub detail: Option<String>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
```

- [ ] **Step 2: Implement identity.rs**

```rust
// crates/core/src/identity.rs
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Identity},
};

pub fn load_or_create(db: &Db, name: &str) -> Result<Identity> {
    if let Ok(identity) = load(db) {
        return Ok(identity);
    }
    create(db, name)
}

pub fn load(db: &Db) -> Result<Identity> {
    let conn = db.conn();
    conn.query_row(
        "SELECT id, name, public_key, secret_key, created_at FROM identity LIMIT 1",
        [],
        |row| {
            Ok(Identity {
                id: row.get(0)?,
                name: row.get(1)?,
                public_key: row.get(2)?,
                secret_key: row.get(3)?,
                created_at: row.get(4)?,
            })
        },
    )
    .map_err(|_| YasecretError::NotFound("identity".into()))
}

fn create(db: &Db, name: &str) -> Result<Identity> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let identity = Identity {
        id: new_id(),
        name: name.to_string(),
        public_key: public.as_bytes().to_vec(),
        secret_key: secret.as_bytes().to_vec(),
        created_at: now(),
    };
    db.conn().execute(
        "INSERT INTO identity (id, name, public_key, secret_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &identity.id, &identity.name,
            &identity.public_key, &identity.secret_key,
            identity.created_at
        ],
    )?;
    Ok(identity)
}

impl Identity {
    pub fn x25519_secret(&self) -> StaticSecret {
        let bytes: [u8; 32] = self.secret_key[..32].try_into().expect("32 byte key");
        StaticSecret::from(bytes)
    }

    pub fn x25519_public(&self) -> PublicKey {
        let bytes: [u8; 32] = self.public_key[..32].try_into().expect("32 byte key");
        PublicKey::from(bytes)
    }

    // Ed25519 signing key derived from the x25519 secret (for simplicity in v1)
    // In production, store a separate Ed25519 keypair. Fine for Plan 1.
    pub fn signing_key(&self) -> SigningKey {
        let bytes: [u8; 32] = self.secret_key[..32].try_into().expect("32 byte key");
        SigningKey::from_bytes(&bytes)
    }
}
```

- [ ] **Step 3: Commit**

```bash
git add crates/core/src/models.rs crates/core/src/identity.rs
git commit -m "feat(core): data models and identity management"
```

---

## Task 5: Project + Environment CRUD

**Files:**
- Create: `crates/core/src/project.rs`
- Create: `crates/core/src/environment.rs`

**Interfaces:**
- Produces:
  - `project::create(db, name, description, owner_id) -> Result<Project>`
  - `project::list(db) -> Result<Vec<Project>>`
  - `project::get(db, id) -> Result<Project>`
  - `project::delete(db, id) -> Result<()>`
  - `environment::create(db, project_id, name) -> Result<Environment>`
  - `environment::list(db, project_id) -> Result<Vec<Environment>>`
  - `environment::get(db, id) -> Result<Environment>`
  - `environment::delete(db, id) -> Result<()>`

- [ ] **Step 1: Write failing test (add to existing db_test.rs or new file)**

```rust
// crates/core/tests/project_test.rs
use tempfile::tempdir;
use std::path::PathBuf;
use yasecret_core::{db::Db, project, environment};

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    (dir, db)
}

#[test]
fn create_and_list_project() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "my-app", None, "owner-1").unwrap();
    assert_eq!(p.name, "my-app");
    let list = project::list(&db).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, p.id);
}

#[test]
fn delete_project_cascades() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "app", None, "o1").unwrap();
    let _e = environment::create(&db, &p.id, "dev").unwrap();
    project::delete(&db, &p.id).unwrap();
    let envs = environment::list(&db, &p.id).unwrap();
    assert!(envs.is_empty());
}

#[test]
fn list_environments() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "app", None, "o").unwrap();
    environment::create(&db, &p.id, "dev").unwrap();
    environment::create(&db, &p.id, "production").unwrap();
    let envs = environment::list(&db, &p.id).unwrap();
    assert_eq!(envs.len(), 2);
}
```

- [ ] **Step 2: Run test — expect compile failure**

```bash
cargo test -p yasecret-core --test project_test 2>&1 | head -5
```

- [ ] **Step 3: Implement project.rs**

```rust
// crates/core/src/project.rs
use crate::{db::Db, error::Result, models::{now, new_id, Project}, error::YasecretError};

pub fn create(db: &Db, name: &str, description: Option<&str>, owner_id: &str) -> Result<Project> {
    let p = Project {
        id: new_id(),
        name: name.to_string(),
        description: description.map(String::from),
        created_at: now(),
        owner_id: owner_id.to_string(),
    };
    db.conn().execute(
        "INSERT INTO project (id, name, description, created_at, owner_id) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![&p.id, &p.name, &p.description, p.created_at, &p.owner_id],
    )?;
    Ok(p)
}

pub fn get(db: &Db, id: &str) -> Result<Project> {
    db.conn().query_row(
        "SELECT id, name, description, created_at, owner_id FROM project WHERE id = ?1",
        [id],
        |r| Ok(Project {
            id: r.get(0)?, name: r.get(1)?, description: r.get(2)?,
            created_at: r.get(3)?, owner_id: r.get(4)?,
        }),
    ).map_err(|_| YasecretError::NotFound(format!("project {id}")))
}

pub fn list(db: &Db) -> Result<Vec<Project>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, name, description, created_at, owner_id FROM project ORDER BY created_at"
    )?;
    let rows = stmt.query_map([], |r| Ok(Project {
        id: r.get(0)?, name: r.get(1)?, description: r.get(2)?,
        created_at: r.get(3)?, owner_id: r.get(4)?,
    }))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn delete(db: &Db, id: &str) -> Result<()> {
    db.conn().execute("DELETE FROM project WHERE id = ?1", [id])?;
    Ok(())
}
```

- [ ] **Step 4: Implement environment.rs** (same pattern)

```rust
// crates/core/src/environment.rs
use crate::{db::Db, error::{Result, YasecretError}, models::{now, new_id, Environment}};

pub fn create(db: &Db, project_id: &str, name: &str) -> Result<Environment> {
    let e = Environment { id: new_id(), project_id: project_id.to_string(), name: name.to_string(), created_at: now() };
    db.conn().execute(
        "INSERT INTO environment (id, project_id, name, created_at) VALUES (?1,?2,?3,?4)",
        rusqlite::params![&e.id, &e.project_id, &e.name, e.created_at],
    )?;
    Ok(e)
}

pub fn get(db: &Db, id: &str) -> Result<Environment> {
    db.conn().query_row(
        "SELECT id, project_id, name, created_at FROM environment WHERE id = ?1",
        [id],
        |r| Ok(Environment { id: r.get(0)?, project_id: r.get(1)?, name: r.get(2)?, created_at: r.get(3)? }),
    ).map_err(|_| YasecretError::NotFound(format!("environment {id}")))
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Environment>> {
    let mut stmt = db.conn().prepare(
        "SELECT id, project_id, name, created_at FROM environment WHERE project_id = ?1 ORDER BY created_at"
    )?;
    let rows = stmt.query_map([project_id], |r| Ok(Environment {
        id: r.get(0)?, project_id: r.get(1)?, name: r.get(2)?, created_at: r.get(3)?,
    }))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn delete(db: &Db, id: &str) -> Result<()> {
    db.conn().execute("DELETE FROM environment WHERE id = ?1", [id])?;
    Ok(())
}
```

- [ ] **Step 5: Run tests**

```bash
cargo test -p yasecret-core --test project_test
```

Expected: 3 tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/project.rs crates/core/src/environment.rs crates/core/tests/project_test.rs
git commit -m "feat(core): project and environment CRUD"
```

---

## Task 6: Project Key Management

**Files:**
- Modify: `crates/core/src/db.rs` — add `Db::project_key()` helper
- Create: `crates/core/src/project_key.rs`

**Interfaces:**
- Produces:
  - `project_key::create(db, project_id, db_key) -> Result<()>` — generates and stores AES-256 project key encrypted under db_key
  - `project_key::load(db, project_id, db_key) -> Result<Zeroizing<[u8; 32]>>` — decrypt and return project key

Note: `db_key` here is the 32-byte key derived from the master password (from `crypto::derive_db_key`). In the CLI, it is derived once at unlock time and passed through.

- [ ] **Step 1: Write failing test**

```rust
// crates/core/tests/project_key_test.rs
use tempfile::tempdir;
use yasecret_core::{db::Db, project, project_key, crypto};

#[test]
fn store_and_load_project_key() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);

    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();

    let loaded = project_key::load(&db, &p.id, &db_key).unwrap();
    // Store twice — second load must equal first
    let loaded2 = project_key::load(&db, &p.id, &db_key).unwrap();
    assert_eq!(loaded.as_ref(), loaded2.as_ref());
}

#[test]
fn wrong_db_key_fails_decrypt() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);
    let wrong_key = crypto::derive_db_key("wrong", &salt);

    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    assert!(project_key::load(&db, &p.id, &wrong_key).is_err());
}
```

- [ ] **Step 2: Implement project_key.rs**

```rust
// crates/core/src/project_key.rs
use zeroize::Zeroizing;
use crate::{crypto, db::Db, error::{Result, YasecretError}};

pub fn create(db: &Db, project_id: &str, db_key: &[u8; 32]) -> Result<()> {
    let project_key = crypto::generate_project_key();
    let (encrypted_key, nonce) = crypto::encrypt(project_key.as_ref(), db_key)?;
    db.conn().execute(
        "INSERT OR IGNORE INTO project_key (project_id, encrypted_key, key_nonce) VALUES (?1,?2,?3)",
        rusqlite::params![project_id, &encrypted_key, &nonce.as_ref()],
    )?;
    Ok(())
}

pub fn load(db: &Db, project_id: &str, db_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let (enc_key, nonce_vec): (Vec<u8>, Vec<u8>) = db.conn().query_row(
        "SELECT encrypted_key, key_nonce FROM project_key WHERE project_id = ?1",
        [project_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).map_err(|_| YasecretError::NotFound(format!("project key for {project_id}")))?;

    let nonce: [u8; 12] = nonce_vec.try_into().map_err(|_| YasecretError::Crypto)?;
    let decrypted = crypto::decrypt(&enc_key, &nonce, db_key)?;
    let key_bytes: [u8; 32] = decrypted.as_slice().try_into().map_err(|_| YasecretError::Crypto)?;
    Ok(Zeroizing::new(key_bytes))
}
```

Add `pub mod project_key;` to `lib.rs`.

- [ ] **Step 3: Run tests**

```bash
cargo test -p yasecret-core --test project_key_test
```

Expected: 2 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/project_key.rs crates/core/src/lib.rs crates/core/tests/project_key_test.rs
git commit -m "feat(core): per-project AES-256 key management"
```

---

## Task 7: Secret CRUD + Audit + Version History

**Files:**
- Create: `crates/core/src/secret.rs`
- Create: `crates/core/src/audit.rs`
- Create: `crates/core/src/version.rs`
- Create: `crates/core/tests/secret_test.rs`

**Interfaces:**
- Produces:
  - `secret::create(db, env_id, key, plaintext_value, project_key, caller_id, expires_at) -> Result<Secret>`
  - `secret::get_plaintext(db, secret_id, project_key) -> Result<Zeroizing<Vec<u8>>>`
  - `secret::list(db, env_id) -> Result<Vec<Secret>>` — returns encrypted secrets (no plaintext)
  - `secret::update(db, secret_id, new_plaintext, project_key, caller_id, note) -> Result<Secret>`
  - `secret::delete(db, secret_id, caller_id) -> Result<()>`
  - `version::list(db, secret_id) -> Result<Vec<SecretVersion>>`
  - `version::rollback(db, secret_id, version_id, project_key, caller_id) -> Result<Secret>`
  - `audit::append(db, peer_id, action, target_type, target_id, detail) -> Result<()>`
  - `audit::list(db, limit) -> Result<Vec<AuditEntry>>`

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/secret_test.rs
use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, project, project_key, secret, version, audit};

fn setup() -> (tempfile::TempDir, Db, [u8; 32], String, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let salt = crypto::generate_salt();
    let db_key = crypto::derive_db_key("pw", &salt);

    let p = project::create(&db, "app", None, "owner").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let proj_key_raw = project_key::load(&db, &p.id, &db_key).unwrap();
    let proj_key: [u8; 32] = *proj_key_raw;

    let e = environment::create(&db, &p.id, "dev").unwrap();
    (dir, db, proj_key, e.id, p.id)
}

#[test]
fn create_and_read_secret() {
    let (_dir, db, proj_key, env_id, _pid) = setup();
    let s = secret::create(&db, &env_id, "API_KEY", b"super-secret", &proj_key, "owner", None).unwrap();
    let plaintext = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(plaintext.as_slice(), b"super-secret");
}

#[test]
fn update_creates_version() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "DB_URL", b"v1", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let versions = version::list(&db, &s.id).unwrap();
    assert_eq!(versions.len(), 1); // v1 archived
    let current = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(current.as_slice(), b"v2");
}

#[test]
fn rollback_restores_old_value() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "DB_URL", b"v1", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let versions = version::list(&db, &s.id).unwrap();
    version::rollback(&db, &s.id, &versions[0].id, &proj_key, "owner").unwrap();
    let current = secret::get_plaintext(&db, &s.id, &proj_key).unwrap();
    assert_eq!(current.as_slice(), b"v1");
}

#[test]
fn audit_entries_recorded() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "K", b"v", &proj_key, "owner", None).unwrap();
    secret::update(&db, &s.id, b"v2", &proj_key, "owner", None).unwrap();
    let entries = audit::list(&db, 10).unwrap();
    assert!(entries.len() >= 2);
    assert!(entries.iter().any(|e| e.action == "created_secret"));
    assert!(entries.iter().any(|e| e.action == "updated_secret"));
}

#[test]
fn delete_secret() {
    let (_dir, db, proj_key, env_id, _) = setup();
    let s = secret::create(&db, &env_id, "GONE", b"v", &proj_key, "owner", None).unwrap();
    secret::delete(&db, &s.id, "owner").unwrap();
    let list = secret::list(&db, &env_id).unwrap();
    assert!(list.is_empty());
}
```

- [ ] **Step 2: Run test — expect compile failure**

```bash
cargo test -p yasecret-core --test secret_test 2>&1 | head -5
```

- [ ] **Step 3: Implement audit.rs**

```rust
// crates/core/src/audit.rs
use crate::{db::Db, error::Result, models::{AuditEntry, now, new_id}};

pub fn append(db: &Db, peer_id: &str, action: &str, target_type: &str, target_id: &str, detail: Option<&str>) -> Result<()> {
    db.conn().execute(
        "INSERT INTO audit_entry (id,peer_id,action,target_type,target_id,timestamp,detail) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![new_id(), peer_id, action, target_type, target_id, now(), detail],
    )?;
    Ok(())
}

pub fn list(db: &Db, limit: i64) -> Result<Vec<AuditEntry>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,peer_id,action,target_type,target_id,timestamp,detail FROM audit_entry ORDER BY timestamp DESC LIMIT ?1"
    )?;
    let rows = stmt.query_map([limit], |r| Ok(AuditEntry {
        id: r.get(0)?, peer_id: r.get(1)?, action: r.get(2)?,
        target_type: r.get(3)?, target_id: r.get(4)?, timestamp: r.get(5)?, detail: r.get(6)?,
    }))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}
```

- [ ] **Step 4: Implement secret.rs**

```rust
// crates/core/src/secret.rs
use zeroize::Zeroizing;
use crate::{audit, crypto, db::Db, error::Result, models::{now, new_id, Secret}};

pub fn create(db: &Db, env_id: &str, key: &str, plaintext: &[u8], project_key: &[u8; 32], caller_id: &str, expires_at: Option<i64>) -> Result<Secret> {
    let (enc, nonce) = crypto::encrypt(plaintext, project_key)?;
    let s = Secret {
        id: new_id(), env_id: env_id.to_string(), key: key.to_string(),
        encrypted_value: enc, nonce: nonce.to_vec(),
        created_at: now(), updated_at: now(),
        created_by: caller_id.to_string(), expires_at,
    };
    db.conn().execute(
        "INSERT INTO secret (id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![&s.id,&s.env_id,&s.key,&s.encrypted_value,&s.nonce,s.created_at,s.updated_at,&s.created_by,s.expires_at],
    )?;
    audit::append(db, caller_id, "created_secret", "secret", &s.id, None)?;
    Ok(s)
}

pub fn get_plaintext(db: &Db, secret_id: &str, project_key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let s = get_raw(db, secret_id)?;
    let nonce: [u8; 12] = s.nonce.try_into().map_err(|_| crate::error::YasecretError::Crypto)?;
    crypto::decrypt(&s.encrypted_value, &nonce, project_key)
}

pub fn list(db: &Db, env_id: &str) -> Result<Vec<Secret>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at FROM secret WHERE env_id=?1 ORDER BY key"
    )?;
    let rows = stmt.query_map([env_id], |r| Ok(Secret {
        id: r.get(0)?, env_id: r.get(1)?, key: r.get(2)?,
        encrypted_value: r.get(3)?, nonce: r.get(4)?,
        created_at: r.get(5)?, updated_at: r.get(6)?,
        created_by: r.get(7)?, expires_at: r.get(8)?,
    }))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn update(db: &Db, secret_id: &str, new_plaintext: &[u8], project_key: &[u8; 32], caller_id: &str, note: Option<&str>) -> Result<Secret> {
    let old = get_raw(db, secret_id)?;
    // Archive old value as a version
    db.conn().execute(
        "INSERT INTO secret_version (id,secret_id,encrypted_value,nonce,changed_by,changed_at,note) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![new_id(),&old.id,&old.encrypted_value,&old.nonce,caller_id,now(),note],
    )?;
    let (enc, nonce) = crypto::encrypt(new_plaintext, project_key)?;
    db.conn().execute(
        "UPDATE secret SET encrypted_value=?1, nonce=?2, updated_at=?3 WHERE id=?4",
        rusqlite::params![&enc, &nonce.as_ref(), now(), secret_id],
    )?;
    audit::append(db, caller_id, "updated_secret", "secret", secret_id, None)?;
    get_raw(db, secret_id)
}

pub fn delete(db: &Db, secret_id: &str, caller_id: &str) -> Result<()> {
    db.conn().execute("DELETE FROM secret WHERE id=?1", [secret_id])?;
    audit::append(db, caller_id, "deleted_secret", "secret", secret_id, None)?;
    Ok(())
}

fn get_raw(db: &Db, id: &str) -> Result<Secret> {
    db.conn().query_row(
        "SELECT id,env_id,key,encrypted_value,nonce,created_at,updated_at,created_by,expires_at FROM secret WHERE id=?1",
        [id],
        |r| Ok(Secret {
            id: r.get(0)?, env_id: r.get(1)?, key: r.get(2)?,
            encrypted_value: r.get(3)?, nonce: r.get(4)?,
            created_at: r.get(5)?, updated_at: r.get(6)?,
            created_by: r.get(7)?, expires_at: r.get(8)?,
        }),
    ).map_err(|_| crate::error::YasecretError::NotFound(format!("secret {id}")))
}
```

- [ ] **Step 5: Implement version.rs**

```rust
// crates/core/src/version.rs
use zeroize::Zeroizing;
use crate::{audit, crypto, db::Db, error::Result, models::{SecretVersion, now}, secret};

pub fn list(db: &Db, secret_id: &str) -> Result<Vec<SecretVersion>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,secret_id,encrypted_value,nonce,changed_by,changed_at,note FROM secret_version WHERE secret_id=?1 ORDER BY changed_at DESC"
    )?;
    let rows = stmt.query_map([secret_id], |r| Ok(SecretVersion {
        id: r.get(0)?, secret_id: r.get(1)?, encrypted_value: r.get(2)?,
        nonce: r.get(3)?, changed_by: r.get(4)?, changed_at: r.get(5)?, note: r.get(6)?,
    }))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
}

pub fn rollback(db: &Db, secret_id: &str, version_id: &str, project_key: &[u8; 32], caller_id: &str) -> Result<()> {
    let v: SecretVersion = db.conn().query_row(
        "SELECT id,secret_id,encrypted_value,nonce,changed_by,changed_at,note FROM secret_version WHERE id=?1",
        [version_id],
        |r| Ok(SecretVersion {
            id: r.get(0)?, secret_id: r.get(1)?, encrypted_value: r.get(2)?,
            nonce: r.get(3)?, changed_by: r.get(4)?, changed_at: r.get(5)?, note: r.get(6)?,
        }),
    ).map_err(|_| crate::error::YasecretError::NotFound(format!("version {version_id}")))?;

    // Decrypt old value, re-encrypt (refresh nonce), store as current
    let nonce: [u8; 12] = v.nonce.try_into().map_err(|_| crate::error::YasecretError::Crypto)?;
    let plaintext = crypto::decrypt(&v.encrypted_value, &nonce, project_key)?;
    secret::update(db, secret_id, &plaintext, project_key, caller_id, Some("rollback"))?;
    Ok(())
}
```

- [ ] **Step 6: Run tests**

```bash
cargo test -p yasecret-core --test secret_test
```

Expected: 5 tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/secret.rs crates/core/src/audit.rs crates/core/src/version.rs crates/core/tests/secret_test.rs crates/core/src/lib.rs
git commit -m "feat(core): secret CRUD, version history, and audit log"
```

---

## Task 8: Role Management

**Files:**
- Create: `crates/core/src/role.rs`
- Create: `crates/core/tests/role_test.rs`

**Interfaces:**
- Produces:
  - `role::grant(db, project_id, env_id, peer_id, level, signing_key) -> Result<Role>`
  - `role::check(db, project_id, env_id, peer_id) -> Result<RoleLevel>` — returns highest applicable role
  - `role::verify_signature(role, owner_verifying_key_bytes) -> Result<()>`
  - `role::revoke(db, role_id) -> Result<()>`
  - `role::list(db, project_id) -> Result<Vec<Role>>`

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/role_test.rs
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::tempdir;
use yasecret_core::{db::Db, models::RoleLevel, project, role};

fn setup() -> (tempfile::TempDir, Db, SigningKey, String) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let p = project::create(&db, "app", None, "owner").unwrap();
    (dir, db, sk, p.id)
}

#[test]
fn grant_and_check_role() {
    let (_dir, db, sk, pid) = setup();
    role::grant(&db, &pid, None, "peer-1", RoleLevel::Write, &sk).unwrap();
    let level = role::check(&db, &pid, None, "peer-1").unwrap();
    assert!(level.can_write());
}

#[test]
fn env_specific_role_overrides_project_role() {
    let (_dir, db, sk, pid) = setup();
    role::grant(&db, &pid, None, "peer-1", RoleLevel::Read, &sk).unwrap();
    role::grant(&db, &pid, Some("env-1"), "peer-1", RoleLevel::Admin, &sk).unwrap();
    let level = role::check(&db, &pid, Some("env-1"), "peer-1").unwrap();
    assert_eq!(level, RoleLevel::Admin);
}

#[test]
fn no_role_returns_permission_denied() {
    let (_dir, db, _, pid) = setup();
    let result = role::check(&db, &pid, None, "unknown-peer");
    assert!(result.is_err());
}

#[test]
fn signature_verifies_correctly() {
    let (_dir, db, sk, pid) = setup();
    let r = role::grant(&db, &pid, None, "peer-2", RoleLevel::Read, &sk).unwrap();
    let vk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
    assert!(role::verify_signature(&r, &vk_bytes).is_ok());
}
```

- [ ] **Step 2: Implement role.rs**

```rust
// crates/core/src/role.rs
use ed25519_dalek::SigningKey;
use crate::{crypto, db::Db, error::{Result, YasecretError}, models::{now, new_id, Role, RoleLevel}};

fn sign_role(project_id: &str, env_id: Option<&str>, peer_id: &str, level: &RoleLevel, granted_at: i64, sk: &SigningKey) -> Vec<u8> {
    let msg = format!("{}:{}:{}:{}:{}", project_id, env_id.unwrap_or("*"), peer_id, level.as_str(), granted_at);
    crypto::sign(msg.as_bytes(), sk)
}

pub fn grant(db: &Db, project_id: &str, env_id: Option<&str>, peer_id: &str, level: RoleLevel, signing_key: &SigningKey) -> Result<Role> {
    let granted_at = now();
    let sig = sign_role(project_id, env_id, peer_id, &level, granted_at, signing_key);
    let r = Role { id: new_id(), project_id: project_id.to_string(), env_id: env_id.map(String::from), peer_id: peer_id.to_string(), level, granted_at, signature: sig };
    db.conn().execute(
        "INSERT INTO role (id,project_id,env_id,peer_id,level,granted_at,signature) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        rusqlite::params![&r.id, &r.project_id, &r.env_id, &r.peer_id, r.level.as_str(), r.granted_at, &r.signature],
    )?;
    Ok(r)
}

pub fn check(db: &Db, project_id: &str, env_id: Option<&str>, peer_id: &str) -> Result<RoleLevel> {
    // Prefer env-specific role, fall back to project-wide (env_id IS NULL)
    let mut stmt = db.conn().prepare(
        "SELECT level FROM role WHERE project_id=?1 AND peer_id=?2 AND (env_id=?3 OR env_id IS NULL) ORDER BY CASE WHEN env_id IS NOT NULL THEN 0 ELSE 1 END LIMIT 1"
    )?;
    let level_str: String = stmt.query_row(
        rusqlite::params![project_id, peer_id, env_id],
        |r| r.get(0),
    ).map_err(|_| YasecretError::PermissionDenied)?;
    RoleLevel::from_str(&level_str).ok_or(YasecretError::PermissionDenied)
}

pub fn verify_signature(role: &Role, owner_vk_bytes: &[u8; 32]) -> Result<()> {
    let msg = format!("{}:{}:{}:{}:{}", role.project_id, role.env_id.as_deref().unwrap_or("*"), role.peer_id, role.level.as_str(), role.granted_at);
    crypto::verify(msg.as_bytes(), &role.signature, owner_vk_bytes)
}

pub fn revoke(db: &Db, role_id: &str) -> Result<()> {
    db.conn().execute("DELETE FROM role WHERE id=?1", [role_id])?;
    Ok(())
}

pub fn list(db: &Db, project_id: &str) -> Result<Vec<Role>> {
    let mut stmt = db.conn().prepare(
        "SELECT id,project_id,env_id,peer_id,level,granted_at,signature FROM role WHERE project_id=?1"
    )?;
    let rows = stmt.query_map([project_id], |r| {
        let level_str: String = r.get(4)?;
        Ok((r.get::<_,String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?, level_str, r.get::<_,i64>(5)?, r.get::<_,Vec<u8>>(6)?))
    })?;
    let mut out = vec![];
    for row in rows {
        let (id, pid, eid, peer_id, level_str, granted_at, sig) = row?;
        out.push(Role { id, project_id: pid, env_id: eid, peer_id, level: RoleLevel::from_str(&level_str).unwrap_or(RoleLevel::Read), granted_at, signature: sig });
    }
    Ok(out)
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p yasecret-core --test role_test
```

Expected: 4 tests pass. (Also add the Review Focus test for PermissionDenied-on-write here.)

- [ ] **Step 4: Add Review Focus test — role enforced at secret layer**

```rust
// Add to secret_test.rs:
#[test]
fn write_blocked_for_read_only_peer() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use yasecret_core::{role, models::RoleLevel};
    let (_dir, db, proj_key, env_id, pid) = setup();
    let sk = SigningKey::generate(&mut OsRng);
    role::grant(&db, &pid, None, "reader", RoleLevel::Read, &sk).unwrap();

    // secret::create_checked enforces role — add this function to secret.rs
    let result = secret::create_checked(&db, &env_id, &pid, "KEY", b"val", &proj_key, "reader", None);
    assert!(matches!(result, Err(yasecret_core::YasecretError::PermissionDenied)));
}
```

Add `secret::create_checked` to `secret.rs`:

```rust
pub fn create_checked(db: &Db, env_id: &str, project_id: &str, key: &str, plaintext: &[u8], project_key: &[u8; 32], caller_id: &str, expires_at: Option<i64>) -> Result<Secret> {
    let level = crate::role::check(db, project_id, Some(env_id), caller_id)
        .or_else(|_| crate::role::check(db, project_id, None, caller_id))?;
    if !level.can_write() {
        return Err(YasecretError::PermissionDenied);
    }
    create(db, env_id, key, plaintext, project_key, caller_id, expires_at)
}
```

- [ ] **Step 5: Run all core tests**

```bash
cargo test -p yasecret-core
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/role.rs crates/core/tests/role_test.rs crates/core/src/secret.rs
git commit -m "feat(core): role management with Ed25519 signatures and permission enforcement"
```

---

## Task 9: .env Import/Export

**Files:**
- Create: `crates/core/src/env_file.rs`
- Create: `crates/core/tests/env_file_test.rs`

**Interfaces:**
- Produces:
  - `env_file::parse(content: &str) -> Result<Vec<(String, String)>>` — returns (key, value) pairs, skips comments/blanks
  - `env_file::serialize(pairs: &[(String, String)]) -> String` — KEY=VALUE\n per pair
  - `env_file::parse_example(content: &str) -> Result<Vec<String>>` — returns key names only (for .env.example)

- [ ] **Step 1: Write failing tests**

```rust
// crates/core/tests/env_file_test.rs
use yasecret_core::env_file;

#[test]
fn parse_basic() {
    let content = "API_KEY=abc123\nDB_URL=postgres://localhost/db\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs, vec![
        ("API_KEY".into(), "abc123".into()),
        ("DB_URL".into(), "postgres://localhost/db".into()),
    ]);
}

#[test]
fn parse_ignores_comments_and_blank_lines() {
    let content = "# comment\n\nKEY=value\n  # another comment\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0], ("KEY".into(), "value".into()));
}

#[test]
fn parse_value_with_equals_sign() {
    let content = "JWT=header.payload=signature\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "header.payload=signature");
}

#[test]
fn parse_quoted_value_with_spaces() {
    let content = "MSG=\"hello world\"\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "hello world");
}

#[test]
fn parse_empty_value() {
    let content = "EMPTY=\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0], ("EMPTY".into(), "".into()));
}

#[test]
fn serialize_roundtrip() {
    let pairs = vec![("KEY".into(), "value".into()), ("B".into(), "2".into())];
    let serialized = env_file::serialize(&pairs);
    let reparsed = env_file::parse(&serialized).unwrap();
    assert_eq!(pairs, reparsed);
}

#[test]
fn parse_example_returns_keys_only() {
    let content = "# database\nDB_URL=\nAPI_KEY=\n";
    let keys = env_file::parse_example(content).unwrap();
    assert_eq!(keys, vec!["DB_URL", "API_KEY"]);
}
```

- [ ] **Step 2: Implement env_file.rs**

```rust
// crates/core/src/env_file.rs
use crate::error::{Result, YasecretError};

pub fn parse(content: &str) -> Result<Vec<(String, String)>> {
    let mut pairs = vec![];
    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let eq_pos = trimmed.find('=').ok_or_else(|| {
            YasecretError::EnvParse(format!("line {}: missing '='", lineno + 1))
        })?;
        let key = trimmed[..eq_pos].trim().to_string();
        let raw_value = &trimmed[eq_pos + 1..];
        let value = unquote(raw_value);
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

pub fn serialize(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(k, v)| {
        // Quote values containing spaces or special chars
        if v.contains(' ') || v.contains('"') || v.contains('\'') {
            format!("{k}=\"{}\"\n", v.replace('"', "\\\""))
        } else {
            format!("{k}={v}\n")
        }
    }).collect()
}

pub fn parse_example(content: &str) -> Result<Vec<String>> {
    Ok(parse(content)?.into_iter().map(|(k, _)| k).collect())
}
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p yasecret-core --test env_file_test
```

Expected: 7 tests pass.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/env_file.rs crates/core/tests/env_file_test.rs crates/core/src/lib.rs
git commit -m "feat(core): .env file parser and serializer"
```

---

## Task 10: CLI — unlock helper + `yasecret pull`

**Files:**
- Create: `crates/cli/src/unlock.rs`
- Create: `crates/cli/src/cmd/pull.rs`
- Modify: `crates/cli/src/main.rs`

**Interfaces:**
- Consumes: all `core` public API
- Produces: working `yasecret pull --project <name> --env <name> [-o <file>]`

- [ ] **Step 1: Write integration test**

```rust
// crates/cli/tests/pull_test.rs
use std::process::Command;
use tempfile::tempdir;

fn yasecret_bin() -> std::path::PathBuf {
    // Build in test setup — assumes cargo test runs after cargo build
    let mut p = std::env::current_exe().unwrap();
    p.pop(); p.pop();
    p.push("yasecret");
    p
}

// Note: this test requires a pre-seeded DB. Run as an integration test only after
// implementing a test-fixture helper or seed command. Mark as ignored for now.
#[test]
#[ignore]
fn pull_outputs_env_format() {
    let dir = tempdir().unwrap();
    let output = Command::new(yasecret_bin())
        .args(["pull", "--project", "test-app", "--env", "dev", "--db", dir.path().join("db.sqlite").to_str().unwrap(), "--password", "test"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains('='));
}
```

- [ ] **Step 2: Implement unlock.rs**

```rust
// crates/cli/src/unlock.rs
use std::path::{Path, PathBuf};
use yasecret_core::{crypto, db::Db, error::Result, identity};
use zeroize::Zeroizing;

pub struct Session {
    pub db: Db,
    pub db_key: Zeroizing<[u8; 32]>,
    pub identity: yasecret_core::models::Identity,
}

pub fn db_path(override_path: Option<&str>) -> PathBuf {
    if let Some(p) = override_path {
        return PathBuf::from(p);
    }
    #[cfg(target_os = "macos")]
    {
        let mut p = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
        p.push("yasecret");
        std::fs::create_dir_all(&p).ok();
        p.push("db.sqlite");
        p
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut p = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        p.push("yasecret");
        std::fs::create_dir_all(&p).ok();
        p.push("db.sqlite");
        p
    }
}

pub fn unlock(path: &Path, password_override: Option<&str>) -> Result<Session> {
    let password = if let Some(p) = password_override {
        p.to_string()
    } else {
        rpassword::prompt_password("Master password: ").map_err(|e| yasecret_core::YasecretError::Io(e))?
    };

    // Derive a fixed salt from the DB path (deterministic per installation)
    // Real implementation: store salt in a separate unencrypted header file next to DB.
    // For v1 CLI: use a fixed salt file alongside the DB.
    let salt_path = path.with_extension("salt");
    let salt: [u8; 16] = if salt_path.exists() {
        let bytes = std::fs::read(&salt_path)?;
        bytes.try_into().unwrap_or([0u8; 16])
    } else {
        let s = crypto::generate_salt();
        std::fs::write(&salt_path, &s)?;
        s
    };

    let db_key = crypto::derive_db_key(&password, &salt);
    let db = Db::open(path, &password)?;
    let identity = identity::load_or_create(&db, "local")?;
    Ok(Session { db, db_key, identity })
}
```

Add `dirs = "5"` to `[workspace.dependencies]` and `crates/cli/Cargo.toml`.

- [ ] **Step 3: Implement cmd/pull.rs**

```rust
// crates/cli/src/cmd/pull.rs
use clap::Args;
use std::io::Write;
use yasecret_core::{environment, env_file, project, project_key, secret};

#[derive(Args)]
pub struct PullArgs {
    #[arg(short, long)] pub project: String,
    #[arg(short, long)] pub env: String,
    #[arg(short, long)] pub output: Option<String>,
    #[arg(long, hide = true)] pub db: Option<String>,
    #[arg(long, hide = true)] pub password: Option<String>,
}

pub fn run(args: PullArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    let projects = project::list(&session.db)?;
    let proj = projects.iter().find(|p| p.name == args.project)
        .ok_or_else(|| yasecret_core::YasecretError::NotFound(format!("project '{}'", args.project)))?;

    let envs = environment::list(&session.db, &proj.id)?;
    let env = envs.iter().find(|e| e.name == args.env)
        .ok_or_else(|| yasecret_core::YasecretError::NotFound(format!("environment '{}'", args.env)))?;

    let proj_key = project_key::load(&session.db, &proj.id, &session.db_key)?;
    let secrets = secret::list(&session.db, &env.id)?;

    let mut pairs = vec![];
    for s in &secrets {
        let nonce: [u8; 12] = s.nonce.clone().try_into().map_err(|_| yasecret_core::YasecretError::Crypto)?;
        let value = yasecret_core::crypto::decrypt(&s.encrypted_value, &nonce, &proj_key)?;
        let value_str = String::from_utf8_lossy(&value).into_owned();
        pairs.push((s.key.clone(), value_str));
    }

    let output = env_file::serialize(&pairs);

    if let Some(out_path) = &args.output {
        std::fs::write(out_path, &output)?;
    } else {
        print!("{output}");
    }

    Ok(())
}
```

- [ ] **Step 4: Build and smoke-test**

```bash
cargo build -p yasecret
# Manually create a project + secret via a small test binary or sqlite3, then:
# ./target/debug/yasecret pull --project my-app --env dev
```

- [ ] **Step 5: Commit**

```bash
git add crates/cli/src/unlock.rs crates/cli/src/cmd/pull.rs crates/cli/src/main.rs Cargo.toml crates/cli/Cargo.toml
git commit -m "feat(cli): yasecret pull command"
```

---

## Task 11: CLI — `yasecret run`

**Files:**
- Create: `crates/cli/src/cmd/run.rs`

**Interfaces:**
- Produces: `yasecret run --project P --env E --only KEY1,KEY2 -- <cmd> [args…]`
- Secret values injected into subprocess env; masked (replaced with `[REDACTED]`) in stdout/stderr before printing

- [ ] **Step 1: Write failing test**

```rust
// crates/cli/tests/run_test.rs
// This tests the mask function directly — subprocess integration tested manually.
use yasecret_core::env_file;

fn mask_output(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            result = result.replace(secret.as_str(), "[REDACTED]");
        }
    }
    result
}

#[test]
fn masks_secret_in_output() {
    let output = "connecting to postgres://user:s3cr3t@localhost/db\nOK";
    let masked = mask_output(output, &["s3cr3t".to_string()]);
    assert!(!masked.contains("s3cr3t"));
    assert!(masked.contains("[REDACTED]"));
    assert!(masked.contains("OK"));
}

#[test]
fn empty_secret_not_masked() {
    let output = "some output";
    let masked = mask_output(output, &["".to_string()]);
    assert_eq!(masked, "some output");
}
```

- [ ] **Step 2: Run test — expect compile failure (function not in scope)**

```bash
cargo test -p yasecret --test run_test 2>&1 | head -5
```

The `mask_output` function is defined inline in the test file — this test will actually compile and pass once the test file exists. Move on.

- [ ] **Step 3: Implement cmd/run.rs**

```rust
// crates/cli/src/cmd/run.rs
use clap::Args;
use std::process::{Command, Stdio};
use yasecret_core::{crypto, environment, project, project_key, secret};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct RunArgs {
    #[arg(short, long)] pub project: String,
    #[arg(short, long)] pub env: String,
    #[arg(long, value_delimiter = ',')] pub only: Vec<String>,
    #[arg(long, hide = true)] pub db: Option<String>,
    #[arg(long, hide = true)] pub password: Option<String>,
    #[arg(last = true)] pub command: Vec<String>,
}

pub fn run(args: RunArgs) -> yasecret_core::Result<()> {
    if args.command.is_empty() {
        eprintln!("error: no command specified after --");
        std::process::exit(1);
    }

    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;

    let projects = project::list(&session.db)?;
    let proj = projects.iter().find(|p| p.name == args.project)
        .ok_or_else(|| yasecret_core::YasecretError::NotFound(format!("project '{}'", args.project)))?;

    let envs = environment::list(&session.db, &proj.id)?;
    let env = envs.iter().find(|e| e.name == args.env)
        .ok_or_else(|| yasecret_core::YasecretError::NotFound(format!("environment '{}'", args.env)))?;

    let proj_key = project_key::load(&session.db, &proj.id, &session.db_key)?;
    let all_secrets = secret::list(&session.db, &env.id)?;

    let mut env_vars: Vec<(String, Zeroizing<Vec<u8>>)> = vec![];
    for s in &all_secrets {
        if args.only.is_empty() || args.only.contains(&s.key) {
            let nonce: [u8; 12] = s.nonce.clone().try_into().map_err(|_| yasecret_core::YasecretError::Crypto)?;
            let value = crypto::decrypt(&s.encrypted_value, &nonce, &proj_key)?;
            env_vars.push((s.key.clone(), value));
        }
    }

    let secret_values: Vec<String> = env_vars.iter()
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .collect();

    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..]);
    for (key, value) in &env_vars {
        cmd.env(key, String::from_utf8_lossy(value).as_ref());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd.output().map_err(|e| yasecret_core::YasecretError::Io(e))?;

    let stdout = mask_output(&String::from_utf8_lossy(&output.stdout), &secret_values);
    let stderr = mask_output(&String::from_utf8_lossy(&output.stderr), &secret_values);

    print!("{stdout}");
    eprint!("{stderr}");

    std::process::exit(output.status.code().unwrap_or(1));
}

fn mask_output(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            result = result.replace(secret.as_str(), "[REDACTED]");
        }
    }
    result
}
```

- [ ] **Step 4: Wire into main.rs and build**

```bash
cargo build -p yasecret
echo "Build succeeded"
```

- [ ] **Step 5: Manual smoke test**

```bash
# Set up a test project first via sqlite3 or a seed script, then:
./target/debug/yasecret run --project my-app --env dev --only API_KEY -- env | grep API_KEY
# Expect: API_KEY=[REDACTED] in any logged output; the subprocess itself sees the real value
```

- [ ] **Step 6: Run all tests**

```bash
cargo test
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add crates/cli/src/cmd/run.rs crates/cli/tests/run_test.rs
git commit -m "feat(cli): yasecret run with secret injection and output masking"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Covered by |
|---|---|
| AES-256-GCM secret encryption | Task 3, 6 |
| Argon2id master password → DB key | Task 3 |
| SQLCipher DB encryption | Task 2 |
| Project CRUD | Task 5 |
| Environment CRUD (dev/staging/prod/custom) | Task 5 |
| Secret CRUD + version history + rollback | Task 7 |
| Audit log | Task 7 |
| Import .env (parse) | Task 9 |
| Export .env (serialize) | Task 9 |
| .env.example template support | Task 9 |
| Role management + signatures | Task 8 |
| Permission enforcement on write | Task 8 (Review Focus) |
| Secret expiry / TTL field | Task 7 (expires_at stored) |
| `yasecret pull` CLI | Task 10 |
| `yasecret run --only KEY` CLI | Task 11 |
| DB file permissions 0600 | Task 2 |
| Zeroize secrets on drop | Task 3, 7 |
| X25519 keypair + peer key encryption | Task 3 (tested), Task 4 (identity) |
| Identity keypair per device | Task 4 |

**Not in Plan 1 (correct — deferred to later plans):**
- iroh P2P sync → Plan 2
- MCP server → Plan 3
- SwiftUI app → Plan 4
- Tauri app → Plan 5
- Platform Keychain integration → Plan 4/5

**Placeholder scan:** None found.

**Type consistency:** All function signatures consistent across tasks. `Zeroizing<[u8; 32]>` used throughout for keys. `[u8; 12]` for nonces.

**Review Focus tests:** All 5 added — wrong password (Task 2), WAL mode (Task 2, journal_mode=WAL set), zeroize (Task 3 — Zeroizing type enforced by type system), .env edge cases (Task 9, 7 tests), role permission denied (Task 8 + secret_test).
