# yasecret — Design Spec

**Date:** 2026-10-15  
**Status:** Approved for implementation

---

## Overview

`yasecret` is a local-first, open-source secrets and environment variable manager for macOS (SwiftUI), Windows, and Linux (Tauri). It stores secrets encrypted on-device and supports optional P2P sync between peers via [iroh](https://iroh.computer/). It integrates with Claude Code via an MCP server.

It is a spiritual clone of EnvManager, excluding cloud platform sync and proxy functions.

---

## Repo Structure

Cargo workspace monorepo:

```
yasecret/
├── Cargo.toml              # workspace
├── crates/
│   ├── core/               # Rust library — storage, encryption, business logic
│   ├── sync/               # iroh P2P layer (thin wrapper around iroh + iroh-docs)
│   └── cli/                # Rust binary: `yasecret pull`, `yasecret run`, `yasecret mcp`
├── macos/                  # Xcode project — SwiftUI app, consumes core via UniFFI
├── desktop/                # Tauri app — React + Tailwind frontend, Rust backend = core + sync
└── docs/
```

**Key insight:** Tauri's backend is native Rust, so `desktop/` calls `core/` and `sync/` directly as crates — no FFI. Only `macos/` requires UniFFI to bridge Swift ↔ Rust.

---

## Data Model

Single SQLite database, encrypted with SQLCipher. Stored at:
- macOS: `~/Library/Application Support/yasecret/db.sqlite`
- Linux: `~/.local/share/yasecret/db.sqlite`
- Windows: `%APPDATA%\yasecret\db.sqlite`

### Schema

```sql
-- Local device identity
CREATE TABLE identity (
    id          TEXT PRIMARY KEY,   -- iroh node public key (base32)
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

-- Known peers (from P2P connections)
CREATE TABLE peer (
    id          TEXT PRIMARY KEY,   -- iroh node public key
    name        TEXT NOT NULL,
    first_seen  INTEGER NOT NULL
);

CREATE TABLE project (
    id          TEXT PRIMARY KEY,   -- UUID
    name        TEXT NOT NULL,
    description TEXT,
    created_at  INTEGER NOT NULL,
    owner_id    TEXT NOT NULL       -- identity.id or peer.id
);

CREATE TABLE environment (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES project(id),
    name        TEXT NOT NULL,      -- dev | staging | production | custom
    created_at  INTEGER NOT NULL
);

CREATE TABLE secret (
    id              TEXT PRIMARY KEY,
    env_id          TEXT NOT NULL REFERENCES environment(id),
    key             TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,  -- AES-256-GCM, encrypted with project key
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    created_by      TEXT NOT NULL,  -- identity or peer id
    expires_at      INTEGER         -- nullable; TTL for rotation reminders
);

CREATE TABLE secret_version (
    id              TEXT PRIMARY KEY,
    secret_id       TEXT NOT NULL REFERENCES secret(id),
    encrypted_value BLOB NOT NULL,
    changed_by      TEXT NOT NULL,
    changed_at      INTEGER NOT NULL,
    note            TEXT
);

CREATE TABLE project_key (
    project_id      TEXT PRIMARY KEY REFERENCES project(id),
    encrypted_key   BLOB NOT NULL   -- project AES key, encrypted with local DB key
);

CREATE TABLE peer_project_key (
    project_id      TEXT NOT NULL,
    peer_id         TEXT NOT NULL,
    encrypted_key   BLOB NOT NULL,  -- project AES key, encrypted with peer's X25519 public key
    PRIMARY KEY (project_id, peer_id)
);

-- Role: signed by project owner keypair
CREATE TABLE role (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    env_id      TEXT,               -- NULL = all environments
    peer_id     TEXT NOT NULL,
    level       TEXT NOT NULL,      -- read | write | admin
    granted_at  INTEGER NOT NULL,
    signature   BLOB NOT NULL       -- owner signs (peer_id || project_id || env_id || level || granted_at)
);

CREATE TABLE audit_entry (
    id          TEXT PRIMARY KEY,
    peer_id     TEXT NOT NULL,      -- who performed the action
    action      TEXT NOT NULL,      -- created_secret | updated_secret | deleted_secret | etc.
    target_type TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    timestamp   INTEGER NOT NULL,
    detail      TEXT                -- JSON blob
);

-- iroh Doc mapping per shared project
CREATE TABLE sync_doc (
    project_id  TEXT PRIMARY KEY REFERENCES project(id),
    doc_id      TEXT NOT NULL,      -- iroh Doc ID
    ticket      TEXT                -- last generated DocTicket (for re-inviting)
);

-- MCP TOFU session tokens
CREATE TABLE mcp_session (
    token       TEXT PRIMARY KEY,
    granted_at  INTEGER NOT NULL,
    label       TEXT                -- e.g. "Claude Code"
);
```

---

## Encryption

### Layers

1. **DB-level:** SQLCipher encrypts the entire database file with a 256-bit key.
2. **Secret-level:** Each secret value is also AES-256-GCM encrypted with a per-project key (defense in depth; protects secrets if DB key is ever exported for backup).
3. **P2P transport:** iroh uses QUIC with TLS — encrypted in transit automatically.

### Key derivation

```
master_password
    → Argon2id (time=3, mem=64MB, parallelism=4, salt=random 16B stored in db header)
    → 256-bit DB key
    → SQLCipher opens DB
    → project_key table contains per-project AES keys encrypted with DB key
```

### Platform unlock (after first entry)

| Platform | Storage | Auth |
|---|---|---|
| macOS | Keychain (kSecClassGenericPassword) | Touch ID via LocalAuthentication |
| Linux | libsecret / Secret Service | system unlock |
| Windows | DPAPI (via Tauri plugin) | Windows Hello |

Master password → DB key stored in platform keychain after first successful unlock. App unlocks silently on subsequent opens (biometric prompt optional).

---

## P2P Sync

### Stack

- **iroh-net:** QUIC transport, NAT hole-punching, relay nodes for WAN, mDNS for LAN
- **iroh-docs:** CRDT key-value store, last-write-wins by timestamp, per-entry author signatures

### What syncs

| Syncs via iroh-docs | Local only |
|---|---|
| Secret keys + encrypted values | DB key / master password |
| Secret version history | MCP session tokens |
| Environment structure | Audit entries (each peer keeps own log) |
| Project metadata | Platform keychain entries |
| Signed role assignments | |
| `peer_project_key` entries (encrypted per-peer) | |

### Sharing flow

1. Owner opens project → clicks **Share**
2. `core` generates a random AES-256 project key (if not already shared)
3. `sync` creates an iroh Doc, stores `doc_id` in `sync_doc`
4. App asks for invitee's iroh node public key (displayed as QR or copyable string in app)
5. `core` encrypts project key with invitee's X25519 public key → stored in `peer_project_key`
6. `sync` generates a `DocTicket` (includes relay hints, doc ID)
7. Owner sends DocTicket to invitee out-of-band (share sheet, copy/paste)
8. Invitee pastes DocTicket → iroh joins Doc → syncs encrypted blobs
9. Invitee decrypts project key from `peer_project_key` using own private key → can read secrets

### Role sync

Roles are iroh-doc entries with key `role/{peer_id}/{env_id_or_*}`. Each role record includes an Ed25519 signature from the project owner. Peers verify the signature on import — forged roles are rejected. Owner revokes by writing a `role/{peer_id}/revoked` entry (also signed).

### Conflict resolution

iroh-docs uses last-write-wins per entry by author timestamp. Version history (`secret_version`) accumulates all writes from all peers — no entries discarded.

### Offline

iroh-docs buffers writes locally. Sync resumes automatically when peers reconnect. App is fully functional offline.

---

## Feature Scope (v1)

### In scope

- Project CRUD + environment management (dev/staging/prod/custom)
- Secret CRUD with masked values in UI (show/hide toggle)
- Version history per secret (full history, rollback)
- Import `.env` file (paste or drag-drop)
- Export `.env` file for selected environment
- `.env.example` template per project (keys, no values)
- Audit log (local per-device, read-only UI)
- Secret expiry / rotation reminders (optional TTL per secret, local notification)
- P2P share via DocTicket (LAN + WAN)
- Signed role assignments (read / write / admin per project or per environment)
- Keychain integration (platform-native unlock)
- CLI: `yasecret pull`, `yasecret run --only KEY`
- MCP server: `yasecret mcp` (Claude Code integration)

### Out of scope (v1)

- Cloud platform sync (Vercel, Railway, Render, etc.)
- Proxy functions
- Web dashboard
- Self-hosted relay server (uses iroh's public relays)

---

## UI — macOS (SwiftUI)

3-column NavigationSplitView:

```
┌──────────────┬──────────────────┬───────────────────────────────┐
│  Projects    │  Environments    │  Secrets                      │
│              │                  │                               │
│ ▶ my-app     │ ● dev            │  KEY           VALUE          │
│   api-svc    │   staging        │  DATABASE_URL  ••••••  👁 📋  │
│              │   production     │  API_KEY       ••••••  👁 📋  │
│   + New      │   + New Env      │  STRIPE_KEY  ⚠️ expires 7d   │
│              │                  │                               │
│              │                  │  [Import .env]  [Export .env] │
└──────────────┴──────────────────┴───────────────────────────────┘
│ Audit Log │ Share │ Roles │ Settings │
```

- Lock icon in toolbar → re-lock app (clears in-memory key)
- Share sheet → generates DocTicket + QR for peer public key exchange
- Audit log in bottom sheet
- Touch ID prompt on launch (or master password fallback)

## UI — Tauri (Windows/Linux)

React + Tailwind, identical layout. Same feature parity. Tauri v2.

---

## CLI

```bash
# Write .env to stdout or file
yasecret pull --project my-app --env production
yasecret pull --project my-app --env production -o .env

# Run command with secrets injected; masks values in output
yasecret run --project my-app --env dev --only DATABASE_URL,API_KEY -- npm start

# Start MCP server (stdio)
yasecret mcp
```

Binary installed to `/usr/local/bin/yasecret` (or via Homebrew formula for macOS).

---

## MCP Server (Claude Integration)

Runs as stdio MCP server. Claude Code adds to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "yasecret": {
      "command": "yasecret",
      "args": ["mcp"]
    }
  }
}
```

### TOFU (Trust On First Use)

First connection: app shows system notification "Claude Code wants access to yasecret". User approves in app → generates session token stored in `mcp_session` table. Subsequent connections present token — auto-approved. Revokable in app Settings → Integrations.

### MCP Tools

| Tool | Description | Requires `get_secret` enabled |
|---|---|---|
| `list_projects()` | Project + environment names | No |
| `list_secret_keys(project, env)` | Key names only, no values | No |
| `run_with_secrets(project, env, keys[], cmd)` | Run cmd with secrets injected; masks in output returned to Claude | No |
| `get_secret(project, env, key)` | Returns plaintext value | Yes (opt-in in Settings) |
| `import_env(project, env, content)` | Import .env content into project | No |

`get_secret` is disabled by default. User enables it in Settings → Integrations → "Allow Claude to read secret values".

---

## Crate Dependencies

| Crate | Dependency | Purpose |
|---|---|---|
| `core` | `rusqlite` + `rusqlite-bundled-sqlcipher` | Encrypted SQLite |
| `core` | `aes-gcm` | Secret-level encryption |
| `core` | `argon2` | Master password → DB key |
| `core` | `x25519-dalek` | Peer key exchange |
| `core` | `ed25519-dalek` | Role signature verification |
| `core` | `serde`, `serde_json` | Serialization |
| `core` | `uuid` | ID generation |
| `sync` | `iroh`, `iroh-docs` | P2P sync |
| `cli` | `clap` | CLI argument parsing |
| `cli` | `rmcp` | MCP server (stdio) |
| `macos` (build) | `uniffi` | Swift ↔ Rust FFI |
| `desktop` | `tauri` v2 | Desktop shell |
| `desktop` frontend | React, Tailwind, Zustand | UI + state |

---

## Security Considerations

- Secrets never logged, never in error messages
- CLI `run` command masks known secret values in all subprocess output (regex replacement before printing)
- MCP `run_with_secrets` output sanitized before returning to Claude
- iroh peer connections use mutual TLS; peers are identified by keypair, not hostname
- DB file permissions: 0600
- In-memory keys zeroed on app lock or process exit (using `zeroize` crate)
- Role signatures prevent privilege escalation over P2P
