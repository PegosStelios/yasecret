# Plan 5 — macOS app feature parity (EnvManager gap close)

**Goal:** Make the macOS app a complete daily driver: everything the Rust core/CLI already does is reachable from the GUI, plus the EnvManager features that fit our local-first P2P design.

**Spec:** docs/superpowers/specs/2026-10-15-yasecret-design.md (v1 scope; cloud-platform sync and proxy functions stay out of scope).

**Research source:** envmanager.com homepage + docs (variables, secrets, importing, environments, team, roles, CLI commands/run/dev/templates/validation/export formats), read 2026-10-15.

## Global constraints
- No `Co-Authored-By` / attribution lines in commits (user rule).
- Rust changes: TDD in `crates/core/tests` / `crates/ffi` tests; `cargo test --workspace` green before commit.
- After FFI changes: `cargo build -p yasecret-ffi` then regenerate `macos/Generated/` with uniffi-bindgen.
- Swift: `xcodebuild test` green; rebuild + launch app after each phase for the user to try.
- New DB columns via additive `ALTER TABLE` guarded by `PRAGMA table_info` (existing vaults must keep opening).

## Phase 1 — daily usability
- core: `secret.is_secret` column (default 1), `secret::set_kind`, `secret::rename_key`, `env_file::parse_any` (.env with `export ` prefix, or JSON object), `env_file::looks_secret(key)`, `environment::clone`, `environment::secret_count`.
- ffi: `FfiSecret{is_secret, updated_at}`, `FfiEnvironment{secret_count}`, `create_secret(..., is_secret)`, `edit_secret(project, secret, new_key?, new_value?, is_secret?)`, `clone_environment`, `preview_import` → rows {key, value, exists, suggested_secret}, `apply_import(items, overwrite)` → {added, updated, skipped} in one transaction.
- app: variables table (key / value / type / updated) with search, plain values visible + secrets masked, add/edit sheet (key validation, secret toggle auto-suggested), double-click to edit, context menu (edit, copy key, copy value, delete w/ confirm), empty state with Add/Import; import wizard (paste / browse / drag-drop → preview with new/exists + secret toggles + skip/overwrite); clone environment; default Development/Staging/Production on new project; variable counts per environment; delete confirmations; lock button + auto-lock on sleep/screen lock.

## Phase 2 — sharing in the app
- Both modes (user decision):
  - **Invite link (default):** owner → Share → single-use link (`yasecret://join?…`) = doc ticket + one-time key that wraps the project key; expires 24h. Teammate → Join → paste → synced.
  - **Secure invite:** teammate copies their device code (X25519 pubkey; copy button + QR) → owner pastes → ticket bound to that key.
- ffi: async-safe wrappers around `yasecret-sync` (own tokio runtime inside the session), `share_invite_link`, `share_with_peer`, `join`, `device_code`, `list_peers`, `sync_status`, `revoke_peer`.
- app: Share sheet (mode toggle, copy/QR), Join sheet (paste link), Members list per project (role read/write/admin, revoke), sync status indicator, `is_secret` synced.

## Phase 3 — trust & history
- Version history per variable (list, reveal old value, rollback) — core already has `version::list/rollback`.
- Audit log view (filter by project) — core `audit::list`.
- Compare environments: side-by-side diff (missing / different / same).

## Phase 4 — extras
- Export formats: .env, JSON, docker-compose, k8s Secret, k8s ConfigMap; choose variables; preview before save.
- `.env.example` generation per environment.
- Expiry: set expiry in editor, badge on expiring/expired rows, local notification.
- Menu bar commands + keyboard shortcuts (⌘N add, ⌘F search, ⌘I import, ⌘E export).
