# Plan 6 — Windows app (Tauri v2)

**Goal:** Ship Yasecret on Windows with the same features and three-column layout as the macOS app, built as an installer by GitHub Actions on a Windows runner.

**Spec:** docs/superpowers/specs/2026-10-15-yasecret-design.md, "UI — Tauri (Windows/Linux)": React + Tailwind, identical layout, same feature parity, Tauri v2.

## Decisions (2026-10-16, with the user)
- Windows installers are built by GitHub Actions on `windows-latest` (needs the repo on GitHub; ask before pushing).
- No Windows machine available: the Tauri app is click-tested on macOS (same React UI and Rust backend); the user tries the installer.

## Architecture
- `desktop/` — Vite + React + TypeScript + Tailwind v4 frontend.
- `desktop/src-tauri/` — Tauri 2 backend, a workspace member. It depends on `crates/ffi` as a normal Rust library and keeps one `YasecretSession` in state, so every feature and the sync engine are shared with the Mac app instead of re-implemented.
- `crates/ffi` records gain optional `serde` derives (camelCase) behind a `serde` feature so Tauri commands can return them directly.
- Platform pieces: `keyring` (Windows Credential Manager / macOS Keychain) for "remember password on this device"; idle auto-lock (no portable screen-lock hook); `tauri-plugin-deep-link` for `yasecret://join`; `tauri-plugin-single-instance` so a link reaches the running app; dialog, clipboard (auto-clear after 60 s) and notification plugins.
- Windows SQLCipher: `rusqlite` with `bundled-sqlcipher-vendored-openssl` on `cfg(windows)`.

## Global constraints
- No `Co-Authored-By` lines in commits.
- Same debug hooks as macOS: `YASECRET_DB_PATH` + `YASECRET_DEV_PASSWORD` open a throwaway vault (debug builds only).
- Rust tests and the macOS Swift suite stay green.

## Steps
1. ffi: `lib` crate type, serde feature; workspace member for the Tauri crate; Windows rusqlite feature.
2. Tauri backend: commands mirroring every `YasecretSession` method the Mac app uses, plus unlock/lock, remember-password, deep-link and revision events.
3. Frontend: unlock screen; projects / environments / variables columns with the same headers, footers, empty states; editor, import wizard, export, history, activity, compare, share and join sheets; search, shortcuts (Ctrl+N/F/I/E, Ctrl+Shift+L).
4. Click-test on macOS with a test vault (screenshots).
5. `.github/workflows/windows.yml`: build NSIS + MSI installers with `tauri-apps/tauri-action`, upload as artifacts.
