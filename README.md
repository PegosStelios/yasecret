# Yasecret

A local-first secrets manager for `.env` files. Your variables live in an encrypted vault on your own machine, sync directly between your team's devices without a server, and can be used by scripts and AI coding agents without being pasted anywhere.

- **macOS app** (SwiftUI) and **Windows app** (Tauri), sharing one Rust core.
- **CLI** for pulling, pushing and diffing `.env` files, keeping one live while you develop, and running commands with secrets injected.
- **MCP server** so Claude Code can use secrets without seeing their values.

![Yasecret on macOS](docs/screenshots/macos-main.png)

> Status: early (0.1). It works end to end and is covered by tests, but it has not had an external security review. Don't trust it with production credentials you can't rotate.

## Features

- **Projects, environments, variables.** Default development / staging / production environments, clone an environment, compare two side by side.
- **Plain and secret variables.** Secrets stay masked until revealed; plain values are shown. Names like `*_KEY`, `*_TOKEN`, `*_SECRET`, `*PASSWORD*` are flagged as secrets automatically.
- **Import** `.env` or JSON (paste, drop a file, or pick one) with a preview: new vs existing keys, skip or overwrite, per-row secret toggle.
- **Export** as `.env`, JSON, Docker Compose, Kubernetes Secret / ConfigMap, or a keys-only `.env.example`.
- **History** of every value with one-click restore, plus an **activity log** (adds, edits, deletes, reveals, synced changes).
- **Expiry dates** on variables with reminders a week before.
- **Sharing without a server.** Devices sync peer-to-peer; invite teammates with edit or view-only access.
- **Locking.** Touch ID / Keychain on macOS; Windows Hello on Windows (the remembered password lives in Credential Manager and Yasecret asks for Hello before using it); auto-lock on sleep or screen lock (macOS) or after 10 minutes idle (Windows). Copied secrets are cleared from the clipboard after 60 seconds.

## Screenshots

| Sharing a project | Importing a `.env` |
|---|---|
| ![Share sheet with an invite link and the people list](docs/screenshots/macos-share.png) | ![Import preview marking new and existing keys and detected secrets](docs/screenshots/macos-import.png) |

The desktop app (Tauri, the Windows build) has the same layout. Shown here running on macOS:

![Tauri desktop app](docs/screenshots/desktop-tauri.png)

## Install

Tagged versions are published on the [Releases](../../releases) page: a Windows installer (`*-setup.exe` per-user, `.msi` for managed installs) and a macOS app for Apple silicon and Intel (`Yasecret-macOS.zip`). Between releases, every push to `main` builds Windows installers you can download from the latest [Windows build](../../actions/workflows/windows.yml) run under *Artifacts*.

**Windows.** The app checks for updates on launch and offers to install them. Updates are signed with Yasecret's update key and verified before they're applied. The installer itself isn't code-signed yet, so SmartScreen will warn on first install; choose *More info → Run anyway*.

**macOS.** The app isn't signed with a Developer ID yet, so after unzipping, right-click *Yasecret.app → Open* the first time (or run `xattr -dr com.apple.quarantine Yasecret.app`). You can also build from source (below).

**Cutting a release:** bump `version` in `desktop/src-tauri/tauri.conf.json`, then push a matching tag (`git tag v0.2.0 && git push origin v0.2.0`). The [Release](.github/workflows/release.yml) workflow builds both apps into a draft release; publishing the draft makes the update available. It needs the `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` secrets; adding `APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_TEAM_ID`, `APPLE_ID` and `APPLE_APP_PASSWORD` turns on Developer ID signing and notarization for the Mac app.

## How sharing works

Each project you share becomes a replicated document synced over [iroh](https://iroh.computer) (QUIC with NAT traversal and public relays). There is no Yasecret server; devices talk directly whenever both are open and unlocked.

- Values are encrypted with a per-project AES-256-GCM key before they leave your machine. The vault file is encrypted with SQLCipher, and each project key is wrapped with a key derived from your master password using Argon2id.
- **Invite link:** single use, expires after 24 hours. It carries a one-time key that unwraps the project key, so send it over a private channel.
- **Device-bound invite:** your teammate sends you their device code (an X25519 public key); the project key is encrypted to that device only, so the link is safe to send anywhere.
- Every change is accepted only if its author holds an access grant signed by the project owner (Ed25519), and joiners must prove they hold the project key before they're admitted. Holding the doc ticket alone gets you nothing.
- **Removing someone** rotates the project key and re-encrypts every value, so they can't read anything written afterwards. **Stop sharing** does the same for everyone.
- Conflicts resolve last-write-wins per variable; deletions sync as tombstones; every overwritten value stays in history.

### Always-on peer

Devices only sync while they're online at the same time. To keep a project reachable when your laptop is closed, run a relay on any machine that stays on (a server, a NAS, a Raspberry Pi):

```bash
yasecret relay code          # prints this relay's code
# In Yasecret: Share → Always-on peer → paste the code → Add, then run the command it gives you:
yasecret relay add 'yasecret://relay?...'
yasecret relay               # keep this running (systemd, launchd, tmux…)
```

The relay gets a read-only copy of the project document. It stores encrypted values and never receives the project key, but it can see what the document itself shows: project, environment and variable names, and member device names. New invite links include the relay, so teammates can join and pick up changes while the owner is offline; the owner admits them the next time they're online (up to a week after the invite expires). Removing a relay stops members from dialing it, but it keeps what it already stored and devices that remember it may keep syncing with it; to cut a relay off completely, stop sharing and share the project again.

Limitations: without a relay, the owner's device must be online for someone to join. Only the owner can invite or change access. Activity logs are kept per device.

## CLI

```bash
cargo install --path crates/cli        # installs `yasecret`

yasecret pull --project my-app --env development -o .env
yasecret push --project my-app --env development -i .env   # adds new keys; --overwrite to replace, --dry-run to preview
yasecret diff --project my-app --env development -i .env   # key names only; exits 1 when they differ (CI-friendly)
yasecret dev  --project my-app --env development -o .env   # rewrites .env whenever the environment changes
yasecret run  --project my-app --env development --only DATABASE_URL -- npm run migrate
yasecret peers self                    # this device's code, for device-bound invites
yasecret share --project my-app        # prints an invite link and stays online until you stop it
yasecret join 'yasecret://join?...'
```

`push` stores names that look sensitive (`*_KEY`, `*PASSWORD*`, `*TOKEN*`…) as secrets and the rest as plain variables. `dev` also picks up changes the desktop app syncs in from teammates. `run` injects only the variables you name with `--only`, and masks their values in the command's output. The CLI prompts for your master password. While the desktop app is running it owns the sync node, so share and join from the app instead.

## Claude Code (MCP)

```json
{
  "mcpServers": {
    "yasecret": { "command": "yasecret", "args": ["mcp"] }
  }
}
```

Tools: `list_projects`, `list_secret_keys` (names only), `run_with_secrets` (injects values and masks them in the output returned to Claude), `import_env`, and `get_secret`, which returns a plaintext value only when `YASECRET_MCP_ALLOW_PLAINTEXT=1` is set. The macOS app notifies you when an MCP client gets access.

Known limitation: `yasecret mcp` currently prompts for the master password on a terminal, so it can't unlock when an MCP client launches it in the background. Unattended unlock is on the roadmap.

## Build from source

Requirements: Rust (stable), and for the apps either Xcode 15+ with [XcodeGen](https://github.com/yonaskolb/XcodeGen) (macOS) or Node 22 + pnpm (Windows/Linux desktop).

```bash
cargo test --workspace --exclude yasecret-desktop     # core, sync, CLI, FFI

# macOS app
cd macos && xcodegen generate && cd ..
xcodebuild -project macos/Yasecret.xcodeproj -scheme Yasecret build

# Desktop app (Tauri)
cd desktop && pnpm install
pnpm tauri dev                         # run locally
pnpm tauri build                       # installers for the current OS
```

The macOS build signs with an Apple Development identity (see `macos/project.yml`); change `DEVELOPMENT_TEAM` to your own team or set signing to automatic.

## Layout

| Path | What |
|---|---|
| `crates/core` | Vault: SQLCipher storage, crypto, projects, environments, variables, history, audit log, `.env` parsing and export |
| `crates/sync` | Peer-to-peer sync service on iroh: invites, grants, reconcile |
| `crates/ffi` | `YasecretSession`, the API both apps use (UniFFI bindings for Swift, plain Rust for Tauri) |
| `crates/cli` | `yasecret` CLI and MCP server |
| `macos/` | SwiftUI app |
| `desktop/` | Tauri v2 app (React + TypeScript + Tailwind) for Windows; Linux builds but is untested |
| `docs/superpowers/` | Design spec and implementation plans |

## License

Yasecret is free software under the [GNU Affero General Public License v3.0 or later](LICENSE). You can use, study, modify and share it; if you distribute it, or run a modified version as a network service, you must make your source code available under the same license.
