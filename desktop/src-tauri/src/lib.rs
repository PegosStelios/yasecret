use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use serde::Serialize;
use tauri::{Emitter, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use yasecret_ffi::{
    FfiActivity, FfiDiffRow, FfiEnvironment, FfiError, FfiImportItem, FfiImportRow, FfiImportSummary, FfiMember, FfiRelay,
    FfiProject, FfiSecret, FfiSyncStatus, FfiVersion, YasecretSession,
};

type CmdResult<T> = Result<T, String>;

struct Vault {
    db_path: String,
    session: Arc<Mutex<Option<Arc<YasecretSession>>>>,
    /// Why background sync failed to start, if it did.
    sync_error: Arc<Mutex<Option<String>>>,
}

impl Vault {
    fn session(&self) -> CmdResult<Arc<YasecretSession>> {
        self.session.lock().unwrap().clone().ok_or_else(|| "The vault is locked".to_string())
    }
}

fn message(e: FfiError) -> String {
    match e {
        FfiError::WrongPassword => "Wrong password — try again".into(),
        FfiError::NotFound { msg } => format!("Not found: {msg}"),
        FfiError::PermissionDenied => "You have view-only access to this shared project, so you can't change it".into(),
        FfiError::Crypto => "Couldn't decrypt this value with the vault key".into(),
        FfiError::Io { msg } => format!("File error: {msg}"),
        FfiError::Db { msg } => format!("Database error: {msg}"),
        FfiError::Parse { msg } | FfiError::Sync { msg } => msg,
    }
}

/// Runs vault work off the UI thread; SQLCipher calls and P2P joins can take a while.
async fn blocking<T: Send + 'static>(
    vault: &State<'_, Vault>,
    f: impl FnOnce(Arc<YasecretSession>) -> Result<T, FfiError> + Send + 'static,
) -> CmdResult<T> {
    let session = vault.session()?;
    tauri::async_runtime::spawn_blocking(move || f(session).map_err(message))
        .await
        .map_err(|e| e.to_string())?
}

fn keyring_entry(db_path: &str) -> Option<keyring::Entry> {
    use sha2::Digest;
    let account = hex::encode(&sha2::Sha256::digest(db_path.as_bytes())[..8]);
    keyring::Entry::new("com.yasecret.desktop", &format!("master-password-{account}")).ok()
}

fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Desktop".into())
}

// ── Unlock / lock ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultState {
    first_run: bool,
    unlocked: bool,
    has_remembered: bool,
    dev_password: bool,
}

#[tauri::command]
fn vault_state(vault: State<'_, Vault>) -> VaultState {
    VaultState {
        first_run: !Path::new(&vault.db_path).exists(),
        unlocked: vault.session.lock().unwrap().is_some(),
        has_remembered: keyring_entry(&vault.db_path).and_then(|e| e.get_password().ok()).is_some(),
        dev_password: dev_password().is_some(),
    }
}

/// Opens the vault (key derivation runs on a blocking thread) and starts sync in the background.
async fn open_session(vault: &Vault, password: String) -> CmdResult<()> {
    let path = vault.db_path.clone();
    let session = tauri::async_runtime::spawn_blocking(move || YasecretSession::new(path, password))
        .await
        .map_err(|e| e.to_string())?
        .map_err(message)?;
    if let Some(old) = vault.session.lock().unwrap().replace(session.clone()) {
        std::thread::spawn(move || old.stop_sync());
    }
    *vault.sync_error.lock().unwrap() = None;
    let (slot, error) = (vault.session.clone(), vault.sync_error.clone());
    std::thread::spawn(move || {
        let result = session.start_sync(device_name());
        let still_current = slot.lock().unwrap().as_ref().is_some_and(|s| Arc::ptr_eq(s, &session));
        match result {
            // Locked (or re-unlocked) while starting: this session is gone, so stop its sync.
            Ok(()) if !still_current => session.stop_sync(),
            Ok(()) => {}
            Err(e) if still_current => *error.lock().unwrap() = Some(message(e)),
            Err(_) => {}
        }
    });
    Ok(())
}

#[tauri::command]
async fn unlock(vault: State<'_, Vault>, password: String, confirm: Option<String>, remember: bool) -> CmdResult<()> {
    let first_run = !Path::new(&vault.db_path).exists();
    if first_run && confirm.as_deref() != Some(password.as_str()) {
        return Err("Passwords don't match — confirm your master password".into());
    }
    if password.is_empty() {
        return Err("Enter your master password".into());
    }
    open_session(&vault, password.clone()).await?;
    if let Some(entry) = keyring_entry(&vault.db_path) {
        if remember {
            let _ = entry.set_password(&password);
        } else {
            let _ = entry.delete_credential();
        }
    }
    Ok(())
}

#[tauri::command]
async fn unlock_remembered(vault: State<'_, Vault>) -> CmdResult<()> {
    let password = keyring_entry(&vault.db_path)
        .and_then(|e| e.get_password().ok())
        .ok_or_else(|| "No saved password on this device".to_string())?;
    open_session(&vault, password).await
}

fn dev_password() -> Option<String> {
    if cfg!(debug_assertions) && std::env::var_os("YASECRET_DB_PATH").is_some() {
        std::env::var("YASECRET_DEV_PASSWORD").ok()
    } else {
        None
    }
}

/// Debug builds only: unlock a throwaway test vault without typing.
#[tauri::command]
async fn dev_unlock(vault: State<'_, Vault>) -> CmdResult<()> {
    let pw = dev_password().ok_or_else(|| "not available".to_string())?;
    open_session(&vault, pw).await
}

#[tauri::command]
async fn lock(vault: State<'_, Vault>) -> CmdResult<()> {
    let session = vault.session.lock().unwrap().take();
    if let Some(s) = session {
        tauri::async_runtime::spawn_blocking(move || s.stop_sync()).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn forget_password(vault: State<'_, Vault>) {
    if let Some(e) = keyring_entry(&vault.db_path) {
        let _ = e.delete_credential();
    }
}

// ── Projects & environments ──────────────────────────────────────────────────

#[tauri::command]
async fn list_projects(vault: State<'_, Vault>) -> CmdResult<Vec<FfiProject>> {
    blocking(&vault, |s| s.list_projects()).await
}

#[tauri::command]
async fn shared_project_ids(vault: State<'_, Vault>) -> CmdResult<Vec<String>> {
    blocking(&vault, |s| s.shared_project_ids()).await
}

#[tauri::command]
async fn create_project(vault: State<'_, Vault>, name: String, with_defaults: bool) -> CmdResult<FfiProject> {
    blocking(&vault, move |s| {
        let p = s.create_project(name, None)?;
        if with_defaults {
            for env in ["development", "staging", "production"] {
                s.create_environment(p.id.clone(), env.into())?;
            }
        }
        Ok(p)
    })
    .await
}

#[tauri::command]
async fn rename_project(vault: State<'_, Vault>, project_id: String, name: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.rename_project(project_id, name)).await
}

#[tauri::command]
async fn delete_project(vault: State<'_, Vault>, project_id: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.delete_project(project_id)).await
}

#[tauri::command]
async fn list_environments(vault: State<'_, Vault>, project_id: String) -> CmdResult<Vec<FfiEnvironment>> {
    blocking(&vault, move |s| s.list_environments(project_id)).await
}

#[tauri::command]
async fn create_environment(vault: State<'_, Vault>, project_id: String, name: String) -> CmdResult<FfiEnvironment> {
    blocking(&vault, move |s| s.create_environment(project_id, name)).await
}

#[tauri::command]
async fn rename_environment(vault: State<'_, Vault>, env_id: String, name: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.rename_environment(env_id, name)).await
}

#[tauri::command]
async fn clone_environment(vault: State<'_, Vault>, env_id: String, name: String) -> CmdResult<FfiEnvironment> {
    blocking(&vault, move |s| s.clone_environment(env_id, name)).await
}

#[tauri::command]
async fn delete_environment(vault: State<'_, Vault>, env_id: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.delete_environment(env_id)).await
}

// ── Variables ────────────────────────────────────────────────────────────────

#[tauri::command]
async fn list_secrets(vault: State<'_, Vault>, env_id: String) -> CmdResult<Vec<FfiSecret>> {
    blocking(&vault, move |s| s.list_secrets(env_id)).await
}

#[tauri::command]
async fn create_secret(
    vault: State<'_, Vault>,
    project_id: String,
    env_id: String,
    key: String,
    value: String,
    is_secret: bool,
    expires_at: Option<i64>,
) -> CmdResult<FfiSecret> {
    blocking(&vault, move |s| s.create_secret(project_id, env_id, key, value, expires_at, is_secret)).await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn edit_secret(
    vault: State<'_, Vault>,
    project_id: String,
    secret_id: String,
    new_key: Option<String>,
    new_value: Option<String>,
    is_secret: Option<bool>,
    expiry_changed: bool,
    expires_at: Option<i64>,
) -> CmdResult<()> {
    blocking(&vault, move |s| {
        s.edit_secret(project_id.clone(), secret_id.clone(), new_key, new_value, is_secret)?;
        if expiry_changed {
            s.set_expiry(project_id, secret_id, expires_at)?;
        }
        Ok(())
    })
    .await
}

#[tauri::command]
async fn delete_secrets(vault: State<'_, Vault>, secret_ids: Vec<String>) -> CmdResult<()> {
    blocking(&vault, move |s| {
        for id in secret_ids {
            s.delete_secret(id)?;
        }
        Ok(())
    })
    .await
}

#[tauri::command]
async fn get_value(vault: State<'_, Vault>, project_id: String, secret_id: String, reveal: bool) -> CmdResult<String> {
    blocking(&vault, move |s| {
        let v = s.get_secret_plaintext(project_id, secret_id.clone())?;
        if reveal {
            s.record_reveal(secret_id)?;
        }
        Ok(v)
    })
    .await
}

#[tauri::command]
fn looks_secret(key: String) -> bool {
    yasecret_ffi::looks_secret(key)
}

#[tauri::command]
fn is_valid_key(key: String) -> bool {
    yasecret_ffi::is_valid_key(key)
}

// ── Import / export / files ──────────────────────────────────────────────────

#[tauri::command]
async fn preview_import(vault: State<'_, Vault>, env_id: String, content: String) -> CmdResult<Vec<FfiImportRow>> {
    blocking(&vault, move |s| s.preview_import(env_id, content)).await
}

#[tauri::command]
async fn apply_import(
    vault: State<'_, Vault>,
    project_id: String,
    env_id: String,
    items: Vec<FfiImportItem>,
    overwrite: bool,
) -> CmdResult<FfiImportSummary> {
    blocking(&vault, move |s| s.apply_import(project_id, env_id, items, overwrite)).await
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn export_variables(
    vault: State<'_, Vault>,
    project_id: String,
    env_id: String,
    format: String,
    keys: Option<Vec<String>>,
    include_secret_values: bool,
    name: String,
) -> CmdResult<String> {
    blocking(&vault, move |s| s.export_variables(project_id, env_id, format, keys, include_secret_values, name)).await
}

#[tauri::command]
fn read_text_file(path: String) -> CmdResult<String> {
    std::fs::read_to_string(&path).map_err(|e| format!("Couldn't read {path}: {e}"))
}

#[tauri::command]
fn write_text_file(path: String, contents: String) -> CmdResult<()> {
    std::fs::write(&path, contents).map_err(|e| format!("Couldn't write {path}: {e}"))
}

/// Copies text; sensitive values are wiped from the clipboard after a minute
/// unless something else was copied meanwhile.
#[tauri::command]
fn copy_text(app: tauri::AppHandle, text: String, sensitive: bool) -> CmdResult<()> {
    app.clipboard().write_text(text.clone()).map_err(|e| e.to_string())?;
    if sensitive {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(60));
            if app.clipboard().read_text().ok().as_deref() == Some(text.as_str()) {
                let _ = app.clipboard().clear();
            }
        });
    }
    Ok(())
}

// ── History, activity, compare ───────────────────────────────────────────────

#[tauri::command]
async fn list_versions(vault: State<'_, Vault>, project_id: String, secret_id: String) -> CmdResult<Vec<FfiVersion>> {
    blocking(&vault, move |s| s.list_versions(project_id, secret_id)).await
}

#[tauri::command]
async fn restore_version(vault: State<'_, Vault>, project_id: String, secret_id: String, version_id: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.restore_version(project_id, secret_id, version_id)).await
}

#[tauri::command]
async fn list_activity(vault: State<'_, Vault>, project_id: String) -> CmdResult<Vec<FfiActivity>> {
    blocking(&vault, move |s| s.list_activity(Some(project_id), 500)).await
}

#[tauri::command]
async fn compare_environments(vault: State<'_, Vault>, project_id: String, left: String, right: String) -> CmdResult<Vec<FfiDiffRow>> {
    blocking(&vault, move |s| s.compare_environments(project_id, left, right)).await
}

// ── Sharing ──────────────────────────────────────────────────────────────────

#[tauri::command]
async fn device_code(vault: State<'_, Vault>) -> CmdResult<String> {
    blocking(&vault, |s| s.device_code()).await
}

#[tauri::command]
async fn create_invite(vault: State<'_, Vault>, project_id: String, device_code: Option<String>, level: String) -> CmdResult<String> {
    blocking(&vault, move |s| s.create_invite(project_id, device_code, level)).await
}

#[tauri::command]
async fn join_project(vault: State<'_, Vault>, link: String) -> CmdResult<String> {
    blocking(&vault, move |s| s.join_project(link)).await
}

#[tauri::command]
async fn list_members(vault: State<'_, Vault>, project_id: String) -> CmdResult<Vec<FfiMember>> {
    blocking(&vault, move |s| s.list_members(project_id)).await
}

#[tauri::command]
async fn add_relay(vault: State<'_, Vault>, project_id: String, code: String, name: String) -> CmdResult<String> {
    blocking(&vault, move |s| s.add_relay(project_id, code, name)).await
}

#[tauri::command]
async fn remove_relay(vault: State<'_, Vault>, project_id: String, code: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.remove_relay(project_id, code)).await
}

#[tauri::command]
async fn list_relays(vault: State<'_, Vault>, project_id: String) -> CmdResult<Vec<FfiRelay>> {
    blocking(&vault, move |s| s.list_relays(project_id)).await
}

#[tauri::command]
async fn set_member_level(vault: State<'_, Vault>, project_id: String, peer_id: String, level: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.set_member_level(project_id, peer_id, level)).await
}

#[tauri::command]
async fn sync_status(vault: State<'_, Vault>, project_id: String) -> CmdResult<FfiSyncStatus> {
    let start_error = vault.sync_error.lock().unwrap().clone();
    let mut st = blocking(&vault, move |s| s.sync_status(project_id)).await?;
    if st.shared && st.last_error.is_none() {
        st.last_error = start_error.map(|e| format!("Sharing unavailable: {e}"));
    }
    Ok(st)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpiringVariable {
    id: String,
    label: String,
    expired: bool,
}

/// Variables that expired or expire within `days`, across all projects.
#[tauri::command]
async fn expiring_variables(vault: State<'_, Vault>, days: i64) -> CmdResult<Vec<ExpiringVariable>> {
    blocking(&vault, move |s| {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let mut out = Vec::new();
        for p in s.list_projects()? {
            for e in s.list_environments(p.id.clone())? {
                for v in s.list_secrets(e.id.clone())? {
                    if let Some(exp) = v.expires_at.filter(|exp| *exp < now + days * 86_400) {
                        out.push(ExpiringVariable { id: v.id, label: format!("{} ({}/{})", v.key, p.name, e.name), expired: exp <= now });
                    }
                }
            }
        }
        Ok(out)
    })
    .await
}

#[tauri::command]
fn sync_revision(vault: State<'_, Vault>) -> u64 {
    vault.session.lock().unwrap().as_ref().map(|s| s.sync_revision()).unwrap_or(0)
}

#[tauri::command]
async fn stop_sharing(vault: State<'_, Vault>, project_id: String) -> CmdResult<()> {
    blocking(&vault, move |s| s.stop_sharing(project_id)).await
}

// ── App ──────────────────────────────────────────────────────────────────────

fn db_path() -> String {
    if cfg!(debug_assertions) {
        if let Ok(p) = std::env::var("YASECRET_DB_PATH") {
            return p;
        }
    }
    yasecret_ffi::default_db_path()
}

pub fn run() {
    #[cfg_attr(not(any(windows, target_os = "linux")), allow(unused_mut))]
    let mut builder = tauri::Builder::default();
    // A second launch (e.g. from a yasecret:// link) hands its link to the running app.
    #[cfg(any(windows, target_os = "linux"))]
    {
        // With the deep-link feature the link itself reaches on_open_url; here we only bring
        // the existing window forward.
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }));
    }
    builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .manage(Vault { db_path: db_path(), session: Arc::new(Mutex::new(None)), sync_error: Arc::new(Mutex::new(None)) })
        .setup(|app| {
            use tauri_plugin_deep_link::DeepLinkExt;
            #[cfg(any(windows, target_os = "linux"))]
            let _ = app.deep_link().register_all();
            let handle = app.handle().clone();
            app.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    let _ = handle.emit("join-link", url.to_string());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            vault_state,
            unlock,
            unlock_remembered,
            dev_unlock,
            lock,
            forget_password,
            list_projects,
            shared_project_ids,
            create_project,
            rename_project,
            delete_project,
            list_environments,
            create_environment,
            rename_environment,
            clone_environment,
            delete_environment,
            list_secrets,
            create_secret,
            edit_secret,
            delete_secrets,
            get_value,
            looks_secret,
            is_valid_key,
            preview_import,
            apply_import,
            export_variables,
            read_text_file,
            write_text_file,
            copy_text,
            list_versions,
            restore_version,
            list_activity,
            compare_environments,
            device_code,
            create_invite,
            join_project,
            list_members,
            set_member_level,
            add_relay,
            remove_relay,
            list_relays,
            sync_status,
            expiring_variables,
            sync_revision,
            stop_sharing,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Yasecret");
}
