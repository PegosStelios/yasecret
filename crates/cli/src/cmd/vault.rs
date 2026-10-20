use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use yasecret_core::{vault, YasecretError};

#[derive(Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub action: VaultAction,
    #[arg(long, hide = true, global = true)]
    pub db: Option<String>,
    #[arg(long, hide = true, global = true)]
    pub password: Option<String>,
}

#[derive(Subcommand)]
pub enum VaultAction {
    /// Change the master password
    Passwd {
        #[arg(long, hide = true)]
        new_password: Option<String>,
    },
    /// Make a recovery key that can reset a forgotten master password (retires the old one)
    RecoveryKey,
    /// Set a new master password using your recovery key
    Recover {
        #[arg(long, hide = true)]
        key: Option<String>,
        #[arg(long, hide = true)]
        new_password: Option<String>,
    },
    /// Write an encrypted backup of the whole vault
    Backup { file: PathBuf },
    /// Restore a backup (asks for the password the vault had when it was backed up)
    Restore {
        file: PathBuf,
        /// Replace the existing vault
        #[arg(long)]
        replace: bool,
    },
}

pub fn run(args: VaultArgs) -> yasecret_core::Result<()> {
    let path = crate::unlock::db_path(args.db.as_deref());
    match args.action {
        VaultAction::Passwd { new_password } => {
            ensure_closed(&path)?;
            let old = match args.password {
                Some(p) => p,
                None => prompt("Current master password: ")?,
            };
            let new = match new_password {
                Some(p) => p,
                None => new_password_prompt()?,
            };
            vault::change_password(&path, &old, &new)?;
            println!("Master password changed. Saved copies of the old one (Keychain, Credential Manager) no longer work.");
        }
        VaultAction::RecoveryKey => {
            let password = match args.password {
                Some(p) => p,
                None => prompt("Master password: ")?,
            };
            let key = vault::create_recovery_key(&path, &password)?;
            println!("Your recovery key:\n\n  {key}\n");
            println!("Keep it somewhere safe and offline. Anyone with it and your vault files can reset the master password. Any earlier recovery key no longer works.");
        }
        VaultAction::Recover { key, new_password } => {
            ensure_closed(&path)?;
            let key = match key {
                Some(k) => k,
                None => prompt("Recovery key: ")?,
            };
            let new = match new_password {
                Some(p) => p,
                None => new_password_prompt()?,
            };
            vault::recover(&path, &key, &new)?;
            println!("Master password reset. Your recovery key still works.");
        }
        VaultAction::Backup { file } => {
            let session = crate::unlock::unlock(&path, args.password.as_deref())?;
            vault::backup(&session.db, &path, &file)?;
            println!("Backed up to {}. Restoring it needs the current master password.", file.display());
        }
        VaultAction::Restore { file, replace } => {
            if path.exists() && !replace {
                return Err(YasecretError::Io(std::io::Error::other(format!(
                    "a vault already exists at {}; add --replace to overwrite it",
                    path.display()
                ))));
            }
            ensure_closed(&path)?;
            let password = match args.password {
                Some(p) => p,
                None => prompt("Password of the backed-up vault: ")?,
            };
            vault::restore(&file, &path, &password)?;
            println!("Restored {} to {}.", file.display(), path.display());
        }
    }
    Ok(())
}

/// The app keeps the vault open while unlocked (and holds the sync lock); rewriting the
/// file under it would corrupt it.
fn ensure_closed(path: &Path) -> yasecret_core::Result<()> {
    let sync_dir = path.parent().unwrap_or_else(|| Path::new(".")).join("sync");
    if yasecret_sync::relay::is_running(&sync_dir) {
        return Err(YasecretError::Io(std::io::Error::other(
            "Yasecret is running with this vault — quit it (or lock it and close the window) first",
        )));
    }
    Ok(())
}

fn prompt(label: &str) -> yasecret_core::Result<String> {
    rpassword::prompt_password(label).map_err(YasecretError::Io)
}

fn new_password_prompt() -> yasecret_core::Result<String> {
    let a = prompt("New master password: ")?;
    let b = prompt("Repeat new master password: ")?;
    if a != b {
        return Err(YasecretError::EnvParse("the passwords don't match".into()));
    }
    Ok(a)
}
