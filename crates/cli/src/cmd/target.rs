//! Resolves `--project` / `--env` names to an unlocked vault plus the project key.

use yasecret_core::{crypto, env_file, environment, models::Environment, models::Project, project, project_key, secret, YasecretError};
use zeroize::Zeroizing;

pub struct Target {
    pub session: crate::unlock::Session,
    pub project: Project,
    pub env: Environment,
    pub key: Zeroizing<[u8; 32]>,
}

impl Target {
    pub fn open(project_name: &str, env_name: &str, db: Option<&str>, password: Option<&str>) -> yasecret_core::Result<Self> {
        let path = crate::unlock::db_path(db);
        let session = crate::unlock::unlock(&path, password)?;
        let project = project::list(&session.db)?
            .into_iter()
            .find(|p| p.name == project_name)
            .ok_or_else(|| YasecretError::NotFound(format!("project '{project_name}'")))?;
        let env = environment::list(&session.db, &project.id)?
            .into_iter()
            .find(|e| e.name == env_name)
            .ok_or_else(|| YasecretError::NotFound(format!("environment '{env_name}' in '{project_name}'")))?;
        let key = project_key::load(&session.db, &project.id, &session.db_key)?;
        Ok(Self { session, project, env, key })
    }

    /// Current variables as (key, value), sorted by key. Reloads the project key, which
    /// changes when the project's key is rotated (a member removed, sharing stopped).
    pub fn pairs(&mut self) -> yasecret_core::Result<Vec<(String, String)>> {
        Ok(self.items()?.into_iter().map(|i| (i.key, i.value)).collect())
    }

    /// Like `pairs`, keeping whether each variable is marked secret.
    pub fn items(&mut self) -> yasecret_core::Result<Vec<env_file::ExportItem>> {
        self.key = project_key::load(&self.session.db, &self.project.id, &self.session.db_key)?;
        secret::list(&self.session.db, &self.env.id)?
            .into_iter()
            .map(|s| {
                let nonce: [u8; 12] = s.nonce.clone().try_into().map_err(|_| YasecretError::Crypto)?;
                let v = crypto::decrypt(&s.encrypted_value, &nonce, &self.key)?;
                Ok(env_file::ExportItem { key: s.key, value: String::from_utf8_lossy(&v).into_owned(), is_secret: s.is_secret })
            })
            .collect()
    }
}

/// Writes a .env file readable only by the current user.
pub fn write_private(path: &str, content: &str) -> yasecret_core::Result<()> {
    std::fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
