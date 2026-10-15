use std::path::{Path, PathBuf};

use rmcp::{tool, ServerHandler, tool_handler, tool_router};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::serde::Deserialize;
use rmcp::schemars::JsonSchema;
use yasecret_core::db::Db;

pub struct YasecretServer {
    db_path: PathBuf,
    password: String,
    pub allow_plaintext: bool,
}

impl YasecretServer {
    pub fn new(db_path: impl AsRef<Path>, password: String, allow_plaintext: bool) -> Self {
        Self {
            db_path: db_path.as_ref().to_path_buf(),
            password,
            allow_plaintext,
        }
    }

    fn open_db(&self) -> Result<Db, String> {
        Db::open(&self.db_path, &self.password).map_err(|e| e.to_string())
    }

    fn open_db_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        let salt_path = self.db_path.with_extension("salt");
        let salt_bytes = std::fs::read(&salt_path)
            .map_err(|e| format!("cannot read salt file: {e}"))?;
        let salt: [u8; 16] = salt_bytes
            .try_into()
            .map_err(|_| "salt file must be 16 bytes".to_string())?;
        Ok(yasecret_core::crypto::derive_db_key(&self.password, &salt))
    }
}

// ── Tool parameter types ──────────────────────────────────────────────────────

#[derive(Deserialize, JsonSchema)]
pub struct ListSecretKeysInput {
    pub project: String,
    pub env: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct RunWithSecretsInput {
    pub project: String,
    pub env: String,
    /// Secret key names to inject; empty = inject all
    pub keys: Vec<String>,
    /// Command and args, e.g. ["npm", "start"]
    pub cmd: Vec<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct GetSecretInput {
    pub project: String,
    pub env: String,
    pub key: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct ImportEnvInput {
    pub project: String,
    pub env: String,
    /// Raw .env file content
    pub content: String,
}

// ── Impl helpers (pub for unit tests) ────────────────────────────────────────

impl YasecretServer {
    pub fn list_projects_impl(&self) -> String {
        let db = match self.open_db() {
            Ok(d) => d,
            Err(e) => return format!("error: {e}"),
        };
        let projects = match yasecret_core::project::list(&db) {
            Ok(p) => p,
            Err(e) => return format!("error: {e}"),
        };
        let mut out = vec![];
        for proj in &projects {
            let envs = yasecret_core::environment::list(&db, &proj.id).unwrap_or_default();
            let env_names: Vec<String> = envs.iter().map(|e| format!("\"{}\"", e.name)).collect();
            out.push(format!(
                r#"{{"project":"{}","envs":[{}]}}"#,
                proj.name,
                env_names.join(",")
            ));
        }
        format!("[{}]", out.join(","))
    }

    pub fn list_secret_keys_impl(&self, project_name: &str, env_name: &str) -> String {
        let db = match self.open_db() {
            Ok(d) => d,
            Err(e) => return format!("error: {e}"),
        };
        let (_proj, env) = match self.resolve_project_env(&db, project_name, env_name) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let secrets = match yasecret_core::secret::list(&db, &env.id) {
            Ok(s) => s,
            Err(e) => return format!("error: {e}"),
        };
        let keys: Vec<String> = secrets.iter().map(|s| format!("\"{}\"", s.key)).collect();
        format!("[{}]", keys.join(","))
    }

    pub fn run_with_secrets_impl(
        &self,
        project_name: &str,
        env_name: &str,
        keys: &[String],
        cmd: &[String],
    ) -> String {
        use std::process::{Command as StdCommand, Stdio};
        use zeroize::Zeroizing;

        if cmd.is_empty() {
            return "error: cmd must not be empty".to_string();
        }
        let db = match self.open_db() {
            Ok(d) => d,
            Err(e) => return format!("error: {e}"),
        };
        let db_key = match self.open_db_key() {
            Ok(k) => k,
            Err(e) => return format!("error: {e}"),
        };
        let (proj, env) = match self.resolve_project_env(&db, project_name, env_name) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let proj_key = match yasecret_core::project_key::load(&db, &proj.id, &db_key) {
            Ok(k) => k,
            Err(e) => return format!("error loading project key: {e}"),
        };
        let all_secrets = match yasecret_core::secret::list(&db, &env.id) {
            Ok(s) => s,
            Err(e) => return format!("error: {e}"),
        };

        let mut env_vars: Vec<(String, Zeroizing<Vec<u8>>)> = vec![];
        for s in &all_secrets {
            if keys.is_empty() || keys.contains(&s.key) {
                let nonce: [u8; 12] = match s.nonce.clone().try_into() {
                    Ok(n) => n,
                    Err(_) => return format!("error: corrupt nonce for key '{}'", s.key),
                };
                match yasecret_core::crypto::decrypt(&s.encrypted_value, &nonce, &proj_key) {
                    Ok(v) => env_vars.push((s.key.clone(), v)),
                    Err(e) => return format!("error decrypting '{}': {e}", s.key),
                }
            }
        }

        let secret_values: Vec<String> = env_vars
            .iter()
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
            .collect();

        let mut process = StdCommand::new(&cmd[0]);
        process.args(&cmd[1..]);
        for (key, val) in &env_vars {
            process.env(key, String::from_utf8_lossy(val).as_ref());
        }
        process.stdout(Stdio::piped()).stderr(Stdio::piped());

        let output = match process.output() {
            Ok(o) => o,
            Err(e) => return format!("error running command: {e}"),
        };

        let stdout = mask(&String::from_utf8_lossy(&output.stdout), &secret_values);
        let stderr = mask(&String::from_utf8_lossy(&output.stderr), &secret_values);
        let status = output.status.code().unwrap_or(-1);

        format!("exit_code: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    }

    pub fn get_secret_impl(&self, project_name: &str, env_name: &str, key: &str) -> String {
        if !self.allow_plaintext {
            return "error: get_secret is disabled. Set YASECRET_MCP_ALLOW_PLAINTEXT=1 to enable.".to_string();
        }
        let db = match self.open_db() {
            Ok(d) => d,
            Err(e) => return format!("error: {e}"),
        };
        let db_key = match self.open_db_key() {
            Ok(k) => k,
            Err(e) => return format!("error: {e}"),
        };
        let (proj, env) = match self.resolve_project_env(&db, project_name, env_name) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let proj_key = match yasecret_core::project_key::load(&db, &proj.id, &db_key) {
            Ok(k) => k,
            Err(e) => return format!("error: {e}"),
        };
        let secrets = match yasecret_core::secret::list(&db, &env.id) {
            Ok(s) => s,
            Err(e) => return format!("error: {e}"),
        };
        let secret = match secrets.iter().find(|s| s.key == key) {
            Some(s) => s,
            None => return format!("error: key '{}' not found", key),
        };
        let nonce: [u8; 12] = match secret.nonce.clone().try_into() {
            Ok(n) => n,
            Err(_) => return "error: corrupt nonce".to_string(),
        };
        match yasecret_core::crypto::decrypt(&secret.encrypted_value, &nonce, &proj_key) {
            Ok(v) => String::from_utf8_lossy(&v).into_owned(),
            Err(e) => format!("error decrypting: {e}"),
        }
    }

    pub fn import_env_impl(&self, project_name: &str, env_name: &str, content: &str) -> String {
        let db = match self.open_db() {
            Ok(d) => d,
            Err(e) => return format!("error: {e}"),
        };
        let db_key = match self.open_db_key() {
            Ok(k) => k,
            Err(e) => return format!("error: {e}"),
        };
        let pairs = match yasecret_core::env_file::parse(content) {
            Ok(p) => p,
            Err(e) => return format!("error parsing .env: {e}"),
        };
        let (proj, env) = match self.resolve_project_env(&db, project_name, env_name) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let proj_key = match yasecret_core::project_key::load(&db, &proj.id, &db_key) {
            Ok(k) => k,
            Err(e) => return format!("error: {e}"),
        };
        let identity = match yasecret_core::identity::load(&db) {
            Ok(id) => id,
            Err(e) => return format!("error loading identity: {e}"),
        };
        let mut count = 0;
        for (key, value) in &pairs {
            match yasecret_core::secret::create(
                &db, &env.id, key, value.as_bytes(), &proj_key, &identity.id, None,
            ) {
                Ok(_) => count += 1,
                Err(e) => return format!("error importing key '{key}': {e}"),
            }
        }
        format!("imported {count} secret(s)")
    }

    fn resolve_project_env(
        &self,
        db: &Db,
        project_name: &str,
        env_name: &str,
    ) -> Result<(yasecret_core::models::Project, yasecret_core::models::Environment), String> {
        let projects = yasecret_core::project::list(db).map_err(|e| format!("error: {e}"))?;
        let proj = projects
            .into_iter()
            .find(|p| p.name == project_name)
            .ok_or_else(|| format!("error: project '{}' not found", project_name))?;
        let envs = yasecret_core::environment::list(db, &proj.id)
            .map_err(|e| format!("error: {e}"))?;
        let env = envs
            .into_iter()
            .find(|e| e.name == env_name)
            .ok_or_else(|| format!("error: environment '{}' not found in project '{}'", env_name, project_name))?;
        Ok((proj, env))
    }
}

// ── Tool router ───────────────────────────────────────────────────────────────

#[tool_router]
impl YasecretServer {
    #[tool(description = "List all projects and their environment names in yasecret")]
    pub fn list_projects(&self) -> String {
        self.list_projects_impl()
    }

    #[tool(description = "List secret key names (never values) for a given project and environment")]
    pub fn list_secret_keys(&self, Parameters(p): Parameters<ListSecretKeysInput>) -> String {
        self.list_secret_keys_impl(&p.project, &p.env)
    }

    #[tool(description = "Run a command with secrets injected as environment variables. Secret values are masked in the returned output. Use list_secret_keys first to see available key names.")]
    pub fn run_with_secrets(&self, Parameters(p): Parameters<RunWithSecretsInput>) -> String {
        self.run_with_secrets_impl(&p.project, &p.env, &p.keys, &p.cmd)
    }

    #[tool(description = "Get the plaintext value of one secret. Requires YASECRET_MCP_ALLOW_PLAINTEXT=1 to be set. Disabled by default to prevent accidental exposure.")]
    pub fn get_secret(&self, Parameters(p): Parameters<GetSecretInput>) -> String {
        self.get_secret_impl(&p.project, &p.env, &p.key)
    }

    #[tool(description = "Import secrets from .env file content into a project environment. Existing keys with the same name will error — remove them first.")]
    pub fn import_env(&self, Parameters(p): Parameters<ImportEnvInput>) -> String {
        self.import_env_impl(&p.project, &p.env, &p.content)
    }
}

#[tool_handler(
    name = "yasecret",
    version = "0.1.0",
    instructions = "Manage secrets stored in yasecret. Start with list_projects to see available projects and environments, then list_secret_keys to see key names, then run_with_secrets to run commands with secrets injected."
)]
impl ServerHandler for YasecretServer {}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn mask(output: &str, secrets: &[String]) -> String {
    let mut result = output.to_string();
    for s in secrets {
        if !s.is_empty() {
            result = result.replace(s.as_str(), "[REDACTED]");
        }
    }
    result
}
