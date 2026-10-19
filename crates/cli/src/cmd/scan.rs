use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::Command,
};

use clap::Args;
use yasecret_core::{crypto, environment, project, project_key, secret, YasecretError};
use zeroize::Zeroizing;

#[derive(Args)]
pub struct ScanArgs {
    /// Directory or git repository to scan
    #[arg(long, default_value = ".")]
    pub path: String,
    /// Only look at this project's secrets (default: all projects)
    #[arg(short, long)]
    pub project: Option<String>,
    /// Scan what's staged for commit (for a pre-commit hook)
    #[arg(long, conflicts_with = "history")]
    pub staged: bool,
    /// Scan every commit in the repository's history
    #[arg(long)]
    pub history: bool,
    #[arg(long, hide = true)]
    pub db: Option<String>,
    #[arg(long, hide = true)]
    pub password: Option<String>,
}

/// Shorter values match too much ordinary text to be worth reporting.
const MIN_LEN: usize = 8;
const MAX_FILE: u64 = 5 * 1024 * 1024;

struct Needle {
    value: Zeroizing<String>,
    labels: Vec<String>,
}

/// Looks for vault secrets in files and git history. Reports where and which key, never
/// the value. Returns true when anything was found.
pub fn run(args: ScanArgs) -> yasecret_core::Result<bool> {
    let needles = load_secrets(&args)?;
    let root = PathBuf::from(&args.path);
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut report = |place: String, line: &str| {
        for n in &needles {
            if line.contains(n.value.as_str()) {
                found.insert(format!("{place}  {}", n.labels.join(", ")));
            }
        }
    };

    if args.staged {
        let names = git(&root, &["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"])?;
        for name in names.split('\0').filter(|n| !n.is_empty()) {
            let Ok(text) = git(&root, &["show", &format!(":{name}")]) else { continue };
            for (i, line) in text.lines().enumerate() {
                report(format!("{name}:{}", i + 1), line);
            }
        }
    } else if args.history {
        let log = git(&root, &["log", "-p", "--all", "--no-color", "--no-ext-diff", "--format=commit:%h"])?;
        let (mut commit, mut file) = (String::new(), String::new());
        for line in log.lines() {
            if let Some(c) = line.strip_prefix("commit:") {
                commit = c.to_string();
            } else if let Some(f) = line.strip_prefix("+++ b/") {
                file = f.to_string();
            } else if line.starts_with('+') && !line.starts_with("+++") {
                report(format!("{commit} {file}"), line);
            }
        }
    } else {
        for file in working_files(&root)? {
            let Some(text) = read_text(&file) else { continue };
            let shown = file.strip_prefix(&root).unwrap_or(&file).display().to_string();
            for (i, line) in text.lines().enumerate() {
                report(format!("{shown}:{}", i + 1), line);
            }
        }
    }

    if found.is_empty() {
        eprintln!("No secrets from the vault found ({} checked).", needles.len());
        return Ok(false);
    }
    println!("Found secrets from the vault:");
    for f in &found {
        println!("  {f}");
    }
    println!("Rotate any secret that was committed or shared: removing it from the file doesn't remove it from history.");
    Ok(true)
}

fn load_secrets(args: &ScanArgs) -> yasecret_core::Result<Vec<Needle>> {
    let path = crate::unlock::db_path(args.db.as_deref());
    let session = crate::unlock::unlock(&path, args.password.as_deref())?;
    let projects: Vec<_> = project::list(&session.db)?
        .into_iter()
        .filter(|p| args.project.as_deref().is_none_or(|name| p.name == name))
        .collect();
    if let (Some(name), true) = (&args.project, projects.is_empty()) {
        return Err(YasecretError::NotFound(format!("project '{name}'")));
    }
    let mut needles: Vec<Needle> = Vec::new();
    for p in projects {
        let key = project_key::load(&session.db, &p.id, &session.db_key)?;
        for e in environment::list(&session.db, &p.id)? {
            for s in secret::list(&session.db, &e.id)?.into_iter().filter(|s| s.is_secret) {
                let nonce: [u8; 12] = s.nonce.clone().try_into().map_err(|_| YasecretError::Crypto)?;
                let value = Zeroizing::new(String::from_utf8_lossy(&crypto::decrypt(&s.encrypted_value, &nonce, &key)?).into_owned());
                if value.trim().len() < MIN_LEN {
                    continue;
                }
                let label = format!("{} ({}/{})", s.key, p.name, e.name);
                match needles.iter_mut().find(|n| *n.value == *value) {
                    Some(n) => n.labels.push(label),
                    None => needles.push(Needle { value, labels: vec![label] }),
                }
            }
        }
    }
    Ok(needles)
}

fn git(dir: &Path, args: &[&str]) -> yasecret_core::Result<String> {
    let out = Command::new("git").arg("-C").arg(dir).args(args).output()?;
    if !out.status.success() {
        return Err(YasecretError::Io(std::io::Error::other(format!(
            "git {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        ))));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Tracked and untracked-but-not-ignored files in a git repository, or every file below a
/// plain directory (skipping dependency and build folders).
fn working_files(root: &Path) -> yasecret_core::Result<Vec<PathBuf>> {
    if let Ok(list) = git(root, &["ls-files", "-z", "-co", "--exclude-standard"]) {
        return Ok(list.split('\0').filter(|n| !n.is_empty()).map(|n| root.join(n)).collect());
    }
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            if path.is_dir() {
                if ![".git", "node_modules", "target", ".venv", "dist", "build"].contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// File contents, unless it's large or binary.
fn read_text(path: &Path) -> Option<String> {
    if std::fs::metadata(path).ok()?.len() > MAX_FILE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}
