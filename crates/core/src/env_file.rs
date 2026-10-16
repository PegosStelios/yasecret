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
        let key = trimmed[..eq_pos].trim();
        let key = key.strip_prefix("export ").map(str::trim).unwrap_or(key).to_string();
        let raw_value = &trimmed[eq_pos + 1..];
        let value = unquote(raw_value);
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 {
        let first = s.chars().next().unwrap();
        let last = s.chars().last().unwrap();
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            return s[1..s.len() - 1].to_string();
        }
    }
    s.to_string()
}

pub fn serialize(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            if v.contains(' ') || v.contains('"') || v.contains('\'') {
                format!("{k}=\"{}\"\n", v.replace('"', "\\\""))
            } else {
                format!("{k}={v}\n")
            }
        })
        .collect()
}

pub fn parse_example(content: &str) -> Result<Vec<String>> {
    Ok(parse(content)?.into_iter().map(|(k, _)| k).collect())
}

/// Parses either a dotenv file or a flat JSON object of scalars.
pub fn parse_any(content: &str) -> Result<Vec<(String, String)>> {
    if !content.trim_start().starts_with('{') {
        return parse(content);
    }
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| YasecretError::EnvParse(format!("invalid JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| YasecretError::EnvParse("JSON must be an object".into()))?;
    obj.iter()
        .map(|(k, v)| {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Null => String::new(),
                _ => return Err(YasecretError::EnvParse(format!("{k}: nested values are not supported"))),
            };
            Ok((k.clone(), s))
        })
        .collect()
}

const SECRET_HINTS: &[&str] = &[
    "SECRET", "KEY", "TOKEN", "PASSWORD", "PASSWD", "PASS", "PRIVATE", "AUTH", "CREDENTIAL", "DATABASE_URL", "DSN",
];

pub fn looks_secret(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_HINTS.iter().any(|h| upper.contains(h))
}

pub fn valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

#[derive(Debug, Clone)]
pub struct ExportItem {
    pub key: String,
    pub value: String,
    pub is_secret: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Dotenv,
    Json,
    DockerCompose,
    K8sSecret,
    K8sConfigMap,
    /// `.env.example`: keys only, secrets marked.
    Example,
}

impl ExportFormat {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "dotenv" => Self::Dotenv,
            "json" => Self::Json,
            "docker-compose" => Self::DockerCompose,
            "k8s-secret" => Self::K8sSecret,
            "k8s-configmap" => Self::K8sConfigMap,
            "example" => Self::Example,
            _ => return None,
        })
    }
}

/// Renders variables in a deploy-friendly format. `name` is the service / resource name.
pub fn export(items: &[ExportItem], format: ExportFormat, name: &str) -> Result<String> {
    let quoted = |v: &str| serde_json::to_string(v).unwrap_or_else(|_| "\"\"".into());
    Ok(match format {
        ExportFormat::Dotenv => {
            let pairs: Vec<(String, String)> = items.iter().map(|i| (i.key.clone(), i.value.clone())).collect();
            serialize(&pairs)
        }
        ExportFormat::Json => {
            let map: serde_json::Map<String, serde_json::Value> = items
                .iter()
                .map(|i| (i.key.clone(), serde_json::Value::String(i.value.clone())))
                .collect();
            serde_json::to_string_pretty(&map).map_err(|e| YasecretError::EnvParse(e.to_string()))? + "\n"
        }
        ExportFormat::DockerCompose => {
            let service = k8s_name(name, "app");
            let mut out = format!("services:\n  {service}:\n    environment:\n");
            for i in items {
                out.push_str(&format!("      {}: {}\n", i.key, quoted(&i.value)));
            }
            out
        }
        ExportFormat::K8sSecret => {
            let mut out = format!(
                "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {}\ntype: Opaque\ndata:\n",
                k8s_name(name, "app-secrets")
            );
            for i in items {
                out.push_str(&format!("  {}: {}\n", i.key, base64(i.value.as_bytes())));
            }
            out
        }
        ExportFormat::K8sConfigMap => {
            let mut out = format!(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {}\ndata:\n",
                k8s_name(name, "app-config")
            );
            for i in items {
                out.push_str(&format!("  {}: {}\n", i.key, quoted(&i.value)));
            }
            out
        }
        ExportFormat::Example => items
            .iter()
            .map(|i| if i.is_secret { format!("{}=  # secret\n", i.key) } else { format!("{}=\n", i.key) })
            .collect(),
    })
}

/// Lowercase alphanumerics and dashes, at most 63 chars (Kubernetes resource names).
fn k8s_name(name: &str, fallback: &str) -> String {
    let mut out = String::new();
    for c in name.to_ascii_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out: String = out.trim_matches('-').chars().take(63).collect();
    let out = out.trim_end_matches('-').to_string();
    if out.is_empty() { fallback.to_string() } else { out }
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}
