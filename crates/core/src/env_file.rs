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
