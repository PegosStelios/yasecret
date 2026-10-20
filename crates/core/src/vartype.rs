//! Optional types for variables, checked whenever a value changes. Error messages describe
//! the expected type and never include the value, which may be a secret.

use crate::error::{Result, YasecretError};

/// Every type a variable can have; a variable without one is plain text.
pub const TYPES: [&str; 6] = ["url", "number", "port", "boolean", "email", "json"];

pub fn label(t: &str) -> &'static str {
    match t {
        "url" => "a URL",
        "number" => "a number",
        "port" => "a port (1–65535)",
        "boolean" => "true or false",
        "email" => "an email address",
        "json" => "JSON",
        _ => "a known type",
    }
}

/// Ok when `value` fits type `t`. Empty values always fit: whether a key must be set is
/// `yasecret check`'s job.
pub fn check(t: &str, value: &str) -> Result<()> {
    if !TYPES.contains(&t) {
        return Err(YasecretError::InvalidValue(format!("unknown variable type “{t}” (use one of: {})", TYPES.join(", "))));
    }
    let v = value.trim();
    if v.is_empty() {
        return Ok(());
    }
    let ok = match t {
        "url" => is_url(v),
        "number" => v.parse::<f64>().is_ok_and(f64::is_finite),
        "port" => v.parse::<u32>().is_ok_and(|p| (1..=65535).contains(&p)),
        "boolean" => ["true", "false", "yes", "no", "on", "off", "1", "0"].contains(&v.to_ascii_lowercase().as_str()),
        "email" => is_email(v),
        "json" => serde_json::from_str::<serde_json::Value>(v).is_ok(),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(YasecretError::InvalidValue(format!("expected {}", label(t))))
    }
}

fn is_url(v: &str) -> bool {
    let Some((scheme, rest)) = v.split_once("://") else { return false };
    !scheme.is_empty()
        && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
        && !v.chars().any(char::is_whitespace)
}

fn is_email(v: &str) -> bool {
    let Some((local, domain)) = v.split_once('@') else { return false };
    !local.is_empty()
        && !domain.contains('@')
        && domain.split('.').count() >= 2
        && domain.split('.').all(|p| !p.is_empty())
        && !v.chars().any(char::is_whitespace)
}

/// A likely type for a variable name, offered as the default when adding it.
pub fn suggest(key: &str) -> Option<&'static str> {
    let k = key.to_ascii_uppercase();
    let ends = |s: &[&str]| s.iter().any(|x| k.ends_with(x));
    let starts = |s: &[&str]| s.iter().any(|x| k.starts_with(x));
    if k == "PORT" || ends(&["_PORT"]) {
        Some("port")
    } else if ends(&["_URL", "_URI", "_ENDPOINT", "_WEBHOOK"]) || k == "URL" {
        Some("url")
    } else if k.contains("EMAIL") {
        Some("email")
    } else if ends(&["_JSON"]) {
        Some("json")
    } else if starts(&["ENABLE_", "DISABLE_", "IS_", "USE_", "ALLOW_"]) || ends(&["_ENABLED", "_DISABLED"]) {
        Some("boolean")
    } else if starts(&["MAX_", "MIN_", "NUM_"]) || ends(&["_TIMEOUT", "_COUNT", "_LIMIT", "_SIZE", "_RETRIES", "_TTL", "_WORKERS", "_SECONDS", "_MS"]) {
        Some("number")
    } else {
        None
    }
}
