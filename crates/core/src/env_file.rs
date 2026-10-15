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
        let key = trimmed[..eq_pos].trim().to_string();
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
