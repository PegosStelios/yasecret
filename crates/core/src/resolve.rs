//! What an environment's variables actually are where they're used (pull, run, export…):
//! variables inherited from parent environments, then `${KEY}` references expanded.
//!
//! A reference expands only when KEY is a variable of the resolved environment, so text like
//! `${HOME}` in a value stays as written; `$${` writes a literal `${`.

use std::collections::{BTreeMap, HashMap};

use crate::{
    db::Db,
    environment,
    error::{Result, YasecretError},
    secret,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedVar {
    pub key: String,
    pub value: String,
    pub is_secret: bool,
    /// Name of the ancestor environment it comes from; `None` when it's the environment's own.
    pub inherited_from: Option<String>,
}

/// The environment's variables with inheritance and references applied, sorted by key.
pub fn resolved(db: &Db, env_id: &str, project_key: &[u8; 32]) -> Result<Vec<ResolvedVar>> {
    // Nearest first: the environment itself, its parent, and so on.
    let mut chain = vec![environment::get(db, env_id)?];
    while let Some(parent) = chain.last().and_then(|e| e.inherits_from.clone()) {
        if chain.iter().any(|e| e.id == parent) || chain.len() > 32 {
            break;
        }
        // A parent that isn't here (deleted, or not synced yet) ends the chain.
        let Ok(env) = environment::get(db, &parent) else { break };
        chain.push(env);
    }
    let mut vars: BTreeMap<String, ResolvedVar> = BTreeMap::new();
    for (depth, env) in chain.iter().enumerate().rev() {
        for s in secret::list(db, &env.id)? {
            let value = String::from_utf8_lossy(&secret::get_plaintext(db, &s.id, project_key)?).into_owned();
            let inherited_from = (depth > 0).then(|| env.name.clone());
            vars.insert(s.key.clone(), ResolvedVar { key: s.key, value, is_secret: s.is_secret, inherited_from });
        }
    }

    let raw: HashMap<String, String> = vars.iter().map(|(k, v)| (k.clone(), v.value.clone())).collect();
    let mut done: HashMap<String, String> = HashMap::new();
    for key in vars.keys() {
        expand(key, &raw, &mut done, &mut Vec::new())?;
    }
    Ok(vars
        .into_values()
        .map(|mut v| {
            v.value = done.remove(&v.key).unwrap_or(v.value);
            v
        })
        .collect())
}

fn expand(key: &str, raw: &HashMap<String, String>, done: &mut HashMap<String, String>, stack: &mut Vec<String>) -> Result<String> {
    if let Some(v) = done.get(key) {
        return Ok(v.clone());
    }
    if let Some(pos) = stack.iter().position(|k| k == key) {
        let mut cycle = stack[pos..].to_vec();
        cycle.push(key.to_string());
        return Err(YasecretError::EnvParse(format!("these variables refer to each other: {}", cycle.join(" → "))));
    }
    stack.push(key.to_string());
    let text = &raw[key];
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        if let Some(r) = after.strip_prefix("$${") {
            out.push_str("${");
            rest = r;
        } else if let Some(name) = after.strip_prefix("${").and_then(|r| r.find('}').map(|end| &r[..end])) {
            if raw.contains_key(name) {
                out.push_str(&expand(name, raw, done, stack)?);
            } else {
                out.push_str(&after[..name.len() + 3]);
            }
            rest = &after[name.len() + 3..];
        } else {
            out.push('$');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    stack.pop();
    done.insert(key.to_string(), out.clone());
    Ok(out)
}
