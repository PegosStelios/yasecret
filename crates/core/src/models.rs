use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub name: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub owner_id: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub project_id: String,
    pub name: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Environment whose variables this one inherits (its own variables win).
    pub inherits_from: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Secret {
    pub id: String,
    pub env_id: String,
    pub key: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
    pub created_by: String,
    pub expires_at: Option<i64>,
    pub is_secret: bool,
    /// One of `vartype::TYPES`; `None` is plain text.
    pub value_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecretVersion {
    pub id: String,
    pub secret_id: String,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub changed_by: String,
    pub changed_at: i64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleLevel {
    Read,
    Write,
    Admin,
}

impl RoleLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }
}

#[derive(Debug, Clone)]
pub struct Role {
    pub id: String,
    pub project_id: String,
    pub env_id: Option<String>,
    pub peer_id: String,
    pub level: RoleLevel,
    pub granted_at: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub peer_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub timestamp: i64,
    pub detail: Option<String>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
