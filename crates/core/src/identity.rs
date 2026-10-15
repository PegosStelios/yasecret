use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    db::Db,
    error::{Result, YasecretError},
    models::{now, new_id, Identity},
};

pub fn load_or_create(db: &Db, name: &str) -> Result<Identity> {
    if let Ok(identity) = load(db) {
        return Ok(identity);
    }
    create(db, name)
}

pub fn load(db: &Db) -> Result<Identity> {
    db.conn()
        .query_row(
            "SELECT id, name, public_key, secret_key, created_at FROM identity LIMIT 1",
            [],
            |row| {
                Ok(Identity {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    public_key: row.get(2)?,
                    secret_key: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .map_err(|_| YasecretError::NotFound("identity".into()))
}

fn create(db: &Db, name: &str) -> Result<Identity> {
    use rand::rngs::OsRng;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let identity = Identity {
        id: new_id(),
        name: name.to_string(),
        public_key: public.as_bytes().to_vec(),
        secret_key: secret.as_bytes().to_vec(),
        created_at: now(),
    };
    db.conn().execute(
        "INSERT INTO identity (id, name, public_key, secret_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &identity.id,
            &identity.name,
            &identity.public_key,
            &identity.secret_key,
            identity.created_at
        ],
    )?;
    Ok(identity)
}

impl Identity {
    pub fn x25519_secret(&self) -> StaticSecret {
        let bytes: [u8; 32] = self.secret_key[..32].try_into().expect("32 byte key");
        StaticSecret::from(bytes)
    }

    pub fn x25519_public(&self) -> PublicKey {
        let bytes: [u8; 32] = self.public_key[..32].try_into().expect("32 byte key");
        PublicKey::from(bytes)
    }

    pub fn signing_key(&self) -> SigningKey {
        use sha2::{Digest, Sha512};
        let x25519_bytes: [u8; 32] = self.secret_key[..32].try_into().expect("32 byte key");
        // Derive a separate Ed25519 key via SHA-512 to enforce key separation.
        let mut h = Sha512::new();
        h.update(b"yasecret-signing-key-v1");
        h.update(x25519_bytes);
        let hash = h.finalize();
        let derived: [u8; 32] = hash[..32].try_into().expect("32 bytes");
        SigningKey::from_bytes(&derived)
    }
}
