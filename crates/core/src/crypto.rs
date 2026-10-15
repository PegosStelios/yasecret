use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Argon2, Params};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::error::{Result, YasecretError};

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_db_key(password: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(65536, 3, 4, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, output.as_mut())
        .expect("argon2 hash failed");
    output
}

pub fn generate_project_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| YasecretError::Crypto)?;
    Ok((ciphertext, nonce_bytes))
}

pub fn decrypt(ciphertext: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| YasecretError::Crypto)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn generate_identity_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Encrypt `plaintext` for a peer's X25519 public key using ephemeral ECDH.
/// Output layout: [ephemeral_pub(32)] ++ [nonce(12)] ++ [ciphertext]
pub fn encrypt_for_peer(plaintext: &[u8], peer_pub_bytes: &[u8; 32]) -> Result<Vec<u8>> {
    let peer_pub = PublicKey::from(*peer_pub_bytes);
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&peer_pub);

    let aes_key = kdf(shared.as_bytes());
    let (ciphertext, nonce) = encrypt(plaintext, &aes_key)?;

    let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_from_peer(data: &[u8], our_secret: &StaticSecret) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 44 {
        return Err(YasecretError::Crypto);
    }
    let ephemeral_pub_bytes: [u8; 32] = data[..32].try_into().unwrap();
    let nonce: [u8; 12] = data[32..44].try_into().unwrap();
    let ciphertext = &data[44..];

    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
    let shared = our_secret.diffie_hellman(&ephemeral_pub);
    let aes_key = kdf(shared.as_bytes());
    decrypt(ciphertext, &nonce, &aes_key)
}

fn kdf(shared_secret: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(b"yasecret-peer-key-v1");
    let result = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&result);
    key
}

pub fn sign(message: &[u8], signing_key: &SigningKey) -> Vec<u8> {
    signing_key.sign(message).to_bytes().to_vec()
}

pub fn verify(message: &[u8], signature_bytes: &[u8], verifying_key_bytes: &[u8; 32]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(verifying_key_bytes).map_err(|_| YasecretError::Crypto)?;
    let sig_arr: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| YasecretError::Crypto)?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).map_err(|_| YasecretError::Crypto)
}
