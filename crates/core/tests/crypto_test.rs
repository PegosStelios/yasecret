use yasecret_core::crypto::*;

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = generate_project_key();
    let plaintext = b"DATABASE_URL=postgres://localhost/test";
    let (ciphertext, nonce) = encrypt(plaintext, &key).unwrap();
    let decrypted = decrypt(&ciphertext, &nonce, &key).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
}

#[test]
fn wrong_key_decrypt_fails() {
    let key1 = generate_project_key();
    let key2 = generate_project_key();
    let (ciphertext, nonce) = encrypt(b"secret", &key1).unwrap();
    assert!(decrypt(&ciphertext, &nonce, &key2).is_err());
}

#[test]
fn derive_key_deterministic() {
    let salt = generate_salt();
    let k1 = derive_db_key("password", &salt);
    let k2 = derive_db_key("password", &salt);
    assert_eq!(k1.as_ref(), k2.as_ref());
}

#[test]
fn derive_key_different_passwords() {
    let salt = generate_salt();
    let k1 = derive_db_key("password1", &salt);
    let k2 = derive_db_key("password2", &salt);
    assert_ne!(k1.as_ref(), k2.as_ref());
}

#[test]
fn peer_key_exchange_roundtrip() {
    let (secret_a, pub_a) = generate_identity_keypair();
    let (_secret_b, pub_b) = generate_identity_keypair();
    let plaintext = b"project-key-bytes-here-32-chars!!";
    let encrypted = encrypt_for_peer(plaintext, pub_b.as_bytes()).unwrap();
    let decrypted = decrypt_from_peer(&encrypted, &_secret_b).unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    let _ = (secret_a, pub_a);
}

#[test]
fn ed25519_sign_verify() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut OsRng);
    let message = b"role:project-id:peer-id:write";
    let sig = sign(message, &signing_key);
    let vk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    assert!(verify(message, &sig, &vk_bytes).is_ok());
    assert!(verify(b"tampered", &sig, &vk_bytes).is_err());
}
