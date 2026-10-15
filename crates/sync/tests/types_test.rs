use yasecret_sync::types::{
    doc_keys, SyncEnvMeta, SyncProjectMeta, SyncRole, SyncSecret,
};

#[test]
fn sync_project_meta_round_trips() {
    let meta = SyncProjectMeta {
        id: "proj-1".into(),
        name: "my-app".into(),
        description: None,
        owner_id: "owner-1".into(),
        owner_signing_pub_key: "aabbcc".into(),
        created_at: 1234567890,
    };
    let json = serde_json::to_vec(&meta).unwrap();
    let back: SyncProjectMeta = serde_json::from_slice(&json).unwrap();
    assert_eq!(back.id, "proj-1");
    assert_eq!(back.owner_signing_pub_key, "aabbcc");
}

#[test]
fn sync_env_meta_round_trips() {
    let env = SyncEnvMeta {
        id: "env-1".into(),
        project_id: "proj-1".into(),
        name: "dev".into(),
        created_at: 111,
    };
    let json = serde_json::to_vec(&env).unwrap();
    let back: SyncEnvMeta = serde_json::from_slice(&json).unwrap();
    assert_eq!(back.name, "dev");
}

#[test]
fn sync_secret_round_trips() {
    let s = SyncSecret {
        id: "s1".into(),
        key: "API_KEY".into(),
        encrypted_value: vec![1, 2, 3],
        nonce: vec![0u8; 12],
        created_at: 100,
        updated_at: 200,
        created_by: "owner".into(),
        expires_at: None,
    };
    let json = serde_json::to_vec(&s).unwrap();
    let back: SyncSecret = serde_json::from_slice(&json).unwrap();
    assert_eq!(back.encrypted_value, vec![1, 2, 3]);
    assert_eq!(back.nonce.len(), 12);
}

#[test]
fn sync_role_round_trips() {
    let r = SyncRole {
        id: "r1".into(),
        project_id: "proj-1".into(),
        env_id: Some("env-1".into()),
        peer_id: "peer-1".into(),
        level: "write".into(),
        granted_at: 999,
        signature: vec![0u8; 64],
    };
    let json = serde_json::to_vec(&r).unwrap();
    let back: SyncRole = serde_json::from_slice(&json).unwrap();
    assert_eq!(back.signature.len(), 64);
    assert_eq!(back.level, "write");
}

#[test]
fn doc_keys_are_correct() {
    assert_eq!(doc_keys::project_meta(), b"project/meta");
    assert_eq!(doc_keys::env_meta("env-1"), b"env/env-1/meta" as &[u8]);
    assert_eq!(doc_keys::secret("env-1", "DB_URL"), b"secret/env-1/DB_URL" as &[u8]);
    assert_eq!(doc_keys::role("peer-1", Some("env-1")), b"role/peer-1/env-1" as &[u8]);
    assert_eq!(doc_keys::role("peer-1", None), b"role/peer-1/*" as &[u8]);
    assert_eq!(doc_keys::peer_key("peer-1"), b"peer_key/peer-1" as &[u8]);
}
