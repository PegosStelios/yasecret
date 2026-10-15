use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, environment, identity, project, project_key, role};
use yasecret_sync::{
    applier::{apply_peer_key_entry, apply_role_entry, push_env_meta, push_peer_key, push_project_meta, push_secret},
    doc_manager,
    node::SyncNode,
    peer_key::load_my_peer_key,
    types::{SyncEnvMeta, SyncProjectMeta, SyncRole, SyncSecret},
};
use zeroize::Zeroizing;

/// C1 fix: apply_peer_key_entry must write encrypted blob to peer_project_key table
/// so that load_my_peer_key can find it on the joiner side.
#[test]
fn apply_peer_key_entry_enables_load_my_peer_key() {
    let dir = tempdir().unwrap();
    let (db, db_key) = seed(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let joiner = identity::load_or_create(&db, "joiner-same-db").unwrap();
    // Use owner as project owner, joiner as the peer
    let proj = project::create(&db, "app-c1", None, &owner.id).unwrap();
    project_key::create(&db, &proj.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &proj.id, &db_key).unwrap();

    // Simulate share: encrypt proj_key for joiner's X25519 pub key
    let joiner_pub: [u8; 32] = *joiner.x25519_public().as_bytes();
    let joiner_peer_id = hex::encode(joiner_pub);
    let encrypted_blob = yasecret_core::crypto::encrypt_for_peer(&*proj_key, &joiner_pub).unwrap();

    // The subscriber calls apply_peer_key_entry when it receives the blob
    apply_peer_key_entry(&db, &proj.id, &joiner_peer_id, &encrypted_blob).unwrap();

    // Now joiner should be able to load the key
    let loaded = load_my_peer_key(&db, &proj.id, &joiner).unwrap();
    assert_eq!(&*loaded, &*proj_key, "loaded key must match original project key");
}

async fn make_node(dir: &tempfile::TempDir) -> SyncNode {
    SyncNode::start(dir.path(), &[1u8; 32]).await.unwrap()
}

fn seed(dir: &tempfile::TempDir) -> (Db, Zeroizing<[u8; 32]>) {
    let db_path = dir.path().join("db.sqlite");
    let salt = crypto::generate_salt();
    std::fs::write(dir.path().join("db.salt"), salt).unwrap();
    let db_key = crypto::derive_db_key("pw", &salt);
    let db = Db::open(&db_path, "pw").unwrap();
    (db, db_key)
}

#[tokio::test]
async fn push_and_read_project_meta() {
    let dir = tempdir().unwrap();
    let (db, _) = seed(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let proj = project::create(&db, "shared-app", None, &owner.id).unwrap();
    let node = make_node(&dir).await;
    let author = node.client().author_create().await.unwrap();
    doc_manager::create_project_doc(&db, &node, &proj.id)
        .await
        .unwrap();
    let doc_id = doc_manager::get_doc_id(&db, &proj.id).unwrap();

    let meta = SyncProjectMeta {
        id: proj.id.clone(),
        name: "shared-app".into(),
        description: None,
        owner_id: owner.id.clone(),
        owner_signing_pub_key: hex::encode(owner.signing_key().verifying_key().as_bytes()),
        created_at: proj.created_at,
    };
    push_project_meta(&node, &doc_id, &meta, author).await.unwrap();

    // Read back from doc to confirm entry was written
    let ns: iroh_docs::NamespaceId = doc_id.parse().unwrap();
    let doc = node.client().open(ns).await.unwrap().unwrap();
    let entry = doc
        .get_exact(author, yasecret_sync::types::doc_keys::project_meta(), false)
        .await
        .unwrap();
    assert!(entry.is_some(), "project/meta entry must exist after push");
    node.stop().await;
}

#[tokio::test]
async fn push_secret_and_read_back() {
    let dir = tempdir().unwrap();
    let (db, db_key) = seed(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let proj = project::create(&db, "app2", None, &owner.id).unwrap();
    project_key::create(&db, &proj.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &proj.id, &db_key).unwrap();
    let env = environment::create(&db, &proj.id, "dev").unwrap();
    let node = make_node(&dir).await;
    let author = node.client().author_create().await.unwrap();
    doc_manager::create_project_doc(&db, &node, &proj.id)
        .await
        .unwrap();
    let doc_id = doc_manager::get_doc_id(&db, &proj.id).unwrap();

    let (enc, nonce) = crypto::encrypt(b"supersecret", &proj_key).unwrap();
    let s = SyncSecret {
        id: "s1".into(),
        key: "DB_URL".into(),
        encrypted_value: enc,
        nonce: nonce.to_vec(),
        created_at: 1000,
        updated_at: 1000,
        created_by: owner.id.clone(),
        expires_at: None,
    };
    push_secret(&node, &doc_id, &env.id, &s, author).await.unwrap();

    let ns: iroh_docs::NamespaceId = doc_id.parse().unwrap();
    let doc = node.client().open(ns).await.unwrap().unwrap();
    let key_bytes = yasecret_sync::types::doc_keys::secret(&env.id, "DB_URL");
    let entry = doc.get_exact(author, &key_bytes, false).await.unwrap();
    assert!(entry.is_some(), "secret entry must exist after push");
    node.stop().await;
}

#[tokio::test]
async fn apply_role_bad_signature_ignored() {
    let dir = tempdir().unwrap();
    let (db, _) = seed(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let proj = project::create(&db, "app3", None, &owner.id).unwrap();

    let bad_role = SyncRole {
        id: "r-bad".into(),
        project_id: proj.id.clone(),
        env_id: None,
        peer_id: "attacker".into(),
        level: "admin".into(),
        granted_at: 9999999,
        signature: vec![0u8; 64],
    };

    // Use owner's Ed25519 verifying key (correct key type for verify_signature)
    let owner_vk: [u8; 32] = *owner.signing_key().verifying_key().as_bytes();
    let result = apply_role_entry(&db, &bad_role, &owner_vk);
    assert!(result.is_ok(), "apply_role_entry must return Ok on bad sig (silent drop)");

    // DB must have no role for "attacker"
    let roles = role::list(&db, &proj.id).unwrap();
    assert!(
        roles.iter().all(|r| r.peer_id != "attacker"),
        "bad-signature role must not be written to DB"
    );
}
