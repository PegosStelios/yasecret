use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, identity, models::Identity, project, project_key};
use yasecret_sync::peer_key::{load_my_peer_key, store_peer_key};
use zeroize::Zeroizing;

fn open_db(dir: &tempfile::TempDir) -> (Db, Zeroizing<[u8; 32]>) {
    let db_path = dir.path().join("db.sqlite");
    let salt = crypto::generate_salt();
    std::fs::write(dir.path().join("db.salt"), salt).unwrap();
    let db_key = crypto::derive_db_key("pw", &salt);
    let db = Db::open(&db_path, "pw").unwrap();
    (db, db_key)
}

#[test]
fn store_and_load_peer_key_round_trips() {
    let dir = tempdir().unwrap();
    let (db, db_key) = open_db(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let proj = project::create(&db, "my-app", None, &owner.id).unwrap();
    project_key::create(&db, &proj.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &proj.id, &db_key).unwrap();

    // Simulate a peer with a fresh X25519 keypair
    let (peer_secret, peer_public) = crypto::generate_identity_keypair();
    let peer_id = hex::encode(peer_public.as_bytes());

    store_peer_key(&db, &proj.id, &peer_id, peer_public.as_bytes(), &proj_key).unwrap();

    // Load as peer
    let peer_identity = Identity {
        id: peer_id.clone(),
        name: "peer".into(),
        public_key: peer_public.as_bytes().to_vec(),
        secret_key: peer_secret.as_bytes().to_vec(),
        created_at: 0,
    };
    let loaded = load_my_peer_key(&db, &proj.id, &peer_identity).unwrap();
    assert_eq!(loaded.as_slice(), proj_key.as_slice());
}

#[test]
fn load_my_peer_key_wrong_identity_errors() {
    let dir = tempdir().unwrap();
    let (db, db_key) = open_db(&dir);
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let proj = project::create(&db, "my-app", None, &owner.id).unwrap();
    project_key::create(&db, &proj.id, &db_key).unwrap();
    let proj_key = project_key::load(&db, &proj.id, &db_key).unwrap();

    let (_, peer_public) = crypto::generate_identity_keypair();
    let peer_id = hex::encode(peer_public.as_bytes());
    store_peer_key(&db, &proj.id, &peer_id, peer_public.as_bytes(), &proj_key).unwrap();

    // Wrong identity (different keypair)
    let (wrong_secret, wrong_public) = crypto::generate_identity_keypair();
    let wrong_identity = Identity {
        id: hex::encode(wrong_public.as_bytes()),
        name: "wrong".into(),
        public_key: wrong_public.as_bytes().to_vec(),
        secret_key: wrong_secret.as_bytes().to_vec(),
        created_at: 0,
    };
    let result = load_my_peer_key(&db, &proj.id, &wrong_identity);
    assert!(result.is_err(), "expected error for wrong identity");
}
