use tempfile::tempdir;
use yasecret_core::{crypto, db::Db, identity, project, project_key};
use yasecret_sync::{doc_manager, node::SyncNode};
use zeroize::Zeroizing;

async fn test_node(dir: &tempfile::TempDir) -> SyncNode {
    SyncNode::start(dir.path(), &[0u8; 32]).await.unwrap()
}

fn seed_db(dir: &tempfile::TempDir) -> (Db, Zeroizing<[u8; 32]>, yasecret_core::models::Project) {
    let db_path = dir.path().join("db.sqlite");
    let salt = crypto::generate_salt();
    std::fs::write(dir.path().join("db.salt"), salt).unwrap();
    let db_key = crypto::derive_db_key("pw", &salt);
    let db = Db::open(&db_path, "pw").unwrap();
    let owner = identity::load_or_create(&db, "owner").unwrap();
    let p = project::create(&db, "my-app", None, &owner.id).unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    (db, db_key, p)
}

#[tokio::test]
async fn create_project_doc_returns_parseable_ticket() {
    let dir = tempdir().unwrap();
    let (db, _, proj) = seed_db(&dir);
    let node = test_node(&dir).await;
    let ticket = doc_manager::create_project_doc(&db, &node, &proj.id)
        .await
        .unwrap();
    assert!(!ticket.is_empty());
    let parsed: Result<iroh_docs::DocTicket, _> = ticket.parse();
    assert!(parsed.is_ok(), "ticket must parse as DocTicket, got: {ticket}");
    node.stop().await;
}

#[tokio::test]
async fn join_with_garbage_ticket_errors() {
    let dir = tempdir().unwrap();
    let (db, _, proj) = seed_db(&dir);
    let node = test_node(&dir).await;
    let result = doc_manager::join_project_doc(&db, &node, "not-a-real-ticket", &proj.id).await;
    assert!(
        matches!(result, Err(yasecret_sync::SyncError::InvalidTicket)),
        "expected InvalidTicket, got: {result:?}"
    );
    node.stop().await;
}

#[tokio::test]
async fn get_doc_id_returns_stored_id() {
    let dir = tempdir().unwrap();
    let (db, _, proj) = seed_db(&dir);
    let node = test_node(&dir).await;
    doc_manager::create_project_doc(&db, &node, &proj.id)
        .await
        .unwrap();
    let doc_id = doc_manager::get_doc_id(&db, &proj.id).unwrap();
    assert!(!doc_id.is_empty());
    node.stop().await;
}

#[tokio::test]
async fn get_doc_id_for_missing_project_errors() {
    let dir = tempdir().unwrap();
    let (db, _, _) = seed_db(&dir);
    let result = doc_manager::get_doc_id(&db, "nonexistent-project-id");
    assert!(result.is_err());
}
