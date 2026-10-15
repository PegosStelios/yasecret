use std::io::Write;
use tempfile::tempdir;
use yasecret_sync::node::SyncNode;

#[tokio::test]
async fn node_starts_and_returns_nonempty_node_id() {
    let dir = tempdir().unwrap();
    let key = [42u8; 32];
    let node = SyncNode::start(dir.path(), &key).await.unwrap();
    let id = node.node_id();
    assert!(!id.is_empty(), "node_id must be non-empty");
    node.stop().await;
}

#[tokio::test]
async fn node_id_is_stable_for_same_key() {
    let dir = tempdir().unwrap();
    let key = [7u8; 32];
    let node1 = SyncNode::start(dir.path(), &key).await.unwrap();
    let id1 = node1.node_id();
    node1.stop().await;
    let node2 = SyncNode::start(dir.path(), &key).await.unwrap();
    let id2 = node2.node_id();
    node2.stop().await;
    assert_eq!(id1, id2);
}

#[tokio::test]
async fn start_with_corrupt_key_file_errors() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("sync.key");
    let mut f = std::fs::File::create(&key_path).unwrap();
    f.write_all(b"tooshort").unwrap();

    let key = [0u8; 32];
    let result = SyncNode::start(dir.path(), &key).await;
    assert!(result.is_err(), "should error when sync.key is wrong length");
}
