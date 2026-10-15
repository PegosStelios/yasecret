use std::path::PathBuf;
use tempfile::tempdir;
use yasecret_core::{db::Db, environment, project};

fn open_db() -> (tempfile::TempDir, Db) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.sqlite");
    let db = Db::open(&path, "pw").unwrap();
    (dir, db)
}

#[test]
fn create_and_list_project() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "my-app", None, "owner-1").unwrap();
    assert_eq!(p.name, "my-app");
    let list = project::list(&db).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, p.id);
}

#[test]
fn get_project_not_found() {
    let (_dir, db) = open_db();
    assert!(project::get(&db, "nonexistent").is_err());
}

#[test]
fn delete_project_cascades() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "app", None, "o1").unwrap();
    environment::create(&db, &p.id, "dev").unwrap();
    project::delete(&db, &p.id).unwrap();
    let envs = environment::list(&db, &p.id).unwrap();
    assert!(envs.is_empty());
}

#[test]
fn list_environments() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "app", None, "o").unwrap();
    environment::create(&db, &p.id, "dev").unwrap();
    environment::create(&db, &p.id, "production").unwrap();
    let envs = environment::list(&db, &p.id).unwrap();
    assert_eq!(envs.len(), 2);
}

#[test]
fn delete_environment() {
    let (_dir, db) = open_db();
    let p = project::create(&db, "app", None, "o").unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    environment::delete(&db, &e.id).unwrap();
    let envs = environment::list(&db, &p.id).unwrap();
    assert!(envs.is_empty());
}
