//! Typed variables: validation, suggestions, and enforcement where values change.

use yasecret_core::{crypto, db::Db, environment, project, project_key, secret, vartype, YasecretError};

#[test]
fn values_are_checked_against_their_type() {
    use vartype::check;
    assert!(check("url", "https://api.example.com/v1").is_ok());
    assert!(check("url", "postgres://u:p@db:5432/app").is_ok());
    assert!(check("url", "not a url").is_err());
    assert!(check("number", "-12.5").is_ok() && check("number", "12a").is_err());
    assert!(check("port", "5432").is_ok() && check("port", "70000").is_err() && check("port", "0").is_err());
    assert!(check("boolean", "TRUE").is_ok() && check("boolean", "0").is_ok() && check("boolean", "maybe").is_err());
    assert!(check("email", "ops@example.com").is_ok() && check("email", "ops@").is_err());
    assert!(check("json", r#"{"a":[1,2]}"#).is_ok() && check("json", "{a:1}").is_err());
    assert!(check("url", "").is_ok(), "an empty value is allowed: required keys are `yasecret check`'s job");
    assert!(matches!(check("colour", "red"), Err(YasecretError::InvalidValue(_))), "unknown types are refused");
}

#[test]
fn types_are_suggested_from_the_name() {
    assert_eq!(vartype::suggest("DATABASE_URL"), Some("url"));
    assert_eq!(vartype::suggest("API_ENDPOINT"), Some("url"));
    assert_eq!(vartype::suggest("PORT"), Some("port"));
    assert_eq!(vartype::suggest("REDIS_PORT"), Some("port"));
    assert_eq!(vartype::suggest("ENABLE_SIGNUPS"), Some("boolean"));
    assert_eq!(vartype::suggest("ADMIN_EMAIL"), Some("email"));
    assert_eq!(vartype::suggest("MAX_RETRIES"), Some("number"));
    assert_eq!(vartype::suggest("API_KEY"), None);
}

#[test]
fn a_typed_variable_refuses_values_that_dont_fit_including_on_push() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db.sqlite"), "pw").unwrap();
    let db_key = crypto::derive_db_key("pw", &crypto::generate_salt());
    let p = project::create(&db, "app", None, "me").unwrap();
    project_key::create(&db, &p.id, &db_key).unwrap();
    let k = project_key::load(&db, &p.id, &db_key).unwrap();
    let e = environment::create(&db, &p.id, "dev").unwrap();
    let port = secret::create_with_kind(&db, &e.id, "PORT", b"3000", &k, "me", None, false).unwrap();

    assert!(secret::set_value_type(&db, &port.id, Some("url"), &k).is_err(), "the current value must fit the new type");
    secret::set_value_type(&db, &port.id, Some("port"), &k).unwrap();
    assert_eq!(secret::list(&db, &e.id).unwrap()[0].value_type.as_deref(), Some("port"));
    assert!(secret::update(&db, &port.id, b"abc", &k, "me", None).is_err());
    secret::update(&db, &port.id, b"8080", &k, "me", None).unwrap();

    let bad = vec![("PORT".to_string(), "eighty".to_string()), ("NEW".to_string(), "x".to_string())];
    match secret::merge(&db, &e.id, &bad, &k, "me", None, true, false) {
        Err(YasecretError::InvalidValue(msg)) => assert!(msg.contains("PORT"), "{msg}"),
        other => panic!("expected a validation error, got {other:?}"),
    }
    assert_eq!(secret::list(&db, &e.id).unwrap().len(), 1, "nothing from a refused push is written");
}
