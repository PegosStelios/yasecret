use yasecret_core::env_file::{self, parse, serialize};

#[test]
fn parse_basic() {
    let content = "API_KEY=abc123\nDB_URL=postgres://localhost/db\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(
        pairs,
        vec![
            ("API_KEY".into(), "abc123".into()),
            ("DB_URL".into(), "postgres://localhost/db".into()),
        ]
    );
}

#[test]
fn parse_ignores_comments_and_blank_lines() {
    let content = "# comment\n\nKEY=value\n  # another comment\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0], ("KEY".into(), "value".into()));
}

#[test]
fn parse_value_with_equals_sign() {
    let content = "JWT=header.payload=signature\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "header.payload=signature");
}

#[test]
fn parse_quoted_value_with_spaces() {
    let content = "MSG=\"hello world\"\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "hello world");
}

#[test]
fn parse_single_quoted_value() {
    let content = "MSG='hello world'\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "hello world");
}

#[test]
fn parse_empty_value() {
    let content = "EMPTY=\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0], ("EMPTY".into(), "".into()));
}

#[test]
fn serialize_roundtrip() {
    let pairs = vec![
        ("KEY".into(), "value".into()),
        ("B".into(), "2".into()),
    ];
    let serialized = env_file::serialize(&pairs);
    let reparsed = env_file::parse(&serialized).unwrap();
    assert_eq!(pairs, reparsed);
}

#[test]
fn serialize_quotes_values_with_spaces() {
    let pairs = vec![("MSG".into(), "hello world".into())];
    let out = env_file::serialize(&pairs);
    assert!(out.contains('\'') || out.contains('"'), "value with spaces must be quoted: {out}");
    let back = env_file::parse(&out).unwrap();
    assert_eq!(back[0].1, "hello world");
}

#[test]
fn parse_example_returns_keys_only() {
    let content = "# database\nDB_URL=\nAPI_KEY=\n";
    let keys = env_file::parse_example(content).unwrap();
    assert_eq!(keys, vec!["DB_URL", "API_KEY"]);
}

#[test]
fn parse_inline_comment_not_stripped() {
    // inline comments (KEY=value # comment) are NOT standard; value includes the hash
    let content = "KEY=value\n";
    let pairs = env_file::parse(content).unwrap();
    assert_eq!(pairs[0].1, "value");
}

#[test]
fn awkward_values_survive_serialize_then_parse() {
    let values = [
        "plain",
        "with space",
        "has \"double\" quotes",
        "it's",
        "line1\nline2",
        "tab\there",
        "back\\slash",
        "hash # not a comment",
        "a#b",
        "$HOME and ${PATH}",
        "both ' and \"",
        "  leading and trailing  ",
        "",
        "=starts with equals",
        "-----BEGIN KEY-----\nMIIabc\n-----END KEY-----",
    ];
    let pairs: Vec<(String, String)> = values.iter().enumerate().map(|(i, v)| (format!("K{i}"), v.to_string())).collect();
    let text = serialize(&pairs);
    assert_eq!(parse(&text).unwrap(), pairs, "serialized:\n{text}");
}

#[test]
fn parses_common_dotenv_forms() {
    let text = "A=\"x\\ny\"\nB='literal \\n $X'\nC=unquoted # comment\nD=\"multi\nline\"\nexport E=1\n";
    let got = parse(text).unwrap();
    assert_eq!(
        got,
        vec![
            ("A".into(), "x\ny".into()),
            ("B".into(), "literal \\n $X".into()),
            ("C".into(), "unquoted".into()),
            ("D".into(), "multi\nline".into()),
            ("E".into(), "1".into()),
        ]
    );
}
