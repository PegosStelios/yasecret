//! Rotation helpers: generated values, provider recognition, AWS request signing.

use yasecret_core::rotate;

#[test]
fn generated_values_have_the_requested_shape() {
    let a = rotate::generate(48, rotate::Charset::UrlSafe);
    let b = rotate::generate(48, rotate::Charset::UrlSafe);
    assert_eq!(a.len(), 48);
    assert_ne!(a, b);
    assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    let hex = rotate::generate(64, rotate::Charset::Hex);
    assert!(hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()));
    let alnum = rotate::generate(20, rotate::Charset::Alphanumeric);
    assert!(alnum.chars().all(|c| c.is_ascii_alphanumeric()));
}

#[test]
fn providers_are_recognised_from_the_value_or_name() {
    let name = |k: &str, v: &str| rotate::provider(k, v).map(|p| p.name);
    assert_eq!(name("STRIPE_SECRET_KEY", "sk_live_51Habc"), Some("Stripe"));
    assert_eq!(name("GITHUB_TOKEN", "ghp_abcdef"), Some("GitHub"));
    assert_eq!(name("GH", "github_pat_11AB"), Some("GitHub"));
    assert_eq!(name("OPENAI_API_KEY", "sk-proj-abc"), Some("OpenAI"));
    assert_eq!(name("ANTHROPIC_API_KEY", "sk-ant-api03-abc"), Some("Anthropic"));
    assert_eq!(name("SLACK_BOT_TOKEN", "xoxb-1-2-3"), Some("Slack"));
    assert_eq!(name("SENDGRID_API_KEY", "SG.abc.def"), Some("SendGrid"));
    assert_eq!(name("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"), Some("AWS"));
    assert_eq!(name("JWT_SECRET", "anything"), None);
    let stripe = rotate::provider("STRIPE_SECRET_KEY", "sk_live_x").unwrap();
    assert!(stripe.dashboard.starts_with("https://dashboard.stripe.com/"));
    assert!(rotate::provider("X", "sk_test_x").unwrap().dashboard.contains("/test/"), "test-mode keys link to test mode");
}

#[test]
fn aws_signature_matches_the_published_example() {
    // From AWS's Signature Version 4 documentation (IAM ListUsers).
    let sig = rotate::aws::sign(
        &rotate::aws::Credentials { access_key: "AKIDEXAMPLE".into(), secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into() },
        "GET",
        "iam.amazonaws.com",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &[("content-type", "application/x-www-form-urlencoded; charset=utf-8")],
        b"",
        "us-east-1",
        "iam",
        "20150830T123600Z",
    );
    assert!(sig.authorization.ends_with("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"), "{}", sig.authorization);
    assert!(sig.authorization.contains("SignedHeaders=content-type;host;x-amz-date"));
}

#[test]
fn aws_dates_are_utc_timestamps() {
    assert_eq!(rotate::aws::amz_date(1_440_938_160), "20150830T123600Z");
    assert_eq!(rotate::aws::amz_date(951_782_400), "20000229T000000Z");
}
