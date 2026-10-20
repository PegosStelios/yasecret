//! Help replacing a secret: generated values, where to roll a provider's key, and AWS access
//! key rotation (request signing here; the HTTP calls live in the CLI).

use rand::{rngs::OsRng, Rng};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// Letters, digits, `-` and `_`.
    UrlSafe,
    Alphanumeric,
    Hex,
}

/// A random value from the OS generator.
pub fn generate(length: usize, charset: Charset) -> String {
    let alphabet: &[u8] = match charset {
        Charset::UrlSafe => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        Charset::Alphanumeric => b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        Charset::Hex => b"0123456789abcdef",
    };
    (0..length).map(|_| alphabet[OsRng.gen_range(0..alphabet.len())] as char).collect()
}

/// A service whose keys can't be rolled through a public API: where to do it by hand.
#[derive(Debug, Clone, PartialEq)]
pub struct Provider {
    pub name: &'static str,
    pub dashboard: String,
    pub steps: &'static str,
}

/// The service a key belongs to, recognised from its value (or name).
pub fn provider(key: &str, value: &str) -> Option<Provider> {
    let k = key.to_ascii_uppercase();
    let p = |name, dashboard: &str, steps| Some(Provider { name, dashboard: dashboard.to_string(), steps });
    if value.starts_with("sk_live_") || value.starts_with("rk_live_") || value.starts_with("sk_test_") || value.starts_with("rk_test_") {
        let mode = if value.contains("_test_") { "test/" } else { "" };
        return p("Stripe", &format!("https://dashboard.stripe.com/{mode}apikeys"), "Roll the key (choose when the old one expires), copy the new one and paste it here.");
    }
    if ["ghp_", "github_pat_", "gho_", "ghs_", "ghu_"].iter().any(|x| value.starts_with(x)) {
        return p("GitHub", "https://github.com/settings/tokens", "Regenerate the token (or create a new one with the same scopes and delete the old one), then paste it here.");
    }
    if value.starts_with("sk-ant-") {
        return p("Anthropic", "https://console.anthropic.com/settings/keys", "Create a new key, paste it here, then disable the old one.");
    }
    if value.starts_with("sk-proj-") || (value.starts_with("sk-") && k.contains("OPENAI")) {
        return p("OpenAI", "https://platform.openai.com/api-keys", "Create a new secret key, paste it here, then revoke the old one.");
    }
    if ["xoxb-", "xoxp-", "xoxa-"].iter().any(|x| value.starts_with(x)) {
        return p("Slack", "https://api.slack.com/apps", "Open the app → OAuth & Permissions → rotate or reinstall to get a new token, then paste it here.");
    }
    if value.starts_with("SG.") {
        return p("SendGrid", "https://app.sendgrid.com/settings/api_keys", "Create a new API key with the same permissions, paste it here, then delete the old one.");
    }
    if (value.starts_with("AKIA") || value.starts_with("ASIA")) && k.contains("AWS") || k == "AWS_SECRET_ACCESS_KEY" {
        return p("AWS", "https://console.aws.amazon.com/iam/home#/security_credentials", "Run `yasecret rotate aws` to replace the key pair automatically, or create a new access key in IAM, paste both values, then deactivate the old key.");
    }
    None
}

/// AWS Signature Version 4, for the IAM and STS calls access-key rotation needs.
pub mod aws {
    use sha2::{Digest, Sha256};

    #[derive(Clone)]
    pub struct Credentials {
        pub access_key: String,
        pub secret_key: String,
    }

    pub struct Signed {
        pub authorization: String,
        pub amz_date: String,
    }

    fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            k[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<_>>());
        inner.update(msg);
        let mut outer = Sha256::new();
        outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<_>>());
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// Percent-encodes per AWS: everything but unreserved characters.
    pub fn encode(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    /// Signs a request. `query` is `k=v` pairs joined with `&` (already encoded); they're
    /// sorted here. `amz_date` is `YYYYMMDDTHHMMSSZ`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        creds: &Credentials,
        method: &str,
        host: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
        payload: &[u8],
        region: &str,
        service: &str,
        amz_date: &str,
    ) -> Signed {
        let date = &amz_date[..8];
        let mut params: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).collect();
        params.sort();
        let mut all: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_string())).collect();
        all.push(("host".into(), host.into()));
        all.push(("x-amz-date".into(), amz_date.into()));
        all.sort();
        let canonical_headers: String = all.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
        let signed_headers = all.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{method}\n{path}\n{}\n{canonical_headers}\n{signed_headers}\n{}",
            params.join("&"),
            hex::encode(Sha256::digest(payload))
        );
        let scope = format!("{date}/{region}/{service}/aws4_request");
        let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
        let k_date = hmac(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, service.as_bytes());
        let k_signing = hmac(&k_service, b"aws4_request");
        let signature = hex::encode(hmac(&k_signing, to_sign.as_bytes()));
        Signed {
            authorization: format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                creds.access_key
            ),
            amz_date: amz_date.to_string(),
        }
    }

    /// `YYYYMMDDTHHMMSSZ` for a Unix time (UTC), as AWS expects.
    pub fn amz_date(unix: i64) -> String {
        let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
        // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!("{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
    }

    /// The text of the first `<tag>…</tag>` in an AWS XML response.
    pub fn xml_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
        let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
        let end = xml[start..].find(&format!("</{tag}>"))? + start;
        Some(&xml[start..end])
    }
}
