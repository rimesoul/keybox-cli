use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Helper ──────────────────────────────────────────────────────────

fn chrono_now_iso() -> String {
    // Use std::time + manual formatting, or use chrono crate if already a dependency
    // For now: return a fixed string placeholder; real implementation will use proper time
    "2026-01-01T00:00:00Z".to_string()
}

// ── KeyPair ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyPair {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub protector: String,
}

// ── Credential ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub domain: String,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_access_at: Option<String>,
    pub crypt_level: String,
    pub secret: String,
}

// ── KeyStore ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub key_pairs: HashMap<String, KeyPair>,
    #[serde(default)]
    pub credentials: HashMap<String, Credential>,
}

impl KeyStore {
    pub fn credential_key(domain: &str, account: &str) -> String {
        format!("{}:{}", domain, account)
    }

    pub fn empty() -> Self {
        let now = chrono_now_iso();
        KeyStore {
            version: 1,
            created_at: now.clone(),
            updated_at: now,
            key_pairs: HashMap::new(),
            credentials: HashMap::new(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_keystore_serialization() {
        let ks = KeyStore::empty();
        let json = serde_json::to_string(&ks).unwrap();
        assert!(json.contains("\"version\":1"));
        let parsed: KeyStore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 1);
        assert!(parsed.credentials.is_empty());
        assert!(parsed.key_pairs.is_empty());
    }

    #[test]
    fn test_credential_roundtrip() {
        let mut ks = KeyStore::empty();
        ks.credentials.insert("github.com:brian".into(), Credential {
            id: "uuid-1".into(),
            domain: "github.com".into(),
            account: "brian".into(),
            description: Some("token".into()),
            tags: vec!["git".into()],
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            last_access_at: None,
            crypt_level: "secret".into(),
            secret: "base64_encrypted".into(),
        });
        let json = serde_json::to_string(&ks).unwrap();
        let parsed: KeyStore = serde_json::from_str(&json).unwrap();
        let cred = &parsed.credentials["github.com:brian"];
        assert_eq!(cred.domain, "github.com");
        assert_eq!(cred.tags, vec!["git"]);
    }

    #[test]
    fn test_credential_key_format() {
        assert_eq!(KeyStore::credential_key("github.com", "brian"), "github.com:brian");
        assert_eq!(KeyStore::credential_key("default", "test"), "default:test");
    }
}
