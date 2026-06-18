use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Helper ──────────────────────────────────────────────────────────

fn chrono_now_iso() -> String {
    // Use std::time + manual formatting, or use chrono crate if already a dependency
    // For now: return a fixed string placeholder; real implementation will use proper time
    "2026-01-01T00:00:00Z".to_string()
}

// ── CryptLevel ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CryptLevel {
    Secret,
    Con,
    Top,
}

impl std::str::FromStr for CryptLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "secret" => Ok(CryptLevel::Secret),
            "con" => Ok(CryptLevel::Con),
            "top" => Ok(CryptLevel::Top),
            _ => Err(format!("unknown crypt level: {s}")),
        }
    }
}

impl std::fmt::Display for CryptLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CryptLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptLevel::Secret => "secret",
            CryptLevel::Con => "con",
            CryptLevel::Top => "top",
        }
    }
}

// ── KeyPair ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub protector: String,
}

// ── Credential ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub crypt_level: CryptLevel,
    pub secret: String,
}

// ── KeyStore ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    pub version: u32,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub key_pairs: HashMap<String, KeyPair>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
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
            crypt_level: CryptLevel::Secret,
            secret: "base64_encrypted".into(),
        });
        let json = serde_json::to_string(&ks).unwrap();
        let parsed: KeyStore = serde_json::from_str(&json).unwrap();
        let cred = &parsed.credentials["github.com:brian"];
        assert_eq!(cred.id, "uuid-1");
        assert_eq!(cred.domain, "github.com");
        assert_eq!(cred.account, "brian");
        assert_eq!(cred.description, Some("token".to_string()));
        assert_eq!(cred.last_access_at, None);
        assert_eq!(cred.crypt_level, CryptLevel::Secret);
        assert_eq!(cred.secret, "base64_encrypted");
        assert_eq!(cred.tags, vec!["git"]);
        assert_eq!(cred.created_at, "2026-01-01T00:00:00Z");
        assert_eq!(cred.updated_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_credential_key_format() {
        assert_eq!(KeyStore::credential_key("github.com", "brian"), "github.com:brian");
        assert_eq!(KeyStore::credential_key("default", "test"), "default:test");
    }

    #[test]
    fn test_keypair_equality() {
        let kp1 = KeyPair {
            public_key: "pk".into(),
            encrypted_private_key: "sk".into(),
            protector: "test".into(),
        };
        let kp2 = kp1.clone();
        assert_eq!(kp1, kp2);
    }

    #[test]
    fn test_deserialize_keystore_missing_optionals() {
        let json = r#"{"version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let ks: KeyStore = serde_json::from_str(json).unwrap();
        assert!(ks.key_pairs.is_empty());
        assert!(ks.credentials.is_empty());
    }

    #[test]
    fn test_deserialize_credential_missing_tags() {
        let json = r#"{"id":"x","domain":"d","account":"a","created_at":"t","updated_at":"t","crypt_level":"secret","secret":"s"}"#;
        let cred: Credential = serde_json::from_str(json).unwrap();
        assert!(cred.tags.is_empty());
        assert_eq!(cred.description, None);
    }
}
