use super::format;
use super::schema::KeyStore;
use std::path::Path;

/// Load and parse the keystore file
pub fn load_store(path: &Path, aes_key: &[u8]) -> Result<KeyStore, String> {
    let json_bytes = format::load_keystore(path, aes_key)?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("Failed to parse keystore JSON: {}", e))
}

/// Serialize and atomically save the keystore
pub fn save_store(path: &Path, store: &KeyStore, aes_key: &[u8]) -> Result<(), String> {
    let json_bytes = serde_json::to_vec(store)
        .map_err(|e| format!("Failed to serialize keystore: {}", e))?;
    format::save_keystore(path, &json_bytes, aes_key)
}

/// Determine the keystore file path for the given base config directory
pub fn keystore_path(base: &Path) -> std::path::PathBuf {
    base.join("keybox.keystore")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::format;
    use crate::keystore::schema::{Credential, CryptLevel};
    use tempfile::tempdir;

    #[test]
    fn test_load_save_empty_store() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let key = format::generate_aes_key().unwrap();

        let store = KeyStore::empty();
        save_store(&path, &store, &key).unwrap();
        assert!(path.exists());

        let loaded = load_store(&path, &key).unwrap();
        assert_eq!(loaded.version, 1);
        assert!(loaded.credentials.is_empty());
        assert!(loaded.key_pairs.is_empty());
    }

    #[test]
    fn test_load_save_with_credential() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let key = format::generate_aes_key().unwrap();

        let mut store = KeyStore::empty();
        store.credentials.insert(
            "github.com:brian".into(),
            Credential {
                id: "uuid-1".into(),
                domain: "github.com".into(),
                account: "brian".into(),
                description: Some("token".into()),
                tags: vec!["git".into()],
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: "2026-01-01T00:00:00Z".into(),
                last_access_at: None,
                crypt_level: CryptLevel::Secret,
                secret: "encrypted_base64".into(),
            },
        );

        save_store(&path, &store, &key).unwrap();
        let loaded = load_store(&path, &key).unwrap();

        assert_eq!(loaded.credentials.len(), 1);
        let cred = &loaded.credentials["github.com:brian"];
        assert_eq!(cred.domain, "github.com");
        assert_eq!(cred.crypt_level, CryptLevel::Secret);
        assert_eq!(cred.secret, "encrypted_base64");
    }

    #[test]
    fn test_load_wrong_key_fails() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let key1 = format::generate_aes_key().unwrap();
        let key2 = format::generate_aes_key().unwrap();

        save_store(&path, &KeyStore::empty(), &key1).unwrap();
        assert!(load_store(&path, &key2).is_err());
    }

    #[test]
    fn test_keystore_path() {
        let base = std::path::Path::new("/home/user/.config/keybox");
        assert_eq!(
            keystore_path(base),
            std::path::Path::new("/home/user/.config/keybox/keybox.keystore")
        );
    }
}
