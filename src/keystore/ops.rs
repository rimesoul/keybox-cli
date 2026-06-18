use super::format;
use super::schema::KeyStore;
use crate::protect::IdentityProtector;
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

/// Protect (encrypt) data using the given protector, returning the encrypted bytes.
/// Uses a temp file as intermediate to bridge the file-based protector interface
/// with in-memory byte storage needed by the keystore.
pub fn protect_to_bytes(
    protector: &dyn IdentityProtector,
    data: &[u8],
    marker_base: &Path,
) -> Result<Vec<u8>, String> {
    // Create a temp file for the protector to write to
    let tmp = marker_base.with_extension("protect.tmp");
    protector.protect(data, &tmp)?;

    // Read back the protected blob (or marker content on macOS)
    std::fs::read(&tmp)
        .map_err(|e| format!("Failed to read protected data: {}", e))
}

/// Unprotect (decrypt) data previously protected with `protect_to_bytes`.
/// Writes the encrypted bytes to a temp file so the file-based protector can read it.
pub fn unprotect_from_bytes(
    protector: &dyn IdentityProtector,
    encrypted_bytes: &[u8],
    marker_path: &Path,
) -> Result<Vec<u8>, String> {
    // Write encrypted bytes to temp file so protector can read it
    std::fs::write(marker_path, encrypted_bytes)
        .map_err(|e| format!("Failed to write temp identity file: {}", e))?;

    protector.unprotect(marker_path)
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

#[cfg(test)]
mod protector_tests {
    use super::*;
    use tempfile::tempdir;

    // Test-only protector that simply base64 encodes/decodes
    struct TestProtector;
    impl crate::protect::IdentityProtector for TestProtector {
        fn protect(&self, data: &[u8], path: &std::path::Path) -> Result<(), String> {
            let encoded = base64_encode(data);
            std::fs::write(path, encoded).map_err(|e| format!("write: {}", e))
        }
        fn unprotect(&self, path: &std::path::Path) -> Result<Vec<u8>, String> {
            let encoded = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
            base64_decode(&encoded)
        }
    }

    fn base64_encode(data: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
    fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|e| format!("base64: {}", e))
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("marker");
        let protector = TestProtector;
        let original = b"AGE-SECRET-KEY-1TESTTESTTEST";

        let encrypted = protect_to_bytes(&protector, original, &marker).unwrap();
        // Encrypted bytes should not equal original
        assert_ne!(encrypted, original);

        let decrypted = unprotect_from_bytes(&protector, &encrypted, &marker).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_unprotect_wrong_data_fails() {
        let dir = tempdir().unwrap();
        let marker = dir.path().join("marker");
        let protector = TestProtector;
        let garbage = b"not-valid-base64!!!";

        let result = unprotect_from_bytes(&protector, garbage, &marker);
        assert!(result.is_err());
    }
}
