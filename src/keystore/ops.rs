use super::format;
use super::schema::{Credential, CryptLevel, KeyStore};
use crate::crypto::age_ops;
use crate::protect::IdentityProtector;
use base64::Engine;
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

// ── Base64 helpers ──────────────────────────────────────────────────

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("Base64 decode: {}", e))
}

// ── Local time helper (mirrors schema::chrono_now_iso) ──────────────

fn chrono_now_iso() -> String {
    // Placeholder — real implementation will use proper time
    "2026-01-01T00:00:00Z".to_string()
}

// ── CRUD Operations ─────────────────────────────────────────────────

/// Initialize a new keystore file. Creates an empty KeyStore, encrypts it,
/// and writes it atomically. Returns the outer AES key.
pub fn init_store(path: &Path) -> Result<[u8; 32], String> {
    if path.exists() {
        return Err("Keystore already exists".into());
    }
    let aes_key = format::generate_aes_key()?;
    let store = KeyStore::empty();
    let json = serde_json::to_vec(&store)
        .map_err(|e| format!("Serialize error: {}", e))?;
    format::save_keystore(path, &json, &aes_key)?;
    Ok(aes_key)
}

/// Add a credential to the keystore. Encrypts the secret with age using
/// the crypt_level's public key (recipient). Returns the credential ID.
pub fn add_credential(
    path: &Path,
    aes_key: &[u8],
    domain: &str,
    account: &str,
    plaintext_secret: &str,
    crypt_level: &CryptLevel,
    description: Option<&str>,
    tags: &[String],
) -> Result<String, String> {
    let mut store = load_store(path, aes_key)?;
    let key = KeyStore::credential_key(domain, account);

    if store.credentials.contains_key(&key) {
        return Err(format!("Credential already exists: {}", key));
    }

    let level_str = crypt_level.as_str();
    let kp = store.key_pairs.get(level_str).ok_or_else(|| {
        format!(
            "Level '{}' not initialized. Run 'keybox init --level {}'",
            level_str, level_str
        )
    })?;

    // Parse the age recipient from the stored public key string
    let recipient: age::x25519::Recipient = kp
        .public_key
        .parse()
        .map_err(|e| format!("Invalid age public key: {}", e))?;

    // Encrypt the plaintext secret with age
    let ciphertext = age_ops::encrypt_with_recipient(&recipient, plaintext_secret.as_bytes())
        .map_err(|e| format!("Age encryption failed: {}", e))?;
    let secret = b64_encode(&ciphertext);

    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono_now_iso();

    store.credentials.insert(
        key.clone(),
        Credential {
            id: id.clone(),
            domain: domain.to_string(),
            account: account.to_string(),
            description: description.map(|s| s.to_string()),
            tags: tags.to_vec(),
            created_at: now.clone(),
            updated_at: now,
            last_access_at: None,
            crypt_level: crypt_level.clone(),
            secret,
        },
    );

    save_store(path, &store, aes_key)?;
    Ok(id)
}

/// Get credential metadata (without decrypting the secret).
pub fn get_credential(
    path: &Path,
    aes_key: &[u8],
    domain: &str,
    account: &str,
) -> Result<Credential, String> {
    let store = load_store(path, aes_key)?;
    let key = KeyStore::credential_key(domain, account);
    store
        .credentials
        .get(&key)
        .cloned()
        .ok_or_else(|| format!("Credential not found: {}", key))
}

/// Decrypt and return the secret value for a credential.
/// The caller must provide the decrypted age identity (private key).
/// Returns the plaintext secret as bytes.
pub fn get_password(
    path: &Path,
    aes_key: &[u8],
    domain: &str,
    account: &str,
    identity: &age::x25519::Identity,
) -> Result<Vec<u8>, String> {
    let cred = get_credential(path, aes_key, domain, account)?;
    let ciphertext = b64_decode(&cred.secret)?;
    age_ops::decrypt_with_identity(identity, &ciphertext)
        .map_err(|e| format!("Age decryption failed: {}", e))
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

// ── CRUD tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod crud_tests {
    use super::*;
    use crate::crypto::age_ops;
    use crate::keystore::format;
    use crate::keystore::schema::{CryptLevel, KeyPair, KeyStore};
    use tempfile::tempdir;

    fn setup_store_with_secret_keypair(path: &std::path::Path) -> ([u8; 32], age::x25519::Identity) {
        let aes_key = format::generate_aes_key().unwrap();
        let (identity, recipient) = age_ops::generate_keypair();
        let mut store = KeyStore::empty();
        store.key_pairs.insert(
            "secret".into(),
            KeyPair {
                public_key: recipient.to_string(),
                encrypted_private_key: "placeholder_protected_identity".into(),
                protector: "test".into(),
            },
        );
        let json = serde_json::to_vec(&store).unwrap();
        format::save_keystore(path, &json, &aes_key).unwrap();
        (aes_key, identity)
    }

    #[test]
    fn test_init_store_creates_file() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let key = init_store(&path).unwrap();
        assert!(path.exists());
        let store = load_store(&path, &key).unwrap();
        assert_eq!(store.version, 1);
        assert!(store.credentials.is_empty());
    }

    #[test]
    fn test_init_store_rejects_existing() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        init_store(&path).unwrap();
        assert!(init_store(&path).is_err());
    }

    #[test]
    fn test_add_and_get_credential() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let (aes_key, _identity) = setup_store_with_secret_keypair(&path);

        let id = add_credential(
            &path,
            &aes_key,
            "github.com",
            "brian",
            "mytoken",
            &CryptLevel::Secret,
            Some("test cred"),
            &["git".into()],
        )
        .unwrap();
        assert!(!id.is_empty());

        let cred = get_credential(&path, &aes_key, "github.com", "brian").unwrap();
        assert_eq!(cred.domain, "github.com");
        assert_eq!(cred.description, Some("test cred".into()));
        assert_eq!(cred.crypt_level, CryptLevel::Secret);
    }

    #[test]
    fn test_add_duplicate_rejected() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let (aes_key, _) = setup_store_with_secret_keypair(&path);

        add_credential(
            &path,
            &aes_key,
            "github.com",
            "brian",
            "t1",
            &CryptLevel::Secret,
            None,
            &[],
        )
        .unwrap();
        let result = add_credential(
            &path,
            &aes_key,
            "github.com",
            "brian",
            "t2",
            &CryptLevel::Secret,
            None,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_get_password_roundtrip() {
        let dir = tempdir().unwrap();
        let path = keystore_path(dir.path());
        let (aes_key, identity) = setup_store_with_secret_keypair(&path);

        add_credential(
            &path,
            &aes_key,
            "github.com",
            "brian",
            "super-secret-token",
            &CryptLevel::Secret,
            None,
            &[],
        )
        .unwrap();

        let decrypted =
            get_password(&path, &aes_key, "github.com", "brian", &identity).unwrap();
        assert_eq!(
            std::str::from_utf8(&decrypted).unwrap(),
            "super-secret-token"
        );
    }
}
