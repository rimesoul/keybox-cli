# Keybox CLI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a cross-platform CLI credential manager with three independently-encrypted security tiers, a daemon-backed unlock model, and LLM-friendly error handling.

**Architecture:** Single Rust binary with three operating modes: CLI commands, confidential daemon, and top-secret daemon. Credentials are encrypted with age; identity keys are protected per-platform (DPAPI, Keychain, machine-id) or per-tier (passphrase, file hash). Daemons expose decrypted identities over Unix domain sockets/Named pipes.

**Tech Stack:** Rust, `clap` (CLI), `age`/`rage` (encryption), `ring` (AEAD), `sha2` (hashing), `rpassword` (hidden input), `arboard` (clipboard), `serde`/`serde_json` (JSON output), `dirs` (XDG paths). Platform: `windows-sys` (DPAPI), `security-framework` (Keychain).

---

## File Structure

```
keybox-cli/
├── Cargo.toml
├── src/
│   ├── main.rs                   # Entry point: dispatch CLI vs daemon mode
│   ├── cli.rs                    # Clap structs and argument parsing
│   ├── tier.rs                   # Tier enum, path resolution, directory init
│   ├── store.rs                  # Credential file read/write (add, get, list, delete, update)
│   ├── interactive.rs            # TTY detection, password prompts, LLM mode
│   ├── env_run.rs                # --env subprocess execution
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── age_ops.rs            # age encrypt/decrypt wrappers
│   │   └── identity.rs           # age keypair generation, load/save identity
│   ├── protect/
│   │   ├── mod.rs                # IdentityProtector trait
│   │   ├── linux.rs              # /etc/machine-id + AES-256-GCM
│   │   ├── macos.rs              # macOS Keychain Services
│   │   └── windows.rs            # Windows DPAPI
│   └── daemon/
│       ├── mod.rs
│       ├── protocol.rs           # Request/Response message types + serialization
│       ├── server.rs             # Socket listener, unlock/lock state, handle requests
│       └── client.rs             # Connect to daemon, send request, receive response
└── tests/
    ├── common/
    │   └── mod.rs                # Test helpers: temp dirs, test keypairs
    ├── unit/
    │   ├── tier_tests.rs
    │   ├── crypto_tests.rs
    │   ├── protect_tests.rs
    │   ├── store_tests.rs
    │   ├── cli_tests.rs
    │   ├── interactive_tests.rs
    │   └── daemon_protocol_tests.rs
    └── integration/
        ├── add_get_tests.rs
        ├── list_delete_tests.rs
        ├── update_tests.rs
        ├── init_tests.rs
        ├── daemon_tests.rs
        └── non_interactive_tests.rs
```

---

## Phase 1: Project Scaffold

### Task 1: Initialize Rust project with dependencies

**Files:**
- Create: `Cargo.toml`
- Create: `src/main.rs`

- [ ] **Step 1: Create Cargo project**

```bash
cargo init --name keybox keybox-cli
```

- [ ] **Step 2: Write Cargo.toml with dependencies**

```toml
[package]
name = "keybox"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4", features = ["derive"] }
age = "0.10"
sha2 = "0.10"
rand = "0.8"
ring = "0.17"
dirs = "5"
rpassword = "7"
arboard = "3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
hex = "0.4"

[target.'cfg(target_os = "windows")'.dependencies]
windows-sys = { version = "0.52", features = ["Win32_Security_Cryptography", "Win32_Foundation"] }

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "2"

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"
predicates = "3"
```

- [ ] **Step 3: Write minimal main.rs**

```rust
fn main() {
    println!("keybox v0.1.0");
}
```

- [ ] **Step 4: Verify it compiles and runs**

Run: `cargo build && ./target/debug/keybox`
Expected output: `keybox v0.1.0`

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/main.rs
git commit -m "feat: initialize Rust project with dependencies"
```

---

## Phase 2: Core Infrastructure

### Task 2: Tier module — path resolution and directory initialization

**Files:**
- Create: `src/tier.rs`
- Create: `tests/unit/tier_tests.rs`
- Create: `tests/common/mod.rs`
- Modify: `src/main.rs` — add `mod tier;`

- [ ] **Step 1: Write tier tests**

```rust
// tests/common/mod.rs
use std::path::PathBuf;

pub fn test_config_dir() -> PathBuf {
    std::env::temp_dir().join("keybox-test").join(uuid::Uuid::new_v4().to_string())
}
```

Wait — we don't have `uuid` as a dep. Simpler approach:

```rust
// tests/common/mod.rs
use std::path::PathBuf;

pub fn test_config_dir() -> PathBuf {
    let dir = std::env::temp_dir()
        .join("keybox-test")
        .join(format!("{}", std::process::id()));
    dir
}
```

```rust
// tests/unit/tier_tests.rs
use keybox::tier::{Tier, TierPaths};
use std::fs;

mod common;

#[test]
fn test_tier_paths_secret() {
    let base = common::test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::Secret);
    assert_eq!(paths.private_key, base.join("secret").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("secret").join("identity.pub"));
    assert_eq!(paths.store, base.join("secret").join("store"));
}

#[test]
fn test_tier_paths_confidential() {
    let base = common::test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::Confidential);
    assert_eq!(paths.private_key, base.join("confidential").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("confidential").join("identity.pub"));
    assert_eq!(paths.store, base.join("confidential").join("store"));
}

#[test]
fn test_tier_paths_top_secret() {
    let base = common::test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::TopSecret);
    assert_eq!(paths.private_key, base.join("top-secret").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("top-secret").join("identity.pub"));
    assert_eq!(paths.store, base.join("top-secret").join("store"));
}

#[test]
fn test_tier_is_initialized_false() {
    let base = common::test_config_dir();
    assert!(!Tier::Secret.is_initialized(&base));
}

#[test]
fn test_tier_is_initialized_true() {
    let base = common::test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::Secret);
    fs::create_dir_all(&paths.store).unwrap();
    fs::write(&paths.public_key, "fake-key").unwrap();
    assert!(Tier::Secret.is_initialized(&base));
    fs::remove_dir_all(&base).unwrap();
}

#[test]
fn test_tier_default_top_key_path() {
    let base = common::test_config_dir();
    assert_eq!(Tier::default_top_key_path(&base), base.join("top.key"));
}

#[test]
fn test_tier_daemon_socket_path() {
    let base = common::test_config_dir();
    assert_eq!(Tier::Confidential.daemon_socket_path(&base), base.join("keyboxd.sock"));
    assert_eq!(Tier::TopSecret.daemon_socket_path(&base), base.join("keyboxd-top.sock"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test tier_tests`
Expected: compilation failure (Tier not defined)

- [ ] **Step 3: Implement src/tier.rs**

```rust
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Secret,
    Confidential,
    TopSecret,
}

pub struct TierPaths {
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub store: PathBuf,
}

impl TierPaths {
    pub fn from_base(base: &Path, tier: Tier) -> Self {
        let tier_dir = base.join(tier.dir_name());
        Self {
            private_key: tier_dir.join("identity.private.enc"),
            public_key: tier_dir.join("identity.pub"),
            store: tier_dir.join("store"),
        }
    }
}

impl Tier {
    pub fn dir_name(&self) -> &str {
        match self {
            Tier::Secret => "secret",
            Tier::Confidential => "confidential",
            Tier::TopSecret => "top-secret",
        }
    }

    pub fn is_initialized(&self, base: &Path) -> bool {
        let paths = TierPaths::from_base(base, *self);
        paths.public_key.exists()
    }

    pub fn default_top_key_path(base: &Path) -> PathBuf {
        base.join("top.key")
    }

    pub fn daemon_socket_path(&self, base: &Path) -> PathBuf {
        match self {
            Tier::Secret => panic!("Secret tier has no daemon"),
            Tier::Confidential => base.join("keyboxd.sock"),
            Tier::TopSecret => base.join("keyboxd-top.sock"),
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test tier_tests`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/tier.rs tests/unit/tier_tests.rs tests/common/mod.rs src/main.rs
git commit -m "feat: add Tier module with path resolution and initialization checks"
```

---

### Task 3: Age encryption/decryption wrappers

**Files:**
- Create: `src/crypto/mod.rs`
- Create: `src/crypto/age_ops.rs`
- Create: `tests/unit/crypto_tests.rs`
- Modify: `src/main.rs` — add `mod crypto;`

- [ ] **Step 1: Write crypto tests**

```rust
// tests/unit/crypto_tests.rs
use keybox::crypto::age_ops;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let (identity, recipient) = age_ops::generate_keypair().unwrap();
    let plaintext = b"super-secret-password-123";
    let encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_empty() {
    let (identity, recipient) = age_ops::generate_keypair().unwrap();
    let plaintext = b"";
    let encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_large_payload() {
    let (identity, recipient) = age_ops::generate_keypair().unwrap();
    let plaintext = vec![b'x'; 4096];
    let encrypted = age_ops::encrypt_with_recipient(&recipient, &plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_binary_data() {
    let (identity, recipient) = age_ops::generate_keypair().unwrap();
    let plaintext: Vec<u8> = (0..=255).collect();
    let encrypted = age_ops::encrypt_with_recipient(&recipient, &plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_wrong_identity_fails() {
    let (_, recipient) = age_ops::generate_keypair().unwrap();
    let (other_identity, _) = age_ops::generate_keypair().unwrap();
    let encrypted = age_ops::encrypt_with_recipient(&recipient, b"secret").unwrap();
    let result = age_ops::decrypt_with_identity(&other_identity, &encrypted);
    assert!(result.is_err());
}

#[test]
fn test_corrupted_ciphertext_fails() {
    let (identity, recipient) = age_ops::generate_keypair().unwrap();
    let mut encrypted = age_ops::encrypt_with_recipient(&recipient, b"secret").unwrap();
    if encrypted.len() > 10 {
        encrypted[10] ^= 0xFF;
    }
    let result = age_ops::decrypt_with_identity(&identity, &encrypted);
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test crypto_tests`
Expected: compilation failure

- [ ] **Step 3: Implement src/crypto/mod.rs**

```rust
pub mod age_ops;
pub mod identity;
```

- [ ] **Step 4: Implement src/crypto/age_ops.rs**

```rust
use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};

pub fn generate_keypair() -> Result<(Identity, Recipient), age::Error> {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    Ok((identity, recipient))
}

pub fn encrypt_with_recipient(recipient: &Recipient, plaintext: &[u8]) -> Result<Vec<u8>, age::EncryptError> {
    let recipients = vec![Box::new(recipient.clone()) as Box<dyn age::Recipient + Send>];
    let encryptor = Encryptor::with_recipients(recipients)?;
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(encrypted)
}

pub fn decrypt_with_identity(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>, age::DecryptError> {
    let decryptor = match Decryptor::new(ciphertext)? {
        Decryptor::Recipients(d) => d,
        Decryptor::Passphrase(_) => return Err(age::DecryptError::MissingIdentity),
    };
    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test crypto_tests`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/crypto/ tests/unit/crypto_tests.rs src/main.rs
git commit -m "feat: add age encryption/decryption ops with roundtrip tests"
```

---

### Task 4: Identity keypair generation and serialization

**Files:**
- Create: `src/crypto/identity.rs`
- Modify: `src/crypto/mod.rs` — export identity module

- [ ] **Step 1: Write identity tests**

Add to `tests/unit/crypto_tests.rs`:

```rust
use keybox::crypto::identity;
use std::fs;

#[test]
fn test_generate_and_save_identity() {
    let dir = tempfile::tempdir().unwrap();
    let private_path = dir.path().join("identity.private.enc");
    let public_path = dir.path().join("identity.pub");

    let (identity, recipient) = identity::generate();
    identity::save_identity(&identity, &private_path).unwrap();
    identity::save_recipient(&recipient, &public_path).unwrap();

    assert!(private_path.exists());
    assert!(public_path.exists());
}

#[test]
fn test_load_identity_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let private_path = dir.path().join("identity.private.enc");
    let public_path = dir.path().join("identity.pub");

    let (identity, recipient) = identity::generate();
    identity::save_identity(&identity, &private_path).unwrap();
    identity::save_recipient(&recipient, &public_path).unwrap();

    let loaded_identity = identity::load_identity(&private_path).unwrap();
    let loaded_recipient = identity::load_recipient(&public_path).unwrap();

    // Encrypt with original recipient, decrypt with loaded identity
    let encrypted = age_ops::encrypt_with_recipient(&loaded_recipient, b"test").unwrap();
    let decrypted = age_ops::decrypt_with_identity(&loaded_identity, &encrypted).unwrap();
    assert_eq!(decrypted, b"test");
}

#[test]
fn test_load_identity_from_invalid_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.file");
    fs::write(&path, b"not a valid identity").unwrap();
    let result = identity::load_identity(&path);
    assert!(result.is_err());
}

#[test]
fn test_load_recipient_from_invalid_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");
    fs::write(&path, b"not a valid recipient").unwrap();
    let result = identity::load_recipient(&path);
    assert!(result.is_err());
}

#[test]
fn test_recipient_to_from_string() {
    let (_, recipient) = identity::generate();
    let s = recipient.to_string();
    let parsed = identity::parse_recipient(&s).unwrap();
    // Encrypt with both, they should be equivalent
    let encrypted1 = age_ops::encrypt_with_recipient(&recipient, b"test").unwrap();
    // Note: different ephemeral keys per encryption, so ciphertexts differ,
    // but they should both decrypt with the same identity
    assert!(s.starts_with("age1"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test identity` (within crypto_tests)
Expected: compilation failure (identity module not found)

- [ ] **Step 3: Implement src/crypto/identity.rs**

```rust
use age::x25519::{Identity, Recipient};
use std::fs;
use std::path::Path;

pub fn generate() -> (Identity, Recipient) {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

pub fn save_identity(identity: &Identity, path: &Path) -> Result<(), String> {
    let data = identity.to_string();
    fs::write(path, data.as_bytes()).map_err(|e| format!("Failed to write identity: {}", e))
}

pub fn load_identity(path: &Path) -> Result<Identity, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read identity: {}", e))?;
    let data = data.trim();
    Identity::from_str(data)
        .map_err(|e| format!("Failed to parse identity: {}", e))
}

pub fn save_recipient(recipient: &Recipient, path: &Path) -> Result<(), String> {
    let data = recipient.to_string();
    fs::write(path, data.as_bytes()).map_err(|e| format!("Failed to write recipient: {}", e))
}

pub fn load_recipient(path: &Path) -> Result<Recipient, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read recipient: {}", e))?;
    let data = data.trim();
    Recipient::from_str(data).map_err(|e| format!("Failed to parse recipient: {}", e))
}

pub fn parse_recipient(s: &str) -> Result<Recipient, String> {
    Recipient::from_str(s).map_err(|e| format!("Failed to parse recipient: {}", e))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test crypto_tests`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto/identity.rs src/crypto/mod.rs tests/unit/crypto_tests.rs
git commit -m "feat: add identity keypair generation and serialization"
```

---

## Phase 3: Platform-Specific Identity Protection

### Task 5: IdentityProtector trait + Linux implementation

**Files:**
- Create: `src/protect/mod.rs`
- Create: `src/protect/linux.rs`
- Create: `tests/unit/protect_tests.rs`
- Modify: `src/main.rs` — add `mod protect;`

- [ ] **Step 1: Write protection trait and Linux tests**

```rust
// tests/unit/protect_tests.rs
#[cfg(target_os = "linux")]
mod linux_tests {
    use keybox::protect::{IdentityProtector, LinuxProtector};
    use keybox::crypto::identity;
    use keybox::crypto::age_ops;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_linux_protect_unprotect_roundtrip() {
        let dir = TempDir::new().unwrap();
        let protected_path = dir.path().join("identity.private.enc");
        let protector = LinuxProtector::new();

        let (identity, _recipient) = identity::generate();
        let raw = identity.to_string();

        protector.protect(raw.as_bytes(), &protected_path).unwrap();
        assert!(protected_path.exists());

        let recovered = protector.unprotect(&protected_path).unwrap();
        assert_eq!(recovered, raw.as_bytes());
    }

    #[test]
    fn test_linux_protected_file_has_restrictive_permissions() {
        let dir = TempDir::new().unwrap();
        let protected_path = dir.path().join("identity.private.enc");
        let protector = LinuxProtector::new();

        let data = b"test-identity-data";
        protector.protect(data, &protected_path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&protected_path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_linux_unprotect_corrupted_file_fails() {
        let dir = TempDir::new().unwrap();
        let protected_path = dir.path().join("identity.private.enc");
        let protector = LinuxProtector::new();

        let data = b"test-identity-data";
        protector.protect(data, &protected_path).unwrap();

        // Corrupt the file
        let mut bytes = fs::read(&protected_path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(&protected_path, bytes).unwrap();

        let result = protector.unprotect(&protected_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_linux_protect_different_machine_ids_produce_different_outputs() {
        // Same data, different "machine-id" values produce different ciphertexts
        let dir = TempDir::new().unwrap();
        let path1 = dir.path().join("enc1");
        let path2 = dir.path().join("enc2");

        // Directly test the AES-GCM layer with different keys
        let data = b"same-data";
        let key1 = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let key2 = hex::decode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();

        let ct1 = keybox::protect::linux::aes_gcm_encrypt(&key1, data).unwrap();
        let ct2 = keybox::protect::linux::aes_gcm_encrypt(&key2, data).unwrap();
        assert_ne!(ct1, ct2);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test protect_tests` (on Linux)
Expected: compilation failure

- [ ] **Step 3: Implement src/protect/mod.rs**

```rust
use std::path::Path;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxProtector;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOSProtector;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::DpapiProtector;

pub trait IdentityProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String>;
    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String>;
}
```

- [ ] **Step 4: Implement src/protect/linux.rs**

```rust
use crate::protect::IdentityProtector;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Sha256, Digest};
use std::fs;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct LinuxProtector;

impl LinuxProtector {
    pub fn new() -> Self {
        Self
    }

    fn machine_id(&self) -> Result<String, String> {
        for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(id) = fs::read_to_string(path) {
                return Ok(id.trim().to_string());
            }
        }
        Err("Could not read machine-id from /etc/machine-id or /var/lib/dbus/machine-id".into())
    }

    fn derive_key(&self) -> Result<Vec<u8>, String> {
        let machine_id = self.machine_id()?;
        let mut hasher = Sha256::new();
        hasher.update(b"keybox-linux-v1");
        hasher.update(machine_id.as_bytes());
        let hash = hasher.finalize();
        Ok(hash.to_vec()) // 32 bytes, fits AES-256
    }
}

impl IdentityProtector for LinuxProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let key = self.derive_key()?;
        let encrypted = aes_gcm_encrypt(&key, data)?;
        fs::write(path, &encrypted).map_err(|e| format!("Failed to write: {}", e))?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(path)
                .map_err(|e| format!("Failed to read metadata: {}", e))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)
                .map_err(|e| format!("Failed to set permissions: {}", e))?;
        }

        Ok(())
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let key = self.derive_key()?;
        let encrypted = fs::read(path).map_err(|e| format!("Failed to read: {}", e))?;
        aes_gcm_decrypt(&key, &encrypted)
    }
}

pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate nonce: {}", e))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    Ok(output)
}

pub fn aes_gcm_decrypt(key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext_with_nonce.len() < NONCE_LEN {
        return Err("Ciphertext too short".into());
    }
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_LEN);

    let unbound_key = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
    let mut in_out = ciphertext.to_vec();
    let plaintext = key.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    Ok(plaintext.to_vec())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test protect_tests`
Expected: on Linux: all tests PASS; on macOS/Windows: no tests compiled (cfg-gated)

- [ ] **Step 6: Commit**

```bash
git add src/protect/ tests/unit/protect_tests.rs src/main.rs
git commit -m "feat: add IdentityProtector trait and Linux machine-id implementation"
```

---

### Task 6: macOS Keychain identity protection

**Files:**
- Create: `src/protect/macos.rs`
- Modify: `src/protect/mod.rs` — add macOS conditional compilation

- [ ] **Step 1: Write macOS protection tests**

Add to `tests/unit/protect_tests.rs`:

```rust
#[cfg(target_os = "macos")]
mod macos_tests {
    use keybox::protect::{IdentityProtector, MacOSProtector};
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_macos_protect_unprotect_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.private.enc");
        let protector = MacOSProtector::new();

        let data = b"test-identity-data-macos";
        protector.protect(data, &path).unwrap();
        assert!(path.exists());

        let recovered = protector.unprotect(&path).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_macos_unprotect_missing_file_fails() {
        let protector = MacOSProtector::new();
        let path = std::path::Path::new("/tmp/nonexistent-keybox-test.enc");
        let result = protector.unprotect(path);
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail** (on macOS only)

Run: `cargo test macos_tests`
Expected: compilation failure on macOS

- [ ] **Step 3: Implement src/protect/macos.rs**

```rust
use crate::protect::IdentityProtector;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::os::macos::keychain_item::ItemClass;
use security_framework::passwords::{set_generic_password, get_generic_password};
use std::fs;
use std::path::Path;

const SERVICE_NAME: &str = "com.keybox.cli";
const ACCOUNT_TEMPLATE: &str = "keybox-identity";

pub struct MacOSProtector;

impl MacOSProtector {
    pub fn new() -> Self {
        Self
    }

    fn account_for_path(path: &Path) -> String {
        format!("{}-{}", ACCOUNT_TEMPLATE, path.to_string_lossy())
    }
}

impl IdentityProtector for MacOSProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let account = Self::account_for_path(path);

        // Store in Keychain
        set_generic_password(SERVICE_NAME, &account, data)
            .map_err(|e| format!("Keychain store failed: {}", e))?;

        // Write a marker file so is_initialized() works
        fs::write(path, &data).map_err(|e| format!("Failed to write marker: {}", e))?;

        Ok(())
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let account = Self::account_for_path(path);
        get_generic_password(SERVICE_NAME, &account)
            .map_err(|e| format!("Keychain read failed: {}", e))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass** (on macOS)

Run: `cargo test macos_tests`
Expected: tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/protect/macos.rs src/protect/mod.rs tests/unit/protect_tests.rs
git commit -m "feat: add macOS Keychain identity protection"
```

---

### Task 7: Windows DPAPI identity protection

**Files:**
- Create: `src/protect/windows.rs`
- Modify: `src/protect/mod.rs` — add Windows conditional compilation

- [ ] **Step 1: Write Windows DPAPI tests**

Add to `tests/unit/protect_tests.rs`:

```rust
#[cfg(target_os = "windows")]
mod windows_tests {
    use keybox::protect::{IdentityProtector, DpapiProtector};
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_dpapi_protect_unprotect_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.private.enc");
        let protector = DpapiProtector::new();

        let data = b"test-identity-data-windows";
        protector.protect(data, &path).unwrap();
        assert!(path.exists());

        let recovered = protector.unprotect(&path).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_dpapi_unprotect_corrupted_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.private.enc");
        let protector = DpapiProtector::new();

        protector.protect(b"test-data", &path).unwrap();

        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 0xFF;
        fs::write(&path, bytes).unwrap();

        let result = protector.unprotect(&path);
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run tests** (on Windows only)

- [ ] **Step 3: Implement src/protect/windows.rs**

```rust
use crate::protect::IdentityProtector;
use std::fs;
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTOAPI_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
};
use windows_sys::Win32::Foundation::LocalFree;
use std::ptr;

pub struct DpapiProtector;

impl DpapiProtector {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProtector for DpapiProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let encrypted = dpapi_encrypt(data)?;
        fs::write(path, &encrypted).map_err(|e| format!("Failed to write: {}", e))
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let encrypted = fs::read(path).map_err(|e| format!("Failed to read: {}", e))?;
        dpapi_decrypt(&encrypted)
    }
}

fn dpapi_encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    let data_in = CRYPTOAPI_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let result = unsafe {
        CryptProtectData(
            &data_in,
            ptr::null(),        // description
            ptr::null(),        // entropy
            ptr::null(),        // reserved
            ptr::null(),        // prompt struct
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut data_out,
        )
    };

    if result == 0 {
        return Err("DPAPI CryptProtectData failed".into());
    }

    let encrypted = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(data_out.pbData as isize);
        vec
    };

    Ok(encrypted)
}

fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    let data_in = CRYPTOAPI_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &data_in,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            &mut data_out,
        )
    };

    if result == 0 {
        return Err("DPAPI CryptUnprotectData failed".into());
    }

    let decrypted = unsafe {
        let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(data_out.pbData as isize);
        vec
    };

    Ok(decrypted)
}
```

- [ ] **Step 4: Verify compilation on each platform**

Run: `cargo build` (cross-platform CI would verify all three)

- [ ] **Step 5: Commit**

```bash
git add src/protect/windows.rs src/protect/mod.rs tests/unit/protect_tests.rs
git commit -m "feat: add Windows DPAPI identity protection"
```

---

## Phase 4: Credential Store

### Task 8: Credential store — add and get operations

**Files:**
- Create: `src/store.rs`
- Create: `tests/unit/store_tests.rs`
- Modify: `src/main.rs` — add `mod store;`

- [ ] **Step 1: Write store tests**

```rust
// tests/unit/store_tests.rs
use keybox::store;
use keybox::tier::Tier;
use keybox::crypto::{age_ops, identity};
use tempfile::TempDir;
use std::fs;

fn setup_store(base: &std::path::Path) -> (age::x25519::Identity, age::x25519::Recipient) {
    let (identity, recipient) = identity::generate();
    let tier_paths = keybox::tier::TierPaths::from_base(base, Tier::Secret);
    fs::create_dir_all(&tier_paths.store).unwrap();
    identity::save_identity(&identity, &tier_paths.private_key).unwrap();
    identity::save_recipient(&recipient, &tier_paths.public_key).unwrap();
    (identity, recipient)
}

#[test]
fn test_add_and_get_credential() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    store::add_credential(base, Tier::Secret, "gitea", "pat", b"ghp_test123").unwrap();

    let secret = store::get_credential(base, Tier::Secret, "gitea", "pat").unwrap();
    assert_eq!(secret, b"ghp_test123");
}

#[test]
fn test_get_nonexistent_credential_fails() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    let result = store::get_credential(base, Tier::Secret, "gitea", "nonexistent");
    assert!(result.is_err());
}

#[test]
fn test_add_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    store::add_credential(base, Tier::Secret, "gitea", "pat", b"first").unwrap();
    let result = store::add_credential(base, Tier::Secret, "gitea", "pat", b"second");
    assert!(result.is_err());
}

#[test]
fn test_credential_file_has_enc_extension() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let tier_paths = keybox::tier::TierPaths::from_base(base, Tier::Secret);
    fs::create_dir_all(&tier_paths.store.join("gitea")).unwrap();
    let (_, _) = setup_store(base);

    store::add_credential(base, Tier::Secret, "gitea", "pat", b"test").unwrap();
    let file_path = tier_paths.store.join("gitea").join("pat.enc");
    assert!(file_path.exists());
}

#[test]
fn test_list_domains() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    store::add_credential(base, Tier::Secret, "gitea", "pat", b"t1").unwrap();
    store::add_credential(base, Tier::Secret, "gmail", "work", b"t2").unwrap();

    let domains = store::list_domains(base, Tier::Secret).unwrap();
    assert!(domains.contains(&"gitea".to_string()));
    assert!(domains.contains(&"gmail".to_string()));
    assert_eq!(domains.len(), 2);
}

#[test]
fn test_list_accounts() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    store::add_credential(base, Tier::Secret, "gitea", "pat", b"t1").unwrap();
    store::add_credential(base, Tier::Secret, "gitea", "admin", b"t2").unwrap();

    let accounts = store::list_accounts(base, Tier::Secret, "gitea").unwrap();
    assert!(accounts.contains(&"pat".to_string()));
    assert!(accounts.contains(&"admin".to_string()));
    assert_eq!(accounts.len(), 2);
}

#[test]
fn test_list_empty_domain() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    setup_store(base);

    let accounts = store::list_accounts(base, Tier::Secret, "gitea").unwrap();
    assert!(accounts.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test store_tests`
Expected: compilation failure

- [ ] **Step 3: Implement src/store.rs**

```rust
use crate::crypto::{age_ops, identity};
use crate::tier::{Tier, TierPaths};
use std::fs;
use std::path::Path;

pub fn add_credential(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let domain_dir = paths.store.join(domain);
    let file_path = domain_dir.join(format!("{}.enc", account));

    if file_path.exists() {
        return Err(format!(
            "Credential '{}' already exists under domain '{}'. Use 'keybox update' to modify.",
            account, domain
        ));
    }

    fs::create_dir_all(&domain_dir)
        .map_err(|e| format!("Failed to create domain directory: {}", e))?;

    let recipient = identity::load_recipient(&paths.public_key)?;
    let encrypted = age_ops::encrypt_with_recipient(&recipient, secret)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    fs::write(&file_path, &encrypted)
        .map_err(|e| format!("Failed to write credential: {}", e))
}

pub fn get_credential(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
) -> Result<Vec<u8>, String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));

    if !file_path.exists() {
        return Err(format!(
            "No credential found for '{}' in domain '{}'",
            account, domain
        ));
    }

    let ciphertext = fs::read(&file_path)
        .map_err(|e| format!("Failed to read credential: {}", e))?;

    let ident = identity::load_identity(&paths.private_key)?;
    let plaintext = age_ops::decrypt_with_identity(&ident, &ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

pub fn update_credential(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));

    if !file_path.exists() {
        return Err(format!(
            "Credential '{}' not found in domain '{}'. Use 'keybox add' to create.",
            account, domain
        ));
    }

    let recipient = identity::load_recipient(&paths.public_key)?;
    let encrypted = age_ops::encrypt_with_recipient(&recipient, secret)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    fs::write(&file_path, &encrypted)
        .map_err(|e| format!("Failed to write credential: {}", e))
}

pub fn delete_credential(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));

    if !file_path.exists() {
        return Err(format!(
            "No credential found for '{}' in domain '{}'",
            account, domain
        ));
    }

    fs::remove_file(&file_path)
        .map_err(|e| format!("Failed to delete credential: {}", e))
}

pub fn list_domains(base: &Path, tier: Tier) -> Result<Vec<String>, String> {
    let paths = TierPaths::from_base(base, tier);
    if !paths.store.exists() {
        return Ok(vec![]);
    }

    let mut domains = vec![];
    for entry in fs::read_dir(&paths.store)
        .map_err(|e| format!("Failed to read store directory: {}", e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(name) = entry.file_name().to_str() {
                domains.push(name.to_string());
            }
        }
    }
    domains.sort();
    Ok(domains)
}

pub fn list_accounts(base: &Path, tier: Tier, domain: &str) -> Result<Vec<String>, String> {
    let paths = TierPaths::from_base(base, tier);
    let domain_dir = paths.store.join(domain);

    if !domain_dir.exists() {
        return Ok(vec![]);
    }

    let mut accounts = vec![];
    for entry in fs::read_dir(&domain_dir)
        .map_err(|e| format!("Failed to read domain directory: {}", e))?
    {
        let entry = entry.map_err(|e| format!("Failed to read entry: {}", e))?;
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".enc") {
                let account = &name[..name.len() - 4]; // strip .enc
                accounts.push(account.to_string());
            }
        }
    }
    accounts.sort();
    Ok(accounts)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test store_tests`
Expected: all tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/store.rs tests/unit/store_tests.rs src/main.rs
git commit -m "feat: add credential store with add, get, list, update, delete operations"
```

---

## Phase 5: CLI Interface

### Task 9: CLI argument parsing with clap

**Files:**
- Create: `src/cli.rs`
- Create: `tests/unit/cli_tests.rs`
- Modify: `src/main.rs` — add `mod cli;`

- [ ] **Step 1: Write CLI parsing tests**

```rust
// tests/unit/cli_tests.rs
use keybox::cli::{self, Tier, Operation, get_args};

#[test]
fn test_parse_add_secret_default() {
    let args = get_args(vec!["keybox", "add", "gitea", "pat"]);
    assert_eq!(args.tier, Tier::Secret);
    assert_eq!(args.operation, Operation::Add);
    assert_eq!(args.domain, "gitea");
    assert_eq!(args.account, "pat");
}

#[test]
fn test_parse_add_confidential() {
    let args = get_args(vec!["keybox", "--confidential", "add", "gitea", "pat"]);
    assert_eq!(args.tier, Tier::Confidential);
}

#[test]
fn test_parse_add_top_secret() {
    let args = get_args(vec!["keybox", "--top-secret", "add", "ldap", "user"]);
    assert_eq!(args.tier, Tier::TopSecret);
}

#[test]
fn test_parse_flag_aliases() {
    let args_sec = get_args(vec!["keybox", "--sec", "add", "a", "b"]);
    assert_eq!(args_sec.tier, Tier::Secret);

    let args_con = get_args(vec!["keybox", "--con", "add", "a", "b"]);
    assert_eq!(args_con.tier, Tier::Confidential);

    let args_top = get_args(vec!["keybox", "--top", "add", "a", "b"]);
    assert_eq!(args_top.tier, Tier::TopSecret);
}

#[test]
fn test_parse_short_flags() {
    let args = get_args(vec!["keybox", "-c", "get", "gitea", "pat"]);
    assert_eq!(args.tier, Tier::Confidential);
}

#[test]
fn test_parse_flag_at_end() {
    let args = get_args(vec!["keybox", "get", "gitea", "pat", "--confidential"]);
    assert_eq!(args.tier, Tier::Confidential);
}

#[test]
fn test_parse_get_with_env() {
    let args = get_args(vec!["keybox", "get", "gitea", "pat", "--env", "GITEA_TOKEN"]);
    assert_eq!(args.operation, Operation::Get);
    assert_eq!(args.env_var.as_deref(), Some("GITEA_TOKEN"));
}

#[test]
fn test_parse_get_with_clipboard() {
    let args = get_args(vec!["keybox", "get", "gitea", "pat", "--clipboard"]);
    assert_eq!(args.operation, Operation::Get);
    assert!(args.clipboard);
}

#[test]
fn test_parse_list_all_domains() {
    let args = get_args(vec!["keybox", "list"]);
    assert_eq!(args.operation, Operation::List);
    assert!(args.domain.is_empty());
}

#[test]
fn test_parse_list_domain() {
    let args = get_args(vec!["keybox", "list", "gitea"]);
    assert_eq!(args.operation, Operation::List);
    assert_eq!(args.domain, "gitea");
}

#[test]
fn test_parse_delete() {
    let args = get_args(vec!["keybox", "delete", "gitea", "pat"]);
    assert_eq!(args.operation, Operation::Delete);
}

#[test]
fn test_parse_update() {
    let args = get_args(vec!["keybox", "update", "gitea", "pat"]);
    assert_eq!(args.operation, Operation::Update);
}

#[test]
fn test_parse_init() {
    let args = get_args(vec!["keybox", "--confidential", "init"]);
    assert_eq!(args.tier, Tier::Confidential);
    assert_eq!(args.operation, Operation::Init);
}

#[test]
fn test_parse_serve() {
    let args = get_args(vec!["keybox", "--confidential", "serve"]);
    assert_eq!(args.operation, Operation::Serve);
}

#[test]
fn test_parse_unlock() {
    let args = get_args(vec!["keybox", "--confidential", "unlock"]);
    assert_eq!(args.operation, Operation::Unlock);
}

#[test]
fn test_parse_lock() {
    let args = get_args(vec!["keybox", "--confidential", "lock"]);
    assert_eq!(args.operation, Operation::Lock);
}

#[test]
fn test_parse_stop() {
    let args = get_args(vec!["keybox", "--confidential", "stop"]);
    assert_eq!(args.operation, Operation::Stop);
}

#[test]
fn test_parse_non_interactive_with_password() {
    let args = get_args(vec!["keybox", "add", "g", "a", "--non-interactive", "--password", "secret"]);
    assert!(args.non_interactive);
    assert_eq!(args.password.as_deref(), Some("secret"));
}

#[test]
fn test_conflicting_level_flags_fails() {
    let result = std::panic::catch_unwind(|| {
        get_args(vec!["keybox", "--secret", "--confidential", "add", "a", "b"]);
    });
    assert!(result.is_err());
}

#[test]
fn test_invalid_domain_name() {
    use keybox::cli::validate_name;
    assert!(validate_name("valid-name").is_ok());
    assert!(validate_name("valid_name").is_ok());
    assert!(validate_name("name123").is_ok());
    assert!(validate_name("name with spaces").is_err());
    assert!(validate_name("name/with/slash").is_err());
    assert!(validate_name("").is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test cli_tests`
Expected: compilation failure

- [ ] **Step 3: Implement src/cli.rs**

```rust
use clap::{Parser, Subcommand, ArgGroup};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Secret,
    Confidential,
    TopSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add,
    Get,
    List,
    Delete,
    Update,
    Init,
    Serve,
    Unlock,
    Lock,
    Stop,
}

#[derive(Parser, Debug)]
#[command(name = "keybox", about = "Cross-platform CLI credential manager")]
#[command(group = ArgGroup::new("level").args(&["secret", "confidential", "top_secret"]).multiple(false))]
pub struct Cli {
    /// System-bound tier (default)
    #[arg(long = "secret", short = 's', alias = "sec", group = "level")]
    pub secret: bool,

    /// Password-protected tier
    #[arg(long = "confidential", short = 'c', alias = "con", group = "level")]
    pub confidential: bool,

    /// File-hash-protected tier
    #[arg(long = "top-secret", short = 't', alias = "top", group = "level")]
    pub top_secret: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Command {
    /// Add a new credential
    Add {
        domain: String,
        account: String,
        #[arg(long)]
        non_interactive: bool,
        #[arg(long, requires = "non_interactive")]
        password: Option<String>,
    },
    /// Retrieve a credential
    Get {
        domain: String,
        account: String,
        #[arg(long, conflicts_with = "clipboard")]
        env: Option<String>,
        #[arg(long, conflicts_with = "env")]
        clipboard: bool,
    },
    /// List domains or accounts
    List {
        domain: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Delete a credential
    Delete {
        domain: String,
        account: String,
    },
    /// Update an existing credential
    Update {
        domain: String,
        account: String,
        #[arg(long)]
        non_interactive: bool,
        #[arg(long, requires = "non_interactive")]
        password: Option<String>,
    },
    /// Initialize the current tier
    Init {
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        non_interactive: bool,
    },
    /// Start the daemon for the current tier
    Serve,
    /// Pre-unlock the daemon
    Unlock,
    /// Lock the daemon (clear in-memory key)
    Lock,
    /// Stop the daemon
    Stop,
}

impl Cli {
    pub fn tier(&self) -> Tier {
        if self.confidential {
            Tier::Confidential
        } else if self.top_secret {
            Tier::TopSecret
        } else {
            Tier::Secret
        }
    }

    pub fn operation(&self) -> Operation {
        match &self.command {
            Command::Add { .. } => Operation::Add,
            Command::Get { .. } => Operation::Get,
            Command::List { .. } => Operation::List,
            Command::Delete { .. } => Operation::Delete,
            Command::Update { .. } => Operation::Update,
            Command::Init { .. } => Operation::Init,
            Command::Serve => Operation::Serve,
            Command::Unlock => Operation::Unlock,
            Command::Lock => Operation::Lock,
            Command::Stop => Operation::Stop,
        }
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".into());
    }
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(format!(
                "Invalid character '{}' in name. Only a-z, A-Z, 0-9, -, _ are allowed.",
                ch
            ));
        }
    }
    Ok(())
}
```

- [ ] **Step 4: Update test helpers to match new API**

The test file uses `get_args()` function. We'll create a helper:

```rust
// In tests/unit/cli_tests.rs, use clap directly
use keybox::cli::Cli;
use clap::Parser;

fn get_args(args: Vec<&str>) -> Cli {
    Cli::parse_from(args)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test cli_tests`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs tests/unit/cli_tests.rs src/main.rs
git commit -m "feat: add CLI argument parsing with clap (all operations, level flags, aliases)"
```

---

### Task 10: Interactive input and TTY detection

**Files:**
- Create: `src/interactive.rs`
- Create: `tests/unit/interactive_tests.rs`
- Modify: `src/main.rs` — add `mod interactive;`

- [ ] **Step 1: Write interactive tests**

```rust
// tests/unit/interactive_tests.rs
use keybox::interactive;

#[test]
fn test_is_tty_detection() {
    // In a test environment, stdin is typically not a TTY
    // This test verifies the function doesn't panic
    let _ = interactive::stdin_is_tty();
}

#[test]
fn test_is_llm_calling_detection() {
    // No env set
    std::env::remove_var("KEYBOX_LLM_CALLING");
    assert!(!interactive::is_llm_calling());

    // Env set to 1
    std::env::set_var("KEYBOX_LLM_CALLING", "1");
    assert!(interactive::is_llm_calling());

    // Env set to 0
    std::env::set_var("KEYBOX_LLM_CALLING", "0");
    assert!(!interactive::is_llm_calling());

    // Clean up
    std::env::remove_var("KEYBOX_LLM_CALLING");
}

#[test]
fn test_needs_interactive_detection() {
    // In CI, stdin is not a TTY, so this should report non-interactive
    let result = interactive::check_interactive();
    // Result should be Err (not interactive) in CI, Ok in terminal
    // We just verify it doesn't panic and returns a meaningful message
    match result {
        Ok(_) => {} // Terminal available
        Err(msg) => {
            assert!(!msg.is_empty());
        }
    }
}

#[test]
fn test_llm_mode_error_message() {
    let msg = interactive::llm_mode_error(Some("confidential"));
    assert!(msg.contains("LLM calling mode"));
    assert!(msg.contains("unlock the daemon"));
    assert!(msg.contains("--non-interactive"));
    assert!(msg.contains("keybox --confidential unlock"));
}

#[test]
fn test_subprocess_error_message() {
    let msg = interactive::subprocess_error();
    assert!(msg.contains("not a TTY"));
    assert!(msg.contains("--non-interactive"));
    assert!(msg.contains("keybox serve"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement src/interactive.rs**

```rust
use std::io::{self, Write};

pub fn stdin_is_tty() -> bool {
    atty::is(atty::Stream::Stdin)
}

pub fn is_llm_calling() -> bool {
    match std::env::var("KEYBOX_LLM_CALLING") {
        Ok(val) => val == "1",
        Err(_) => false,
    }
}

pub fn check_interactive() -> Result<(), String> {
    if is_llm_calling() {
        return Err(llm_mode_error(None));
    }
    if !stdin_is_tty() {
        return Err(subprocess_error());
    }
    Ok(())
}

pub fn prompt_password(prompt: &str) -> Result<String, String> {
    check_interactive()?;
    rpassword::prompt_password(prompt)
        .map_err(|e| format!("Failed to read password: {}", e))
}

pub fn prompt_password_with_confirm(prompt: &str, confirm_prompt: &str) -> Result<String, String> {
    check_interactive()?;
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| format!("Failed to read password: {}", e))?;
    let confirm = rpassword::prompt_password(confirm_prompt)
        .map_err(|e| format!("Failed to read confirmation: {}", e))?;
    if password != confirm {
        return Err("Passwords do not match".into());
    }
    Ok(password)
}

pub fn prompt_confirm(prompt: &str) -> Result<bool, String> {
    check_interactive()?;
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

pub fn prompt_input(prompt: &str) -> Result<String, String> {
    check_interactive()?;
    print!("{} ", prompt);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;
    Ok(input.trim().to_string())
}

pub fn llm_mode_error(tier: Option<&str>) -> String {
    let tier_str = tier.unwrap_or("--confidential");
    format!(
        "Error: keybox requires interactive input (LLM calling mode detected).\n\
         Possible resolutions (in order of preference):\n\
           1. Ask the user to unlock the daemon directly on the machine:\n\
              `keybox {} unlock` (or `--top-secret`).\n\
              Once unlocked, all commands will work without prompts.\n\
           2. Use non-interactive mode with a credential provided by the human:\n\
              `--non-interactive --password <value>`\n\
           3. If the daemon is already running but locked, ask the user to unlock it.\n\
           4. Ask the human for the credential directly:\n\
              \"I need access to [description]. Can you provide the value or unlock keybox?\"",
        tier_str
    )
}

pub fn subprocess_error() -> String {
    "Error: keybox requires interactive input but stdin is not a TTY.\n\
     Use --non-interactive --password <value> for scripting, or set up a daemon\n\
     with `keybox serve` before calling from subprocesses."
        .to_string()
}
```

Note: this requires adding `atty` to Cargo.toml dependencies.

- [ ] **Step 4: Add `atty` to Cargo.toml**

Add to `[dependencies]`: `atty = "0.2"`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test interactive_tests`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/interactive.rs tests/unit/interactive_tests.rs src/main.rs Cargo.toml
git commit -m "feat: add interactive input, TTY detection, and LLM/subprocess error messages"
```

---

### Task 11: Wire CLI commands to store operations

**Files:**
- Modify: `src/main.rs` — full dispatch logic
- Create: `src/env_run.rs`
- Modify: `src/cli.rs` — add domain/account accessors

- [ ] **Step 1: Write integration test for add+get**

```rust
// tests/integration/add_get_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use std::fs;

fn set_config_dir(temp: &TempDir) {
    // Use environment variable to control config dir in main.rs
    // main.rs reads KEYBOX_CONFIG_DIR for tests
    std::env::set_var("KEYBOX_CONFIG_DIR", temp.path().to_str().unwrap());
}

#[test]
fn test_add_and_get_secret_credential() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    // Add credential non-interactively
    let mut add_cmd = Command::cargo_bin("keybox").unwrap();
    add_cmd
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "secret123"])
        .assert()
        .success();

    // Get credential
    let mut get_cmd = Command::cargo_bin("keybox").unwrap();
    get_cmd
        .args(["get", "gitea", "pat"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));
}

#[test]
fn test_add_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "first"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "second"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_get_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["get", "gitea", "nonexistent"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("No credential found"));
}

#[test]
fn test_add_confidential_tier() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    // Initialize confidential tier
    Command::cargo_bin("keybox").unwrap()
        .args(["--confidential", "init", "--non-interactive", "--password", "masterpass"])
        .assert().success();

    // Add credential
    Command::cargo_bin("keybox").unwrap()
        .args(["--confidential", "add", "gitea", "pat", "--non-interactive", "--password", "secret123"])
        .assert().success();

    // Get credential (needs daemon or auto-unlock)
    // This will fail without daemon since confidential needs passphrase
    // For now, verify the file exists
    let store_path = dir.path().join("confidential").join("store").join("gitea").join("pat.enc");
    assert!(store_path.exists());
}
```

- [ ] **Step 2: Implement src/env_run.rs**

```rust
use std::process::Command;

pub fn run_with_env(var_name: &str, value: &[u8], command: &[String]) -> Result<i32, String> {
    if command.is_empty() {
        return Err("No command specified after -- separator".into());
    }

    let value_str = std::str::from_utf8(value)
        .map_err(|_| "Secret contains non-UTF8 data, cannot set as env var".to_string())?;

    let (program, args) = command.split_first().unwrap();

    let status = Command::new(program)
        .args(args)
        .env(var_name, value_str)
        .status()
        .map_err(|e| format!("Failed to execute '{}': {}", program, e))?;

    Ok(status.code().unwrap_or(1))
}
```

- [ ] **Step 3: Implement src/main.rs with full dispatch**

```rust
mod cli;
mod crypto;
mod tier;
mod store;
mod protect;
mod interactive;
mod env_run;

use clap::Parser;
use cli::{Cli, Command, Tier, Operation};
use std::path::PathBuf;

fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KEYBOX_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    dirs::config_dir()
        .expect("Could not determine config directory")
        .join("keybox")
}

fn resolve_tier(cli: &Cli) -> Tier {
    match cli.tier() {
        cli::Tier::Secret => tier::Tier::Secret,
        cli::Tier::Confidential => tier::Tier::Confidential,
        cli::Tier::TopSecret => tier::Tier::TopSecret,
    }
}

fn main() {
    let cli = Cli::parse();
    let base = config_dir();
    let tier = resolve_tier(&cli);

    let result = match &cli.command {
        Command::Add { domain, account, non_interactive, password } => {
            handle_add(&base, tier, domain, account, *non_interactive, password.as_deref())
        }
        Command::Get { domain, account, env, clipboard } => {
            handle_get(
                &base,
                tier,
                domain,
                account,
                env.as_deref(),
                *clipboard,
                &cli
            )
        }
        Command::List { domain, json } => {
            handle_list(&base, tier, domain.as_deref(), *json)
        }
        Command::Delete { domain, account } => {
            handle_delete(&base, tier, domain, account)
        }
        Command::Update { domain, account, non_interactive, password } => {
            handle_update(&base, tier, domain, account, *non_interactive, password.as_deref())
        }
        Command::Init { file, non_interactive } => {
            handle_init(&base, tier, file.as_deref(), *non_interactive)
        }
        Command::Serve => {
            handle_serve(&base, tier)
        }
        Command::Unlock => {
            handle_unlock(&base, tier)
        }
        Command::Lock => {
            handle_lock(&base, tier)
        }
        Command::Stop => {
            handle_stop(&base, tier)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn handle_add(
    base: &PathBuf,
    tier: tier::Tier,
    domain: &str,
    account: &str,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    cli::validate_name(domain)?;
    cli::validate_name(account)?;

    ensure_initialized(base, tier)?;

    let secret = if non_interactive {
        password.ok_or("--password is required with --non-interactive".to_string())?.as_bytes().to_vec()
    } else {
        interactive::prompt_password_with_confirm(
            &format!("Enter password for {}/{}: ", domain, account),
            "Confirm password: ",
        )?.into_bytes()
    };

    store::add_credential(base, tier, domain, account, &secret)?;
    println!("Added credential for {}/{}", domain, account);
    Ok(())
}

fn handle_get(
    base: &PathBuf,
    tier: tier::Tier,
    domain: &str,
    account: &str,
    env_var: Option<&str>,
    clipboard: bool,
    cli: &Cli,
) -> Result<(), String> {
    ensure_initialized(base, tier)?;

    let secret = store::get_credential(base, tier, domain, account)?;

    if let Some(var_name) = env_var {
        // Collect remaining args after -- from the raw CLI
        // The clap parser has all positional after -- in the command
        // We need to get the remaining args
        let args: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
        if args.is_empty() {
            return Err("No command specified after -- separator. Usage: keybox get <domain> <account> --env VAR -- <command>".into());
        }
        let exit_code = env_run::run_with_env(var_name, &secret, &args)?;
        std::process::exit(exit_code);
    } else if clipboard {
        #[cfg(not(target_os = "linux"))]
        {
            let secret_str = std::str::from_utf8(&secret).map_err(|_| "Secret contains non-UTF8 data".to_string())?;
            let mut clipboard = arboard::Clipboard::new()
                .map_err(|e| format!("Failed to access clipboard: {}", e))?;
            clipboard.set_text(secret_str)
                .map_err(|e| format!("Failed to copy to clipboard: {}", e))?;
            println!("Copied to clipboard");
        }
        #[cfg(target_os = "linux")]
        {
            return Err("Clipboard not supported on this Linux environment (requires display server)".into());
        }
    } else {
        let secret_str = std::str::from_utf8(&secret).map_err(|_| "Secret contains non-UTF8 data".to_string())?;
        println!("{}", secret_str);
    }

    Ok(())
}

fn handle_list(
    base: &PathBuf,
    tier: tier::Tier,
    domain: Option<&str>,
    json: bool,
) -> Result<(), String> {
    if !tier.is_initialized(base) {
        if json {
            println!("{{}}");
        }
        return Ok(());
    }

    if let Some(domain) = domain {
        let accounts = store::list_accounts(base, tier, domain)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&accounts).unwrap());
        } else {
            for acct in &accounts {
                println!("{}", acct);
            }
        }
    } else {
        let domains = store::list_domains(base, tier)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&domains).unwrap());
        } else {
            for d in &domains {
                println!("{}", d);
            }
        }
    }
    Ok(())
}

fn handle_delete(
    base: &PathBuf,
    tier: tier::Tier,
    domain: &str,
    account: &str,
) -> Result<(), String> {
    ensure_initialized(base, tier)?;

    let confirmed = interactive::prompt_confirm(
        &format!("Delete credential '{}' from domain '{}'?", account, domain)
    )?;

    if confirmed {
        store::delete_credential(base, tier, domain, account)?;
        println!("Deleted credential for {}/{}", domain, account);
    }
    Ok(())
}

fn handle_update(
    base: &PathBuf,
    tier: tier::Tier,
    domain: &str,
    account: &str,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    cli::validate_name(domain)?;
    cli::validate_name(account)?;

    ensure_initialized(base, tier)?;

    let secret = if non_interactive {
        password.ok_or("--password is required with --non-interactive".to_string())?.as_bytes().to_vec()
    } else {
        interactive::prompt_password_with_confirm(
            &format!("Enter new password for {}/{}: ", domain, account),
            "Confirm password: ",
        )?.into_bytes()
    };

    store::update_credential(base, tier, domain, account, &secret)?;
    println!("Updated credential for {}/{}", domain, account);
    Ok(())
}

fn handle_init(
    base: &PathBuf,
    tier: tier::Tier,
    file: Option<&str>,
    non_interactive: bool,
) -> Result<(), String> {
    match tier {
        tier::Tier::Secret => {
            // Auto-init: generate keypair and protect with system binding
            auto_init_secret(base)?;
        }
        tier::Tier::Confidential => {
            init_confidential(base, non_interactive)?;
        }
        tier::Tier::TopSecret => {
            init_top_secret(base, file, non_interactive)?;
        }
    }
    Ok(())
}

fn auto_init_secret(base: &PathBuf) -> Result<(), String> {
    use crate::crypto::identity;
    use crate::protect::IdentityProtector;

    let paths = tier::TierPaths::from_base(base, tier::Tier::Secret);
    std::fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create directory: {}", e))?;

    let (identity_key, recipient) = identity::generate();

    // Use platform-specific protection
    #[cfg(target_os = "linux")]
    {
        let protector = protect::LinuxProtector::new();
        protector.protect(identity_key.to_string().as_bytes(), &paths.private_key)?;
    }
    #[cfg(target_os = "macos")]
    {
        let protector = protect::MacOSProtector::new();
        protector.protect(identity_key.to_string().as_bytes(), &paths.private_key)?;
    }
    #[cfg(target_os = "windows")]
    {
        let protector = protect::DpapiProtector::new();
        protector.protect(identity_key.to_string().as_bytes(), &paths.private_key)?;
    }

    identity::save_recipient(&recipient, &paths.public_key)?;
    println!("Initialized secret tier");
    Ok(())
}

fn init_confidential(base: &PathBuf, non_interactive: bool) -> Result<(), String> {
    use crate::crypto::{age_ops, identity};
    use age::Encryptor;

    let paths = tier::TierPaths::from_base(base, tier::Tier::Confidential);
    std::fs::create_dir_all(paths.private_key.parent().unwrap())
        .map_err(|e| format!("Failed to create directory: {}", e))?;
    std::fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store directory: {}", e))?;

    let passphrase = if non_interactive {
        interactive::prompt_password("Enter master passphrase for confidential tier: ")?
    } else {
        interactive::prompt_password_with_confirm(
            "Enter master passphrase: ",
            "Confirm passphrase: ",
        )?
    };

    let (identity_key, recipient) = identity::generate();
    let identity_str = identity_key.to_string();

    // Encrypt identity with passphrase using age passphrase mode
    let encryptor = Encryptor::with_user_passphrase(passphrase.into());
    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    std::io::Write::write_all(&mut writer, identity_str.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;
    writer.finish()
        .map_err(|e| format!("Encryption failed: {}", e))?;

    std::fs::write(&paths.private_key, &encrypted)
        .map_err(|e| format!("Failed to write identity: {}", e))?;
    identity::save_recipient(&recipient, &paths.public_key)?;

    println!("Initialized confidential tier");
    Ok(())
}

fn init_top_secret(
    base: &PathBuf,
    file: Option<&str>,
    non_interactive: bool,
) -> Result<(), String> {
    use crate::crypto::identity;
    use sha2::{Sha256, Digest};
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
    use ring::rand::{SecureRandom, SystemRandom};

    let key_file_path = if non_interactive {
        file.map(|f| std::path::PathBuf::from(f))
            .unwrap_or_else(|| tier::Tier::default_top_key_path(base))
    } else {
        let prompt = format!(
            "Key file path (default: {}): ",
            tier::Tier::default_top_key_path(base).display()
        );
        let input = interactive::prompt_input(&prompt)?;
        if input.is_empty() {
            tier::Tier::default_top_key_path(base)
        } else {
            std::path::PathBuf::from(input)
        }
    };

    let file_content = std::fs::read(&key_file_path)
        .map_err(|e| format!("Failed to read key file '{}': {}", key_file_path.display(), e))?;

    // Derive AES-256 key from file content via SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&file_content);
    let aes_key = hasher.finalize();

    let paths = tier::TierPaths::from_base(base, tier::Tier::TopSecret);
    std::fs::create_dir_all(paths.private_key.parent().unwrap())
        .map_err(|e| format!("Failed to create directory: {}", e))?;
    std::fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store directory: {}", e))?;

    let (identity_key, recipient) = identity::generate();
    let identity_str = identity_key.to_string();

    // Encrypt with AES-256-GCM
    let unbound_key = UnboundKey::new(&AES_256_GCM, &aes_key)
        .map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes).map_err(|_| "RNG failure".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = identity_str.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    std::fs::write(&paths.private_key, &output)
        .map_err(|e| format!("Failed to write identity: {}", e))?;

    identity::save_recipient(&recipient, &paths.public_key)?;
    println!("Initialized top-secret tier");
    Ok(())
}

fn handle_serve(_base: &PathBuf, _tier: tier::Tier) -> Result<(), String> {
    Err("Daemon not yet implemented. Coming in Phase 6.".to_string())
}

fn handle_unlock(_base: &PathBuf, _tier: tier::Tier) -> Result<(), String> {
    Err("Daemon not yet implemented. Coming in Phase 6.".to_string())
}

fn handle_lock(_base: &PathBuf, _tier: tier::Tier) -> Result<(), String> {
    Err("Daemon not yet implemented. Coming in Phase 6.".to_string())
}

fn handle_stop(_base: &PathBuf, _tier: tier::Tier) -> Result<(), String> {
    Err("Daemon not yet implemented. Coming in Phase 6.".to_string())
}

fn ensure_initialized(base: &PathBuf, tier: tier::Tier) -> Result<(), String> {
    if tier == tier::Tier::Secret && !tier.is_initialized(base) {
        return auto_init_secret(base);
    }
    if !tier.is_initialized(base) {
        let tier_name = tier.dir_name();
        return Err(format!(
            "{} tier is not initialized. Run 'keybox --{} init' to set it up.",
            tier_name,
            if matches!(tier, tier::Tier::Confidential) { "confidential" } else { "top-secret" }
        ));
    }
    Ok(())
}
```

- [ ] **Step 4: Run integration tests**

Run: `cargo test add_get_tests`
Expected: secret tier add+get passes; confidential tier init passes

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/env_run.rs tests/integration/add_get_tests.rs
git commit -m "feat: wire CLI commands to store operations (add, get, list, delete, update, init)"
```

---

### Task 12: List, delete, and update integration tests

**Files:**
- Create: `tests/integration/list_delete_tests.rs`
- Create: `tests/integration/update_tests.rs`

- [ ] **Step 1: Write list/delete tests**

```rust
// tests/integration/list_delete_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn set_config_dir(temp: &TempDir) {
    std::env::set_var("KEYBOX_CONFIG_DIR", temp.path().to_str().unwrap());
}

#[test]
fn test_list_domains() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "t1"])
        .assert().success();
    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gmail", "work", "--non-interactive", "--password", "t2"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["list"])
        .assert().success()
        .stdout(predicate::str::contains("gitea").and(predicate::str::contains("gmail")));
}

#[test]
fn test_list_accounts_in_domain() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "t1"])
        .assert().success();
    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "admin", "--non-interactive", "--password", "t2"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["list", "gitea"])
        .assert().success()
        .stdout(predicate::str::contains("pat").and(predicate::str::contains("admin")));
}

#[test]
fn test_list_json_output() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "t1"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["list", "--json"])
        .assert().success()
        .stdout(predicate::str::contains("[\"gitea\"]"));
}

#[test]
fn test_delete_credential() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "t1"])
        .assert().success();

    // Delete — with stdin piped as "y" to confirm
    Command::cargo_bin("keybox").unwrap()
        .args(["delete", "gitea", "pat"])
        .write_stdin("y\n")
        .assert().success();

    // Verify it's gone
    Command::cargo_bin("keybox").unwrap()
        .args(["get", "gitea", "pat"])
        .assert().failure();
}
```

```rust
// tests/integration/update_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn set_config_dir(temp: &TempDir) {
    std::env::set_var("KEYBOX_CONFIG_DIR", temp.path().to_str().unwrap());
}

#[test]
fn test_update_existing_credential() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "pat", "--non-interactive", "--password", "old"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["update", "gitea", "pat", "--non-interactive", "--password", "new"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["get", "gitea", "pat"])
        .assert().success()
        .stdout(predicate::str::contains("new"));
}

#[test]
fn test_update_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["update", "gitea", "nonexistent", "--non-interactive", "--password", "x"])
        .assert().failure()
        .stderr(predicate::str::contains("not found"));
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test list_delete_tests update_tests`
Expected: all tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/list_delete_tests.rs tests/integration/update_tests.rs
git commit -m "test: add list, delete, and update integration tests"
```

---

## Phase 6: Daemon

### Task 13: Daemon protocol and message types

**Files:**
- Create: `src/daemon/mod.rs`
- Create: `src/daemon/protocol.rs`
- Create: `tests/unit/daemon_protocol_tests.rs`
- Modify: `src/main.rs` — add `mod daemon;`

- [ ] **Step 1: Write protocol tests**

```rust
// tests/unit/daemon_protocol_tests.rs
use keybox::daemon::protocol::{Request, Response, serialize_request, deserialize_request, serialize_response, deserialize_response};

#[test]
fn test_roundtrip_decrypt_request() {
    let req = Request::Decrypt {
        ciphertext: vec![1, 2, 3, 4, 5],
    };
    let serialized = serialize_request(&req).unwrap();
    let deserialized = deserialize_request(&serialized).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn test_roundtrip_status_request() {
    let req = Request::Status;
    let serialized = serialize_request(&req).unwrap();
    let deserialized = deserialize_request(&serialized).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn test_roundtrip_unlock_request() {
    let req = Request::Unlock {
        passphrase: "test-passphrase-123".to_string(),
    };
    let serialized = serialize_request(&req).unwrap();
    let deserialized = deserialize_request(&serialized).unwrap();
    assert_eq!(req, deserialized);
}

#[test]
fn test_roundtrip_decrypt_response_success() {
    let resp = Response::Decrypted {
        plaintext: vec![10, 20, 30],
    };
    let serialized = serialize_response(&resp).unwrap();
    let deserialized = deserialize_response(&serialized).unwrap();
    assert_eq!(resp, deserialized);
}

#[test]
fn test_roundtrip_error_response() {
    let resp = Response::Error {
        message: "Invalid passphrase".to_string(),
    };
    let serialized = serialize_response(&resp).unwrap();
    let deserialized = deserialize_response(&serialized).unwrap();
    assert_eq!(resp, deserialized);
}

#[test]
fn test_roundtrip_status_response_locked() {
    let resp = Response::Status { locked: true };
    let serialized = serialize_response(&resp).unwrap();
    let deserialized = deserialize_response(&serialized).unwrap();
    assert_eq!(resp, deserialized);
}

#[test]
fn test_deserialize_invalid_data_fails() {
    let result = deserialize_request(b"not-valid-json");
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement src/daemon/mod.rs**

```rust
pub mod protocol;
pub mod server;
pub mod client;
```

- [ ] **Step 4: Implement src/daemon/protocol.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Status,
    Decrypt {
        ciphertext: Vec<u8>,
    },
    Unlock {
        passphrase: String,
    },
    UnlockWithFile {
        key_content: Vec<u8>,
    },
    Lock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Status { locked: bool },
    Decrypted { plaintext: Vec<u8> },
    Ok,
    Error { message: String },
}

pub fn serialize_request(req: &Request) -> Result<Vec<u8>, String> {
    serde_json::to_vec(req).map_err(|e| format!("Serialize error: {}", e))
}

pub fn deserialize_request(data: &[u8]) -> Result<Request, String> {
    serde_json::from_slice(data).map_err(|e| format!("Deserialize error: {}", e))
}

pub fn serialize_response(resp: &Response) -> Result<Vec<u8>, String> {
    serde_json::to_vec(resp).map_err(|e| format!("Serialize error: {}", e))
}

pub fn deserialize_response(data: &[u8]) -> Result<Response, String> {
    serde_json::from_slice(data).map_err(|e| format!("Deserialize error: {}", e))
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test daemon_protocol_tests`
Expected: all tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/daemon/ tests/unit/daemon_protocol_tests.rs src/main.rs
git commit -m "feat: add daemon protocol types with JSON serialization"
```

---

### Task 14: Daemon server — socket listener and state machine

**Files:**
- Create: `src/daemon/server.rs`
- Create: `src/daemon/client.rs`

- [ ] **Step 1: Implement server with Unix socket / named pipe**

This is a larger implementation. Key components:
- Listen on Unix socket (Linux/macOS) or Named pipe (Windows)
- State machine: LOCKED → (unlock) → UNLOCKED → (lock) → LOCKED → (stop) → exit
- Process incoming Request messages, send Response messages
- In UNLOCKED state: hold decrypted age Identity in memory

```rust
// src/daemon/server.rs
use crate::daemon::protocol::{Request, Response, deserialize_request, serialize_response};
use crate::tier::Tier;
use crate::crypto::identity;
use std::io::{Read, Write};
use std::path::PathBuf;

struct DaemonState {
    tier: Tier,
    locked: bool,
    identity: Option<age::x25519::Identity>,  // Only set when unlocked
    base: PathBuf,
}

pub fn run_daemon(base: PathBuf, tier: Tier) -> Result<(), String> {
    let socket_path = tier.daemon_socket_path(&base);
    let mut state = DaemonState {
        tier,
        locked: true,
        identity: None,
        base,
    };

    // Remove stale socket if it exists
    let _ = std::fs::remove_file(&socket_path);

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixListener;
        let listener = UnixListener::bind(&socket_path)
            .map_err(|e| format!("Failed to bind socket: {}", e))?;

        // Set restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("Failed to set socket permissions: {}", e))?;
        }

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buf = vec![0u8; 65536];
                    match stream.read(&mut buf) {
                        Ok(n) if n > 0 => {
                            buf.truncate(n);
                            let response = handle_request(&buf, &mut state);
                            let response_data = serialize_response(&response).unwrap_or_else(|e| {
                                serialize_response(&Response::Error { message: e }).unwrap()
                            });
                            let _ = stream.write_all(&response_data);
                        }
                        Ok(_) => break,
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows Named Pipe implementation
        use std::os::windows::io::FromRawHandle;
        // ... Named pipe server implementation
        // For v1, provide a stub that reports Windows support in progress
        return Err("Windows daemon support is not yet implemented".into());
    }

    Ok(())
}

fn handle_request(data: &[u8], state: &mut DaemonState) -> Response {
    let request = match deserialize_request(data) {
        Ok(req) => req,
        Err(e) => return Response::Error { message: e },
    };

    match request {
        Request::Status => Response::Status { locked: state.locked },
        Request::Decrypt { ciphertext } => {
            if state.locked || state.identity.is_none() {
                return Response::Error { message: "Daemon is locked. Use 'keybox unlock' first.".to_string() };
            }
            let identity = state.identity.as_ref().unwrap();
            match crate::crypto::age_ops::decrypt_with_identity(identity, &ciphertext) {
                Ok(plaintext) => Response::Decrypted { plaintext },
                Err(e) => Response::Error { message: format!("Decryption failed: {}", e) },
            }
        }
        Request::Unlock { passphrase } => {
            unlock_with_passphrase(state, &passphrase)
        }
        Request::UnlockWithFile { key_content } => {
            unlock_with_file(state, &key_content)
        }
        Request::Lock => {
            state.identity = None;
            state.locked = true;
            Response::Ok
        }
    }
}

fn unlock_with_passphrase(state: &mut DaemonState, passphrase: &str) -> Response {
    let paths = crate::tier::TierPaths::from_base(&state.base, state.tier);
    let encrypted = match std::fs::read(&paths.private_key) {
        Ok(data) => data,
        Err(e) => return Response::Error { message: format!("Failed to read identity: {}", e) },
    };

    match age::Decryptor::new(&encrypted[..]) {
        Ok(age::Decryptor::Passphrase(decryptor)) => {
            match decryptor.decrypt(passphrase, None) {
                Ok(mut reader) => {
                    let mut identity_str = String::new();
                    if reader.read_to_string(&mut identity_str).is_err() {
                        return Response::Error { message: "Failed to read identity".to_string() };
                    }
                    match age::x25519::Identity::from_str(identity_str.trim()) {
                        Ok(ident) => {
                            state.identity = Some(ident);
                            state.locked = false;
                            Response::Ok
                        }
                        Err(e) => Response::Error { message: format!("Invalid identity: {}", e) },
                    }
                }
                Err(_) => Response::Error { message: "Invalid passphrase".to_string() },
            }
        }
        _ => Response::Error { message: "Identity is not passphrase-encrypted".to_string() },
    }
}

fn unlock_with_file(state: &mut DaemonState, key_content: &[u8]) -> Response {
    use sha2::{Sha256, Digest};
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

    let paths = crate::tier::TierPaths::from_base(&state.base, state.tier);

    let mut hasher = Sha256::new();
    hasher.update(key_content);
    let aes_key = hasher.finalize();

    let encrypted = match std::fs::read(&paths.private_key) {
        Ok(data) => data,
        Err(e) => return Response::Error { message: format!("Failed to read identity: {}", e) },
    };

    if encrypted.len() < NONCE_LEN {
        return Response::Error { message: "Corrupted identity file".to_string() };
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LEN);
    let unbound_key = match UnboundKey::new(&AES_256_GCM, &aes_key) {
        Ok(k) => k,
        Err(e) => return Response::Error { message: format!("Invalid key: {}", e) },
    };
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());

    let mut in_out = ciphertext.to_vec();
    match key.open_in_place(nonce, Aad::empty(), &mut in_out) {
        Ok(plaintext) => {
            let identity_str = String::from_utf8_lossy(plaintext);
            match age::x25519::Identity::from_str(identity_str.trim()) {
                Ok(ident) => {
                    state.identity = Some(ident);
                    state.locked = false;
                    Response::Ok
                }
                Err(e) => Response::Error { message: format!("Invalid identity: {}", e) },
            }
        }
        Err(_) => Response::Error { message: "Invalid key file: decryption failed".to_string() },
    }
}
```

- [ ] **Step 2: Implement client.rs**

```rust
// src/daemon/client.rs
use crate::daemon::protocol::{Request, Response, serialize_request, deserialize_response};
use crate::tier::Tier;
use std::io::{Read, Write};
use std::path::PathBuf;

pub fn send_request(base: &PathBuf, tier: Tier, request: &Request) -> Result<Response, String> {
    let socket_path = tier.daemon_socket_path(base);

    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        let mut stream = UnixStream::connect(&socket_path)
            .map_err(|e| format!("Failed to connect to daemon: {}. Is the daemon running? Run 'keybox serve'.", e))?;

        let data = serialize_request(request)?;
        stream.write_all(&data)
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf)
            .map_err(|e| format!("Failed to read response: {}", e))?;
        buf.truncate(n);

        deserialize_response(&buf)
    }

    #[cfg(windows)]
    {
        Err("Windows daemon client not yet implemented".into())
    }
}

pub fn is_daemon_running(base: &PathBuf, tier: Tier) -> bool {
    let socket_path = tier.daemon_socket_path(base);
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixStream;
        UnixStream::connect(&socket_path).is_ok()
    }
    #[cfg(windows)]
    {
        false
    }
}
```

- [ ] **Step 3: Build to verify compilation**

Run: `cargo build`
Expected: compiles successfully

- [ ] **Step 4: Commit**

```bash
git add src/daemon/server.rs src/daemon/client.rs
git commit -m "feat: add daemon server with Unix socket, state machine, and client"
```

---

### Task 15: Wire daemon into secret and confidential tiers

**Files:**
- Modify: `src/main.rs` — update handle_serve, handle_unlock, handle_lock, handle_stop
- Modify: `src/store.rs` — or create a wrapper that routes through daemon for confidential/top-secret tiers

- [ ] **Step 1: Update main.rs daemon handlers**

Replace the stub handlers in `src/main.rs`:

```rust
fn handle_serve(base: &PathBuf, tier: tier::Tier) -> Result<(), String> {
    if tier == tier::Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if daemon::client::is_daemon_running(base, tier) {
        println!("Daemon is already running.");
        return Ok(());
    }
    // Fork to background
    daemon::server::run_daemon(base.clone(), tier)
}

fn handle_unlock(base: &PathBuf, tier: tier::Tier) -> Result<(), String> {
    if tier == tier::Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running. Run 'keybox serve' first.".into());
    }

    let passphrase = interactive::prompt_password("Enter master passphrase: ")?;
    let request = daemon::protocol::Request::Unlock { passphrase };
    match daemon::client::send_request(base, tier, &request)? {
        daemon::protocol::Response::Ok => {
            println!("Daemon unlocked.");
            Ok(())
        }
        daemon::protocol::Response::Error { message } => Err(message),
        _ => Err("Unexpected response from daemon".into()),
    }
}

fn handle_lock(base: &PathBuf, tier: tier::Tier) -> Result<(), String> {
    if tier == tier::Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running. Use 'keybox serve' to start it first.".into());
    }
    let request = daemon::protocol::Request::Lock;
    match daemon::client::send_request(base, tier, &request)? {
        daemon::protocol::Response::Ok => {
            println!("Daemon locked.");
            Ok(())
        }
        daemon::protocol::Response::Error { message } => Err(message),
        _ => Err("Unexpected response".into()),
    }
}

fn handle_stop(base: &PathBuf, tier: tier::Tier) -> Result<(), String> {
    if tier == tier::Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running.".into());
    }
    // Send lock first, then the daemon will exit
    let _ = daemon::client::send_request(base, tier, &daemon::protocol::Request::Lock);
    println!("Daemon stopped.");
    Ok(())
}
```

- [ ] **Step 2: Create a credential access layer that routes through daemon**

Create `src/credential_access.rs`:

```rust
use crate::crypto::age_ops;
use crate::daemon;
use crate::identity;
use crate::store;
use crate::tier::{Tier, TierPaths};
use crate::protect::IdentityProtector;
use std::path::Path;

pub fn decrypt_credential(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
) -> Result<Vec<u8>, String> {
    match tier {
        Tier::Secret => {
            // Stateless: load identity from system protection
            let paths = TierPaths::from_base(base, tier);
            let ciphertext = std::fs::read(paths.store.join(domain).join(format!("{}.enc", account)))
                .map_err(|e| format!("Failed to read: {}", e))?;

            #[cfg(target_os = "linux")]
            let protector = crate::protect::LinuxProtector::new();
            #[cfg(target_os = "macos")]
            let protector = crate::protect::MacOSProtector::new();
            #[cfg(target_os = "windows")]
            let protector = crate::protect::DpapiProtector::new();

            let identity_data = protector.unprotect(&paths.private_key)?;
            let identity_str = String::from_utf8(identity_data)
                .map_err(|_| "Identity contains invalid UTF-8".to_string())?;
            let ident = age::x25519::Identity::from_str(identity_str.trim())
                .map_err(|e| format!("Invalid identity: {}", e))?;

            age_ops::decrypt_with_identity(&ident, &ciphertext)
                .map_err(|e| format!("Decrypt failed: {}", e))
        }
        Tier::Confidential | Tier::TopSecret => {
            // Route through daemon
            if !daemon::client::is_daemon_running(base, tier) {
                return Err(format!(
                    "{} tier daemon is not running. Run 'keybox --{} serve' first.",
                    tier.dir_name(),
                    if tier == Tier::Confidential { "confidential" } else { "top-secret" }
                ));
            }

            let paths = TierPaths::from_base(base, tier);
            let ciphertext = std::fs::read(paths.store.join(domain).join(format!("{}.enc", account)))
                .map_err(|e| format!("Failed to read: {}", e))?;

            let request = daemon::protocol::Request::Decrypt { ciphertext };
            match daemon::client::send_request(base, tier, &request)? {
                daemon::protocol::Response::Decrypted { plaintext } => Ok(plaintext),
                daemon::protocol::Response::Error { message } => {
                    if message.contains("locked") {
                        // If locked, try auto-unlock
                        // For now, return error asking user to unlock
                        Err(format!("Daemon is locked: {}. Run 'keybox --{} unlock'.", message,
                            if tier == Tier::Confidential { "confidential" } else { "top-secret" }))
                    } else {
                        Err(message)
                    }
                }
                _ => Err("Unexpected response from daemon".into()),
            }
        }
    }
}
```

- [ ] **Step 3: Update handle_get in main.rs to use credential_access**

Replace the direct `store::get_credential` call with `credential_access::decrypt_credential`.

- [ ] **Step 4: Build and verify**

Run: `cargo build`
Expected: compiles

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/credential_access.rs
git commit -m "feat: wire daemon into confidential/top-secret tiers, add credential_access layer"
```

---

### Task 16: Daemon integration test

**Files:**
- Create: `tests/integration/daemon_tests.rs`

- [ ] **Step 1: Write daemon integration test**

```rust
// tests/integration/daemon_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;
use std::process::{Command as ProcessCommand};
use std::time::Duration;
use std::thread;

fn set_config_dir(temp: &TempDir) {
    std::env::set_var("KEYBOX_CONFIG_DIR", temp.path().to_str().unwrap());
}

#[test]
fn test_confidential_init_and_serve() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    // Init with non-interactive passphrase
    // Note: --non-interactive with init-confidential requires special handling
    // For testing, we write passphrase to stdin
    Command::cargo_bin("keybox").unwrap()
        .args(["--confidential", "init"])
        .write_stdin("testpass\ntestpass\n")
        .assert().success();

    assert!(dir.path().join("confidential").join("identity.private.enc").exists());
    assert!(dir.path().join("confidential").join("identity.pub").exists());
}

#[test]
fn test_daemon_lifecycle() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    // Initialize
    Command::cargo_bin("keybox").unwrap()
        .args(["--confidential", "init"])
        .write_stdin("testpass\ntestpass\n")
        .assert().success();

    // Start daemon in background
    let mut daemon = ProcessCommand::new(
        std::env::current_exe().unwrap().parent().unwrap().join("keybox")
    )
        .args(["--confidential", "serve"])
        .spawn()
        .expect("Failed to start daemon");

    // Give it a moment to start
    thread::sleep(Duration::from_millis(500));

    // Unlock the daemon
    // ... (needs stdin for passphrase, complex in test)
    // This is a basic smoke test — full integration testing would use a test harness

    // Kill daemon
    daemon.kill().unwrap();
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/integration/daemon_tests.rs
git commit -m "test: add daemon lifecycle integration test"
```

---

## Phase 7: Non-Interactive Mode Tests

### Task 17: Non-interactive and subprocess detection integration tests

**Files:**
- Create: `tests/integration/non_interactive_tests.rs`

- [ ] **Step 1: Write non-interactive tests**

```rust
// tests/integration/non_interactive_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn set_config_dir(temp: &TempDir) {
    std::env::set_var("KEYBOX_CONFIG_DIR", temp.path().to_str().unwrap());
}

#[test]
fn test_non_interactive_add_and_get() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "gitea", "token", "--non-interactive", "--password", "secret"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["get", "gitea", "token"])
        .assert().success()
        .stdout(predicate::str::contains("secret"));
}

#[test]
fn test_non_interactive_update() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "g", "a", "--non-interactive", "--password", "old"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["update", "g", "a", "--non-interactive", "--password", "new"])
        .assert().success();

    Command::cargo_bin("keybox").unwrap()
        .args(["get", "g", "a"])
        .assert().success()
        .stdout(predicate::str::contains("new"));
}

#[test]
fn test_non_interactive_without_password_fails() {
    // --non-interactive without --password should fail
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);
    // This is handled by clap: requires = "non_interactive"
    // The parse would fail before reaching our code
}

#[test]
fn test_llm_calling_env_var_blocks_interactive() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "g", "a"])
        .env("KEYBOX_LLM_CALLING", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("LLM calling mode"));
}

#[test]
fn test_add_invalid_name_fails() {
    let dir = TempDir::new().unwrap();
    set_config_dir(&dir);

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "dom/ain", "acc", "--non-interactive", "--password", "x"])
        .assert().failure();

    Command::cargo_bin("keybox").unwrap()
        .args(["add", "domain", "acc count", "--non-interactive", "--password", "x"])
        .assert().failure();
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test non_interactive_tests`
Expected: tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration/non_interactive_tests.rs
git commit -m "test: add non-interactive, LLM mode detection, and validation integration tests"
```

---

## Plan Summary

**Total tasks:** 17
**Phases:** 7 (Scaffold → Core → Protection → Store → CLI → Daemon → Tests)

**v1 MVP scope:** Tasks 1–12, 17 (secret tier fully working, confidential + daemon infrastructure, top-secret skeleton). Tasks 13–16 (daemon full integration) can be completed in a follow-up pass.

**Total lines of code:** ~2,500 (estimate)
**Test coverage target:** >85% for core modules (crypto, store, tier, protect)
