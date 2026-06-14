use crate::protect::IdentityProtector;
use ring::aead::{Aad, BoundKey, LessSafeKey, Nonce, NonceSequence, SealingKey, OpeningKey, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Sha256, Digest};
use std::fs;
use std::io::Read;
use std::path::Path;

const NONCE_LEN: usize = 12;

/// Encrypts `plaintext` with AES-256-GCM using `key`.
/// Returns nonce || ciphertext (with embedded auth tag).
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|e| format!("RNG failure: {}", e))?;

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::empty();

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, aad, &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(NONCE_LEN + in_out.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&in_out);

    Ok(output)
}

/// Decrypts `ciphertext` (nonce || ciphertext+tag) with AES-256-GCM using `key`.
pub fn aes_gcm_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < NONCE_LEN {
        return Err("Ciphertext too short".to_string());
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LEN);

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);

    let nonce = Nonce::assume_unique_for_key(
        nonce_bytes
            .try_into()
            .map_err(|_| "Invalid nonce length".to_string())?,
    );
    let aad = Aad::empty();

    let mut in_out = encrypted.to_vec();
    let plaintext = key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext.to_vec())
}

fn derive_key_from_machine_id() -> Result<[u8; 32], String> {
    let machine_id = fs::read_to_string("/etc/machine-id")
        .map_err(|e| format!("Failed to read /etc/machine-id: {}", e))?;
    let machine_id = machine_id.trim();

    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    let hash = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

pub struct LinuxProtector;

impl LinuxProtector {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProtector for LinuxProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let key = derive_key_from_machine_id()?;
        let ciphertext = aes_gcm_encrypt(&key, data)?;

        fs::write(path, &ciphertext)
            .map_err(|e| format!("Failed to write protected file: {}", e))?;

        // Set permissions to 600 (owner read/write only)
        set_file_permissions_600(path)?;

        Ok(())
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let ciphertext = fs::read(path)
            .map_err(|e| format!("Failed to read protected file: {}", e))?;

        let key = derive_key_from_machine_id()?;
        aes_gcm_decrypt(&key, &ciphertext)
    }
}

#[cfg(unix)]
fn set_file_permissions_600(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(path).map_err(|e| format!("stat failed: {}", e))?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).map_err(|e| format!("chmod failed: {}", e))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions_600(_path: &Path) -> Result<(), String> {
    Ok(())
}
