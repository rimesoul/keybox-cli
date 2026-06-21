use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};

use crate::error::KeyboxError;

const NONCE_LEN: usize = 12;

/// Derive a 256-bit AES key from arbitrary key file content using SHA-256
/// with a domain-separation tag.
pub fn derive_key_from_file(file_content: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keybox-top-v1");
    hasher.update(file_content);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

/// Encrypt plaintext with AES-256-GCM using a keyfile-derived key.
/// Output format: nonce (12 bytes) || ciphertext + tag.
pub fn encrypt_with_aes_gcm_keyfile(
    plaintext: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, KeyboxError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| KeyboxError::crypto("CSPRNG failure"))?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| KeyboxError::crypto(format!("Bad key: {}", e)))?;
    let lk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    lk.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| KeyboxError::crypto(format!("Encryption failed: {}", e)))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    Ok(output)
}

/// Decrypt ciphertext (nonce || ciphertext+tag) with AES-256-GCM using
/// a keyfile-derived key.
pub fn decrypt_with_aes_gcm_keyfile(
    encrypted: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, KeyboxError> {
    if encrypted.len() < NONCE_LEN + 16 {
        return Err(KeyboxError::crypto("Ciphertext too short"));
    }
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| KeyboxError::crypto(format!("Bad key: {}", e)))?;
    let lk = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&encrypted[..NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = encrypted[NONCE_LEN..].to_vec();
    lk.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| KeyboxError::crypto("Decryption failed — wrong key or corrupted data"))?;
    Ok(in_out)
}
