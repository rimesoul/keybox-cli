use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::KeyboxError;

pub const MAGIC: &[u8; 4] = b"KBOX";
pub const CURRENT_VERSION: u16 = 1;
const KEY_REF_LEN: usize = 8;
const NONCE_LEN: usize = 12;
pub const HEADER_LEN: usize = 4 + 2 + KEY_REF_LEN + NONCE_LEN; // 26

pub fn generate_aes_key() -> Result<[u8; 32], KeyboxError> {
    let rng = SystemRandom::new();
    let mut key = [0u8; 32];
    rng.fill(&mut key)
        .map_err(|_| KeyboxError::crypto("CSPRNG failure"))?;
    Ok(key)
}

pub fn compute_key_ref(aes_key: &[u8]) -> [u8; KEY_REF_LEN] {
    let hash = Sha256::digest(aes_key);
    let mut r = [0u8; KEY_REF_LEN];
    r.copy_from_slice(&hash[..KEY_REF_LEN]);
    r
}

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KeyboxError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| KeyboxError::crypto("CSPRNG failure"))?;

    let uk = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| KeyboxError::crypto(format!("Bad key: {}", e)))?;
    let lk = LessSafeKey::new(uk);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = plaintext.to_vec();
    lk.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| KeyboxError::crypto(format!("GCM encrypt: {}", e)))?;

    Ok((nonce_bytes.to_vec(), in_out))
}

pub fn decrypt_aes_gcm(key: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Vec<u8>, KeyboxError> {
    if nonce.len() != NONCE_LEN {
        return Err(KeyboxError::crypto("Bad nonce length"));
    }
    if ct.len() < 16 {
        return Err(KeyboxError::crypto("Ciphertext too short"));
    }

    let uk = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|e| KeyboxError::crypto(format!("Bad key: {}", e)))?;
    let lk = LessSafeKey::new(uk);
    let mut na = [0u8; NONCE_LEN];
    na.copy_from_slice(nonce);

    let mut in_out = ct.to_vec();
    lk.open_in_place(Nonce::assume_unique_for_key(na), Aad::empty(), &mut in_out)
        .map_err(|_| KeyboxError::crypto("Keystore corrupted or tampered — GCM authentication failed"))
        .map(|p| p.to_vec())
}

/// Read keystore file, verify header, decrypt payload → raw JSON bytes
pub fn load_keystore(path: &Path, aes_key: &[u8]) -> Result<Vec<u8>, KeyboxError> {
    let data = fs::read(path).map_err(|e| KeyboxError::io("reading keystore", e))?;
    if data.len() < HEADER_LEN {
        return Err(KeyboxError::io(
            "validating keystore — file too small",
            std::io::Error::new(std::io::ErrorKind::InvalidData, "file too small"),
        ));
    }
    if &data[0..4] != MAGIC {
        return Err(KeyboxError::io(
            "validating keystore — bad magic",
            std::io::Error::new(std::io::ErrorKind::InvalidData, "bad magic"),
        ));
    }
    let version = u16::from_be_bytes([data[4], data[5]]);
    if version != CURRENT_VERSION {
        return Err(KeyboxError::io(
            format!(
                "unsupported keystore version {} (expected {})",
                version, CURRENT_VERSION
            ),
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported version {}", version),
            ),
        ));
    }
    let expected_ref = compute_key_ref(aes_key);
    if data[6..14] != expected_ref {
        return Err(KeyboxError::io(
            "validating keystore — key_ref mismatch",
            std::io::Error::new(std::io::ErrorKind::InvalidData, "key_ref mismatch"),
        ));
    }
    decrypt_aes_gcm(aes_key, &data[14..26], &data[26..])
}

/// Serialize JSON, encrypt, atomically write to disk
pub fn save_keystore(path: &Path, json_bytes: &[u8], aes_key: &[u8]) -> Result<(), KeyboxError> {
    let (nonce, ct) = encrypt_aes_gcm(aes_key, json_bytes)?;
    let key_ref = compute_key_ref(aes_key);

    let mut buf = Vec::with_capacity(HEADER_LEN + ct.len());
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&CURRENT_VERSION.to_be_bytes());
    buf.extend_from_slice(&key_ref);
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ct);

    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| KeyboxError::io("creating tmp file", e))?;
        f.write_all(&buf)
            .map_err(|e| KeyboxError::io("writing tmp file", e))?;
        f.sync_all()
            .map_err(|e| KeyboxError::io("syncing tmp file", e))?;
    }
    fs::rename(&tmp, path)
        .map_err(|e| KeyboxError::io("renaming tmp to keystore", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn tmp_path() -> (TempDir, PathBuf) {
        let d = TempDir::new().unwrap();
        let p = d.path().join("t.keystore");
        (d, p)
    }

    #[test]
    fn test_key_ref_deterministic() {
        let k = [0x42u8; 32];
        assert_eq!(compute_key_ref(&k), compute_key_ref(&k));
    }

    #[test]
    fn test_key_ref_different_keys() {
        assert_ne!(compute_key_ref(&[0x42u8; 32]), compute_key_ref(&[0x99u8; 32]));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let k = generate_aes_key().unwrap();
        let pt = b"hello world";
        let (n, ct) = encrypt_aes_gcm(&k, pt).unwrap();
        assert_eq!(decrypt_aes_gcm(&k, &n, &ct).unwrap(), pt);
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = generate_aes_key().unwrap();
        let k2 = generate_aes_key().unwrap();
        let (n, ct) = encrypt_aes_gcm(&k1, b"x").unwrap();
        assert!(decrypt_aes_gcm(&k2, &n, &ct).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let k = generate_aes_key().unwrap();
        let (n, mut ct) = encrypt_aes_gcm(&k, b"x").unwrap();
        ct[0] ^= 1;
        assert!(decrypt_aes_gcm(&k, &n, &ct).is_err());
    }

    #[test]
    fn test_save_load_roundtrip() {
        let (_dir, p) = tmp_path();
        let k = generate_aes_key().unwrap();
        let json = b"{\"version\":1}";
        save_keystore(&p, json, &k).unwrap();
        assert_eq!(load_keystore(&p, &k).unwrap(), json);
    }

    #[test]
    fn test_load_wrong_magic() {
        let (_dir, p) = tmp_path();
        std::fs::write(&p, b"BADX\x00\x01aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbb").unwrap();
        let k = generate_aes_key().unwrap();
        assert!(load_keystore(&p, &k).is_err());
    }

    #[test]
    fn test_load_wrong_key_ref() {
        let (_dir, p) = tmp_path();
        let k1 = generate_aes_key().unwrap();
        let k2 = generate_aes_key().unwrap();
        save_keystore(&p, b"x", &k1).unwrap();
        assert!(load_keystore(&p, &k2).is_err());
    }

    #[test]
    fn test_header_size() {
        assert_eq!(HEADER_LEN, 26);
    }
}
