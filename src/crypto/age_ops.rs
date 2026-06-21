use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};

use crate::error::KeyboxError;

/// Generate a fresh x25519 keypair for age encryption.
pub fn generate_keypair() -> (Identity, Recipient) {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

/// Encrypt plaintext to the given recipient.
pub fn encrypt_with_recipient(
    recipient: &Recipient,
    plaintext: &[u8],
) -> Result<Vec<u8>, age::EncryptError> {
    let encryptor = Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .ok_or_else(|| {
            age::EncryptError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no recipients provided",
            ))
        })?;

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(plaintext)?;
    writer.finish()?;
    Ok(encrypted)
}

/// Decrypt ciphertext using the given identity.
pub fn decrypt_with_identity(
    identity: &Identity,
    ciphertext: &[u8],
) -> Result<Vec<u8>, age::DecryptError> {
    let decryptor = Decryptor::new(ciphertext)?;
    let decryptor = match decryptor {
        Decryptor::Recipients(d) => d,
        Decryptor::Passphrase(_) => {
            return Err(age::DecryptError::NoMatchingKeys);
        }
    };

    let mut reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext)?;
    Ok(plaintext)
}

// ── Passphrase-based encryption (for confidential level identity) ────

/// Encrypt plaintext using an age passphrase (scrypt-based).
pub fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, KeyboxError> {
    let encryptor =
        Encryptor::with_user_passphrase(age::secrecy::Secret::new(passphrase.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|_| KeyboxError::crypto("Encryption failed"))?;
    Write::write_all(&mut writer, plaintext)
        .map_err(|_| KeyboxError::crypto("Write failed"))?;
    writer
        .finish()
        .map_err(|_| KeyboxError::crypto("Finish failed"))?;
    Ok(encrypted)
}

/// Decrypt ciphertext that was encrypted with an age passphrase.
pub fn decrypt_with_passphrase(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, KeyboxError> {
    let decryptor =
        Decryptor::new(encrypted).map_err(|e| KeyboxError::crypto(format!("Age decrypt: {}", e)))?;
    let decryptor = match decryptor {
        Decryptor::Passphrase(d) => d,
        _ => return Err(KeyboxError::crypto("Not a passphrase-encrypted file")),
    };
    let mut reader = decryptor
        .decrypt(&age::secrecy::Secret::new(passphrase.to_string()), None)
        .map_err(|_| KeyboxError::crypto("Wrong passphrase"))?;
    let mut plaintext = vec![];
    Read::read_to_end(&mut reader, &mut plaintext)
        .map_err(|e| KeyboxError::crypto(format!("Read: {}", e)))?;
    Ok(plaintext)
}
