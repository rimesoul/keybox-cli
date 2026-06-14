use age::{Decryptor, Encryptor};
use age::x25519::{Identity, Recipient};
use std::io::{Read, Write};

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
