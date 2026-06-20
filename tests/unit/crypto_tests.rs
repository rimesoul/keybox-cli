use keybox::crypto::age_ops;

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let (identity, recipient) = age_ops::generate_keypair();
    let plaintext = b"hello world, this is a secret message";

    let encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_empty_payload() {
    let (identity, recipient) = age_ops::generate_keypair();
    let plaintext: &[u8] = b"";

    let encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_large_payload() {
    let (identity, recipient) = age_ops::generate_keypair();
    let plaintext = vec![0xAB; 1_000_000]; // 1 MB of repeated byte

    let encrypted = age_ops::encrypt_with_recipient(&recipient, &plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_binary_data() {
    let (identity, recipient) = age_ops::generate_keypair();
    // All possible byte values, including null bytes and high bytes
    let plaintext: Vec<u8> = (0..=255).cycle().take(2048).collect();

    let encrypted = age_ops::encrypt_with_recipient(&recipient, &plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&identity, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_wrong_identity_fails() {
    let (_identity, recipient) = age_ops::generate_keypair();
    let plaintext = b"secret data";
    let encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();

    // Generate a different keypair for decryption attempt
    let (wrong_identity, _) = age_ops::generate_keypair();
    let result = age_ops::decrypt_with_identity(&wrong_identity, &encrypted);

    assert!(result.is_err(), "decryption with wrong identity should fail");
}

#[test]
fn test_decrypt_corrupted_ciphertext_fails() {
    let (identity, recipient) = age_ops::generate_keypair();
    let plaintext = b"secret data";
    let mut encrypted = age_ops::encrypt_with_recipient(&recipient, plaintext).unwrap();

    // Corrupt the ciphertext by flipping bits in the body
    if encrypted.len() > 10 {
        // Flip bits in the latter portion (after header) to avoid immediate parse failure
        let len = encrypted.len();
        encrypted[len / 2] ^= 0xFF;
    }

    let result = age_ops::decrypt_with_identity(&identity, &encrypted);

    assert!(result.is_err(), "decryption of corrupted ciphertext should fail");
}
