use keybox::crypto::age_ops;
use keybox::crypto::identity;
use std::fs;

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

// ── Identity keypair tests ──

#[test]
fn test_generate_and_save_identity() {
    let tmp = tempfile::tempdir().unwrap();

    let (identity, recipient) = identity::generate();
    let id_path = tmp.path().join("identity.txt");
    let rec_path = tmp.path().join("recipient.txt");

    identity::save_identity(&identity, &id_path).unwrap();
    identity::save_recipient(&recipient, &rec_path).unwrap();

    assert!(id_path.exists(), "identity file should exist");
    assert!(rec_path.exists(), "recipient file should exist");

    // Verify files are not empty
    let id_data = fs::read_to_string(&id_path).unwrap();
    let rec_data = fs::read_to_string(&rec_path).unwrap();
    assert!(!id_data.is_empty(), "identity file should not be empty");
    assert!(!rec_data.is_empty(), "recipient file should not be empty");
}

#[test]
fn test_load_identity_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();

    let (identity, recipient) = identity::generate();
    let id_path = tmp.path().join("identity.txt");
    let rec_path = tmp.path().join("recipient.txt");

    identity::save_identity(&identity, &id_path).unwrap();
    identity::save_recipient(&recipient, &rec_path).unwrap();

    // Load back
    let loaded_id = identity::load_identity(&id_path).unwrap();
    let loaded_rec = identity::load_recipient(&rec_path).unwrap();

    // Encrypt with loaded recipient, decrypt with loaded identity
    let plaintext = b"roundtrip test data";
    let encrypted = age_ops::encrypt_with_recipient(&loaded_rec, plaintext).unwrap();
    let decrypted = age_ops::decrypt_with_identity(&loaded_id, &encrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_load_identity_from_invalid_file_fails() {
    let tmp = tempfile::tempdir().unwrap();

    let bad_path = tmp.path().join("bad_identity.txt");
    fs::write(&bad_path, "this is not a valid age identity").unwrap();

    let result = identity::load_identity(&bad_path);
    assert!(result.is_err(), "loading invalid identity should fail");
}

#[test]
fn test_load_recipient_from_invalid_file_fails() {
    let tmp = tempfile::tempdir().unwrap();

    let bad_path = tmp.path().join("bad_recipient.txt");
    fs::write(&bad_path, "this is not a valid age recipient").unwrap();

    let result = identity::load_recipient(&bad_path);
    assert!(result.is_err(), "loading invalid recipient should fail");
}

#[test]
fn test_recipient_to_from_string() {
    let (_identity, recipient) = identity::generate();
    let s = recipient.to_string();

    assert!(
        s.starts_with("age1"),
        "recipient string should start with 'age1', got: {}",
        s
    );

    let parsed = identity::parse_recipient(&s).unwrap();
    // Verify the parsed recipient can be used for encryption
    let plaintext = b"parse test";
    let encrypted = age_ops::encrypt_with_recipient(&parsed, plaintext).unwrap();
    assert!(!encrypted.is_empty());
}
