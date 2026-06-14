use keybox::protect::IdentityProtector;
use tempfile::tempdir;

// ── macOS tests ─────────────────────────────────────────────

#[cfg(target_os = "macos")]
use keybox::protect::MacOSProtector;

#[cfg(target_os = "macos")]
#[test]
fn test_macos_protect_unprotect_roundtrip() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.key");

    let data = b"age-identity-secret-key-material";
    let protector = MacOSProtector::new();

    // Protect data into keychain + marker file
    protector.protect(data, &path).unwrap();
    assert!(path.exists(), "marker file should exist after protect");

    // Verify marker does NOT contain the raw secret (Critical fix: marker is constant)
    let marker = std::fs::read(&path).unwrap();
    assert_ne!(marker, data, "marker file must not contain the raw secret");

    // Unprotect and verify roundtrip
    let recovered = protector.unprotect(&path).unwrap();
    assert_eq!(recovered, data);
}

#[cfg(target_os = "macos")]
#[test]
fn test_macos_unprotect_missing_file_fails() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("nonexistent.key");

    let protector = MacOSProtector::new();
    let result = protector.unprotect(&path);

    assert!(result.is_err(), "unprotect on nonexistent path should fail");
}

// ── Linux tests ─────────────────────────────────────────────

#[cfg(target_os = "linux")]
use keybox::protect::LinuxProtector;

#[cfg(target_os = "linux")]
#[test]
fn test_linux_protect_unprotect_roundtrip() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.age");

    let data = b"age-identity-secret-key-material";
    let protector = LinuxProtector::new();

    protector.protect(data, &path).unwrap();
    assert!(path.exists(), "protected file should exist");

    let recovered = protector.unprotect(&path).unwrap();
    assert_eq!(recovered, data);
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_protected_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.age");

    let data = b"age-identity-secret-key-material";
    let protector = LinuxProtector::new();

    protector.protect(data, &path).unwrap();

    let metadata = std::fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode();
    // File should be readable and writable only by owner (600)
    assert_eq!(
        mode & 0o777,
        0o600,
        "protected file should have 0o600 permissions, got {:#o}",
        mode & 0o777
    );
}

#[cfg(target_os = "linux")]
#[test]
fn test_linux_unprotect_corrupted_file_fails() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.age");

    let data = b"age-identity-secret-key-material";
    let protector = LinuxProtector::new();

    protector.protect(data, &path).unwrap();

    // Corrupt the ciphertext by flipping a byte
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let result = protector.unprotect(&path);
    assert!(result.is_err(), "decryption of corrupted file should fail");
}

// ── Windows tests ───────────────────────────────────────────

#[cfg(target_os = "windows")]
use keybox::protect::DpapiProtector;

#[cfg(target_os = "windows")]
#[test]
fn test_windows_dpapi_protect_unprotect_roundtrip() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.dat");

    let data = b"age-identity-secret-key-material";
    let protector = DpapiProtector::new();

    protector.protect(data, &path).unwrap();
    assert!(path.exists(), "protected file should exist");

    let recovered = protector.unprotect(&path).unwrap();
    assert_eq!(recovered, data);
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_dpapi_unprotect_corrupted_fails() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("identity.dat");

    let data = b"age-identity-secret-key-material";
    let protector = DpapiProtector::new();

    protector.protect(data, &path).unwrap();

    // Corrupt the DPAPI blob by flipping a byte
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let result = protector.unprotect(&path);
    assert!(result.is_err(), "decryption of corrupted DPAPI data should fail");
}
