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

    let metadata = fs::metadata(&path).unwrap();
    let mode = metadata.permissions().mode();
    // File should be readable and writable only by owner (600)
    assert_eq!(
        mode & 0o777,
        0o600,
        "protected file should have 0o600 permissions, got {:#o}",
        mode & 0o777
    );
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
