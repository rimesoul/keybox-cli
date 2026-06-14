use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn test_confidential_init() {
    let dir = TempDir::new().unwrap();

    // Init confidential tier non-interactively
    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["--confidential", "init", "--non-interactive", "--password", "master123"])
        .assert().success();

    // Verify files exist
    assert!(dir.path().join("confidential").join("identity.private.enc").exists());
    assert!(dir.path().join("confidential").join("identity.pub").exists());
}
