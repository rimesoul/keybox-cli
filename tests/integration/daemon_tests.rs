// Daemon integration tests.
//
// Current scope:
// - test_init_command_works: verify keystore is created on add
//
// Future (requires non-interactive unlock support):
// - daemon lifecycle (start → unlock → get with token → lock → stop)
// - wrong passphrase rejection
// - token expiry

use assert_cmd::Command;
use tempfile::TempDir;

#[test]
fn test_init_command_works() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("keybox")
        .unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["add", "test:user", "--stdin"])
        .write_stdin("testpass\n")
        .assert()
        .success();

    assert!(dir.path().join("keybox.keystore").exists());
}
