use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_update_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Initialize by adding a credential in a different domain
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Update a nonexistent credential — fails with "not found"
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["update", "password", "nonexistent:ghost"])
        .write_stdin("oldpass\nnewpass\nnewpass\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_update_requires_tty() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add a credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("old-secret\n")
        .assert()
        .success();

    // Update password without TTY fails because password prompts require TTY
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["update", "password", "gitea:pat"])
        .write_stdin("old-secret\nnew-secret-xyz\nnew-secret-xyz\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("stdin is not a TTY"));
}
