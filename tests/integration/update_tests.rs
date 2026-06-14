use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_update_existing() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add credential with old value
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args([
            "add",
            "gitea",
            "pat",
            "--non-interactive",
            "--password",
            "old-secret",
        ])
        .assert()
        .success();

    // Update with new value
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args([
            "update",
            "gitea",
            "pat",
            "--non-interactive",
            "--password",
            "new-secret-xyz",
        ])
        .assert()
        .success();

    // Get returns new value
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "gitea", "pat"])
        .assert()
        .success()
        .stdout(predicate::str::contains("new-secret-xyz"));
}

#[test]
fn test_update_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Initialize the tier first by adding a credential in a different domain
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args([
            "add",
            "gitea",
            "pat",
            "--non-interactive",
            "--password",
            "secret123",
        ])
        .assert()
        .success();

    // Update a nonexistent credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args([
            "update",
            "nonexistent",
            "ghost",
            "--non-interactive",
            "--password",
            "newpass",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
