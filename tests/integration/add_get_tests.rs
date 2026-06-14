use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_add_and_get_secret_credential() {
    let dir = TempDir::new().unwrap();

    // Add credential non-interactively
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
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

    // Get credential and verify output contains the secret
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["get", "gitea", "pat"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));
}
