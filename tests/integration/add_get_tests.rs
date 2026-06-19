use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_add_and_get_secret_credential() {
    let dir = TempDir::new().unwrap();

    // Add credential with secret via stdin
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Get credential and verify output contains the secret (masked in "all" mode)
    // Use --force to display password
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["get", "--user", "gitea:pat", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));
}
