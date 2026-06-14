use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_llm_calling_env_var_blocks_interactive() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // First initialize the tier by adding a credential non-interactively
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

    // Now try add without --non-interactive with KEYBOX_LLM_CALLING=1
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .env("KEYBOX_LLM_CALLING", "1")
        .args(["add", "github", "token"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LLM calling mode"));
}

#[test]
fn test_add_invalid_name_fails() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add with invalid characters (slashes) in domain name
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args([
            "add",
            "evil/domain",
            "user",
            "--non-interactive",
            "--password",
            "secret123",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid character"));
}

#[test]
fn test_get_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Initialize the tier first by adding a credential
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

    // Try to get a nonexistent credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "nowhere", "nobody"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
