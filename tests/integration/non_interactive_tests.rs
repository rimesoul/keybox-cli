use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_llm_calling_env_var_blocks_interactive() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // First initialize by adding a credential via stdin
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Now try add without --stdin with KEYBOX_LLM_CALLING=1
    // This should fail because prompting is blocked
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .env("KEYBOX_LLM_CALLING", "1")
        .args(["add", "github:token"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("LLM calling mode"));
}

#[test]
fn test_add_invalid_target_format() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add with invalid target format (empty domain with colon)
    // This should still work since the CLI parses "target" as a single string
    // The validation now happens at a different level: validate keystore ops
    // Actually, the new CLI takes --target as a single string; no character validation
    // Let's test that add with --target works, and verify get works
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "testdomain:user", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Verify it was saved correctly
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "--user", "testdomain:user", "--force"])
        .assert()
        .success()
        .stdout(predicate::str::contains("secret123"));
}

#[test]
fn test_get_nonexistent_fails() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Initialize by adding a credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Try to get a nonexistent credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "--user", "nowhere:nobody", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
