use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_list_domains() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add credentials in two different domains
    for (target, password) in [
        ("gitea:pat", "secret123"),
        ("github:token", "ghp_abc123"),
    ] {
        let mut cmd = Command::cargo_bin("keybox").unwrap();
        cmd.env("KEYBOX_CONFIG_DIR", config_dir)
            .args(["add", target, "--stdin"])
            .write_stdin(format!("{}\n", password))
            .assert()
            .success();
    }

    // List credentials and verify both appear
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("gitea").and(predicate::str::contains("github")),
        );
}

#[test]
fn test_list_accounts_in_domain() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add two accounts in the same domain
    for (target, password) in [("gitea:pat", "secret123"), ("gitea:oauth", "token456")] {
        let mut cmd = Command::cargo_bin("keybox").unwrap();
        cmd.env("KEYBOX_CONFIG_DIR", config_dir)
            .args(["add", target, "--stdin"])
            .write_stdin(format!("{}\n", password))
            .assert()
            .success();
    }

    // List credentials and verify both appear
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("pat").and(predicate::str::contains("oauth")),
        );
}

#[test]
fn test_list_json_output() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add a credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // List with default format (JSON) and verify JSON array output
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"domain\": \"gitea\"").and(predicate::str::contains("\"account\": \"pat\"")));
}

#[test]
fn test_delete_credential() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add a credential
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["add", "gitea:pat", "--stdin"])
        .write_stdin("secret123\n")
        .assert()
        .success();

    // Delete the credential with stdin "y\n" for confirmation
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["delete", "gitea:pat"])
        .write_stdin("y\n")
        .assert()
        .success();

    // Verify get fails afterward
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "--user", "gitea:pat", "--force"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
