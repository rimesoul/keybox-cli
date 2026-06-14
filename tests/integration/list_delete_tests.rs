use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_list_domains() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add credentials in two different domains
    for (domain, account, password) in [
        ("gitea", "pat", "secret123"),
        ("github", "token", "ghp_abc123"),
    ] {
        let mut cmd = Command::cargo_bin("keybox").unwrap();
        cmd.env("KEYBOX_CONFIG_DIR", config_dir)
            .args([
                "add",
                domain,
                account,
                "--non-interactive",
                "--password",
                password,
            ])
            .assert()
            .success();
    }

    // List domains and verify both appear
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("gitea").and(predicate::str::contains("github")));
}

#[test]
fn test_list_accounts_in_domain() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add two accounts in the same domain
    for (account, password) in [("pat", "secret123"), ("oauth", "token456")] {
        let mut cmd = Command::cargo_bin("keybox").unwrap();
        cmd.env("KEYBOX_CONFIG_DIR", config_dir)
            .args([
                "add",
                "gitea",
                account,
                "--non-interactive",
                "--password",
                password,
            ])
            .assert()
            .success();
    }

    // List accounts in the domain and verify both appear
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list", "gitea"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pat").and(predicate::str::contains("oauth")));
}

#[test]
fn test_list_json_output() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add a credential
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

    // List with --json and verify JSON array output
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[\n").and(predicate::str::contains("gitea").and(predicate::str::contains("]"))));
}

#[test]
fn test_delete_credential() {
    let dir = TempDir::new().unwrap();
    let config_dir = dir.path().to_str().unwrap();

    // Add a credential
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

    // Delete the credential with stdin "y\n" for confirmation (when interactive)
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["delete", "gitea", "pat"])
        .write_stdin("y\n")
        .assert()
        .success();

    // Verify get fails afterward
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.env("KEYBOX_CONFIG_DIR", config_dir)
        .args(["get", "gitea", "pat"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
