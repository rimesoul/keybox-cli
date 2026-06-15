use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_generate_default() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().count() == 16
        }));
}

#[test]
fn test_generate_length() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--length", "32"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().count() == 32
        }));
}

#[test]
fn test_generate_digits_only() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--digits", "--length", "6"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().all(|c| c.is_ascii_digit()) && output.trim().len() == 6
        }));
}

#[test]
fn test_generate_passphrase() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--passphrase", "--length", "4"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().split('-').count() == 4
        }));
}

#[test]
fn test_generate_and_save() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .success();

    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["get", "test", "pin"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().all(|c| c.is_ascii_digit()) && output.trim().len() == 6
        }));
}

#[test]
fn test_generate_save_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .success();

    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn test_generate_uppercase_no_save() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--uppercase", "--length", "10"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().all(|c| c.is_ascii_uppercase()) && output.trim().chars().count() == 10
        }));
}
