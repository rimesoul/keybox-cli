use keybox::crypto::identity;
use keybox::store;
use keybox::tier::{Tier, TierPaths};
use std::fs;

fn setup_tier(tmp: &tempfile::TempDir, tier: Tier) {
    let (identity, recipient) = identity::generate();
    let paths = TierPaths::from_base(tmp.path(), tier);
    fs::create_dir_all(paths.private_key.parent().unwrap()).unwrap();
    identity::save_identity(&identity, &paths.private_key).unwrap();
    identity::save_recipient(&recipient, &paths.public_key).unwrap();
}

#[test]
fn test_add_and_get_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let secret = b"my-password-123";
    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", secret).unwrap();

    let retrieved = store::get_credential(tmp.path(), Tier::Secret, "example.com", "alice").unwrap();
    assert_eq!(retrieved, secret);
}

#[test]
fn test_get_nonexistent_fails() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let result = store::get_credential(tmp.path(), Tier::Secret, "example.com", "alice");
    assert!(result.is_err(), "get non-existent credential should fail");
}

#[test]
fn test_add_duplicate_fails() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret1").unwrap();
    let result = store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret2");
    assert!(result.is_err(), "adding duplicate credential should fail");
}

#[test]
fn test_update_existing() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"old-secret").unwrap();
    store::update_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"new-secret").unwrap();

    let retrieved = store::get_credential(tmp.path(), Tier::Secret, "example.com", "alice").unwrap();
    assert_eq!(retrieved, b"new-secret");
}

#[test]
fn test_update_nonexistent_fails() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let result = store::update_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret");
    assert!(result.is_err(), "updating non-existent credential should fail");
}

#[test]
fn test_delete_removes() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret").unwrap();
    store::delete_credential(tmp.path(), Tier::Secret, "example.com", "alice").unwrap();

    let result = store::get_credential(tmp.path(), Tier::Secret, "example.com", "alice");
    assert!(result.is_err(), "get after delete should fail");
}

#[test]
fn test_delete_nonexistent_fails() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let result = store::delete_credential(tmp.path(), Tier::Secret, "example.com", "alice");
    assert!(result.is_err(), "deleting non-existent credential should fail");
}

#[test]
fn test_list_domains() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret").unwrap();
    store::add_credential(tmp.path(), Tier::Secret, "github.com", "bob", b"secret").unwrap();
    store::add_credential(tmp.path(), Tier::Secret, "api.example.com", "carol", b"secret").unwrap();

    let domains = store::list_domains(tmp.path(), Tier::Secret).unwrap();
    assert_eq!(domains, vec!["api.example.com", "example.com", "github.com"]);
}

#[test]
fn test_list_accounts() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret").unwrap();
    store::add_credential(tmp.path(), Tier::Secret, "example.com", "bob", b"secret").unwrap();
    store::add_credential(tmp.path(), Tier::Secret, "example.com", "carol", b"secret").unwrap();

    let accounts = store::list_accounts(tmp.path(), Tier::Secret, "example.com").unwrap();
    assert_eq!(accounts, vec!["alice", "bob", "carol"]);
}

#[test]
fn test_list_empty_store() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let domains = store::list_domains(tmp.path(), Tier::Secret).unwrap();
    assert!(domains.is_empty(), "empty store should return empty domains list");
}

#[test]
fn test_store_is_tier_scoped() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);
    setup_tier(&tmp, Tier::Confidential);

    store::add_credential(tmp.path(), Tier::Secret, "example.com", "alice", b"secret-tier").unwrap();
    store::add_credential(tmp.path(), Tier::Confidential, "example.com", "alice", b"confidential-tier").unwrap();

    let s = store::get_credential(tmp.path(), Tier::Secret, "example.com", "alice").unwrap();
    let c = store::get_credential(tmp.path(), Tier::Confidential, "example.com", "alice").unwrap();

    assert_eq!(s, b"secret-tier");
    assert_eq!(c, b"confidential-tier");
    assert_ne!(s, c, "different tiers should have independent storage");
}

#[test]
fn test_list_accounts_empty_domain() {
    let tmp = tempfile::tempdir().unwrap();
    setup_tier(&tmp, Tier::Secret);

    let accounts = store::list_accounts(tmp.path(), Tier::Secret, "nonexistent.com").unwrap();
    assert!(accounts.is_empty(), "non-existent domain should return empty accounts list");
}
