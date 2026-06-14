use keybox::tier::{Tier, TierPaths};
use std::fs;
use super::common::test_config_dir;

#[test]
fn test_tier_paths_secret() {
    let base = test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::Secret);
    assert_eq!(paths.private_key, base.join("secret").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("secret").join("identity.pub"));
    assert_eq!(paths.store, base.join("secret").join("store"));
}

#[test]
fn test_tier_paths_confidential() {
    let base = test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::Confidential);
    assert_eq!(paths.private_key, base.join("confidential").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("confidential").join("identity.pub"));
    assert_eq!(paths.store, base.join("confidential").join("store"));
}

#[test]
fn test_tier_paths_top_secret() {
    let base = test_config_dir();
    let paths = TierPaths::from_base(&base, Tier::TopSecret);
    assert_eq!(paths.private_key, base.join("top-secret").join("identity.private.enc"));
    assert_eq!(paths.public_key, base.join("top-secret").join("identity.pub"));
    assert_eq!(paths.store, base.join("top-secret").join("store"));
}

#[test]
fn test_tier_is_initialized_false() {
    let base = test_config_dir();
    assert!(!Tier::Secret.is_initialized(&base));
    assert!(!Tier::Confidential.is_initialized(&base));
    assert!(!Tier::TopSecret.is_initialized(&base));
}

#[test]
fn test_tier_is_initialized_true() {
    let base = tempfile::TempDir::new().unwrap();
    for tier in &[Tier::Secret, Tier::Confidential, Tier::TopSecret] {
        let paths = TierPaths::from_base(base.path(), *tier);
        fs::create_dir_all(paths.public_key.parent().unwrap()).unwrap();
        fs::write(&paths.public_key, "fake-key").unwrap();
        assert!(tier.is_initialized(base.path()));
    }
}

#[test]
fn test_tier_default_top_key_path() {
    let base = test_config_dir();
    assert_eq!(Tier::default_top_key_path(&base), base.join("top.key"));
}

#[test]
fn test_tier_daemon_socket_path() {
    let base = test_config_dir();
    assert_eq!(Tier::Confidential.daemon_socket_path(&base), base.join("keyboxd.sock"));
    assert_eq!(Tier::TopSecret.daemon_socket_path(&base), base.join("keyboxd-top.sock"));
}

#[test]
#[should_panic(expected = "Secret tier has no daemon")]
fn test_tier_secret_no_daemon_socket() {
    let base = test_config_dir();
    Tier::Secret.daemon_socket_path(&base);
}
