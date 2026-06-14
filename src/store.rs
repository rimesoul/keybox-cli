use crate::crypto::{age_ops, identity};
use crate::tier::{Tier, TierPaths};
use std::fs;
use std::path::Path;

pub fn add_credential(
    base: &Path, tier: Tier, domain: &str, account: &str, secret: &[u8],
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let domain_dir = paths.store.join(domain);
    let file_path = domain_dir.join(format!("{}.enc", account));

    if file_path.exists() {
        return Err(format!("already exists: {}/{}", domain, account));
    }
    fs::create_dir_all(&domain_dir).map_err(|e| format!("Failed to create domain dir: {}", e))?;
    let recipient = identity::load_recipient(&paths.public_key)?;
    let encrypted = age_ops::encrypt_with_recipient(&recipient, secret)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    fs::write(&file_path, &encrypted).map_err(|e| format!("Failed to write: {}", e))
}

pub fn get_credential(
    base: &Path, tier: Tier, domain: &str, account: &str,
) -> Result<Vec<u8>, String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));
    if !file_path.exists() {
        return Err(format!("not found: {}/{}", domain, account));
    }
    let ciphertext = fs::read(&file_path).map_err(|e| format!("Failed to read: {}", e))?;
    let ident = identity::load_identity(&paths.private_key)?;
    age_ops::decrypt_with_identity(&ident, &ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))
}

pub fn update_credential(
    base: &Path, tier: Tier, domain: &str, account: &str, secret: &[u8],
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));
    if !file_path.exists() {
        return Err(format!("not found: {}/{}", domain, account));
    }
    let recipient = identity::load_recipient(&paths.public_key)?;
    let encrypted = age_ops::encrypt_with_recipient(&recipient, secret)
        .map_err(|e| format!("Encryption failed: {}", e))?;
    fs::write(&file_path, &encrypted).map_err(|e| format!("Failed to write: {}", e))
}

pub fn delete_credential(
    base: &Path, tier: Tier, domain: &str, account: &str,
) -> Result<(), String> {
    let paths = TierPaths::from_base(base, tier);
    let file_path = paths.store.join(domain).join(format!("{}.enc", account));
    if !file_path.exists() {
        return Err(format!("not found: {}/{}", domain, account));
    }
    fs::remove_file(&file_path).map_err(|e| format!("Failed to delete: {}", e))
}

pub fn list_domains(base: &Path, tier: Tier) -> Result<Vec<String>, String> {
    let paths = TierPaths::from_base(base, tier);
    if !paths.store.exists() {
        return Ok(vec![]);
    }
    let mut domains = vec![];
    for entry in fs::read_dir(&paths.store).map_err(|e| format!("Failed to read store: {}", e))? {
        let entry = entry.map_err(|_| "entry error".to_string())?;
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if let Some(name) = entry.file_name().to_str() {
                domains.push(name.to_string());
            }
        }
    }
    domains.sort();
    Ok(domains)
}

pub fn list_accounts(base: &Path, tier: Tier, domain: &str) -> Result<Vec<String>, String> {
    let paths = TierPaths::from_base(base, tier);
    let domain_dir = paths.store.join(domain);
    if !domain_dir.exists() {
        return Ok(vec![]);
    }
    let mut accounts = vec![];
    for entry in fs::read_dir(&domain_dir).map_err(|e| format!("Failed to read domain: {}", e))? {
        let entry = entry.map_err(|_| "entry error".to_string())?;
        if let Some(name) = entry.file_name().to_str() {
            if let Some(stripped) = name.strip_suffix(".enc") {
                accounts.push(stripped.to_string());
            }
        }
    }
    accounts.sort();
    Ok(accounts)
}
