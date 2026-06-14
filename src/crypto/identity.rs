use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use std::fs;
use std::path::Path;
use std::str::FromStr;

pub fn generate() -> (Identity, Recipient) {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

pub fn save_identity(identity: &Identity, path: &Path) -> Result<(), String> {
    let data = identity.to_string();
    fs::write(path, data.expose_secret().as_bytes())
        .map_err(|e| format!("Failed to write identity: {}", e))
}

pub fn load_identity(path: &Path) -> Result<Identity, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read identity: {}", e))?;
    let data = data.trim();
    Identity::from_str(data).map_err(|e| format!("Failed to parse identity: {}", e))
}

pub fn save_recipient(recipient: &Recipient, path: &Path) -> Result<(), String> {
    let data = recipient.to_string();
    fs::write(path, data.as_bytes()).map_err(|e| format!("Failed to write recipient: {}", e))
}

pub fn load_recipient(path: &Path) -> Result<Recipient, String> {
    let data = fs::read_to_string(path).map_err(|e| format!("Failed to read recipient: {}", e))?;
    let data = data.trim();
    Recipient::from_str(data).map_err(|e| format!("Failed to parse recipient: {}", e))
}

pub fn parse_recipient(s: &str) -> Result<Recipient, String> {
    Recipient::from_str(s).map_err(|e| format!("Failed to parse recipient: {}", e))
}
