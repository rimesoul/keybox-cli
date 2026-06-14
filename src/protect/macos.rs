use crate::protect::IdentityProtector;
use security_framework::passwords::{set_generic_password, get_generic_password};
use std::fs;
use std::path::Path;

const SERVICE_NAME: &str = "com.keybox.cli";
const MARKER_CONTENT: &[u8] = b"keybox-keychain-v1";

pub struct MacOSProtector;

impl Default for MacOSProtector {
    fn default() -> Self {
        Self
    }
}

impl MacOSProtector {
    pub fn new() -> Self {
        Self
    }

    fn account_for_path(path: &Path) -> String {
        format!("keybox-identity-{}", path.to_string_lossy())
    }
}

impl IdentityProtector for MacOSProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let account = Self::account_for_path(path);
        set_generic_password(SERVICE_NAME, &account, data)
            .map_err(|e| format!("Keychain store failed: {}", e))?;
        // Write a constant marker file (not the secret) so filesystem-aware
        // checks can confirm existence without leaking plaintext.
        fs::write(path, MARKER_CONTENT).map_err(|e| format!("Failed to write marker: {}", e))
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let account = Self::account_for_path(path);
        get_generic_password(SERVICE_NAME, &account)
            .map_err(|e| format!("Keychain read failed: {}", e))
    }
}
