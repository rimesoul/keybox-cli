use rand::Rng;
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use base64::Engine;

#[derive(Debug, Clone)]
pub struct TokenData {
    pub scope: String,         // "con" or "top"
    pub expires_at: SystemTime,
}

#[derive(Debug, Default)]
pub struct TokenStore {
    tokens: HashMap<String, TokenData>,
}

impl TokenStore {
    /// Generate a new random 256-bit token, base64-encoded.
    /// Returns the token string for the caller to provide to the user.
    pub fn generate(&mut self, scope: &str, timeout_minutes: u64) -> String {
        let mut rng = rand::thread_rng();
        let raw: [u8; 32] = rng.gen();
        let token = base64::engine::general_purpose::STANDARD.encode(raw);

        self.tokens.insert(token.clone(), TokenData {
            scope: scope.to_string(),
            expires_at: SystemTime::now() + Duration::from_secs(timeout_minutes * 60),
        });
        token
    }

    /// Validate a token against a required scope. Returns Ok(scope) if valid,
    /// or an error message if invalid, expired, or insufficient scope.
    pub fn validate(&self, token: &str, required_scope: &str) -> Result<String, String> {
        let data = self.tokens.get(token)
            .ok_or("Invalid token")?;

        if SystemTime::now() > data.expires_at {
            return Err("Token expired. Run keybox unlock.".into());
        }

        // Exact scope match required — no inheritance
        if data.scope != required_scope {
            return Err(format!(
                "Token scope insufficient. Required: {}, have: {}",
                required_scope, data.scope
            ));
        }

        Ok(data.scope.clone())
    }

    /// Invalidate all tokens (on lock)
    pub fn clear(&mut self) {
        self.tokens.clear();
    }

    /// Remove expired tokens (call periodically in daemon loop)
    pub fn purge_expired(&mut self) {
        let now = SystemTime::now();
        self.tokens.retain(|_, data| data.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_generate_and_validate() {
        let mut store = TokenStore::default();
        let token = store.generate("con", 30);
        assert_eq!(store.validate(&token, "con").unwrap(), "con");
    }

    #[test]
    fn test_wrong_scope_rejected() {
        let mut store = TokenStore::default();
        let token = store.generate("con", 30);
        assert!(store.validate(&token, "top").is_err());
    }

    #[test]
    fn test_invalid_token_rejected() {
        let store = TokenStore::default();
        assert!(store.validate("nonexistent", "con").is_err());
    }

    #[test]
    fn test_expired_token_rejected() {
        let mut store = TokenStore::default();
        // 0-minute timeout = instant expiry
        let token = store.generate("con", 0);
        // Brief sleep to ensure expiry
        sleep(Duration::from_millis(5));
        assert!(store.validate(&token, "con").is_err());
    }

    #[test]
    fn test_clear_invalidates_all() {
        let mut store = TokenStore::default();
        let t1 = store.generate("con", 30);
        let t2 = store.generate("top", 30);
        store.clear();
        assert!(store.validate(&t1, "con").is_err());
        assert!(store.validate(&t2, "top").is_err());
    }

    #[test]
    fn test_token_uniqueness() {
        let mut store = TokenStore::default();
        let t1 = store.generate("con", 30);
        let t2 = store.generate("con", 30);
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_purge_removes_expired() {
        let mut store = TokenStore::default();
        store.generate("con", 0); // expired
        sleep(Duration::from_millis(5));
        store.generate("top", 30); // valid
        store.purge_expired();
        // Only the valid token should remain
        assert_eq!(store.tokens.len(), 1);
    }
}
