/// Structured error type for keybox. Replaces the ad-hoc `Result<_, String>`
/// used throughout the codebase. Callers can `match` on variants instead of
/// string-matching error messages.
///
/// # Migration guide
///
/// During migration from `Result<_, String>`, use the convenience constructors:
///
/// ```ignore
/// // Before: fs::read(path).map_err(|e| format!("Failed to read: {}", e))
/// // After:  fs::read(path).map_err(|e| KeyboxError::io("reading file", e))
/// ```
#[derive(Debug, thiserror::Error)]
pub enum KeyboxError {
    /// File-system and binary-format errors: I/O failures, bad magic,
    /// version mismatch, key_ref mismatch, corrupted keystore.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// Cryptographic failures: AES-GCM, age, passphrase/keyfile decryption,
    /// platform protector (Keychain / DPAPI / machine-id), CSPRNG.
    #[error("{context}")]
    Crypto { context: String },

    /// An entity was not found: credential, keystore (not initialized),
    /// crypt level / keypair (not initialized), unknown protector.
    #[error("{entity} not found: {detail}")]
    NotFound {
        entity: String,
        detail: String,
    },

    /// User input validation failure: empty secret, missing required flag,
    /// unknown field / level / format, password mismatch.
    #[error("{what}")]
    Input { what: String },

    /// JSON serialization/deserialization or Base64 encode/decode failure.
    #[error("{direction} error")]
    Serialization {
        direction: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Daemon IPC failure: connect, send, read, unexpected response.
    #[error("{context}")]
    Daemon { context: String },

    /// Token validation failure: invalid, expired, insufficient scope.
    #[error("token {reason}")]
    Token { reason: String },

    /// Interactive mode unavailable: stdin not a TTY, LLM calling mode
    /// detected, or read failure during prompts.
    #[error("{reason}")]
    Interactive { reason: String },
}

// ── Convenience constructors ─────────────────────────────────────────

impl KeyboxError {
    /// File-system / I/O error with context (e.g. "reading keystore").
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// Cryptographic error (no source needed for most cases).
    pub fn crypto(context: impl Into<String>) -> Self {
        Self::Crypto {
            context: context.into(),
        }
    }

    /// Entity-not-found error.
    ///
    /// `entity` is the type of thing (e.g. "credential", "level 'con'")
    /// `detail` is the specific identifier or hint (e.g. "github.com:brian",
    /// "Run 'keybox init --level con' first").
    pub fn not_found(entity: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::NotFound {
            entity: entity.into(),
            detail: detail.into(),
        }
    }

    /// Invalid user input.
    pub fn input(what: impl Into<String>) -> Self {
        Self::Input {
            what: what.into(),
        }
    }

    /// Serialization / deserialization error.
    pub fn serialization(
        direction: &'static str,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Serialization {
            direction,
            source: Some(Box::new(source)),
        }
    }

    /// Daemon IPC error.
    pub fn daemon(context: impl Into<String>) -> Self {
        Self::Daemon {
            context: context.into(),
        }
    }

    /// Token validation error.
    pub fn token(reason: impl Into<String>) -> Self {
        Self::Token {
            reason: reason.into(),
        }
    }

    /// Interactive-mode error.
    pub fn interactive(reason: impl Into<String>) -> Self {
        Self::Interactive {
            reason: reason.into(),
        }
    }
}

// ── Temporary: allows main.rs / server.rs to use ? while they still ─
// ── return Result<_, String>. Remove once Step 4 is complete.       ──

impl From<KeyboxError> for String {
    fn from(e: KeyboxError) -> Self {
        e.to_string()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_error_display_includes_context_and_source() {
        let err = KeyboxError::io(
            "reading keystore",
            std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        );
        let msg = err.to_string();
        assert!(msg.contains("reading keystore"));
        assert!(msg.contains("no such file"));
    }

    #[test]
    fn test_not_found_display() {
        let err = KeyboxError::not_found("credential", "github.com:brian");
        assert_eq!(err.to_string(), "credential not found: github.com:brian");
    }

    #[test]
    fn test_input_display() {
        let err = KeyboxError::input("length must be at least 1");
        assert_eq!(err.to_string(), "length must be at least 1");
    }

    #[test]
    fn test_crypto_display() {
        let err = KeyboxError::crypto("wrong passphrase");
        assert_eq!(err.to_string(), "wrong passphrase");
    }

    #[test]
    fn test_token_display() {
        let err = KeyboxError::token("expired. Run keybox unlock.");
        assert_eq!(err.to_string(), "token expired. Run keybox unlock.");
    }

    #[test]
    fn test_serialization_json_error() {
        // Simulate a serde_json error
        let bad_json = r#"{"version: 1}"#; // missing closing quote
        let result: Result<serde_json::Value, _> = serde_json::from_str(bad_json);
        let err = KeyboxError::serialization("JSON parse", result.unwrap_err());
        assert!(err.to_string().contains("JSON parse error"));
    }
}
