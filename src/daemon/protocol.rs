use serde::{Deserialize, Serialize};
use crate::error::KeyboxError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Unlock crypt level(s): provide ROTs, get back one token with all scopes
    Unlock {
        levels: Vec<String>,            // ["con"] or ["con", "top"]
        passphrase: Option<String>,     // for con
        keyfile_path: Option<String>,   // for top
        timeout_minutes: u64,
    },
    /// Get a credential field (metadata or password)
    Get {
        domain: String,
        account: String,
        field: String,         // "password", "description", "all", etc.
        token: Option<String>, // required for password on con/top
    },
    /// List credentials (metadata only, no token needed)
    List {
        level: Option<String>,
        tag: Option<String>,
    },
    /// Lock — revoke all tokens and clear identities
    Lock,
    /// Ping — health check
    Ping,
    /// Stop the daemon process
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// Successfully unlocked, returns access token
    Unlocked { token: String, levels: Vec<String> },
    /// Credential field value (password bytes as string, description string, etc.)
    Value(String),
    /// Credential list as JSON
    ListJson(String),
    /// Daemon locked
    Locked,
    /// Pong (health check)
    Pong,
    /// Daemon shutting down
    Shutdown,
    /// Error
    Error(String),
}

pub fn serialize_request(req: &Request) -> Result<Vec<u8>, KeyboxError> {
    serde_json::to_vec(req).map_err(|e| KeyboxError::serialization("JSON serialize", e))
}

pub fn deserialize_request(data: &[u8]) -> Result<Request, KeyboxError> {
    serde_json::from_slice(data).map_err(|e| KeyboxError::serialization("JSON deserialize", e))
}

pub fn serialize_response(resp: &Response) -> Result<Vec<u8>, KeyboxError> {
    serde_json::to_vec(resp).map_err(|e| KeyboxError::serialization("JSON serialize", e))
}

pub fn deserialize_response(data: &[u8]) -> Result<Response, KeyboxError> {
    serde_json::from_slice(data).map_err(|e| KeyboxError::serialization("JSON deserialize", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_unlock_roundtrip() {
        let req = Request::Unlock {
            levels: vec!["con".into()],
            passphrase: Some("hunter2".into()),
            keyfile_path: None,
            timeout_minutes: 30,
        };
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_request_get_roundtrip() {
        let req = Request::Get {
            domain: "github.com".into(),
            account: "brian".into(),
            field: "password".into(),
            token: Some("abc123".into()),
        };
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_request_list_roundtrip() {
        let req = Request::List {
            level: Some("secret".into()),
            tag: None,
        };
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_request_lock_roundtrip() {
        let req = Request::Lock;
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_request_ping_roundtrip() {
        let req = Request::Ping;
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_response_unlocked_roundtrip() {
        let resp = Response::Unlocked {
            token: "tok_abc".into(),
            levels: vec!["con".into()],
        };
        let data = serialize_response(&resp).unwrap();
        let parsed = deserialize_response(&data).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn test_response_error_roundtrip() {
        let resp = Response::Error("something went wrong".into());
        let data = serialize_response(&resp).unwrap();
        let parsed = deserialize_response(&data).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn test_response_value_roundtrip() {
        let resp = Response::Value("plaintext_secret".into());
        let data = serialize_response(&resp).unwrap();
        let parsed = deserialize_response(&data).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn test_response_listjson_roundtrip() {
        let resp = Response::ListJson(r#"[{"id":"1","domain":"x.com"}]"#.into());
        let data = serialize_response(&resp).unwrap();
        let parsed = deserialize_response(&data).unwrap();
        assert_eq!(resp, parsed);
    }

    #[test]
    fn test_deserialize_unknown_variant() {
        let data = br#""UnknownVariant""#;
        let result = deserialize_request(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_stop_roundtrip() {
        let req = Request::Stop;
        let data = serialize_request(&req).unwrap();
        let parsed = deserialize_request(&data).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_response_shutdown_roundtrip() {
        let resp = Response::Shutdown;
        let data = serialize_response(&resp).unwrap();
        let parsed = deserialize_response(&data).unwrap();
        assert_eq!(resp, parsed);
    }
}
