use keybox::daemon::protocol;

#[test]
fn test_roundtrip_unlock_request() {
    let req = protocol::Request::Unlock {
        level: "con".to_string(),
        passphrase: Some("my-secret-passphrase".to_string()),
        keyfile_path: None,
        timeout_minutes: 30,
    };
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_get_request() {
    let req = protocol::Request::Get {
        domain: "example.com".to_string(),
        account: "admin".to_string(),
        field: "password".to_string(),
        token: Some("tok123".to_string()),
    };
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_list_request() {
    let req = protocol::Request::List {
        level: Some("secret".to_string()),
        tag: None,
    };
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_lock_request() {
    let req = protocol::Request::Lock;
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_unlocked_response() {
    let resp = protocol::Response::Unlocked {
        token: "abc123".to_string(),
        level: "con".to_string(),
    };
    let data = protocol::serialize_response(&resp).expect("serialize should succeed");
    let recovered = protocol::deserialize_response(&data).expect("deserialize should succeed");
    assert_eq!(recovered, resp);
}

#[test]
fn test_roundtrip_value_response() {
    let resp = protocol::Response::Value("plaintext_secret".to_string());
    let data = protocol::serialize_response(&resp).expect("serialize should succeed");
    let recovered = protocol::deserialize_response(&data).expect("deserialize should succeed");
    assert_eq!(recovered, resp);
}

#[test]
fn test_roundtrip_error_response() {
    let resp = protocol::Response::Error("something went wrong".to_string());
    let data = protocol::serialize_response(&resp).expect("serialize should succeed");
    let recovered = protocol::deserialize_response(&data).expect("deserialize should succeed");
    assert_eq!(recovered, resp);
}

#[test]
fn test_deserialize_invalid_data_fails() {
    let garbage: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let result = protocol::deserialize_request(&garbage);
    assert!(
        result.is_err(),
        "deserializing garbage should fail, got: {:?}",
        result
    );

    let result = protocol::deserialize_response(&garbage);
    assert!(
        result.is_err(),
        "deserializing garbage response should fail, got: {:?}",
        result
    );
}
