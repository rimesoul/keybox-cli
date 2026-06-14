use keybox::daemon::protocol;

#[test]
fn test_roundtrip_decrypt_request() {
    let req = protocol::Request::Decrypt {
        ciphertext: vec![1, 2, 3, 4, 5],
    };
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_status_response() {
    let resp_locked = protocol::Response::Status { locked: true };
    let data = protocol::serialize_response(&resp_locked).expect("serialize should succeed");
    let recovered = protocol::deserialize_response(&data).expect("deserialize should succeed");
    assert_eq!(recovered, resp_locked);

    let resp_unlocked = protocol::Response::Status { locked: false };
    let data = protocol::serialize_response(&resp_unlocked).expect("serialize should succeed");
    let recovered = protocol::deserialize_response(&data).expect("deserialize should succeed");
    assert_eq!(recovered, resp_unlocked);
}

#[test]
fn test_roundtrip_unlock_request() {
    let req = protocol::Request::Unlock {
        passphrase: "my-secret-passphrase".to_string(),
    };
    let data = protocol::serialize_request(&req).expect("serialize should succeed");
    let recovered = protocol::deserialize_request(&data).expect("deserialize should succeed");
    assert_eq!(recovered, req);
}

#[test]
fn test_roundtrip_error_response() {
    let resp = protocol::Response::Error {
        message: "something went wrong".to_string(),
    };
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
