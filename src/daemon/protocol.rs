use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    Status,
    Decrypt { ciphertext: Vec<u8> },
    Unlock { passphrase: String },
    UnlockWithFile { key_content: Vec<u8> },
    Lock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Status { locked: bool },
    Decrypted { plaintext: Vec<u8> },
    Ok,
    Error { message: String },
}

pub fn serialize_request(req: &Request) -> Result<Vec<u8>, String> {
    serde_json::to_vec(req).map_err(|e| format!("Serialize error: {}", e))
}

pub fn deserialize_request(data: &[u8]) -> Result<Request, String> {
    serde_json::from_slice(data).map_err(|e| format!("Deserialize error: {}", e))
}

pub fn serialize_response(resp: &Response) -> Result<Vec<u8>, String> {
    serde_json::to_vec(resp).map_err(|e| format!("Serialize error: {}", e))
}

pub fn deserialize_response(data: &[u8]) -> Result<Response, String> {
    serde_json::from_slice(data).map_err(|e| format!("Deserialize error: {}", e))
}
