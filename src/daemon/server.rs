use crate::daemon::protocol::{Request, Response, deserialize_request, serialize_response};
use crate::daemon::token::TokenStore;
use crate::keystore::ops;
use crate::keystore::schema::KeyStore;
use crate::crypto::age_ops;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

// ── Base64 helpers (mirrors ops.rs private helpers) ──────────────────

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("Base64 decode: {}", e))
}

// ── Passphrase-based decryption (for con level identity) ─────────────

fn decrypt_with_passphrase(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let decryptor = age::Decryptor::new(encrypted)
        .map_err(|e| format!("Age decrypt: {}", e))?;
    let decryptor = match decryptor {
        age::Decryptor::Passphrase(d) => d,
        _ => return Err("Not a passphrase-encrypted identity".into()),
    };
    let mut reader = decryptor
        .decrypt(&age::secrecy::Secret::new(passphrase.to_string()), None)
        .map_err(|_| "Wrong passphrase".to_string())?;
    let mut plaintext = vec![];
    reader.read_to_end(&mut plaintext)
        .map_err(|e| format!("Read: {}", e))?;
    Ok(plaintext)
}

// ── Keyfile-based AES-GCM decryption (for top level identity) ────────

fn derive_key_from_file(file_content: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"keybox-top-v1");
    hasher.update(file_content);
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    key
}

fn decrypt_with_aes_gcm_keyfile(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    const NONCE_LEN: usize = 12;

    if encrypted.len() < NONCE_LEN + 16 {
        return Err("Identity ciphertext too short".into());
    }
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("Bad key: {}", e))?;
    let lk = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&encrypted[..NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = encrypted[NONCE_LEN..].to_vec();
    lk.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed — wrong key file or corrupted identity".to_string())?;
    Ok(in_out)
}

// ── Secret identity resolution (auto-loaded at startup) ──────────────

#[cfg(target_os = "macos")]
fn resolve_secret_identity(base: &Path) -> Result<age::x25519::Identity, String> {
    use crate::protect::MacOSProtector;
    use crate::protect::IdentityProtector;
    let marker = base.join("secret").join("id.marker");
    let identity_bytes = MacOSProtector::new().unprotect(&marker)?;
    let identity_str = String::from_utf8_lossy(&identity_bytes);
    age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|e| format!("Failed to parse secret identity: {}", e))
}

#[cfg(not(target_os = "macos"))]
fn resolve_secret_identity(base: &Path) -> Result<age::x25519::Identity, String> {
    let id_path = base.join("secret").join("identity");
    let identity_bytes = std::fs::read(&id_path)
        .map_err(|e| format!("Failed to read secret identity: {}", e))?;
    let identity_str = String::from_utf8_lossy(&identity_bytes);
    age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|e| format!("Failed to parse secret identity: {}", e))
}

// ── Daemon state ─────────────────────────────────────────────────────

pub struct DaemonState {
    pub base: PathBuf,
    pub store: KeyStore,
    pub aes_key: Vec<u8>,
    pub tokens: TokenStore,
    /// Decrypted age identities: tier ("con" | "top") → Identity
    pub identities: HashMap<String, age::x25519::Identity>,
    /// Set to false to exit the daemon loop
    pub running: bool,
}

impl DaemonState {
    pub fn new(base: PathBuf) -> Result<Self, String> {
        let keystore_path = ops::keystore_path(&base);
        if !keystore_path.exists() {
            return Err("Keystore not initialized. Run 'keybox init' first.".into());
        }
        let aes_key = load_aes_key(&base)?;
        let store = ops::load_store(&keystore_path, &aes_key)?;

        // Auto-load secret identity (no unlock/token needed)
        let mut identities = HashMap::new();
        if store.key_pairs.contains_key("secret") {
            let secret_id = resolve_secret_identity(&base)?;
            identities.insert("secret".to_string(), secret_id);
        }

        Ok(DaemonState {
            base,
            store,
            aes_key: aes_key.to_vec(),
            tokens: TokenStore::default(),
            identities,
            running: true,
        })
    }

    pub fn handle_request(&mut self, request: Request) -> Response {
        match request {
            Request::Unlock { level, passphrase, keyfile_path, timeout_minutes } => {
                self.handle_unlock(&level, passphrase.as_deref(), keyfile_path.as_deref(), timeout_minutes)
            }
            Request::Get { domain, account, field, token } => {
                self.handle_get(&domain, &account, &field, token.as_deref())
            }
            Request::List { level, tag } => {
                self.handle_list(level.as_deref(), tag.as_deref())
            }
            Request::Lock => self.handle_lock(),
            Request::Ping => Response::Pong,
            Request::Stop => {
                self.handle_lock();
                self.running = false;
                Response::Shutdown
            }
        }
    }

    fn handle_unlock(
        &mut self,
        level: &str,
        passphrase: Option<&str>,
        keyfile_path: Option<&str>,
        timeout_minutes: u64,
    ) -> Response {
        let kp = match self.store.key_pairs.get(level) {
            Some(k) => k,
            None => return Response::Error(format!(
                "Level '{}' not initialized. Run 'keybox init --level {}' first.",
                level, level
            )),
        };

        let identity_bytes = match level {
            "con" => {
                let pp = match passphrase {
                    Some(p) => p,
                    None => return Response::Error("Passphrase required for con level".into()),
                };
                let encrypted = match b64_decode(&kp.encrypted_private_key) {
                    Ok(e) => e,
                    Err(e) => return Response::Error(e),
                };
                match decrypt_with_passphrase(&encrypted, pp) {
                    Ok(b) => b,
                    Err(e) => return Response::Error(e),
                }
            }
            "top" => {
                let path = match keyfile_path {
                    Some(p) => p,
                    None => return Response::Error("Key file path required for top level".into()),
                };
                let file_content = match std::fs::read(path) {
                    Ok(c) => c,
                    Err(e) => return Response::Error(format!("Failed to read key file: {}", e)),
                };
                if file_content.is_empty() {
                    return Response::Error("Key file is empty".into());
                }
                let aes_key = derive_key_from_file(&file_content);
                let encrypted = match b64_decode(&kp.encrypted_private_key) {
                    Ok(e) => e,
                    Err(e) => return Response::Error(e),
                };
                match decrypt_with_aes_gcm_keyfile(&encrypted, &aes_key) {
                    Ok(b) => b,
                    Err(e) => return Response::Error(e),
                }
            }
            _ => return Response::Error(format!("Unknown level: {}", level)),
        };

        let identity_str = String::from_utf8_lossy(&identity_bytes);
        let identity = match age::x25519::Identity::from_str(identity_str.trim()) {
            Ok(id) => id,
            Err(e) => return Response::Error(format!("Invalid identity: {}", e)),
        };

        self.identities.insert(level.to_string(), identity);

        let token = self.tokens.generate(level, timeout_minutes);
        Response::Unlocked { token, level: level.to_string() }
    }

    fn handle_get(
        &self,
        domain: &str,
        account: &str,
        field: &str,
        token: Option<&str>,
    ) -> Response {
        let key = KeyStore::credential_key(domain, account);
        let cred = match self.store.credentials.get(&key) {
            Some(c) => c,
            None => return Response::Error(format!("Credential not found: {}", key)),
        };

        let level_str = cred.crypt_level.as_str();

        match field {
            "password" | "secret" => {
                // For con/top: require token
                if level_str != "secret" {
                    let t = match token {
                        Some(t) => t,
                        None => return Response::Error("Token required for con/top access".into()),
                    };
                    if let Err(e) = self.tokens.validate(t, level_str) {
                        return Response::Error(e);
                    }
                }
                // Get identity for decryption
                let identity = match self.identities.get(level_str) {
                    Some(id) => id,
                    None => return Response::Error(format!(
                        "{} level not unlocked. Run 'keybox unlock --level {}' first.",
                        level_str, level_str
                    )),
                };
                // Decrypt the secret
                let ciphertext = match b64_decode(&cred.secret) {
                    Ok(c) => c,
                    Err(e) => return Response::Error(e),
                };
                let plaintext = match age_ops::decrypt_with_identity(identity, &ciphertext) {
                    Ok(p) => p,
                    Err(e) => return Response::Error(format!("Age decryption failed: {}", e)),
                };
                Response::Value(String::from_utf8_lossy(&plaintext).to_string())
            }
            "description" => {
                Response::Value(cred.description.clone().unwrap_or_default())
            }
            "domain" => {
                Response::Value(cred.domain.clone())
            }
            "account" => {
                Response::Value(cred.account.clone())
            }
            "tags" => {
                Response::Value(cred.tags.join(", "))
            }
            "all" => {
                let mut c = cred.clone();
                c.secret = "<masked>".to_string();
                Response::Value(serde_json::to_string(&c).unwrap_or_default())
            }
            _ => Response::Error(format!("Unknown field: {}", field)),
        }
    }

    fn handle_list(&self, level: Option<&str>, tag: Option<&str>) -> Response {
        let mut results: Vec<_> = self.store.credentials.values()
            .filter(|c| {
                let l_ok = level.is_none_or(|l| c.crypt_level.as_str() == l);
                let t_ok = tag.is_none_or(|t| c.tags.contains(&t.to_string()));
                l_ok && t_ok
            })
            .map(|c| {
                let mut masked = c.clone();
                masked.secret = "<masked>".to_string();
                masked
            })
            .collect();
        results.sort_by(|a, b| {
            let ka = format!("{}:{}", a.domain, a.account);
            let kb = format!("{}:{}", b.domain, b.account);
            ka.cmp(&kb)
        });
        Response::ListJson(serde_json::to_string(&results).unwrap_or_default())
    }

    fn handle_lock(&mut self) -> Response {
        self.tokens.clear();
        // Only clear con/top identities (secret is auto-loaded, no token needed)
        self.identities.retain(|k, _| k == "secret");
        Response::Locked
    }
}

// ── AES key loading (platform-protected) ─────────────────────────────

fn aes_key_path(base: &Path) -> PathBuf {
    base.join("secret").join("aes.key")
}

#[cfg(target_os = "macos")]
fn load_aes_key(base: &Path) -> Result<Vec<u8>, String> {
    use crate::protect::MacOSProtector;
    use crate::protect::IdentityProtector;
    let path = aes_key_path(base);
    if !path.exists() {
        return Err("AES key not found. Run 'keybox init' first.".into());
    }
    MacOSProtector::new().unprotect(&path)
}

#[cfg(not(target_os = "macos"))]
fn load_aes_key(base: &Path) -> Result<Vec<u8>, String> {
    let path = aes_key_path(base);
    if !path.exists() {
        return Err("AES key not found. Run 'keybox init' first.".into());
    }
    std::fs::read(&path).map_err(|e| format!("Failed to read AES key: {}", e))
}

// ── Unix daemon ──────────────────────────────────────────────────────

#[cfg(unix)]
pub fn run_daemon(base: PathBuf) -> Result<(), String> {
    let socket_path = base.join("keyboxd.sock");
    let _ = std::fs::remove_file(&socket_path);

    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .map_err(|e| format!("Failed to bind socket {}: {}", socket_path.display(), e))?;

    // Set 0600 permissions
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set socket permissions: {}", e))?;

    let mut state = DaemonState::new(base)?;

    for stream in listener.incoming() {
        if !state.running {
            break;
        }
        match stream {
            Ok(mut stream) => {
                let mut buf = vec![0u8; 65536];
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        let response = handle_raw_request(&buf, &mut state);
                        let resp_data = serialize_response(&response).unwrap_or_else(|e| {
                            serialize_response(&Response::Error(e)).unwrap()
                        });
                        let _ = stream.write_all(&resp_data);
                    }
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }

    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

// ── Windows daemon ───────────────────────────────────────────────────

#[cfg(windows)]
pub fn run_daemon(base: PathBuf) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, DisconnectNamedPipe};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    extern "system" {
        fn ConnectNamedPipe(hNamedPipe: isize, lpOverlapped: *mut std::ffi::c_void) -> i32;
    }

    let pipe_name = r"\\.\pipe\keyboxd";
    let pipe_name_wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut state = DaemonState::new(base)?;

    loop {
        if !state.running {
            break;
        }
        let handle = unsafe {
            CreateNamedPipeW(
                pipe_name_wide.as_ptr(),
                3, // PIPE_ACCESS_DUPLEX
                0, // PIPE_TYPE_BYTE | PIPE_READMODE_BYTE
                1,
                65536,
                65536,
                0,
                std::ptr::null(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err("Failed to create named pipe".into());
        }

        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err != 535 {
                // ERROR_PIPE_CONNECTED
                unsafe { CloseHandle(handle) };
                return Err(format!("ConnectNamedPipe failed: {}", err));
            }
        }

        let mut pipe =
            unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void as _) };

        let mut buf = vec![0u8; 65536];
        let n = match pipe.read(&mut buf) {
            Ok(n) => n,
            Err(_) => {
                unsafe { DisconnectNamedPipe(handle) };
                unsafe { CloseHandle(handle) };
                break;
            }
        };

        if n > 0 {
            buf.truncate(n);
            let response = handle_raw_request(&buf, &mut state);
            let resp_data = serialize_response(&response).unwrap_or_else(|e| {
                serialize_response(&Response::Error(e)).unwrap()
            });
            let _ = pipe.write_all(&resp_data);
            let _ = pipe.flush();
        }

        unsafe {
            DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }
    }
    Ok(())
}

// ── Request dispatcher (common to both platforms) ────────────────────

fn handle_raw_request(data: &[u8], state: &mut DaemonState) -> Response {
    let request = match deserialize_request(data) {
        Ok(req) => req,
        Err(e) => return Response::Error(e),
    };
    state.handle_request(request)
}

// ── Socket path for clients ──────────────────────────────────────────

pub fn daemon_socket_path(base: &std::path::Path) -> PathBuf {
    base.join("keyboxd.sock")
}
