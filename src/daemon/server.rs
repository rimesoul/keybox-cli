use crate::daemon::protocol::{Request, Response, deserialize_request, serialize_response};
use crate::tier::{Tier, TierPaths};
use crate::crypto::age_ops;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, DisconnectNamedPipe,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
pub fn run_daemon(base: PathBuf, tier: Tier) -> Result<(), String> {
    let socket_path = tier.daemon_socket_path(&base);
    let _ = std::fs::remove_file(&socket_path);

    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .map_err(|e| format!("Failed to bind socket {}: {}", socket_path.display(), e))?;

    // Set 0600 permissions
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set socket permissions: {}", e))?;

    let mut state = DaemonState {
        tier,
        locked: true,
        identity: None,
        base,
    };

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buf = vec![0u8; 65536];
                match stream.read(&mut buf) {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        let response = handle_request(&buf, &mut state);
                        let resp_data = serialize_response(&response).unwrap_or_else(|e| {
                            serialize_response(&Response::Error { message: e }).unwrap()
                        });
                        let _ = stream.write_all(&resp_data);
                    }
                    _ => break, // connection closed
                }
            }
            Err(_) => break,
        }
    }

    // Clean up socket on exit
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

struct DaemonState {
    tier: Tier,
    locked: bool,
    identity: Option<age::x25519::Identity>,
    base: PathBuf,
}

fn handle_request(data: &[u8], state: &mut DaemonState) -> Response {
    let request = match deserialize_request(data) {
        Ok(req) => req,
        Err(e) => return Response::Error { message: e },
    };

    match request {
        Request::Status => Response::Status { locked: state.locked },
        Request::Decrypt { ciphertext } => {
            if state.locked || state.identity.is_none() {
                return Response::Error {
                    message: "Daemon is locked. Use 'keybox unlock' first.".into(),
                };
            }
            let ident = state.identity.as_ref().unwrap();
            match age_ops::decrypt_with_identity(ident, &ciphertext) {
                Ok(pt) => Response::Decrypted { plaintext: pt },
                Err(e) => Response::Error {
                    message: format!("Decrypt failed: {}", e),
                },
            }
        }
        Request::Unlock { passphrase } => unlock_with_passphrase(state, &passphrase),
        Request::UnlockWithFile { key_content } => unlock_with_file(state, &key_content),
        Request::Lock => {
            state.identity = None;
            state.locked = true;
            Response::Ok
        }
    }
}

fn unlock_with_passphrase(state: &mut DaemonState, passphrase: &str) -> Response {
    let paths = TierPaths::from_base(&state.base, state.tier);
    let encrypted = match std::fs::read(&paths.private_key) {
        Ok(d) => d,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to read identity: {}", e),
            }
        }
    };

    // Use age passphrase decryptor
    let decryptor = match age::Decryptor::new(&encrypted[..]) {
        Ok(d) => d,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to parse identity: {}", e),
            }
        }
    };

    match decryptor {
        age::Decryptor::Passphrase(d) => {
            let secret = age::secrecy::Secret::new(passphrase.to_string());
            match d.decrypt(&secret, None) {
                Ok(mut reader) => {
                    let mut s = String::new();
                    use std::io::Read;
                    if reader.read_to_string(&mut s).is_err() {
                        return Response::Error {
                            message: "Failed to read identity".into(),
                        };
                    }
                    match age::x25519::Identity::from_str(s.trim()) {
                        Ok(id) => {
                            state.identity = Some(id);
                            state.locked = false;
                            Response::Ok
                        }
                        Err(e) => Response::Error {
                            message: format!("Invalid identity: {}", e),
                        },
                    }
                }
                Err(_) => Response::Error {
                    message: "Invalid passphrase".into(),
                },
            }
        }
        _ => Response::Error {
            message: "Identity is not passphrase-encrypted".into(),
        },
    }
}

fn unlock_with_file(state: &mut DaemonState, key_content: &[u8]) -> Response {
    use sha2::{Digest, Sha256};
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};

    let paths = TierPaths::from_base(&state.base, state.tier);
    let mut hasher = Sha256::new();
    hasher.update(b"keybox-top-v1");
    hasher.update(key_content);
    let aes_key = hasher.finalize();

    let encrypted = match std::fs::read(&paths.private_key) {
        Ok(d) => d,
        Err(e) => {
            return Response::Error {
                message: format!("Failed to read: {}", e),
            }
        }
    };

    if encrypted.len() < NONCE_LEN {
        return Response::Error {
            message: "Corrupted identity file".into(),
        };
    }
    let nonce_len: usize = NONCE_LEN;
    let (nonce_bytes, ciphertext) = encrypted.split_at(nonce_len);
    let unbound_key = match UnboundKey::new(&AES_256_GCM, &aes_key) {
        Ok(k) => k,
        Err(e) => {
            return Response::Error {
                message: format!("Invalid key: {}", e),
            }
        }
    };
    let key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
    let mut in_out = ciphertext.to_vec();

    match key.open_in_place(nonce, Aad::empty(), &mut in_out) {
        Ok(pt) => {
            let s = String::from_utf8_lossy(pt);
            match age::x25519::Identity::from_str(s.trim()) {
                Ok(id) => {
                    state.identity = Some(id);
                    state.locked = false;
                    Response::Ok
                }
                Err(e) => Response::Error {
                    message: format!("Invalid identity: {}", e),
                },
            }
        }
        Err(_) => Response::Error {
            message: "Invalid key file: decryption failed".into(),
        },
    }
}

#[cfg(windows)]
pub fn run_daemon(base: PathBuf, tier: Tier) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;

    // FFI declarations for Windows APIs not yet in windows-sys 0.52
    extern "system" {
        fn ConnectNamedPipe(hNamedPipe: isize, lpOverlapped: *mut std::ffi::c_void) -> i32;
    }

    let pipe_name = format!(r"\\.\pipe\keyboxd-{}", tier.dir_name());
    let pipe_name_wide: Vec<u16> = OsStr::new(&pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut state = DaemonState {
        tier,
        locked: true,
        identity: None,
        base,
    };

    loop {
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
            // ERROR_PIPE_CONNECTED = 535
            if err != 535 {
                unsafe { CloseHandle(handle) };
                return Err(format!("ConnectNamedPipe failed: {}", err));
            }
        }

        let mut pipe = unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void as _) };

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
            let response = handle_request(&buf, &mut state);
            let resp_data = serialize_response(&response).unwrap_or_else(|e| {
                serialize_response(&Response::Error { message: e }).unwrap()
            });
            let _ = pipe.write_all(&resp_data);
            let _ = pipe.flush();
        }

        unsafe {
            DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }

        if state.identity.is_some() {
            continue;
        }
    }
    Ok(())
}
