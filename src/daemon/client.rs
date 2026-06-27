use crate::daemon::protocol::{Request, Response, deserialize_response, serialize_request};
use crate::error::KeyboxError;
use std::io::{Read, Write};
use std::path::Path;

/// Send a request to the daemon and receive a response.
/// Uses Unix socket on Unix, named pipe on Windows.
#[cfg(unix)]
pub fn send_request(base: &Path, request: &Request) -> Result<Response, KeyboxError> {
    let socket_path = base.join("keyboxd.sock");
    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
        .map_err(|e| KeyboxError::daemon(format!(
            "Failed to connect to daemon at {}: {}. Is the daemon running? Run 'keybox serve'.",
            socket_path.display(), e
        )))?;
    let data = serialize_request(request)?;
    stream
        .write_all(&data)
        .map_err(|e| KeyboxError::daemon(format!("Failed to send: {}", e)))?;
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .map_err(|e| KeyboxError::daemon(format!("Failed to read: {}", e)))?;
    buf.truncate(n);
    deserialize_response(&buf)
}

#[cfg(windows)]
pub fn send_request(base: &Path, request: &Request) -> Result<Response, KeyboxError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Storage::FileSystem::CreateFileW;
    use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE};

    let pipe_name = r"\\.\pipe\keyboxd";
    let pipe_name_wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            pipe_name_wide.as_ptr(),
            0xC0000000 | 0x40000000, // GENERIC_READ | GENERIC_WRITE
            0,
            std::ptr::null(),
            3, // OPEN_EXISTING
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(KeyboxError::daemon(format!(
            "Failed to connect to daemon at {}. Is the daemon running? Run 'keybox serve'.",
            pipe_name
        )));
    }

    let mut pipe = unsafe { std::fs::File::from_raw_handle(handle as *mut std::ffi::c_void) };

    let data = serialize_request(request)?;
    pipe.write_all(&data).map_err(|e| KeyboxError::daemon(format!("Failed to send: {}", e)))?;
    pipe.flush().map_err(|e| KeyboxError::daemon(format!("Failed to flush: {}", e)))?;

    let mut buf = vec![0u8; 65536];
    let n = pipe.read(&mut buf).map_err(|e| KeyboxError::daemon(format!("Failed to read: {}", e)))?;
    if n == 0 {
        return Err(KeyboxError::daemon("Daemon closed connection without response"));
    }

    buf.truncate(n);
    deserialize_response(&buf)
}

/// Check if the daemon is running by attempting a connection.
#[cfg(windows)]
pub fn is_daemon_running(base: &Path) -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CreateFileW;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    let pipe_name = r"\\.\pipe\keyboxd";
    let pipe_name_wide: Vec<u16> = OsStr::new(pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            pipe_name_wide.as_ptr(),
            0x80000000, // GENERIC_READ
            0,
            std::ptr::null(),
            3, // OPEN_EXISTING
            0,
            0,
        )
    };

    if handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
        true
    } else {
        false
    }
}

#[cfg(unix)]
pub fn is_daemon_running(base: &Path) -> bool {
    let socket_path = base.join("keyboxd.sock");
    std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
}

// ── Convenience methods matching the new protocol ────────────────────

/// Send an Unlock request to the daemon.
pub fn unlock(
    base: &Path,
    levels: &[String],
    passphrase: Option<&str>,
    keyfile_path: Option<&str>,
    timeout_minutes: u64,
) -> Result<Response, KeyboxError> {
    send_request(base, &Request::Unlock {
        levels: levels.to_vec(),
        passphrase: passphrase.map(|s| s.to_string()),
        keyfile_path: keyfile_path.map(|s| s.to_string()),
        timeout_minutes,
    })
}

/// Send a Get request to the daemon.
pub fn get(
    base: &Path,
    domain: &str,
    account: &str,
    field: &str,
    token: Option<&str>,
) -> Result<Response, KeyboxError> {
    send_request(base, &Request::Get {
        domain: domain.to_string(),
        account: account.to_string(),
        field: field.to_string(),
        token: token.map(|s| s.to_string()),
    })
}

/// Send a List request to the daemon.
pub fn list(
    base: &Path,
    level: Option<&str>,
    tag: Option<&str>,
) -> Result<Response, KeyboxError> {
    send_request(base, &Request::List {
        level: level.map(|s| s.to_string()),
        tag: tag.map(|s| s.to_string()),
    })
}

/// Send a Lock request to the daemon.
pub fn lock(base: &Path) -> Result<Response, KeyboxError> {
    send_request(base, &Request::Lock)
}

/// Send a Ping request to check daemon health.
pub fn ping(base: &Path) -> Result<Response, KeyboxError> {
    send_request(base, &Request::Ping)
}

/// Send a Stop request to shut down the daemon.
pub fn stop(base: &Path) -> Result<Response, KeyboxError> {
    send_request(base, &Request::Stop)
}
