use crate::daemon::protocol::{Request, Response, deserialize_response, serialize_request};
use crate::tier::Tier;
use std::io::{Read, Write};
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FlushFileBuffers,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, HANDLE, GENERIC_READ, GENERIC_WRITE};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(unix)]
pub fn send_request(base: &Path, tier: Tier, request: &Request) -> Result<Response, String> {
    let socket_path = tier.daemon_socket_path(base);
    let mut stream = std::os::unix::net::UnixStream::connect(&socket_path)
        .map_err(|e| format!("Failed to connect to daemon at {}: {}. Is the daemon running? Run 'keybox --{} serve'.", socket_path.display(), e, tier.dir_name()))?;
    let data = serialize_request(request)?;
    stream
        .write_all(&data)
        .map_err(|e| format!("Failed to send: {}", e))?;
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("Failed to read: {}", e))?;
    buf.truncate(n);
    deserialize_response(&buf)
}

#[cfg(windows)]
pub fn send_request(base: &Path, tier: Tier, request: &Request) -> Result<Response, String> {
    let pipe_name = format!(r"\\.\pipe\keyboxd-{}", tier.dir_name());
    let pipe_name_wide: Vec<u16> = OsStr::new(&pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            pipe_name_wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            3, // OPEN_EXISTING
            0,
            0,
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Failed to connect to daemon at {}. Is the daemon running? Run 'keybox --{} serve'.",
            pipe_name,
            tier.dir_name()
        ));
    }

    let data = serialize_request(request)?;
    let mut bytes_written: u32 = 0;
    unsafe {
        WriteFile(handle, data.as_ptr() as *const std::ffi::c_void, data.len() as u32, &mut bytes_written, std::ptr::null_mut());
        FlushFileBuffers(handle);
    }

    let mut buf = vec![0u8; 65536];
    let mut bytes_read: u32 = 0;
    unsafe {
        ReadFile(handle, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len() as u32, &mut bytes_read, std::ptr::null_mut());
        CloseHandle(handle);
    }

    buf.truncate(bytes_read as usize);
    if buf.is_empty() {
        return Err("Daemon closed connection without response".into());
    }
    deserialize_response(&buf)
}

#[cfg(windows)]
pub fn is_daemon_running(base: &Path, tier: Tier) -> bool {
    let pipe_name = format!(r"\\.\pipe\keyboxd-{}", tier.dir_name());
    let pipe_name_wide: Vec<u16> = OsStr::new(&pipe_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            pipe_name_wide.as_ptr(),
            GENERIC_READ,
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
pub fn is_daemon_running(base: &Path, tier: Tier) -> bool {
    let socket_path = tier.daemon_socket_path(base);
    std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
}
