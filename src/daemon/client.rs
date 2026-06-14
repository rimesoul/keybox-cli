use crate::daemon::protocol::{Request, Response, deserialize_response, serialize_request};
use crate::tier::Tier;
use std::io::{Read, Write};
use std::path::Path;

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

#[cfg(not(unix))]
pub fn send_request(_base: &Path, _tier: Tier, _request: &Request) -> Result<Response, String> {
    Err("Daemon is not yet supported on this platform".into())
}

#[cfg(unix)]
pub fn is_daemon_running(base: &Path, tier: Tier) -> bool {
    let socket_path = tier.daemon_socket_path(base);
    std::os::unix::net::UnixStream::connect(&socket_path).is_ok()
}

#[cfg(not(unix))]
pub fn is_daemon_running(_base: &Path, _tier: Tier) -> bool {
    false
}
