use std::path::Path;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::LinuxProtector;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::MacOSProtector;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::DpapiProtector;

pub trait IdentityProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String>;
    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String>;
}
