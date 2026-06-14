use crate::protect::IdentityProtector;
use std::fs;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
};

pub struct DpapiProtector;

impl Default for DpapiProtector {
    fn default() -> Self {
        Self
    }
}

impl DpapiProtector {
    pub fn new() -> Self {
        Self
    }
}

impl IdentityProtector for DpapiProtector {
    fn protect(&self, data: &[u8], path: &Path) -> Result<(), String> {
        let encrypted = dpapi_encrypt(data)?;
        fs::write(path, &encrypted)
            .map_err(|e| format!("Failed to write protected file: {}", e))
    }

    fn unprotect(&self, path: &Path) -> Result<Vec<u8>, String> {
        let encrypted = fs::read(path)
            .map_err(|e| format!("Failed to read protected file: {}", e))?;
        dpapi_decrypt(&encrypted)
    }
}

fn dpapi_encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptProtectData(
            &mut in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        )
    };

    if result == 0 {
        return Err("CryptProtectData failed".to_string());
    }

    let encrypted = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as isize);
        vec
    };

    Ok(encrypted)
}

fn dpapi_decrypt(encrypted: &[u8]) -> Result<Vec<u8>, String> {
    let mut in_blob = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut u8,
    };

    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };

    let result = unsafe {
        CryptUnprotectData(
            &mut in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };

    if result == 0 {
        return Err("CryptUnprotectData failed".to_string());
    }

    let decrypted = unsafe {
        let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(out_blob.pbData as isize);
        vec
    };

    Ok(decrypted)
}
