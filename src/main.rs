use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use clap::Parser;
use age::secrecy::ExposeSecret;
use keybox::cli::{Cli, Command, GenerateArgs, UpdateSub};
use keybox::crypto::age_ops;
use keybox::generate;
use keybox::interactive;
use keybox::keystore::ops;
use keybox::keystore::schema::{CryptLevel, KeyPair, KeyStore};
use keybox::protect::IdentityProtector;

#[cfg(target_os = "macos")]
use keybox::protect::MacOSProtector;

// ── Helpers: resolve_base, parse_target, keystore paths ─────────────

fn resolve_base(base_opt: Option<&str>) -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("KEYBOX_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(b) = base_opt {
        Ok(PathBuf::from(b))
    } else {
        Ok(dirs::config_dir()
            .ok_or("Cannot determine config directory")?
            .join("keybox"))
    }
}

fn parse_target(target: &str) -> (&str, &str) {
    match target.split_once(':') {
        Some((domain, account)) if !domain.is_empty() => (domain, account),
        Some((_, account)) => ("default", account),
        None => ("default", target),
    }
}

fn get_keystore_path(base: &Path) -> PathBuf {
    ops::keystore_path(base)
}

fn aes_key_path(base: &Path) -> PathBuf {
    base.join("secret").join("aes.key")
}

// ── Helpers: base64 ─────────────────────────────────────────────────

fn b64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("Base64 decode: {}", e))
}

// ── Helpers: AES key persistence (platform-protected) ───────────────

fn store_aes_key(base: &Path, key: &[u8; 32]) -> Result<(), String> {
    let path = aes_key_path(base);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    }
    store_with_protector(base, key, &path)
}

fn load_aes_key(base: &Path) -> Result<[u8; 32], String> {
    let path = aes_key_path(base);
    if !path.exists() {
        return Err("Keystore not initialized. Run 'keybox init' first.".into());
    }
    let bytes = load_with_protector(base, &path)?;
    if bytes.len() != 32 {
        return Err("AES key has wrong length".into());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Platform-specific protect/unprotect ─────────────────────────────

#[cfg(target_os = "macos")]
fn store_with_protector(_base: &Path, data: &[u8], path: &Path) -> Result<(), String> {
    let protector = MacOSProtector::new();
    protector.protect(data, path)
}

#[cfg(target_os = "macos")]
fn load_with_protector(_base: &Path, path: &Path) -> Result<Vec<u8>, String> {
    let protector = MacOSProtector::new();
    protector.unprotect(path)
}

#[cfg(not(target_os = "macos"))]
fn store_with_protector(_base: &Path, data: &[u8], path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    }
    fs::write(path, data).map_err(|e| format!("Failed to write: {}", e))
}

#[cfg(not(target_os = "macos"))]
fn load_with_protector(_base: &Path, path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("Failed to read: {}", e))
}

// ── Helper: parse crypt level string ────────────────────────────────

fn parse_level(s: Option<&str>) -> CryptLevel {
    s.and_then(|l| CryptLevel::from_str(l).ok()).unwrap_or(CryptLevel::Secret)
}

// ── Helper: copy to clipboard ───────────────────────────────────────

fn copy_to_clipboard(secret: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(secret)
        .map_err(|_| "Secret contains non-UTF8 data, cannot copy to clipboard".to_string())?;
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| format!("Clipboard error: {}", e))?;
    clipboard
        .set_text(text)
        .map_err(|e| format!("Clipboard error: {}", e))?;
    Ok(())
}

fn get_trailing_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--") {
        args[pos + 1..].to_vec()
    } else {
        vec![]
    }
}

// ── Passphrase-based encryption (for con level) ─────────────────────

fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use age::Encryptor;
    let encryptor =
        Encryptor::with_user_passphrase(age::secrecy::Secret::new(passphrase.to_string()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|_| "Encryption failed".to_string())?;
    io::Write::write_all(&mut writer, plaintext).map_err(|_| "Write failed".to_string())?;
    writer.finish().map_err(|_| "Finish failed".to_string())?;
    Ok(encrypted)
}

fn decrypt_with_passphrase(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    use age::Decryptor;
    let decryptor =
        Decryptor::new(encrypted).map_err(|e| format!("Age decrypt: {}", e))?;
    let decryptor = match decryptor {
        Decryptor::Passphrase(d) => d,
        _ => return Err("Not a passphrase-encrypted file".into()),
    };
    let mut reader = decryptor
        .decrypt(&age::secrecy::Secret::new(passphrase.to_string()), None)
        .map_err(|_| "Wrong passphrase".to_string())?;
    let mut plaintext = vec![];
    std::io::Read::read_to_end(&mut reader, &mut plaintext)
        .map_err(|e| format!("Read: {}", e))?;
    Ok(plaintext)
}

// ── Keyfile-based AES-GCM encryption (for top level) ────────────────

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

fn encrypt_with_aes_gcm_keyfile(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    use ring::rand::{SecureRandom, SystemRandom};
    const NONCE_LEN: usize = 12;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "CSPRNG failure".to_string())?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("Bad key: {}", e))?;
    let lk = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    lk.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    Ok(output)
}

fn decrypt_with_aes_gcm_keyfile(encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    const NONCE_LEN: usize = 12;

    if encrypted.len() < NONCE_LEN + 16 {
        return Err("Ciphertext too short".into());
    }
    let unbound =
        UnboundKey::new(&AES_256_GCM, key).map_err(|e| format!("Bad key: {}", e))?;
    let lk = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&encrypted[..NONCE_LEN]);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = encrypted[NONCE_LEN..].to_vec();
    lk.open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed — wrong key or corrupted data".to_string())?;
    Ok(in_out)
}

// ── Keypair initialization ──────────────────────────────────────────

/// Generate and store a keypair for the given crypt level.
fn init_keypair(
    store: &mut KeyStore,
    base: &Path,
    level: &CryptLevel,
    passphrase: Option<&str>,
    key_file: Option<&str>,
) -> Result<(), String> {
    let level_str = level.as_str();

    if store.key_pairs.contains_key(level_str) {
        return Ok(()); // already initialized
    }

    let (identity, recipient) = age_ops::generate_keypair();
    let identity_str = identity.to_string();
    let identity_bytes = identity_str.expose_secret().as_bytes();

    let (encrypted_private_key, protector_name) = match level {
        CryptLevel::Secret => {
            #[cfg(target_os = "macos")]
            {
                let protector = MacOSProtector::new();
                let marker = base.join("secret").join("id.marker");
                if let Some(parent) = marker.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create dir: {}", e))?;
                }
                // Use direct protect/unprotect (not protect_to_bytes) so the
                // Keychain account name matches between store and load.
                protector.protect(identity_bytes, &marker)?;
                // The marker content is just a constant; we store an empty
                // encrypted_private_key since the identity lives in Keychain.
                ("".to_string(), "macos".to_string())
            }
            #[cfg(not(target_os = "macos"))]
            {
                let id_path = base.join("secret").join("identity");
                if let Some(parent) = id_path.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("Failed to create dir: {}", e))?;
                }
                fs::write(&id_path, identity_bytes)
                    .map_err(|e| format!("Failed to write: {}", e))?;
                (String::new(), "file".to_string())
            }
        }
        CryptLevel::Con => {
            let pass = passphrase.ok_or("Passphrase required for confidential tier")?;
            let encrypted = encrypt_with_passphrase(identity_bytes, pass)?;
            (b64_encode(&encrypted), "passphrase".to_string())
        }
        CryptLevel::Top => {
            let key_path = key_file.ok_or("Key file required for top-secret tier")?;
            let file_content = fs::read(key_path)
                .map_err(|e| format!("Failed to read key file '{}': {}", key_path, e))?;
            if file_content.is_empty() {
                return Err("Key file is empty".into());
            }
            let aes_key = derive_key_from_file(&file_content);
            let encrypted = encrypt_with_aes_gcm_keyfile(identity_bytes, &aes_key)?;
            (b64_encode(&encrypted), "keyfile".to_string())
        }
    };

    store.key_pairs.insert(
        level_str.to_string(),
        KeyPair {
            public_key: recipient.to_string(),
            encrypted_private_key,
            protector: protector_name,
        },
    );

    Ok(())
}

// ── Identity resolution (decrypt private key for a level) ───────────

fn resolve_identity(
    base: &Path,
    aes_key: &[u8],
    level: &str,
) -> Result<age::x25519::Identity, String> {
    let kp = get_keystore_path(base);
    let store = ops::load_store(&kp, aes_key)?;
    let keypair = store
        .key_pairs
        .get(level)
        .ok_or_else(|| format!("Level '{}' not initialized. Run 'keybox init --level {}' first.", level, level))?;

    let identity_str: String = match keypair.protector.as_str() {
        "macos" | "secret" => {
            #[cfg(target_os = "macos")]
            {
                let protector = MacOSProtector::new();
                let marker = base.join("secret").join("id.marker");
                // Use direct unprotect (not unprotect_from_bytes) to match
                // the direct protect call used during init.
                let identity_bytes = protector.unprotect(&marker)?;
                String::from_utf8(identity_bytes)
                    .map_err(|_| "Identity not valid UTF-8".to_string())?
            }
            #[cfg(not(target_os = "macos"))]
            {
                let id_path = base.join("secret").join("identity");
                let identity_bytes = fs::read(&id_path)
                    .map_err(|e| format!("Failed to read identity: {}", e))?;
                String::from_utf8(identity_bytes)
                    .map_err(|_| "Identity not valid UTF-8".to_string())?
            }
        }
        "passphrase" | "con" => {
            let passphrase =
                interactive::prompt_password("Enter master passphrase for confidential tier: ")?;
            let encrypted = b64_decode(&keypair.encrypted_private_key)?;
            let identity_bytes = decrypt_with_passphrase(&encrypted, &passphrase)?;
            String::from_utf8(identity_bytes)
                .map_err(|_| "Identity not valid UTF-8".to_string())?
        }
        "keyfile" | "top" => {
            let key_path_input =
                interactive::prompt_input("Key file path for top-secret tier: ")?;
            let file_content = fs::read(&key_path_input)
                .map_err(|e| format!("Failed to read key file '{}': {}", key_path_input, e))?;
            if file_content.is_empty() {
                return Err("Key file is empty".into());
            }
            let aes_key_top = derive_key_from_file(&file_content);
            let encrypted = b64_decode(&keypair.encrypted_private_key)?;
            let identity_bytes =
                decrypt_with_aes_gcm_keyfile(&encrypted, &aes_key_top)?;
            String::from_utf8(identity_bytes)
                .map_err(|_| "Identity not valid UTF-8".to_string())?
        }
        _ => return Err(format!("Unknown protector: {}", keypair.protector)),
    };

    age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|e| format!("Failed to parse identity: {}", e))
}

// ── Open keystore (auto-create with secret tier if missing) ─────────

fn open_keystore(base: &Path) -> Result<([u8; 32], PathBuf), String> {
    let kp = get_keystore_path(base);
    if !kp.exists() {
        eprintln!("Initializing keystore...");
        let aes_key = ops::init_store(&kp)?;
        store_aes_key(base, &aes_key)?;

        let mut store = ops::load_store(&kp, &aes_key)?;
        init_keypair(&mut store, base, &CryptLevel::Secret, None, None)?;
        ops::save_store(&kp, &store, &aes_key)?;
        eprintln!("Keystore initialized with secret tier.");
        return Ok((aes_key, kp));
    }
    let aes_key = load_aes_key(base)?;
    Ok((aes_key, kp))
}

// ── Ensure a crypt level is initialized (auto-init secret only) ─────

fn ensure_level(
    base: &Path,
    kp: &Path,
    aes_key: &[u8],
    level: &CryptLevel,
) -> Result<(), String> {
    let store = ops::load_store(kp, aes_key)?;
    if store.key_pairs.contains_key(level.as_str()) {
        return Ok(());
    }
    drop(store);

    if *level == CryptLevel::Secret {
        let mut store = ops::load_store(kp, aes_key)?;
        init_keypair(&mut store, base, level, None, None)?;
        ops::save_store(kp, &store, aes_key)?;
        Ok(())
    } else {
        Err(format!(
            "Level '{}' not initialized. Run 'keybox init --level {}' first.",
            level.as_str(),
            level.as_str()
        ))
    }
}

// ── Command Handlers ────────────────────────────────────────────────

fn handle_init(base: &Path, level: Option<&str>) -> Result<(), String> {
    let kp = get_keystore_path(base);

    if !kp.exists() {
        // Create keystore fresh with secret tier
        let aes_key = ops::init_store(&kp)?;
        store_aes_key(base, &aes_key)?;
        let mut store = ops::load_store(&kp, &aes_key)?;
        init_keypair(&mut store, base, &CryptLevel::Secret, None, None)?;
        ops::save_store(&kp, &store, &aes_key)?;
        println!("Keystore initialized with secret tier.");
        // Fall through to check if additional levels need init
    }

    let aes_key = load_aes_key(base)?;
    let mut store = ops::load_store(&kp, &aes_key)?;
    let mut changed = false;

    let levels_to_init: Vec<CryptLevel> = if let Some(l) = level {
        let cl = CryptLevel::from_str(l).map_err(|e| format!("Invalid level: {}", e))?;
        if store.key_pairs.contains_key(cl.as_str()) {
            println!("Level '{}' already initialized.", cl.as_str());
            return Ok(());
        }
        vec![cl]
    } else {
        // Init all missing levels
        [CryptLevel::Secret, CryptLevel::Con, CryptLevel::Top]
            .iter()
            .filter(|cl| !store.key_pairs.contains_key(cl.as_str()))
            .cloned()
            .collect()
    };

    for cl in &levels_to_init {
        match cl {
            CryptLevel::Secret => {
                init_keypair(&mut store, base, cl, None, None)?;
                println!("Initialized secret tier.");
                changed = true;
            }
            CryptLevel::Con => {
                let passphrase = interactive::prompt_password_with_confirm(
                    "Enter master passphrase for confidential tier: ",
                    "Confirm passphrase: ",
                )?;
                init_keypair(&mut store, base, cl, Some(&passphrase), None)?;
                println!("Initialized confidential tier.");
                changed = true;
            }
            CryptLevel::Top => {
                let key_path =
                    interactive::prompt_input("Key file path for top-secret tier: ")?;
                if key_path.is_empty() {
                    return Err("Key file path is required for top-secret tier".into());
                }
                let content = fs::read(&key_path)
                    .map_err(|e| format!("Failed to read key file: {}", e))?;
                if content.is_empty() {
                    return Err("Key file is empty".into());
                }
                init_keypair(&mut store, base, cl, None, Some(&key_path))?;
                println!("Initialized top-secret tier.");
                changed = true;
            }
        }
    }

    if changed {
        ops::save_store(&kp, &store, &aes_key)?;
    } else if levels_to_init.is_empty() {
        println!("All levels already initialized.");
    }

    Ok(())
}

fn handle_add(
    base: &Path,
    target: &str,
    level: Option<&str>,
    description: Option<&str>,
    tags: &[String],
    stdin: bool,
    no_interactive: bool,
) -> Result<(), String> {
    let (domain, account) = parse_target(target);
    let crypt_level = parse_level(level);

    let (aes_key, kp) = open_keystore(base)?;

    // Ensure the crypt level has a keypair (auto-init secret only)
    ensure_level(base, &kp, &aes_key, &crypt_level)?;

    // Read secret
    let secret = if stdin {
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read stdin: {}", e))?;
        input.trim().to_string()
    } else if no_interactive {
        return Err("--no-interactive requires --stdin to provide the secret".into());
    } else {
        interactive::prompt_password_with_confirm("Secret: ", "Confirm: ")?
    };

    if secret.is_empty() {
        return Err("Secret cannot be empty".into());
    }

    let id = ops::add_credential(
        &kp,
        &aes_key,
        domain,
        account,
        &secret,
        &crypt_level,
        description,
        tags,
    )?;

    let key = KeyStore::credential_key(domain, account);
    eprintln!("Added credential {} (id: {})", key, id);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_get(
    base: &Path,
    field: Option<&str>,
    user: &str,
    clipboard: bool,
    env: Option<&str>,
    force: bool,
    access_token: Option<&str>,
    no_interactive: bool,
) -> Result<(), String> {
    let _ = access_token; // reserved for daemon (Phase 5)

    // When output flags are used, default to getting the password
    let field = if force || clipboard || env.is_some() {
        field.unwrap_or("password")
    } else {
        field.unwrap_or("all")
    };

    let (domain, account) = parse_target(user);
    let (aes_key, kp) = open_keystore(base)?;

    // Always fetch credential metadata first
    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;

    if field == "all" || field == "metadata" {
        let output = if field == "metadata" {
            let mut meta = cred.clone();
            meta.secret = "<masked>".to_string();
            meta
        } else {
            cred.clone() // secret already masked by ops::get_credential? No, it returns actual
        };

        // For "all", print JSON with secret masked (don't decrypt)
        let mut display = output.clone();
        display.secret = "<masked>".to_string();
        let json =
            serde_json::to_string_pretty(&display).map_err(|e| format!("JSON error: {}", e))?;
        println!("{}", json);
        return Ok(());
    }

    if field == "password" {
        if no_interactive {
            return Err(
                "Cannot decrypt password in non-interactive mode. Use --no-interactive only for metadata fields."
                    .into(),
            );
        }
        let level_str = cred.crypt_level.as_str();
        let identity = resolve_identity(base, &aes_key, level_str)?;
        let secret = ops::get_password(&kp, &aes_key, domain, account, &identity)?;

        if let Some(var_name) = env {
            let trailing = get_trailing_args();
            if trailing.is_empty() {
                io::stdout()
                    .write_all(&secret)
                    .map_err(|e| e.to_string())?;
                println!();
            } else {
                let code = keybox::env_run::run_with_env(var_name, &secret, &trailing)?;
                process::exit(code);
            }
        } else if clipboard {
            copy_to_clipboard(&secret)?;
            eprintln!("Password copied to clipboard.");
        } else if force {
            io::stdout()
                .write_all(&secret)
                .map_err(|e| e.to_string())?;
            println!();
        } else {
            eprintln!(
                "Use --force to display the password, --clipboard to copy, or --env to inject."
            );
            println!("<masked>");
        }
        return Ok(());
    }

    // Field-level access
    match field {
        "description" => println!("{}", cred.description.unwrap_or_default()),
        "domain" => println!("{}", cred.domain),
        "account" => println!("{}", cred.account),
        "tags" => println!("{}", cred.tags.join(", ")),
        _ => return Err(format!("Unknown field: '{}'", field)),
    }
    Ok(())
}

fn handle_list(
    base: &Path,
    format: &str,
    level: Option<&str>,
    tag: Option<&str>,
) -> Result<(), String> {
    let (aes_key, kp) = open_keystore(base)?;
    let creds = ops::list_credentials(&kp, &aes_key, level, tag)?;

    match format {
        "json" => {
            let json =
                serde_json::to_string_pretty(&creds).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json);
        }
        "table" => {
            if creds.is_empty() {
                println!("No credentials found.");
            } else {
                for cred in &creds {
                    println!(
                        "{}  [{}/{}]  {}",
                        KeyStore::credential_key(&cred.domain, &cred.account),
                        cred.crypt_level.as_str(),
                        &cred.id[..8.min(cred.id.len())],
                        cred.description.as_deref().unwrap_or("-")
                    );
                }
            }
        }
        _ => return Err(format!("Unknown format: '{}'. Use 'json' or 'table'.", format)),
    }
    Ok(())
}

fn handle_edit(
    base: &Path,
    target: &str,
    description: Option<&str>,
    tags: &[String],
    no_interactive: bool,
) -> Result<(), String> {
    let (domain, account) = parse_target(target);
    let (aes_key, kp) = open_keystore(base)?;

    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;
    let level_str = cred.crypt_level.as_str();

    // For con/top: verify identity before editing
    if level_str == "con" || level_str == "top" {
        if no_interactive {
            return Err(format!(
                "Editing '{}' level credentials requires interactive access. Cannot use --no-interactive.",
                level_str
            ));
        }
        let _ = resolve_identity(base, &aes_key, level_str)?;
    }

    let tags_slice = if tags.is_empty() { None } else { Some(tags) };
    ops::edit_credential(&kp, &aes_key, domain, account, description, tags_slice)?;
    println!("Updated {}/{}", domain, account);
    Ok(())
}

fn handle_update_password(base: &Path, target: &str) -> Result<(), String> {
    let (domain, account) = parse_target(target);
    let (aes_key, kp) = open_keystore(base)?;

    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;
    let level_str = cred.crypt_level.as_str();
    let identity = resolve_identity(base, &aes_key, level_str)?;

    let old_password = interactive::prompt_password("Current password: ")?;
    let new_password =
        interactive::prompt_password_with_confirm("New password: ", "Confirm: ")?;

    ops::update_password(
        &kp,
        &aes_key,
        domain,
        account,
        &old_password,
        &new_password,
        &identity,
    )?;
    println!("Password updated for {}/{}", domain, account);
    Ok(())
}

fn handle_delete(base: &Path, target: &str, no_interactive: bool) -> Result<(), String> {
    let (domain, account) = parse_target(target);
    let (aes_key, kp) = open_keystore(base)?;

    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;
    let level_str = cred.crypt_level.as_str();

    // For con/top: verify identity first
    if level_str == "con" || level_str == "top" {
        if no_interactive {
            return Err(format!(
                "Deleting '{}' level credentials requires interactive access. Cannot use --no-interactive.",
                level_str
            ));
        }
        let _ = resolve_identity(base, &aes_key, level_str)?;
    }

    // Confirm deletion
    if !no_interactive
        && interactive::stdin_is_tty()
        && !interactive::is_llm_calling()
    {
        let prompt = format!(
            "Delete {}/{}? This cannot be undone",
            domain, account
        );
        if !interactive::prompt_confirm(&prompt)? {
            println!("Cancelled.");
            return Ok(());
        }
    }

    ops::delete_credential(&kp, &aes_key, domain, account)?;
    println!("Deleted {}/{}", domain, account);
    Ok(())
}

fn handle_serve(_base: &Path) -> Result<(), String> {
    eprintln!("Daemon support will be implemented in Phase 5.");
    println!("Daemon started (stub)");
    Ok(())
}

fn handle_unlock(
    _base: &Path,
    _level: &str,
    _timeout: u64,
    _clipboard: bool,
    _env: Option<&str>,
) -> Result<(), String> {
    eprintln!("Daemon support will be implemented in Phase 5.");
    Ok(())
}

fn handle_lock(_base: &Path) -> Result<(), String> {
    eprintln!("Daemon support will be implemented in Phase 5.");
    Ok(())
}

fn handle_stop(_base: &Path) -> Result<(), String> {
    eprintln!("Daemon support will be implemented in Phase 5.");
    Ok(())
}

fn handle_generate(base: &Path, args: &GenerateArgs) -> Result<(), String> {
    // --- Generate the password/passphrase ---
    let password = if args.passphrase {
        let words = match &args.wordlist {
            Some(path) => {
                let content = fs::read_to_string(path)
                    .map_err(|e| format!("wordlist not found: {}", e))?;
                let w: Vec<String> = content
                    .lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect();
                if w.is_empty() {
                    return Err("wordlist is empty".into());
                }
                w
            }
            None => generate::load_wordlist(),
        };
        generate::generate_passphrase(args.length, &words)
    } else {
        let has_explicit_charset =
            args.lowercase || args.uppercase || args.digits || args.symbols || args.chinese;
        let charset = if has_explicit_charset {
            if args.exclude_similar {
                generate::build_charset_with_exclude_similar(
                    args.lowercase,
                    args.uppercase,
                    args.digits,
                    args.symbols,
                    args.chinese,
                )
            } else {
                generate::build_charset(
                    args.lowercase,
                    args.uppercase,
                    args.digits,
                    args.symbols,
                    args.chinese,
                )
            }
        } else if args.exclude_similar {
            generate::build_charset_with_exclude_similar(true, true, true, false, false)
        } else {
            generate::default_charset()
        };
        if charset.is_empty() {
            return Err("at least one character set required".into());
        }
        generate::generate_password(args.length, &charset)
    };

    let secret = password.as_bytes();

    // --- If --save, store the credential first ---
    if let Some(save_target) = &args.save {
        let (domain, account) = parse_target(save_target);
        let level = parse_level(args.level.as_deref());

        let (aes_key, kp) = open_keystore(base)?;
        ensure_level(base, &kp, &aes_key, &level)?;

        ops::add_credential(
            &kp,
            &aes_key,
            domain,
            account,
            &password,
            &level,
            args.description.as_deref(),
            &args.tags,
        )
        .map_err(|e| {
            if e.contains("already exists") {
                format!(
                    "Credential {} already exists. Delete it first or use a different name.",
                    KeyStore::credential_key(domain, account)
                )
            } else {
                e
            }
        })?;
        println!("Saved to {}/{}", domain, account);
    }

    // --- Output the generated value ---
    if let Some(var_name) = &args.env {
        let trailing = get_trailing_args();
        if trailing.is_empty() {
            return Err("no command specified after -- separator".into());
        }
        let code = keybox::env_run::run_with_env(var_name, secret, &trailing)?;
        std::process::exit(code);
    } else if args.clipboard {
        let s = std::str::from_utf8(secret)
            .map_err(|_| "Secret contains non-UTF8 data".to_string())?;
        let mut cb = arboard::Clipboard::new()
            .map_err(|e| format!("Failed to access clipboard: {}", e))?;
        cb.set_text(s)
            .map_err(|e| format!("Failed to copy: {}", e))?;
        println!("Password copied to clipboard");
    } else {
        println!("{}", password);
    }

    Ok(())
}

// ── Entry point ─────────────────────────────────────────────────────

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let base = resolve_base(cli.base.as_deref())?;

    match cli.command {
        Command::Init { level } => handle_init(&base, level.as_deref()),
        Command::Add {
            target,
            level,
            description,
            tags,
            stdin,
            no_interactive,
        } => handle_add(
            &base,
            &target,
            level.as_deref(),
            description.as_deref(),
            &tags,
            stdin,
            no_interactive,
        ),
        Command::Get {
            field,
            user,
            clipboard,
            env,
            force,
            access_token,
            no_interactive,
        } => handle_get(
            &base,
            field.as_deref(),
            &user,
            clipboard,
            env.as_deref(),
            force,
            access_token.as_deref(),
            no_interactive,
        ),
        Command::List { format, level, tag } => {
            handle_list(&base, &format, level.as_deref(), tag.as_deref())
        }
        Command::Edit {
            target,
            description,
            tags,
            no_interactive,
        } => handle_edit(&base, &target, description.as_deref(), &tags, no_interactive),
        Command::Update { sub } => match sub {
            UpdateSub::Password { target } => handle_update_password(&base, &target),
        },
        Command::Delete {
            target,
            no_interactive,
        } => handle_delete(&base, &target, no_interactive),
        Command::Serve => handle_serve(&base),
        Command::Unlock {
            level,
            timeout,
            clipboard,
            env,
        } => handle_unlock(&base, &level, timeout, clipboard, env.as_deref()),
        Command::Lock => handle_lock(&base),
        Command::Stop => handle_stop(&base),
        Command::Generate(args) => handle_generate(&base, &args),
    }
}
