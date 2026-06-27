use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use clap::Parser;
use age::secrecy::ExposeSecret;
use keybox::cli::{Cli, Command, GenerateArgs, UpdateSub};
use keybox::crypto::age_ops;
use keybox::crypto::keyfile;
use keybox::error::KeyboxError;
use keybox::generate;
use keybox::interactive;
use keybox::keystore::ops;
use keybox::keystore::schema::{CryptLevel, KeyPair, KeyStore};
use keybox::protect::IdentityProtector;

#[cfg(target_os = "macos")]
use keybox::protect::MacOSProtector;

// ── Helpers: resolve_base, parse_target, keystore paths ─────────────

fn resolve_base(base_opt: Option<&str>) -> Result<PathBuf, KeyboxError> {
    if let Ok(dir) = std::env::var("KEYBOX_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    if let Some(b) = base_opt {
        Ok(PathBuf::from(b))
    } else {
        dirs::config_dir()
            .ok_or_else(|| KeyboxError::input("Cannot determine config directory"))
            .map(|d| d.join("keybox"))
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

// ── Helper: load AES key as fixed-size array ─────────────────────────

fn load_aes_key(base: &Path) -> Result<[u8; 32], KeyboxError> {
    let bytes = ops::load_aes_key_bytes(base)?;
    if bytes.len() != 32 {
        return Err(KeyboxError::crypto("AES key has wrong length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Helper: parse crypt level string ────────────────────────────────

fn parse_level(s: Option<&str>) -> CryptLevel {
    s.and_then(|l| CryptLevel::from_str(l).ok()).unwrap_or(CryptLevel::Secret)
}

// ── Helper: copy to clipboard ───────────────────────────────────────

fn copy_to_clipboard(secret: &[u8]) -> Result<(), KeyboxError> {
    let text = std::str::from_utf8(secret)
        .map_err(|_| KeyboxError::input("Secret contains non-UTF8 data, cannot copy to clipboard"))?;
    let mut clipboard =
        arboard::Clipboard::new().map_err(|e| KeyboxError::input(format!("Clipboard error: {}", e)))?;
    clipboard
        .set_text(text)
        .map_err(|e| KeyboxError::input(format!("Clipboard error: {}", e)))?;
    Ok(())
}

/// Output a secret (password or token) according to the selected flags.
/// Priority: --env > --clipboard > --force > stdout warning.
fn output_secret(secret: &[u8], env: Option<&str>, clipboard: bool, force: bool) -> Result<(), KeyboxError> {
    if let Some(var_name) = env {
        let trailing = get_trailing_args();
        if trailing.is_empty() {
            io::stdout()
                .write_all(secret)
                .map_err(|e| KeyboxError::io("writing secret to stdout", e))?;
            println!();
        } else {
            let code = keybox::env_run::run_with_env(var_name, secret, &trailing)
                .map_err(KeyboxError::input)?;
            process::exit(code);
        }
    } else if clipboard {
        copy_to_clipboard(secret)?;
        eprintln!("Secret copied to clipboard.");
    } else if force {
        io::stdout()
            .write_all(secret)
            .map_err(|e| KeyboxError::io("writing secret to stdout", e))?;
        println!();
    } else {
        eprintln!(
            "Use --force to display, --clipboard to copy, or --env to inject."
        );
        println!("<masked>");
    }
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

// ── Keypair initialization ──────────────────────────────────────────

/// Generate and store a keypair for the given crypt level.
fn init_keypair(
    store: &mut KeyStore,
    base: &Path,
    level: &CryptLevel,
    passphrase: Option<&str>,
    key_file: Option<&str>,
) -> Result<(), KeyboxError> {
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
                ops::store_secret_identity(base, identity_bytes)?;
                (String::new(), "file".to_string())
            }
        }
        CryptLevel::Con => {
            let pass = passphrase.ok_or_else(|| KeyboxError::input("Passphrase required for confidential tier"))?;
            let encrypted = age_ops::encrypt_with_passphrase(identity_bytes, pass)?;
            (ops::b64_encode(&encrypted), "passphrase".to_string())
        }
        CryptLevel::Top => {
            let key_path = key_file.ok_or_else(|| KeyboxError::input("Key file required for top-secret tier"))?;
            let file_content = fs::read(key_path)
                .map_err(|e| format!("Failed to read key file '{}': {}", key_path, e))?;
            if file_content.is_empty() {
                return Err(KeyboxError::input("Key file is empty"));
            }
            let aes_key = keyfile::derive_key_from_file(&file_content);
            let encrypted = keyfile::encrypt_with_aes_gcm_keyfile(identity_bytes, &aes_key)?;
            (ops::b64_encode(&encrypted), "keyfile".to_string())
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
) -> Result<age::x25519::Identity, KeyboxError> {
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
                let identity_bytes = ops::load_secret_identity(base)?;
                String::from_utf8(identity_bytes)
                    .map_err(|_| "Identity not valid UTF-8".to_string())?
            }
        }
        "passphrase" | "con" => {
            let passphrase =
                interactive::prompt_password("Enter master passphrase for confidential tier: ")?;
            let encrypted = ops::b64_decode(&keypair.encrypted_private_key)?;
            let identity_bytes = age_ops::decrypt_with_passphrase(&encrypted, &passphrase)?;
            String::from_utf8(identity_bytes)
                .map_err(|_| "Identity not valid UTF-8".to_string())?
        }
        "keyfile" | "top" => {
            let key_path_input =
                interactive::prompt_input("Key file path for top-secret tier: ")?;
            let file_content = fs::read(&key_path_input)
                .map_err(|e| format!("Failed to read key file '{}': {}", key_path_input, e))?;
            if file_content.is_empty() {
                return Err(KeyboxError::input("Key file is empty"));
            }
            let aes_key_top = keyfile::derive_key_from_file(&file_content);
            let encrypted = ops::b64_decode(&keypair.encrypted_private_key)?;
            let identity_bytes =
                keyfile::decrypt_with_aes_gcm_keyfile(&encrypted, &aes_key_top)?;
            String::from_utf8(identity_bytes)
                .map_err(|_| "Identity not valid UTF-8".to_string())?
        }
        _ => return Err(KeyboxError::not_found("protector", &keypair.protector)),
    };

    age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|e| KeyboxError::crypto(format!("Failed to parse identity: {}", e)))
}

// ── Open keystore (auto-create with secret tier if missing) ─────────

fn open_keystore(base: &Path) -> Result<([u8; 32], PathBuf), KeyboxError> {
    let kp = get_keystore_path(base);
    if !kp.exists() {
        eprintln!("Initializing keystore...");
        let aes_key = ops::init_store(&kp)?;
        ops::store_aes_key(base, &aes_key)?;

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
) -> Result<(), KeyboxError> {
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
        Err(KeyboxError::not_found(
            format!("level '{}'", level.as_str()),
            format!("Run 'keybox init --level {}'", level.as_str()),
        ))
    }
}

// ── Command Handlers ────────────────────────────────────────────────

fn handle_init(base: &Path, level: Option<&str>) -> Result<(), KeyboxError> {
    let kp = get_keystore_path(base);

    if !kp.exists() {
        // Create keystore fresh with secret tier
        let aes_key = ops::init_store(&kp)?;
        ops::store_aes_key(base, &aes_key)?;
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
                    return Err(KeyboxError::input("Key file path is required for top-secret tier"));
                }
                let content = fs::read(&key_path)
                    .map_err(|e| format!("Failed to read key file: {}", e))?;
                if content.is_empty() {
                    return Err(KeyboxError::input("Key file is empty"));
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
) -> Result<(), KeyboxError> {
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
        return Err(KeyboxError::input("--no-interactive requires --stdin to provide the secret"));
    } else {
        interactive::prompt_password_with_confirm("Secret: ", "Confirm: ")?
    };

    if secret.is_empty() {
        return Err(KeyboxError::input("Secret cannot be empty"));
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
) -> Result<(), KeyboxError> {
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
        let mut display = cred.clone();
        display.secret = "<masked>".to_string();
        let json =
            serde_json::to_string_pretty(&display).map_err(|e| format!("JSON error: {}", e))?;
        println!("{}", json);
        return Ok(());
    }

    if field == "password" {
        // If an access token is provided, use the daemon for decryption.
        // Works even in non-interactive mode — the daemon handles identity.
        if let Some(token) = access_token {
            use keybox::daemon::client;
            use keybox::daemon::protocol::Response;

            let response = client::get(base, domain, account, "password", Some(token))?;
            let secret: Vec<u8> = match response {
                Response::Value(s) => s.into_bytes(),
                Response::Error(msg) => return Err(KeyboxError::daemon(msg)),
                _ => return Err(KeyboxError::daemon("Unexpected response from daemon")),
            };
            output_secret(&secret, env, clipboard, force)?;
            return Ok(());
        }

        if no_interactive {
            return Err(KeyboxError::input(
                "Cannot decrypt password in non-interactive mode. Use --no-interactive only for metadata fields."
            ));
        }
        let level_str = cred.crypt_level.as_str();
        let identity = resolve_identity(base, &aes_key, level_str)?;
        let secret = ops::get_password(&kp, &aes_key, domain, account, &identity)?;

        output_secret(&secret, env, clipboard, force)?;
        return Ok(());
    }

    // Field-level access
    match field {
        "description" => println!("{}", cred.description.unwrap_or_default()),
        "domain" => println!("{}", cred.domain),
        "account" => println!("{}", cred.account),
        "tags" => println!("{}", cred.tags.join(", ")),
        _ => return Err(KeyboxError::input(format!("Unknown field: '{}'", field))),
    }
    Ok(())
}

fn handle_list(
    base: &Path,
    format: &str,
    level: Option<&str>,
    tag: Option<&str>,
) -> Result<(), KeyboxError> {
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
        _ => return Err(KeyboxError::input(format!("Unknown format: '{}'. Use 'json' or 'table'.", format))),
    }
    Ok(())
}

fn handle_edit(
    base: &Path,
    target: &str,
    description: Option<&str>,
    tags: &[String],
    no_interactive: bool,
) -> Result<(), KeyboxError> {
    let (domain, account) = parse_target(target);
    let (aes_key, kp) = open_keystore(base)?;

    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;
    let level_str = cred.crypt_level.as_str();

    // For con/top: verify identity before editing
    if level_str == "con" || level_str == "top" {
        if no_interactive {
            return Err(KeyboxError::input(format!(
                "Editing '{}' level credentials requires interactive access. Cannot use --no-interactive.",
                level_str
            )));
        }
        let _ = resolve_identity(base, &aes_key, level_str)?;
    }

    let tags_slice = if tags.is_empty() { None } else { Some(tags) };
    ops::edit_credential(&kp, &aes_key, domain, account, description, tags_slice)?;
    println!("Updated {}/{}", domain, account);
    Ok(())
}

fn handle_update_password(base: &Path, target: &str) -> Result<(), KeyboxError> {
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

fn handle_delete(base: &Path, target: &str, no_interactive: bool) -> Result<(), KeyboxError> {
    let (domain, account) = parse_target(target);
    let (aes_key, kp) = open_keystore(base)?;

    let cred = ops::get_credential(&kp, &aes_key, domain, account)?;
    let level_str = cred.crypt_level.as_str();

    // For con/top: verify identity first
    if level_str == "con" || level_str == "top" {
        if no_interactive {
            return Err(KeyboxError::input(format!(
                "Deleting '{}' level credentials requires interactive access. Cannot use --no-interactive.",
                level_str
            )));
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

fn handle_serve(base: &Path) -> Result<(), KeyboxError> {
    keybox::daemon::server::run_daemon(base.to_path_buf()).map_err(KeyboxError::daemon)
}

fn handle_unlock(
    base: &Path,
    level_opt: Option<&str>,
    timeout: u64,
    clipboard: bool,
    env: Option<&str>,
) -> Result<(), KeyboxError> {
    use keybox::daemon::client;
    use keybox::daemon::protocol::Response;

    // Determine target levels
    let target_levels: Vec<String> = match level_opt {
        Some(l) => l.split(',').map(|s| s.trim().to_string()).collect(),
        None => {
            // Default: all initialized unlockable levels
            let kp = get_keystore_path(base);
            let store = ops::load_store(&kp, &ops::load_aes_key_bytes(base)?)?;
            let mut levels = Vec::new();
            if store.key_pairs.contains_key("con") {
                levels.push("con".to_string());
            }
            if store.key_pairs.contains_key("top") {
                levels.push("top".to_string());
            }
            if levels.is_empty() {
                return Err(KeyboxError::input(
                    "No unlockable levels found. \
                     Run 'keybox init --level confidential' or 'keybox init --level top-secret'."
                ));
            }
            levels
        }
    };

    // Validate levels are known
    for l in &target_levels {
        if l != "con" && l != "top" {
            return Err(KeyboxError::input(format!("Unknown level: '{}'. Use 'con' or 'top'.", l)));
        }
    }

    let is_multi = target_levels.len() > 1;

    // Gather ROTs with retry
    let mut passphrase: Option<String> = None;
    let mut keyfile_path: Option<String> = None;

    for level in &target_levels {
        match level.as_str() {
            "con" => {
                let pp = interactive::prompt_password(
                    "Enter master passphrase for confidential tier: "
                )?;
                passphrase = Some(pp);
            }
            "top" => {
                let path = interactive::prompt_input(
                    "Key file path for top-secret tier: "
                )?;
                if path.is_empty() {
                    return Err(KeyboxError::input("Key file path is required for top-secret tier"));
                }
                keyfile_path = Some(path);
            }
            _ => unreachable!(),
        }
    }

    // Send unlock request with all gathered ROTs
    let response = client::unlock(
        base,
        &target_levels,
        passphrase.as_deref(),
        keyfile_path.as_deref(),
        timeout,
    )?;

    match response {
        Response::Unlocked { token, levels } => {
            eprintln!("Unlocked tiers: {}", levels.join(", "));

            if let Some(var_name) = env {
                if is_multi {
                    eprintln!("Warning: --env not supported with multi-level unlock");
                    eprintln!("Token printed to stdout.");
                    println!("{}", token);
                } else {
                    let trailing = get_trailing_args();
                    if trailing.is_empty() {
                        return Err(KeyboxError::input("no command specified after -- separator"));
                    }
                    let code = keybox::env_run::run_with_env(var_name, token.as_bytes(), &trailing)?;
                    std::process::exit(code);
                }
            } else if clipboard {
                copy_to_clipboard(token.as_bytes())?;
                eprintln!("Token copied to clipboard.");
            } else {
                println!("{}", token);
            }
            Ok(())
        }
        Response::Error(msg) => Err(KeyboxError::daemon(msg)),
        _ => Err(KeyboxError::daemon("Unexpected response from daemon")),
    }
}

fn handle_lock(base: &Path) -> Result<(), KeyboxError> {
    use keybox::daemon::client;
    use keybox::daemon::protocol::Response;

    let response = client::lock(base)?;

    match response {
        Response::Locked => {
            eprintln!("Daemon locked. All tokens revoked.");
            Ok(())
        }
        Response::Error(msg) => Err(KeyboxError::daemon(msg)),
        _ => Err(KeyboxError::daemon("Unexpected response from daemon")),
    }
}

fn handle_stop(base: &Path) -> Result<(), KeyboxError> {
    use keybox::daemon::client;
    use keybox::daemon::protocol::Response;

    let response = client::stop(base)?;

    match response {
        Response::Shutdown => {
            eprintln!("Daemon stopped.");
            Ok(())
        }
        Response::Error(msg) => Err(KeyboxError::daemon(msg)),
        _ => Err(KeyboxError::daemon("Unexpected response from daemon")),
    }
}

fn handle_generate(base: &Path, args: &GenerateArgs) -> Result<(), KeyboxError> {
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
                    return Err(KeyboxError::input("wordlist is empty"));
                }
                w
            }
            None => generate::load_wordlist(),
        };
        generate::generate_passphrase(args.length, &words)?
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
            return Err(KeyboxError::input("at least one character set required"));
        }
        generate::generate_password(args.length, &charset)?
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
        )?;
        println!("Saved to {}/{}", domain, account);
    }

    // --- Output the generated value ---
    if let Some(var_name) = &args.env {
        let trailing = get_trailing_args();
        if trailing.is_empty() {
            return Err(KeyboxError::input("no command specified after -- separator"));
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
        Command::Init { level } => handle_init(&base, level.as_deref())?,
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
        )?,
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
        )?,
        Command::List { format, level, tag } => {
            handle_list(&base, &format, level.as_deref(), tag.as_deref())?
        }
        Command::Edit {
            target,
            description,
            tags,
            no_interactive,
        } => handle_edit(&base, &target, description.as_deref(), &tags, no_interactive)?,
        Command::Update { sub } => match sub {
            UpdateSub::Password { target } => handle_update_password(&base, &target)?,
        },
        Command::Delete {
            target,
            no_interactive,
        } => handle_delete(&base, &target, no_interactive)?,
        Command::Serve => handle_serve(&base)?,
        Command::Unlock {
            level,
            timeout,
            clipboard,
            env,
        } => handle_unlock(&base, level.as_deref(), timeout, clipboard, env.as_deref())?,
        Command::Lock => handle_lock(&base)?,
        Command::Stop => handle_stop(&base)?,
        Command::Generate(args) => handle_generate(&base, &args)?,
    };
    Ok(())
}
