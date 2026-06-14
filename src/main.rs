use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use clap::Parser;
use keybox::cli::{Cli, Command, validate_name};
use keybox::crypto::identity;
use keybox::daemon;
use keybox::daemon::protocol::Request;
use keybox::env_run;
use keybox::interactive;
use keybox::store;
use keybox::tier::{Tier, TierPaths};

// ── Configuration ────────────────────────────────────────────────

/// Resolve the base config directory, preferring the `KEYBOX_CONFIG_DIR`
/// environment variable when set (useful for tests).
fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("KEYBOX_CONFIG_DIR") {
        PathBuf::from(dir)
    } else {
        dirs::config_dir()
            .expect("Could not determine config directory")
            .join("keybox")
    }
}

/// Capture command-line arguments appearing after the `--` separator.
fn get_trailing_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--") {
        args[pos + 1..].to_vec()
    } else {
        vec![]
    }
}

// ── Initialization helpers ───────────────────────────────────────

/// Ensure the given tier is initialised.  The Secret tier is implicitly
/// auto-initialised on macOS; other tiers require an explicit `init`.
fn ensure_initialized(base: &Path, tier: Tier) -> Result<(), String> {
    if tier.is_initialized(base) {
        return Ok(());
    }
    match tier {
        Tier::Secret => auto_init_secret(base),
        Tier::Confidential | Tier::TopSecret => {
            let flag = match tier {
                Tier::Confidential => "--confidential",
                Tier::TopSecret => "--top-secret",
                _ => unreachable!(),
            };
            Err(format!(
                "{} tier not initialized. Run `keybox {} init` first.",
                tier.dir_name(),
                flag
            ))
        }
    }
}

#[cfg(target_os = "macos")]
fn auto_init_secret(base: &Path) -> Result<(), String> {
    use age::secrecy::ExposeSecret;
    use keybox::protect::{IdentityProtector, MacOSProtector};

    let paths = TierPaths::from_base(base, Tier::Secret);
    std::fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store dir: {}", e))?;
    if let Some(parent) = paths.private_key.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create identity dir: {}", e))?;
    }

    let (ident, recipient) = identity::generate();
    let protector = MacOSProtector::new();
    let id_str = ident.to_string();
    protector.protect(id_str.expose_secret().as_bytes(), &paths.private_key)?;
    identity::save_recipient(&recipient, &paths.public_key)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn auto_init_secret(base: &Path) -> Result<(), String> {
    let paths = TierPaths::from_base(base, Tier::Secret);
    std::fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store dir: {}", e))?;
    if let Some(parent) = paths.private_key.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create identity dir: {}", e))?;
    }
    let (ident, recipient) = identity::generate();
    identity::save_identity(&ident, &paths.private_key)?;
    identity::save_recipient(&recipient, &paths.public_key)?;
    Ok(())
}

// ── Identity loading for the Secret tier on macOS ────────────────

#[cfg(target_os = "macos")]
fn load_secret_identity(base: &Path) -> Result<age::x25519::Identity, String> {
    use keybox::protect::{IdentityProtector, MacOSProtector};

    let paths = TierPaths::from_base(base, Tier::Secret);
    let protector = MacOSProtector::new();
    let identity_bytes = protector.unprotect(&paths.private_key)?;
    let identity_str = String::from_utf8(identity_bytes)
        .map_err(|_| "Identity contains invalid UTF-8".to_string())?;
    age::x25519::Identity::from_str(identity_str.trim())
        .map_err(|e| format!("Failed to parse identity: {}", e))
}

// ── Clipboard ────────────────────────────────────────────────────

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

// ── CLI handle functions ─────────────────────────────────────────

fn handle_add(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    validate_name(domain)?;
    validate_name(account)?;
    ensure_initialized(base, tier)?;

    let secret: Vec<u8> = if non_interactive {
        password
            .ok_or_else(|| "--password is required with --non-interactive".to_string())?
            .as_bytes()
            .to_vec()
    } else {
        interactive::prompt_password_with_confirm("Password: ", "Confirm: ")?
            .into_bytes()
    };

    store::add_credential(base, tier, domain, account, &secret)
}

fn handle_get(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
    env: Option<&str>,
    clipboard: bool,
) -> Result<(), String> {
    ensure_initialized(base, tier)?;

    // On macOS the Secret-tier private key lives in the Keychain, not on disk.
    #[cfg(target_os = "macos")]
    let secret = if tier == Tier::Secret {
        let ident = load_secret_identity(base)?;
        store::get_credential_with_identity(base, tier, domain, account, &ident)?
    } else {
        get_credential_via_daemon(base, tier, domain, account)?
    };

    #[cfg(not(target_os = "macos"))]
    let secret = if tier == Tier::Secret {
        store::get_credential(base, tier, domain, account)?
    } else {
        get_credential_via_daemon(base, tier, domain, account)?
    };

    if let Some(var_name) = env {
        let trailing = get_trailing_args();
        if trailing.is_empty() {
            // No command after -- : print like normal get.
            io::stdout()
                .write_all(&secret)
                .map_err(|e| e.to_string())?;
            println!();
        } else {
            let code = env_run::run_with_env(var_name, &secret, &trailing)?;
            process::exit(code);
        }
    } else if clipboard {
        copy_to_clipboard(&secret)?;
        eprintln!("Copied to clipboard.");
    } else {
        io::stdout()
            .write_all(&secret)
            .map_err(|e| e.to_string())?;
        println!();
    }
    Ok(())
}

fn handle_list(
    base: &Path,
    tier: Tier,
    domain: Option<&str>,
    json: bool,
) -> Result<(), String> {
    // Listing does not require initialisation — just show empty.
    if !tier.is_initialized(base) {
        if json {
            println!("[]");
        }
        return Ok(());
    }

    if let Some(dom) = domain {
        let accounts = store::list_accounts(base, tier, dom)?;
        if json {
            let json_str =
                serde_json::to_string_pretty(&accounts).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json_str);
        } else {
            for a in &accounts {
                println!("{}", a);
            }
        }
    } else {
        let domains = store::list_domains(base, tier)?;
        if json {
            let json_str =
                serde_json::to_string_pretty(&domains).map_err(|e| format!("JSON error: {}", e))?;
            println!("{}", json_str);
        } else {
            for d in &domains {
                println!("{}", d);
            }
        }
    }
    Ok(())
}

fn handle_delete(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
) -> Result<(), String> {
    ensure_initialized(base, tier)?;

    if interactive::stdin_is_tty() && !interactive::is_llm_calling() {
        let prompt = format!(
            "Delete {}/{}? This cannot be undone",
            domain, account
        );
        if !interactive::prompt_confirm(&prompt)? {
            println!("Cancelled.");
            return Ok(());
        }
    }

    store::delete_credential(base, tier, domain, account)?;
    println!("Deleted {}/{}", domain, account);
    Ok(())
}

fn handle_update(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    validate_name(domain)?;
    validate_name(account)?;
    ensure_initialized(base, tier)?;

    let secret: Vec<u8> = if non_interactive {
        password
            .ok_or_else(|| "--password is required with --non-interactive".to_string())?
            .as_bytes()
            .to_vec()
    } else {
        interactive::prompt_password_with_confirm("New password: ", "Confirm: ")?
            .into_bytes()
    };

    store::update_credential(base, tier, domain, account, &secret)?;
    println!("Updated {}/{}", domain, account);
    Ok(())
}

fn handle_init(
    base: &Path,
    tier: Tier,
    file: Option<&str>,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    match tier {
        Tier::Secret => auto_init_secret(base),
        Tier::Confidential => init_confidential(base, non_interactive, password),
        Tier::TopSecret => init_top_secret(base, file, non_interactive, password),
    }
}

fn init_confidential(
    base: &Path,
    non_interactive: bool,
    password: Option<&str>,
) -> Result<(), String> {
    use age::secrecy::ExposeSecret;
    use age::Encryptor;

    let paths = TierPaths::from_base(base, Tier::Confidential);
    fs::create_dir_all(paths.private_key.parent().unwrap())
        .map_err(|e| format!("Failed to create dir: {}", e))?;
    fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store dir: {}", e))?;

    let passphrase = if non_interactive {
        password
            .ok_or_else(|| "--password is required with --non-interactive".to_string())?
            .to_string()
    } else {
        interactive::prompt_password_with_confirm(
            "Enter master passphrase: ",
            "Confirm passphrase: ",
        )?
    };

    let (identity_key, recipient) = identity::generate();
    let identity_str = identity_key.to_string();

    // Encrypt identity with age passphrase mode
    let encryptor = Encryptor::with_user_passphrase(age::secrecy::Secret::new(passphrase));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|_| "Encryption failed".to_string())?;
    std::io::Write::write_all(&mut writer, identity_str.expose_secret().as_bytes())
        .map_err(|_| "Write failed".to_string())?;
    writer.finish().map_err(|_| "Finish failed".to_string())?;

    fs::write(&paths.private_key, &encrypted)
        .map_err(|e| format!("Failed to write identity: {}", e))?;
    identity::save_recipient(&recipient, &paths.public_key)?;

    println!("Initialized confidential tier");
    Ok(())
}

fn init_top_secret(
    base: &Path,
    file: Option<&str>,
    non_interactive: bool,
    _password: Option<&str>,
) -> Result<(), String> {
    use age::secrecy::ExposeSecret;
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
    use ring::rand::{SecureRandom, SystemRandom};
    use sha2::{Digest, Sha256};

    let key_path = if let Some(f) = file {
        PathBuf::from(f)
    } else if non_interactive {
        Tier::default_top_key_path(base)
    } else {
        let prompt = format!(
            "Key file path (default: {}): ",
            Tier::default_top_key_path(base).display()
        );
        let input = interactive::prompt_input(&prompt)?;
        if input.is_empty() {
            Tier::default_top_key_path(base)
        } else {
            PathBuf::from(input)
        }
    };

    let file_content = fs::read(&key_path)
        .map_err(|e| format!("Failed to read key file '{}': {}", key_path.display(), e))?;

    let mut hasher = Sha256::new();
    hasher.update(b"keybox-top-v1");
    hasher.update(&file_content);
    let aes_key = hasher.finalize();

    let paths = TierPaths::from_base(base, Tier::TopSecret);
    fs::create_dir_all(paths.private_key.parent().unwrap())
        .map_err(|e| format!("Failed to create dir: {}", e))?;
    fs::create_dir_all(&paths.store)
        .map_err(|e| format!("Failed to create store dir: {}", e))?;

    let (identity_key, recipient) = identity::generate();
    let identity_str = identity_key.to_string();

    // Encrypt with AES-256-GCM
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &aes_key).map_err(|e| format!("Invalid key: {}", e))?;
    let key = LessSafeKey::new(unbound_key);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "RNG failure".to_string())?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = identity_str.expose_secret().as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&in_out);
    fs::write(&paths.private_key, &output)
        .map_err(|e| format!("Failed to write identity: {}", e))?;
    identity::save_recipient(&recipient, &paths.public_key)?;

    println!("Initialized top-secret tier");
    Ok(())
}

fn get_credential_via_daemon(
    base: &Path,
    tier: Tier,
    domain: &str,
    account: &str,
) -> Result<Vec<u8>, String> {
    let paths = TierPaths::from_base(base, tier);
    let ciphertext = fs::read(paths.store.join(domain).join(format!("{}.enc", account)))
        .map_err(|e| format!("Failed to read: {}", e))?;
    let request = Request::Decrypt { ciphertext };
    match daemon::client::send_request(base, tier, &request)? {
        keybox::daemon::protocol::Response::Decrypted { plaintext } => Ok(plaintext),
        keybox::daemon::protocol::Response::Error { message } => Err(message),
        _ => Err("Unexpected daemon response".into()),
    }
}

fn handle_serve(base: &Path, tier: Tier) -> Result<(), String> {
    if tier == Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if daemon::client::is_daemon_running(base, tier) {
        println!("Daemon is already running.");
        return Ok(());
    }
    daemon::server::run_daemon(base.to_path_buf(), tier)
}

fn handle_unlock(base: &Path, tier: Tier) -> Result<(), String> {
    if tier == Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running. Run 'keybox serve' first.".into());
    }
    let passphrase = interactive::prompt_password("Enter master passphrase: ")?;
    let request = Request::Unlock { passphrase };
    match daemon::client::send_request(base, tier, &request)? {
        keybox::daemon::protocol::Response::Ok => {
            println!("Daemon unlocked.");
            Ok(())
        }
        keybox::daemon::protocol::Response::Error { message } => Err(message),
        _ => Err("Unexpected response".into()),
    }
}

fn handle_lock(base: &Path, tier: Tier) -> Result<(), String> {
    if tier == Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running.".into());
    }
    let request = Request::Lock;
    match daemon::client::send_request(base, tier, &request)? {
        keybox::daemon::protocol::Response::Ok => {
            println!("Daemon locked.");
            Ok(())
        }
        keybox::daemon::protocol::Response::Error { message } => Err(message),
        _ => Err("Unexpected response".into()),
    }
}

fn handle_stop(base: &Path, tier: Tier) -> Result<(), String> {
    if tier == Tier::Secret {
        return Err("Secret tier does not use a daemon.".into());
    }
    if !daemon::client::is_daemon_running(base, tier) {
        return Err("Daemon is not running.".into());
    }
    let _ = daemon::client::send_request(base, tier, &Request::Lock);
    println!("Daemon stopped.");
    Ok(())
}

// ── Entry point ──────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let base = config_dir();

    let tier = match cli.tier() {
        keybox::cli::Tier::Secret => Tier::Secret,
        keybox::cli::Tier::Confidential => Tier::Confidential,
        keybox::cli::Tier::TopSecret => Tier::TopSecret,
    };

    let result = match &cli.command {
        Command::Add {
            domain,
            account,
            non_interactive,
            password,
        } => handle_add(
            &base,
            tier,
            domain,
            account,
            *non_interactive,
            password.as_deref(),
        ),
        Command::Get {
            domain,
            account,
            env,
            clipboard,
        } => handle_get(&base, tier, domain, account, env.as_deref(), *clipboard),
        Command::List { domain, json } => {
            handle_list(&base, tier, domain.as_deref(), *json)
        }
        Command::Delete { domain, account } => {
            handle_delete(&base, tier, domain, account)
        }
        Command::Update {
            domain,
            account,
            non_interactive,
            password,
        } => handle_update(
            &base,
            tier,
            domain,
            account,
            *non_interactive,
            password.as_deref(),
        ),
        Command::Init {
            file,
            non_interactive,
            password,
        } => handle_init(
            &base,
            tier,
            file.as_deref(),
            *non_interactive,
            password.as_deref(),
        ),
        Command::Serve => handle_serve(&base, tier),
        Command::Unlock => handle_unlock(&base, tier),
        Command::Lock => handle_lock(&base, tier),
        Command::Stop => handle_stop(&base, tier),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
