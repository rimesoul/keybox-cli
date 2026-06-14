use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::str::FromStr;

use clap::Parser;
use keybox::cli::{Cli, Command, validate_name};
use keybox::crypto::identity;
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
        store::get_credential(base, tier, domain, account)?
    };

    #[cfg(not(target_os = "macos"))]
    let secret = store::get_credential(base, tier, domain, account)?;

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
) -> Result<(), String> {
    if tier == Tier::Confidential && file.is_none() && non_interactive {
        return Err(
            "--confidential init requires --file <recipient-file> in non-interactive mode".into(),
        );
    }
    if tier == Tier::TopSecret && file.is_none() && non_interactive {
        return Err(
            "--top-secret init requires --file <top-key-file> in non-interactive mode".into(),
        );
    }

    match tier {
        Tier::Secret => ensure_initialized(base, tier)?,
        _ => {
            return Err(format!(
                "{} tier init not yet implemented",
                tier.dir_name()
            ));
        }
    }
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
        } => handle_init(&base, tier, file.as_deref(), *non_interactive),
        _ => Err("Not yet implemented".into()),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
