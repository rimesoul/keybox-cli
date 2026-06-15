use clap::Parser;
use keybox::cli::{Cli, Command, Tier, validate_name};

// ── Tier flag tests ──────────────────────────────────────────────

#[test]
fn test_default_tier_is_secret() {
    let cli = Cli::parse_from(["keybox", "serve"]);
    assert_eq!(cli.tier(), Tier::Secret);
    assert!(!cli.secret);
    assert!(!cli.confidential);
    assert!(!cli.top_secret);
}

#[test]
fn test_secret_flag_explicit() {
    let cli = Cli::parse_from(["keybox", "--secret", "serve"]);
    assert_eq!(cli.tier(), Tier::Secret);
    assert!(cli.secret);
}

#[test]
fn test_confidential_flag() {
    let cli = Cli::parse_from(["keybox", "--confidential", "serve"]);
    assert_eq!(cli.tier(), Tier::Confidential);
    assert!(cli.confidential);
}

#[test]
fn test_top_secret_flag() {
    let cli = Cli::parse_from(["keybox", "--top-secret", "serve"]);
    assert_eq!(cli.tier(), Tier::TopSecret);
    assert!(cli.top_secret);
}

#[test]
fn test_sec_alias() {
    let cli = Cli::parse_from(["keybox", "--sec", "serve"]);
    assert_eq!(cli.tier(), Tier::Secret);
    assert!(cli.secret);
}

#[test]
fn test_con_alias() {
    let cli = Cli::parse_from(["keybox", "--con", "serve"]);
    assert_eq!(cli.tier(), Tier::Confidential);
    assert!(cli.confidential);
}

#[test]
fn test_top_alias() {
    let cli = Cli::parse_from(["keybox", "--top", "serve"]);
    assert_eq!(cli.tier(), Tier::TopSecret);
    assert!(cli.top_secret);
}

#[test]
fn test_short_s_flag() {
    let cli = Cli::parse_from(["keybox", "-s", "serve"]);
    assert_eq!(cli.tier(), Tier::Secret);
}

#[test]
fn test_short_c_flag() {
    let cli = Cli::parse_from(["keybox", "-c", "serve"]);
    assert_eq!(cli.tier(), Tier::Confidential);
}

#[test]
fn test_short_t_flag() {
    let cli = Cli::parse_from(["keybox", "-t", "serve"]);
    assert_eq!(cli.tier(), Tier::TopSecret);
}

#[test]
fn test_flag_at_end_of_command() {
    let cli = Cli::parse_from(["keybox", "serve", "--secret"]);
    assert_eq!(cli.tier(), Tier::Secret);
}

#[test]
fn test_conflicting_level_flags_fails() {
    let result = Cli::try_parse_from(["keybox", "--secret", "--confidential", "serve"]);
    assert!(result.is_err());
}

// ── Command parsing tests ─────────────────────────────────────────

#[test]
fn test_add_command_parsing() {
    let cli = Cli::parse_from(["keybox", "add", "example.com", "alice"]);
    match &cli.command {
        Command::Add { domain, account, non_interactive, password } => {
            assert_eq!(domain, "example.com");
            assert_eq!(account, "alice");
            assert!(!non_interactive);
            assert!(password.is_none());
        }
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn test_get_command_with_clipboard() {
    let cli = Cli::parse_from(["keybox", "get", "example.com", "alice", "--clipboard"]);
    match &cli.command {
        Command::Get { domain, account, env, clipboard } => {
            assert_eq!(domain, "example.com");
            assert_eq!(account, "alice");
            assert!(env.is_none());
            assert!(*clipboard);
        }
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_env() {
    let cli = Cli::parse_from(["keybox", "get", "example.com", "alice", "--env", "MY_VAR"]);
    match &cli.command {
        Command::Get { domain, account, env, clipboard } => {
            assert_eq!(domain, "example.com");
            assert_eq!(account, "alice");
            assert_eq!(env.as_deref(), Some("MY_VAR"));
            assert!(!clipboard);
        }
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_env_and_clipboard_conflict_fails() {
    let result = Cli::try_parse_from(["keybox", "get", "example.com", "alice", "--env", "X", "--clipboard"]);
    assert!(result.is_err());
}

#[test]
fn test_list_command_without_domain() {
    let cli = Cli::parse_from(["keybox", "list"]);
    match &cli.command {
        Command::List { domain, json } => {
            assert!(domain.is_none());
            assert!(!json);
        }
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_with_domain() {
    let cli = Cli::parse_from(["keybox", "list", "example.com"]);
    match &cli.command {
        Command::List { domain, json } => {
            assert_eq!(domain.as_deref(), Some("example.com"));
            assert!(!json);
        }
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_json_flag() {
    let cli = Cli::parse_from(["keybox", "list", "--json"]);
    match &cli.command {
        Command::List { domain, json } => {
            assert!(domain.is_none());
            assert!(*json);
        }
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_delete_command_parsing() {
    let cli = Cli::parse_from(["keybox", "delete", "example.com", "alice"]);
    match &cli.command {
        Command::Delete { domain, account } => {
            assert_eq!(domain, "example.com");
            assert_eq!(account, "alice");
        }
        _ => panic!("Expected Delete command"),
    }
}

#[test]
fn test_update_command_parsing() {
    let cli = Cli::parse_from(["keybox", "update", "example.com", "alice"]);
    match &cli.command {
        Command::Update { domain, account, non_interactive, password } => {
            assert_eq!(domain, "example.com");
            assert_eq!(account, "alice");
            assert!(!non_interactive);
            assert!(password.is_none());
        }
        _ => panic!("Expected Update command"),
    }
}

#[test]
fn test_init_command_defaults() {
    let cli = Cli::parse_from(["keybox", "init"]);
    match &cli.command {
        Command::Init { file, non_interactive, .. } => {
            assert!(file.is_none());
            assert!(!non_interactive);
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_init_command_with_options() {
    let cli = Cli::parse_from(["keybox", "init", "--file", "/custom/path", "--non-interactive"]);
    match &cli.command {
        Command::Init { file, non_interactive, .. } => {
            assert_eq!(file.as_deref(), Some("/custom/path"));
            assert!(*non_interactive);
        }
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_serve_command() {
    let cli = Cli::parse_from(["keybox", "serve"]);
    assert!(matches!(cli.command, Command::Serve));
}

#[test]
fn test_unlock_command() {
    let cli = Cli::parse_from(["keybox", "unlock"]);
    assert!(matches!(cli.command, Command::Unlock));
}

#[test]
fn test_lock_command() {
    let cli = Cli::parse_from(["keybox", "lock"]);
    assert!(matches!(cli.command, Command::Lock));
}

#[test]
fn test_stop_command() {
    let cli = Cli::parse_from(["keybox", "stop"]);
    assert!(matches!(cli.command, Command::Stop));
}

#[test]
fn test_non_interactive_password_combo() {
    let cli = Cli::parse_from([
        "keybox", "add", "example.com", "alice",
        "--non-interactive", "--password", "s3cret"
    ]);
    match &cli.command {
        Command::Add { non_interactive, password, .. } => {
            assert!(*non_interactive);
            assert_eq!(password.as_deref(), Some("s3cret"));
        }
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn test_password_without_non_interactive_fails() {
    let result = Cli::try_parse_from([
        "keybox", "add", "example.com", "alice",
        "--password", "s3cret"
    ]);
    assert!(result.is_err());
}

// ── validate_name tests ───────────────────────────────────────────

#[test]
fn test_validate_name_valid() {
    assert!(validate_name("valid-name").is_ok());
    assert!(validate_name("underscore_name").is_ok());
    assert!(validate_name("mixed123").is_ok());
    assert!(validate_name("ALL_CAPS").is_ok());
    assert!(validate_name("single").is_ok());
}

#[test]
fn test_validate_name_empty() {
    assert!(validate_name("").is_err());
}

#[test]
fn test_validate_name_with_spaces() {
    assert!(validate_name("has spaces").is_err());
}

#[test]
fn test_validate_name_with_slashes() {
    assert!(validate_name("has/slash").is_err());
}

#[test]
fn test_validate_name_with_special_chars() {
    assert!(validate_name("has.dot").is_err());
    assert!(validate_name("has@at").is_err());
}

// ── to_operation tests ────────────────────────────────────────────

#[test]
fn test_to_operation_mapping() {
    use keybox::cli::Operation;

    let cmd = Command::Add { domain: "x".into(), account: "y".into(), non_interactive: false, password: None };
    assert_eq!(cmd.to_operation(), Operation::Add);

    let cmd = Command::Get { domain: "x".into(), account: "y".into(), env: None, clipboard: false };
    assert_eq!(cmd.to_operation(), Operation::Get);

    let cmd = Command::List { domain: None, json: false };
    assert_eq!(cmd.to_operation(), Operation::List);

    let cmd = Command::Delete { domain: "x".into(), account: "y".into() };
    assert_eq!(cmd.to_operation(), Operation::Delete);

    let cmd = Command::Update { domain: "x".into(), account: "y".into(), non_interactive: false, password: None };
    assert_eq!(cmd.to_operation(), Operation::Update);

    let cmd = Command::Init { file: None, non_interactive: false, password: None };
    assert_eq!(cmd.to_operation(), Operation::Init);

    assert_eq!(Command::Serve.to_operation(), Operation::Serve);
    assert_eq!(Command::Unlock.to_operation(), Operation::Unlock);
    assert_eq!(Command::Lock.to_operation(), Operation::Lock);
    assert_eq!(Command::Stop.to_operation(), Operation::Stop);

    let cmd = Command::Generate {
        length: 16, lowercase: false, uppercase: false, digits: false,
        symbols: false, chinese: false, passphrase: false, wordlist: None,
        clipboard: false, env: None, save: None, exclude_similar: false,
    };
    assert_eq!(cmd.to_operation(), Operation::Generate);
}

// ── Generate command parsing tests ─────────────────────────────────

#[test]
fn test_generate_command_defaults() {
    let cli = Cli::parse_from(["keybox", "generate"]);
    match &cli.command {
        Command::Generate {
            length, lowercase, uppercase, digits, symbols, chinese,
            passphrase, wordlist, clipboard, env, save, exclude_similar,
        } => {
            assert_eq!(*length, 16);
            assert!(!lowercase);
            assert!(!uppercase);
            assert!(!digits);
            assert!(!symbols);
            assert!(!chinese);
            assert!(!passphrase);
            assert!(wordlist.is_none());
            assert!(!clipboard);
            assert!(env.is_none());
            assert!(save.is_none());
            assert!(!exclude_similar);
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_length() {
    let cli = Cli::parse_from(["keybox", "generate", "--length", "32"]);
    match &cli.command {
        Command::Generate { length, .. } => assert_eq!(*length, 32),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_charset_flags() {
    let cli = Cli::parse_from(["keybox", "generate", "--lowercase", "--uppercase", "--digits"]);
    match &cli.command {
        Command::Generate { lowercase, uppercase, digits, symbols, chinese, .. } => {
            assert!(*lowercase);
            assert!(*uppercase);
            assert!(*digits);
            assert!(!symbols);
            assert!(!chinese);
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_passphrase() {
    let cli = Cli::parse_from(["keybox", "generate", "--passphrase", "--length", "6"]);
    match &cli.command {
        Command::Generate { passphrase, length, .. } => {
            assert!(*passphrase);
            assert_eq!(*length, 6);
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_clipboard() {
    let cli = Cli::parse_from(["keybox", "generate", "--clipboard"]);
    match &cli.command {
        Command::Generate { clipboard, .. } => assert!(*clipboard),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_env() {
    let cli = Cli::parse_from(["keybox", "generate", "--env", "MY_PASSWORD"]);
    match &cli.command {
        Command::Generate { env, .. } => assert_eq!(env.as_deref(), Some("MY_PASSWORD")),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_save() {
    let cli = Cli::parse_from(["keybox", "generate", "--save", "example.com", "alice"]);
    match &cli.command {
        Command::Generate { save, .. } => {
            let s = save.as_ref().unwrap();
            assert_eq!(s[0], "example.com");
            assert_eq!(s[1], "alice");
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_env_clipboard_conflict_fails() {
    let result = Cli::try_parse_from(["keybox", "generate", "--env", "X", "--clipboard"]);
    assert!(result.is_err());
}

#[test]
fn test_generate_command_with_exclude_similar() {
    let cli = Cli::parse_from(["keybox", "generate", "--exclude-similar"]);
    match &cli.command {
        Command::Generate { exclude_similar, .. } => assert!(*exclude_similar),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_wordlist() {
    let cli = Cli::parse_from(["keybox", "generate", "--passphrase", "--wordlist", "/path/to/words.txt"]);
    match &cli.command {
        Command::Generate { passphrase, wordlist, .. } => {
            assert!(*passphrase);
            assert_eq!(wordlist.as_deref(), Some("/path/to/words.txt"));
        }
        _ => panic!("Expected Generate command"),
    }
}
