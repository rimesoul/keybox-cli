use clap::Parser;
use keybox::cli::{Cli, Command, UpdateSub};

// ── Global --base flag ─────────────────────────────────────────────

#[test]
fn test_no_base_flag_uses_default() {
    let cli = Cli::parse_from(["keybox", "serve"]);
    assert!(cli.base.is_none());
}

#[test]
fn test_global_base_flag() {
    let cli = Cli::parse_from(["keybox", "--base", "/custom/path", "serve"]);
    assert_eq!(cli.base.as_deref(), Some("/custom/path"));
}

#[test]
fn test_base_flag_with_subcommand() {
    let cli = Cli::parse_from(["keybox", "--base", "/tmp/kb", "add", "example.com:alice"]);
    assert_eq!(cli.base.as_deref(), Some("/tmp/kb"));
    match &cli.command {
        Command::Add { target, .. } => assert_eq!(target, "example.com:alice"),
        _ => panic!("Expected Add command"),
    }
}

// ── Init command ───────────────────────────────────────────────────

#[test]
fn test_init_command_default() {
    let cli = Cli::parse_from(["keybox", "init"]);
    match &cli.command {
        Command::Init { level } => assert!(level.is_none()),
        _ => panic!("Expected Init command"),
    }
}

#[test]
fn test_init_command_with_level() {
    let cli = Cli::parse_from(["keybox", "init", "--level", "secret"]);
    match &cli.command {
        Command::Init { level } => assert_eq!(level.as_deref(), Some("secret")),
        _ => panic!("Expected Init command"),
    }
}

// ── Add command ────────────────────────────────────────────────────

#[test]
fn test_add_command_basic() {
    let cli = Cli::parse_from(["keybox", "add", "example.com:alice"]);
    match &cli.command {
        Command::Add { target, level, description, tags, stdin, no_interactive } => {
            assert_eq!(target, "example.com:alice");
            assert!(level.is_none());
            assert!(description.is_none());
            assert!(tags.is_empty());
            assert!(!stdin);
            assert!(!no_interactive);
        }
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn test_add_command_default_domain() {
    let cli = Cli::parse_from(["keybox", "add", ":alice"]);
    match &cli.command {
        Command::Add { target, .. } => assert_eq!(target, ":alice"),
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn test_add_command_with_all_options() {
    let cli = Cli::parse_from([
        "keybox", "add", "example.com:alice",
        "--level", "con",
        "--description", "work login",
        "--tags", "work,email",
        "--stdin",
        "--no-interactive",
    ]);
    match &cli.command {
        Command::Add { target, level, description, tags, stdin, no_interactive } => {
            assert_eq!(target, "example.com:alice");
            assert_eq!(level.as_deref(), Some("con"));
            assert_eq!(description.as_deref(), Some("work login"));
            assert_eq!(*tags, ["work".to_string(), "email".to_string()]);
            assert!(*stdin);
            assert!(*no_interactive);
        }
        _ => panic!("Expected Add command"),
    }
}

#[test]
fn test_add_command_tags_multiple() {
    let cli = Cli::parse_from([
        "keybox", "add", "example.com:alice",
        "--tags", "foo,bar,baz",
    ]);
    match &cli.command {
        Command::Add { tags, .. } => assert_eq!(*tags, ["foo".to_string(), "bar".to_string(), "baz".to_string()]),
        _ => panic!("Expected Add command"),
    }
}

// ── Get command ────────────────────────────────────────────────────

#[test]
fn test_get_command_basic() {
    let cli = Cli::parse_from(["keybox", "get", "--user", "example.com:alice"]);
    match &cli.command {
        Command::Get { user, field, clipboard, env, force, access_token, no_interactive } => {
            assert_eq!(user, "example.com:alice");
            assert!(field.is_none());
            assert!(!clipboard);
            assert!(env.is_none());
            assert!(!force);
            assert!(access_token.is_none());
            assert!(!no_interactive);
        }
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_short_u_flag() {
    let cli = Cli::parse_from(["keybox", "get", "-u", "example.com:alice"]);
    match &cli.command {
        Command::Get { user, .. } => assert_eq!(user, "example.com:alice"),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_field() {
    let cli = Cli::parse_from(["keybox", "get", "password", "-u", "example.com:alice"]);
    match &cli.command {
        Command::Get { field, .. } => assert_eq!(field.as_deref(), Some("password")),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_clipboard() {
    let cli = Cli::parse_from(["keybox", "get", "-c", "-u", "example.com:alice"]);
    match &cli.command {
        Command::Get { clipboard, .. } => assert!(*clipboard),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_env() {
    let cli = Cli::parse_from(["keybox", "get", "-e", "MY_VAR", "-u", "example.com:alice"]);
    match &cli.command {
        Command::Get { env, .. } => assert_eq!(env.as_deref(), Some("MY_VAR")),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_force() {
    let cli = Cli::parse_from(["keybox", "get", "-f", "-u", "example.com:alice"]);
    match &cli.command {
        Command::Get { force, .. } => assert!(*force),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_with_access_token() {
    let cli = Cli::parse_from([
        "keybox", "get", "-u", "example.com:alice",
        "--access-token", "abc123",
    ]);
    match &cli.command {
        Command::Get { access_token, .. } => assert_eq!(access_token.as_deref(), Some("abc123")),
        _ => panic!("Expected Get command"),
    }
}

#[test]
fn test_get_command_no_interactive() {
    let cli = Cli::parse_from(["keybox", "get", "-u", "example.com:alice", "--no-interactive"]);
    match &cli.command {
        Command::Get { no_interactive, .. } => assert!(*no_interactive),
        _ => panic!("Expected Get command"),
    }
}

// ── List command ───────────────────────────────────────────────────

#[test]
fn test_list_command_default_format() {
    let cli = Cli::parse_from(["keybox", "list"]);
    match &cli.command {
        Command::List { format, level, tag } => {
            assert_eq!(format, "json");
            assert!(level.is_none());
            assert!(tag.is_none());
        }
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_table_format() {
    let cli = Cli::parse_from(["keybox", "list", "--format", "table"]);
    match &cli.command {
        Command::List { format, .. } => assert_eq!(format, "table"),
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_fmt_alias() {
    // Note: --fmt alias is not yet implemented; use --format
    let cli = Cli::parse_from(["keybox", "list", "--format", "table"]);
    match &cli.command {
        Command::List { format, .. } => assert_eq!(format, "table"),
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_filter_by_level() {
    let cli = Cli::parse_from(["keybox", "list", "--level", "con"]);
    match &cli.command {
        Command::List { level, .. } => assert_eq!(level.as_deref(), Some("con")),
        _ => panic!("Expected List command"),
    }
}

#[test]
fn test_list_command_filter_by_tag() {
    let cli = Cli::parse_from(["keybox", "list", "--tag", "work"]);
    match &cli.command {
        Command::List { tag, .. } => assert_eq!(tag.as_deref(), Some("work")),
        _ => panic!("Expected List command"),
    }
}

// ── Edit command ───────────────────────────────────────────────────

#[test]
fn test_edit_command_basic() {
    let cli = Cli::parse_from(["keybox", "edit", "example.com:alice"]);
    match &cli.command {
        Command::Edit { target, description, tags, no_interactive } => {
            assert_eq!(target, "example.com:alice");
            assert!(description.is_none());
            assert!(tags.is_empty());
            assert!(!no_interactive);
        }
        _ => panic!("Expected Edit command"),
    }
}

#[test]
fn test_edit_command_with_description() {
    let cli = Cli::parse_from([
        "keybox", "edit", "example.com:alice",
        "--description", "new description",
    ]);
    match &cli.command {
        Command::Edit { description, .. } => assert_eq!(description.as_deref(), Some("new description")),
        _ => panic!("Expected Edit command"),
    }
}

#[test]
fn test_edit_command_with_tags() {
    let cli = Cli::parse_from([
        "keybox", "edit", "example.com:alice",
        "--tags", "a,b,c",
    ]);
    match &cli.command {
        Command::Edit { tags, .. } => assert_eq!(*tags, ["a".to_string(), "b".to_string(), "c".to_string()]),
        _ => panic!("Expected Edit command"),
    }
}

#[test]
fn test_edit_command_no_interactive() {
    let cli = Cli::parse_from([
        "keybox", "edit", "example.com:alice",
        "--no-interactive",
    ]);
    match &cli.command {
        Command::Edit { no_interactive, .. } => assert!(*no_interactive),
        _ => panic!("Expected Edit command"),
    }
}

// ── Update command ─────────────────────────────────────────────────

#[test]
fn test_update_password_command() {
    let cli = Cli::parse_from(["keybox", "update", "password", "example.com:alice"]);
    match &cli.command {
        Command::Update { sub } => match sub {
            UpdateSub::Password { target } => assert_eq!(target, "example.com:alice"),
        },
        _ => panic!("Expected Update command"),
    }
}

// ── Delete command ─────────────────────────────────────────────────

#[test]
fn test_delete_command_basic() {
    let cli = Cli::parse_from(["keybox", "delete", "example.com:alice"]);
    match &cli.command {
        Command::Delete { target, no_interactive } => {
            assert_eq!(target, "example.com:alice");
            assert!(!no_interactive);
        }
        _ => panic!("Expected Delete command"),
    }
}

#[test]
fn test_delete_command_no_interactive() {
    let cli = Cli::parse_from(["keybox", "delete", "example.com:alice", "--no-interactive"]);
    match &cli.command {
        Command::Delete { no_interactive, .. } => assert!(*no_interactive),
        _ => panic!("Expected Delete command"),
    }
}

// ── Simple commands ────────────────────────────────────────────────

#[test]
fn test_serve_command() {
    let cli = Cli::parse_from(["keybox", "serve"]);
    assert!(matches!(cli.command, Command::Serve));
}

#[test]
fn test_unlock_command() {
    let cli = Cli::parse_from(["keybox", "unlock", "--level", "con,top", "--timeout", "15"]);
    match &cli.command {
        Command::Unlock { level, timeout, clipboard, env } => {
            assert_eq!(level.as_deref(), Some("con,top"));
            assert_eq!(*timeout, 15);
            assert!(!clipboard);
            assert!(env.is_none());
        }
        _ => panic!("Expected Unlock command"),
    }
}

#[test]
fn test_unlock_command_with_clipboard() {
    let cli = Cli::parse_from(["keybox", "unlock", "--level", "con", "--clipboard"]);
    match &cli.command {
        Command::Unlock { clipboard, .. } => assert!(*clipboard),
        _ => panic!("Expected Unlock command"),
    }
}

#[test]
fn test_unlock_command_with_env() {
    let cli = Cli::parse_from(["keybox", "unlock", "--level", "con", "--env", "TOKEN_VAR"]);
    match &cli.command {
        Command::Unlock { env, .. } => assert_eq!(env.as_deref(), Some("TOKEN_VAR")),
        _ => panic!("Expected Unlock command"),
    }
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

// ── Generate command ───────────────────────────────────────────────

#[test]
fn test_generate_command_defaults() {
    let cli = Cli::parse_from(["keybox", "generate"]);
    match &cli.command {
        Command::Generate(args) => {
            assert_eq!(args.length, 16);
            assert!(!args.passphrase);
            assert!(args.wordlist.is_none());
            assert!(!args.lowercase);
            assert!(!args.uppercase);
            assert!(!args.digits);
            assert!(!args.symbols);
            assert!(!args.chinese);
            assert!(!args.exclude_similar);
            assert!(!args.clipboard);
            assert!(args.env.is_none());
            assert!(args.save.is_none());
            assert!(args.description.is_none());
            assert!(args.tags.is_empty());
            assert!(args.level.is_none());
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_length() {
    let cli = Cli::parse_from(["keybox", "generate", "--length", "32"]);
    match &cli.command {
        Command::Generate(args) => assert_eq!(args.length, 32),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_short_l() {
    let cli = Cli::parse_from(["keybox", "generate", "-l", "24"]);
    match &cli.command {
        Command::Generate(args) => assert_eq!(args.length, 24),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_passphrase() {
    let cli = Cli::parse_from(["keybox", "generate", "--passphrase"]);
    match &cli.command {
        Command::Generate(args) => assert!(args.passphrase),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_with_wordlist() {
    let cli = Cli::parse_from(["keybox", "generate", "--passphrase", "--wordlist", "/path/to/words.txt"]);
    match &cli.command {
        Command::Generate(args) => {
            assert!(args.passphrase);
            assert_eq!(args.wordlist.as_deref(), Some("/path/to/words.txt"));
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_charset_flags() {
    let cli = Cli::parse_from([
        "keybox", "generate",
        "--lowercase", "--uppercase", "--digits", "--symbols", "--chinese",
    ]);
    match &cli.command {
        Command::Generate(args) => {
            assert!(args.lowercase);
            assert!(args.uppercase);
            assert!(args.digits);
            assert!(args.symbols);
            assert!(args.chinese);
        }
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_exclude_similar() {
    let cli = Cli::parse_from(["keybox", "generate", "--exclude-similar"]);
    match &cli.command {
        Command::Generate(args) => assert!(args.exclude_similar),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_clipboard() {
    let cli = Cli::parse_from(["keybox", "generate", "--clipboard"]);
    match &cli.command {
        Command::Generate(args) => assert!(args.clipboard),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_short_c() {
    let cli = Cli::parse_from(["keybox", "generate", "-c"]);
    match &cli.command {
        Command::Generate(args) => assert!(args.clipboard),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_env() {
    let cli = Cli::parse_from(["keybox", "generate", "--env", "MY_GEN_PASS"]);
    match &cli.command {
        Command::Generate(args) => assert_eq!(args.env.as_deref(), Some("MY_GEN_PASS")),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_short_e() {
    let cli = Cli::parse_from(["keybox", "generate", "-e", "MY_GEN_PASS"]);
    match &cli.command {
        Command::Generate(args) => assert_eq!(args.env.as_deref(), Some("MY_GEN_PASS")),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_save() {
    let cli = Cli::parse_from(["keybox", "generate", "--save", "example.com:alice"]);
    match &cli.command {
        Command::Generate(args) => assert_eq!(args.save.as_deref(), Some("example.com:alice")),
        _ => panic!("Expected Generate command"),
    }
}

#[test]
fn test_generate_command_save_with_details() {
    let cli = Cli::parse_from([
        "keybox", "generate",
        "--save", "example.com:alice",
        "--description", "generated password",
        "--tags", "auto,generated",
        "--level", "con",
    ]);
    match &cli.command {
        Command::Generate(args) => {
            assert_eq!(args.save.as_deref(), Some("example.com:alice"));
            assert_eq!(args.description.as_deref(), Some("generated password"));
            assert_eq!(*args.tags, ["auto".to_string(), "generated".to_string()]);
            assert_eq!(args.level.as_deref(), Some("con"));
        }
        _ => panic!("Expected Generate command"),
    }
}
