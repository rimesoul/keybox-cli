use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "keybox", about = "Encrypted credential manager", version)]
pub struct Cli {
    /// Base config directory (default: ~/.config/keybox)
    #[arg(long, global = true)]
    pub base: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize keystore and/or crypt levels
    Init {
        /// Crypt level to initialize: secret, con, or top
        #[arg(long)]
        level: Option<String>,
    },

    /// Add a new credential
    Add {
        /// Credential key as domain:account (use ":account" for default domain)
        target: String,

        /// Crypt level: secret (default), con, or top
        #[arg(long)]
        level: Option<String>,

        /// Human-readable description
        #[arg(long)]
        description: Option<String>,

        /// Comma-separated tags
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,

        /// Read secret from stdin
        #[arg(long)]
        stdin: bool,

        /// Non-interactive mode
        #[arg(long)]
        no_interactive: bool,
    },

    /// Retrieve credential fields
    Get {
        /// Field: password, description, domain, account, tags, metadata, all (default: all)
        field: Option<String>,

        /// Credential key as domain:account
        #[arg(short = 'u', long)]
        user: String,

        /// Copy password to clipboard
        #[arg(short = 'c', long)]
        clipboard: bool,

        /// Inject as env var: VAR or VAR1:VAR2
        #[arg(short = 'e', long)]
        env: Option<String>,

        /// Force display password to stdout
        #[arg(short = 'f', long)]
        force: bool,

        /// Daemon access token
        #[arg(long)]
        access_token: Option<String>,

        /// Non-interactive mode
        #[arg(long)]
        no_interactive: bool,
    },

    /// List credentials (default format: json)
    List {
        /// Output format: json (default) or table
        #[arg(long = "fmt", long = "format", default_value = "json")]
        format: String,

        /// Filter by crypt level
        #[arg(long)]
        level: Option<String>,

        /// Filter by tag
        #[arg(long)]
        tag: Option<String>,
    },

    /// Edit credential metadata
    Edit {
        /// Credential key as domain:account
        target: String,

        /// New description
        #[arg(long)]
        description: Option<String>,

        /// New comma-separated tags
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,

        /// Non-interactive mode
        #[arg(long)]
        no_interactive: bool,
    },

    /// Update credential password
    Update {
        #[command(subcommand)]
        sub: UpdateSub,
    },

    /// Delete a credential
    Delete {
        /// Credential key as domain:account
        target: String,

        /// Non-interactive mode
        #[arg(long)]
        no_interactive: bool,
    },

    /// Start the background daemon
    Serve,

    /// Unlock daemon for crypt level(s)
    Unlock {
        /// Crypt level(s): con, top, or con,top
        #[arg(long)]
        level: String,

        /// Token timeout in minutes (default: 30)
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Copy token to clipboard
        #[arg(long)]
        clipboard: bool,

        /// Inject token into env var
        #[arg(long)]
        env: Option<String>,
    },

    /// Lock daemon (revoke all tokens)
    Lock,

    /// Stop the daemon
    Stop,

    /// Generate random password or passphrase
    Generate(GenerateArgs),
}

#[derive(Subcommand)]
pub enum UpdateSub {
    /// Update credential password
    Password {
        /// Credential key as domain:account
        target: String,
    },
}

#[derive(clap::Args, Clone)]
pub struct GenerateArgs {
    /// Password length (default: 16) or passphrase word count (default: 4)
    #[arg(short = 'l', long, default_value = "16")]
    pub length: usize,

    /// Generate a memorable passphrase instead of random characters
    #[arg(long)]
    pub passphrase: bool,

    /// Custom wordlist file for passphrase generation
    #[arg(long)]
    pub wordlist: Option<String>,

    /// Include lowercase letters
    #[arg(long)]
    pub lowercase: bool,
    /// Include uppercase letters
    #[arg(long)]
    pub uppercase: bool,
    /// Include digits
    #[arg(long)]
    pub digits: bool,
    /// Include symbols
    #[arg(long)]
    pub symbols: bool,
    /// Include CJK characters
    #[arg(long)]
    pub chinese: bool,
    /// Exclude ambiguous characters (0, O, I, l, 1)
    #[arg(long)]
    pub exclude_similar: bool,

    /// Copy to clipboard
    #[arg(short = 'c', long)]
    pub clipboard: bool,

    /// Inject into env var
    #[arg(short = 'e', long)]
    pub env: Option<String>,

    /// Save as credential: domain:account
    #[arg(long)]
    pub save: Option<String>,

    /// Description (only with --save)
    #[arg(long)]
    pub description: Option<String>,

    /// Comma-separated tags (only with --save)
    #[arg(long, value_delimiter = ',')]
    pub tags: Vec<String>,

    /// Crypt level for saved credential (default: secret)
    #[arg(long)]
    pub level: Option<String>,
}
