use clap::{Parser, Subcommand, ArgGroup};

/// Cross-platform CLI credential manager
#[derive(Parser, Debug)]
#[command(name = "keybox", about = "Cross-platform CLI credential manager")]
#[command(group = ArgGroup::new("level").args(&["secret", "confidential", "top_secret"]).multiple(false))]
pub struct Cli {
    /// System-bound tier (default)
    #[arg(long = "secret", short = 's', alias = "sec", group = "level", global = true)]
    pub secret: bool,

    /// Password-protected tier
    #[arg(long = "confidential", short = 'c', alias = "con", group = "level", global = true)]
    pub confidential: bool,

    /// File-hash-protected tier
    #[arg(long = "top-secret", short = 't', alias = "top", group = "level", global = true)]
    pub top_secret: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Command {
    /// Add a new credential
    Add {
        domain: String,
        account: String,
        #[arg(long)]
        non_interactive: bool,
        #[arg(long, requires = "non_interactive")]
        password: Option<String>,
    },
    /// Retrieve a credential
    Get {
        domain: String,
        account: String,
        #[arg(long, conflicts_with = "clipboard")]
        env: Option<String>,
        #[arg(long, conflicts_with = "env")]
        clipboard: bool,
    },
    /// List domains or accounts
    List {
        domain: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Delete a credential
    Delete {
        domain: String,
        account: String,
    },
    /// Update an existing credential
    Update {
        domain: String,
        account: String,
        #[arg(long)]
        non_interactive: bool,
        #[arg(long, requires = "non_interactive")]
        password: Option<String>,
    },
    /// Initialize the current tier
    Init {
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        non_interactive: bool,
    },
    /// Start the daemon for the current tier
    Serve,
    /// Pre-unlock the daemon
    Unlock,
    /// Lock the daemon (clear in-memory key)
    Lock,
    /// Stop the daemon
    Stop,
}

impl Cli {
    pub fn tier(&self) -> Tier {
        if self.confidential {
            Tier::Confidential
        } else if self.top_secret {
            Tier::TopSecret
        } else {
            Tier::Secret
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Secret,
    Confidential,
    TopSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add,
    Get,
    List,
    Delete,
    Update,
    Init,
    Serve,
    Unlock,
    Lock,
    Stop,
}

impl Command {
    pub fn to_operation(&self) -> Operation {
        match self {
            Command::Add { .. } => Operation::Add,
            Command::Get { .. } => Operation::Get,
            Command::List { .. } => Operation::List,
            Command::Delete { .. } => Operation::Delete,
            Command::Update { .. } => Operation::Update,
            Command::Init { .. } => Operation::Init,
            Command::Serve => Operation::Serve,
            Command::Unlock => Operation::Unlock,
            Command::Lock => Operation::Lock,
            Command::Stop => Operation::Stop,
        }
    }
}

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".into());
    }
    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' {
            return Err(format!(
                "Invalid character '{}' in name. Only a-z, A-Z, 0-9, -, _ allowed.",
                ch
            ));
        }
    }
    Ok(())
}
