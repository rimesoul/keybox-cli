# keybox

[中文文档](README_zh.md)

Cross-platform CLI credential manager. Store passwords, tokens, and API keys
with three independent security tiers. Works on macOS, Linux, and Windows —
including headless SSH sessions.

## Security Model

Three tiers, each with an independent encrypted store. All credentials are
encrypted with [age](https://age-encryption.org) (X25519 + ChaCha20-Poly1305).
What differs is how the age identity (private key) is protected:

| Tier | Flag | Identity Protection | Security Root |
|------|------|--------------------|---------------|
| **Secret** | `--secret` | System-bound (Keychain / DPAPI / machine-id) | Machine access |
| **Confidential** | `--confidential` | Password-derived (age passphrase / scrypt) | Human memory |
| **Top Secret** | `--top-secret` | File-hash-derived (SHA-256 → AES-256-GCM) | Physical medium |

- Tiers are **completely independent** — compromising one does not affect others
- Credentials are never stored in plaintext on disk
- An optional daemon process caches decrypted identities in memory for the
  confidential and top-secret tiers (like ssh-agent)

## Install

### Pre-built binaries

Download from [GitHub Releases](https://github.com/rimesoul/keybox-cli/releases).

### Build from source

```bash
git clone https://github.com/rimesoul/keybox-cli.git
cd keybox-cli
cargo build --release
# Binary at: target/release/keybox
```

## Quick Start

```bash
# Secret tier (default) — auto-initializes, no setup needed
keybox add gitea pat               # prompts for token interactively
keybox get gitea pat               # prints to stdout

# Non-interactive (scripting)
keybox add gitea pat --non-interactive --password "ghp_xxx"

# Confidential tier — needs explicit init with a master passphrase
keybox --confidential init
keybox --confidential add ldap workuser

# Inject into a child process without exposing the secret on screen
keybox get gitea pat --env GITEA_TOKEN -- ./my-script.sh

# Copy to clipboard (no terminal output)
keybox get gitea pat --clipboard
```

## Command Reference

```
keybox [--secret|-s|--sec] [--confidential|-c|--con] [--top-secret|-t|--top]
       <operation> [args...]
```

### Operations

| Command | Description |
|---------|-------------|
| `add <domain> <account>` | Add a credential (interactive prompt or `--non-interactive --password`) |
| `get <domain> <account>` | Retrieve credential (`--clipboard` / `--env <VAR>` / stdout) |
| `list [domain]` | List all domains, or accounts in a domain (`--json`) |
| `update <domain> <account>` | Update an existing credential |
| `delete <domain> <account>` | Delete a credential (confirms) |
| `init` | Initialize the current tier |
| `serve` | Start daemon (confidential/top-secret only) |
| `unlock` | Pre-unlock the daemon |
| `lock` | Lock the daemon (clear in-memory key) |
| `stop` | Stop the daemon |

### Output Flags (for `get`)

| Flag | Behavior |
|------|----------|
| *(default)* | Print to stdout |
| `--clipboard` | Copy to system clipboard |
| `--env <VAR> -- <cmd>` | Inject as env var into child process |

### Level Flag Aliases

| Full | Short | Alias |
|------|-------|-------|
| `--secret` | `-s` | `--sec` |
| `--confidential` | `-c` | `--con` |
| `--top-secret` | `-t` | `--top` |

Flags can appear anywhere on the command line. Default is `--secret`.

## Daemon

The confidential and top-secret tiers use a background daemon to cache
decrypted identities in memory:

```bash
# Start daemon (LOCKED state)
keybox --confidential serve

# Unlock (prompts for passphrase once)
keybox --confidential unlock

# Now all commands work without re-entering passphrase
keybox --confidential get gitea pat
keybox --confidential list openai

# Lock when done
keybox --confidential lock

# Or stop entirely
keybox --confidential stop
```

The daemon auto-spawns if needed when a CLI command is issued and the
daemon isn't running.

## Non-Interactive Mode

For scripting, CI/CD, or when stdin is not a TTY:

```bash
keybox add gitea pat --non-interactive --password "token123"
keybox update gitea pat --non-interactive --password "new-token"
keybox --confidential init --non-interactive --password "master123"
keybox --top-secret init --non-interactive --file /path/to/key
```

When running as a subprocess (or `KEYBOX_LLM_CALLING=1`), keybox refuses
interactive prompts and provides guidance:

```
Error: keybox requires interactive input (LLM calling mode detected).
Possible resolutions:
  1. Ask the user to unlock the daemon: `keybox --confidential unlock`
  2. Use non-interactive mode: --non-interactive --password <value>
  3. If the daemon is running but locked, ask the user to unlock it
```

## Storage

All data is under `~/.config/keybox/`:

```
~/.config/keybox/
├── secret/                    # Tier 1: system-bound
│   ├── identity.private.enc
│   ├── identity.pub
│   └── store/<domain>/<account>.enc
├── confidential/              # Tier 2: password-protected
│   ├── identity.private.enc   # age passphrase-encrypted
│   ├── identity.pub
│   └── store/<domain>/<account>.enc
└── top-secret/                # Tier 3: file-hash-protected
    ├── identity.private.enc   # AES-256-GCM encrypted
    ├── identity.pub
    └── store/<domain>/<account>.enc
```

## Platform Details

| Platform | Secret Tier Protection |
|----------|----------------------|
| macOS | Keychain Services |
| Windows | DPAPI (CryptProtectData) |
| Linux | /etc/machine-id + AES-256-GCM + chmod 600 |

The daemon uses Unix domain sockets on macOS/Linux and is not yet available
on Windows (returns a stub error — the secret tier works statelessly on all
platforms).

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

CI runs on every push to main, testing on ubuntu, macos, and windows.

## License

MIT
