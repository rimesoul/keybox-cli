# keybox

[中文文档](README_zh-CN.md)

Cross-platform CLI credential manager. Store passwords, tokens, and API keys
in a single encrypted keystore with three security tiers and metadata for
LLM-based credential selection. Works on macOS, Linux, and Windows.

## Security Model

A single file (`~/.config/keybox/keybox.keystore`) stores all credentials.
**Two-layer encryption** protects both metadata and secrets:

| Layer | Purpose | Cipher |
|-------|---------|--------|
| **Outer** | Protects metadata + encrypted secrets + key pairs | AES-256-GCM (system protector) |
| **Inner** | Protects each credential's secret independently | age X25519 + ChaCha20-Poly1305 |

Three crypt levels determine how the inner age private key is protected:

| Level | ROT | How Private Key Is Protected |
|-------|-----|------------------------------|
| **secret** (default) | Machine access | System protector (Keychain / DPAPI / machine-id) — auto-decrypt |
| **confidential** (`con`) | Human memory | Master passphrase via age scrypt |
| **top-secret** (`top`) | Physical medium | Key file content SHA-256 → AES-256-GCM |

- Encryption (adding credentials) only needs the **public key** — never requires passphrase or key file
- Decryption (getting passwords) requires unlocking the **private key** via the level's ROT
- All metadata (names, descriptions, tags, timestamps) is encrypted in the outer layer
- Two-layer AEAD integrity: AES-256-GCM for the file, age AEAD for each secret

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
# Initialize (secret level auto-initializes; confidential/top-secret are optional)
keybox init

# Add credentials
keybox add github.com:brian           # prompts for token, saves at secret level
keybox add aws:admin --level confidential      # saves at confidential level
keybox add :my-root --tags "default"  # default domain (omitted domain)

# Get credentials
# Default: shows warning, requires --clipboard/--env/--force
keybox get password -u github.com:brian --clipboard   # copy to clipboard
keybox get password -u aws:admin --clipboard          # prompts for passphrase (confidential level)
keybox get password -u github.com:brian --force       # force display to stdout
keybox get password -u github.com:brian --env GITHUB_TOKEN  # inject as env var
keybox get description -u github.com:brian            # prints metadata (no decrypt needed)

# List all credentials (JSON by default)
keybox list
keybox list --fmt table --tag git

# Generate random password
keybox gen --length 32 --clipboard
keybox gen --save github.com:new-token --description "CI bot"
```

## Command Reference

```
keybox [--base <dir>] <command> [args...]
```

### Commands

| Command | Description |
|---------|-------------|
| `init [--level <secret\|con\|top>]` | Initialize keystore and/or crypt levels |
| `add <domain:account> [--level] [--description] [--tags]` | Add a credential (default: secret level) |
| `get [field] -u <domain:account>` | Retrieve field: password, description, tags, metadata, all |
| `list [--fmt json\|table] [--level] [--tag]` | List credentials (default: JSON, secrets masked) |
| `edit <domain:account> --description/--tags` | Edit credential metadata |
| `update password <domain:account>` | Update credential secret (verifies old password) |
| `delete <domain:account>` | Delete a credential |
| `gen [--length] [--passphrase] [--save]` | Generate random password/passphrase |
| `serve` | Start background daemon |
| `unlock --level <con\|top> [--timeout]` | Unlock daemon, get access token |
| `lock` | Lock daemon (revoke all tokens) |
| `stop` | Stop daemon |

### Get Flags

| Flag | Behavior |
|------|----------|
| *(default)* | Warning shown — secret never printed without `--force` |
| `--clipboard, -c` | Copy password to clipboard |
| `--env, -e <VAR>` or `-e <VAR1:VAR2>` | Inject as env var(s) |
| `--force, -f` | Force display password to stdout |
| `--access-token <token>` | Use daemon token (confidential/top-secret, non-interactive) |

### Crypt Levels

Levels are specified per-command via `--level`, not as global flags:

```bash
keybox init --level confidential              # initialize confidential level
keybox add aws:root --level top-secret     # add at top-secret level
keybox unlock --level confidential          # unlock confidential level
```

Default level is `secret` when not specified. The `:account` shorthand uses
`default` as the domain.

## Daemon & Token Access

The daemon (`keybox serve`) holds the keystore in memory. For confidential/top-secret levels,
unlock generates a time-limited access token:

```bash
# Start daemon
keybox serve

# Unlock confidential level (prompts for passphrase), get a 30-min token
keybox unlock --level confidential --timeout 30
# → Token: dGhpcyBpcyBhIHRva2Vu...

# Use token for non-interactive access
keybox get password -u aws:admin --access-token dGhpcyBpcyBhIHRva2Vu...

# Lock revokes all tokens
keybox lock
```

Secret level credentials don't need the daemon — they auto-decrypt directly.

## Non-Interactive Mode

For scripting and CI/CD, use `--no-interactive` with environment variables.

> **⚠️  Avoid setting secrets directly on the command line:**
> `KEYBOX_MASTER_PASSPHRASE=mysecret keybox get ...` exposes the value in
> shell history (`.bash_history`, `.zsh_history`). Always set sensitive
> environment variables inside a wrapper script or a subshell:

```bash
# ✅ Recommended: wrapper script
#!/bin/bash
export KEYBOX_MASTER_PASSPHRASE="mysecret"
keybox get password -u aws:admin --no-interactive --clipboard

# ✅ Or use a subshell
env KEYBOX_MASTER_PASSPHRASE="mysecret" \
    keybox get password -u aws:admin --no-interactive --clipboard

# ✅ Add credential (reads KEYBOX_SET_PASSWORD_ONESHOT automatically)
keybox add github.com:ci --no-interactive

# ✅ Get with daemon token
keybox get password -u aws:admin --no-interactive --clipboard \
    --access-token "$KEYBOX_CON_ACCESS_TOKEN"
```

All sensitive env vars are **cleared** (set to empty) after being read to prevent
accidental persistence in shell sessions.

When running as a subprocess (or `KEYBOX_LLM_CALLING=1`), keybox refuses
interactive prompts and provides guidance.

## Storage

Single keystore file at `~/.config/keybox/keybox.keystore`:

```
Binary header (26 bytes):
  magic "KBOX" | version | key_ref | nonce
Encrypted body (AES-256-GCM):
  JSON with key_pairs + credentials + metadata
```

Each credential record contains:
- `id`, `domain`, `account` — identifiers
- `description`, `tags` — LLM-friendly metadata
- `created_at`, `updated_at`, `last_access_at` — timestamps
- `crypt_level` — secret / con / top
- `secret` — age-encrypted credential value (base64)

## Platform Details

| Platform | System Protector |
|----------|-----------------|
| macOS | Keychain Services |
| Windows | DPAPI (CryptProtectData) |
| Linux | /etc/machine-id + AES-256-GCM + chmod 600 |

The daemon uses Unix domain sockets on macOS/Linux and named pipes on Windows.

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

CI runs on every push to main, testing on ubuntu, macos, and windows.

## License

MIT
