# Keybox CLI — Design Spec

Date: 2026-06-13 | Status: Approved

## Overview

Keybox is a cross-platform CLI credential manager built in Rust. It stores
credentials encrypted with age (modern file encryption) and offers three
independent security tiers with different unlock mechanisms. Designed for
developers who work across Windows, macOS, and headless Linux (SSH) and need
both interactive and automated/scripted credential access.

All three tiers share the same structure — what differs is how the private
identity key is protected:

| Tier | Identity Protection | Security Root |
|------|--------------------|---------------|
| secret | System-bound encryption (DPAPI / machine-id / Keychain) | Machine physical access |
| confidential | Password-derived encryption (age passphrase / scrypt) | Human memory |
| top-secret | File-hash-derived encryption (SHA-256 → AES-GCM) | Physical medium presence |

---

## 1. Directory Layout

```
~/.config/keybox/
├── secret/                        # Tier 1: system-bound, stateless (no daemon)
│   ├── identity.private.enc       # private key, encrypted with system binding
│   ├── identity.pub               # public key (age recipient)
│   └── store/
│       └── <domain>/
│           └── <account>.enc      # encrypted credential
│
├── confidential/                  # Tier 2: password-protected, daemon-backed
│   ├── identity.private.enc       # private key, encrypted with password
│   ├── identity.pub               # public key
│   └── store/
│       └── <domain>/<account>.enc
│
├── top-secret/                    # Tier 3: file-hash-protected, daemon-backed
│   ├── identity.private.enc       # private key, encrypted with file hash
│   ├── identity.pub               # public key
│   └── store/
│       └── <domain>/<account>.enc
│
├── top.key                        # default key file for top-secret tier
├── keyboxd.sock                   # Unix socket for confidential daemon
└── keyboxd-top.sock               # Unix socket for top-secret daemon
```

---

## 2. CLI Interface

### Command Format

```
keybox [LEVEL_FLAG] <operation> [args...] [OUTPUT_FLAG]
```

Level flags may appear at the beginning or end of the command line.
Output flags appear near the end.

### Level Flags (mutually exclusive, default `--secret`)

| Full | Short | Alias | Description |
|------|-------|-------|-------------|
| `--secret` | `-s` | `--sec` | System-bound tier (default) |
| `--confidential` | `-c` | `--con` | Password-protected tier |
| `--top-secret` | `-t` | `--top` | File-hash-protected tier |

### Operations

| Command | Args | Description |
|---------|------|-------------|
| `add` | `<domain> <account>` | Add a credential. Interactive password input (no echo, must confirm). Rejects duplicates — use `update` to overwrite. |
| `update` | `<domain> <account>` | Update an existing credential. Same input flow as `add`. If the credential does not exist, report an error. |
| `get` | `<domain> <account>` | Retrieve credential to stdout. `--clipboard` copies instead. `--env <NAME>` injects into child process. |
| `list` | `[domain]` | Without domain: list all domains. With domain: list accounts under domain. `--json` for structured output. |
| `delete` | `<domain> <account>` | Remove a credential. Confirms before deletion. |
| `init` | *(none)* | Initialize the current tier (only required for confidential and top-secret; secret auto-inits on first use). For top-secret: interactive prompt for key file path, or `--file <path> --non-interactive`. |
| `serve` | *(none)* | Start the daemon for the current tier (confidential/top-secret only). Starts in LOCKED state. |
| `unlock` | *(none)* | Pre-unlock the daemon. Prompts for password/file. Error if daemon not running. |
| `lock` | *(none)* | Clear the daemon's in-memory key. Daemon stays running in LOCKED state. Error if daemon not running. |
| `stop` | *(none)* | Stop the daemon and clear its key from memory. |

### `get` Output Flags (mutually exclusive)

| Flag | Behavior |
|------|----------|
| *(default)* | Print to stdout |
| `--clipboard` | Copy to system clipboard, do not print |
| `--env <VAR_NAME>` | Inject as environment variable into a child process. The secret is **never** printed to stdout. |

**`--env` usage:** The credential value is set as an environment variable and a
child command is executed. The rest of the arguments after a `--` separator
form the child command.

```bash
keybox get gitea pat --env GITEA_TOKEN -- my-script.sh
# GITEA_TOKEN is set in my-script.sh's environment

keybox --confidential get ldap workuser --env LDAP_PASS -- ./login-tool
```

### `add` and `update` Details

- **Interactive (default):** password input hidden (no echo), must confirm by re-entering
- **Non-interactive mode:** `--password <value> --non-interactive` — takes password from command line. Required for scripting/automation. Both flags must be present together.
- Domain/account naming: `[a-zA-Z0-9_-]`, case-sensitive
- `add` on existing credential: error "already exists, use `keybox update` to modify"
- `update` on non-existing credential: error "not found, use `keybox add` to create"

### Non-Interactive / Subprocess Detection

When keybox detects it is running as a subprocess (non-TTY stdin), it must
not attempt interactive prompts. Detection:

1. If stdin is not a TTY → treat as non-interactive
2. If environment variable `KEYBOX_LLM_CALLING=1` is set → treat as non-interactive

In non-interactive mode, any operation that requires interactive input
(passwords, confirmations) **fails with a clear error** instead of hanging or
crashing. Example error messages:

```
Error: keybox requires interactive input but stdin is not a TTY.
Use --non-interactive --password <value> for scripting, or set up a daemon
with `keybox serve` before calling from subprocesses.
```

```
Error: keybox requires interactive input (LLM calling mode detected).
Possible resolutions (in order of preference):
  1. Ask the user to unlock the daemon directly on the machine:
     `keybox --confidential unlock` (or `--top-secret`).
     Once unlocked, all commands will work without prompts.
  2. Use non-interactive mode with a credential provided by the human:
     `--non-interactive --password <value>`
  3. If the daemon is already running but locked, ask the user to unlock it.
  4. Ask the human for the credential directly:
     "I need access to [description]. Can you provide the value or unlock keybox?"
```

---

## 3. Encryption Architecture

### Data Encryption

All credentials are encrypted with **age** (`age-encryption.org`). Each tier
has its own age keypair. Credentials are encrypted with the public key and can
only be decrypted with the corresponding private identity key.

```
Store: password → age::encrypt(identity.pub) → store/<domain>/<account>.enc
Read:  store/<domain>/<account>.enc → age::decrypt(identity) → password
```

### Identity Key Protection (per tier)

| Tier | Platform | Mechanism |
|------|----------|-----------|
| **secret** (stateless) | Windows | DPAPI (`CryptProtectData`) encrypts the identity file. Bound to current user + machine. |
| | macOS | Keychain Services (`SecItemAdd`) stores the identity. Bound to current user's login keychain. |
| | Linux | `/etc/machine-id` as key material for AES-256-GCM encryption of the identity file. File permissions `chmod 600`. |
| **confidential** (daemon) | All | age native passphrase mode (scrypt). `identity.private.enc` contains scrypt-encrypted identity. |
| **top-secret** (daemon) | All | File content → SHA-256 → AES-256-GCM key. `identity.private.enc` encrypted with derived key. |

### Key Points

- Rust crates: `age` (rage) for encryption, `ring` for AEAD, `sha2` for hashing
- Platform-specific: `windows-sys` (DPAPI), `security-framework` (macOS Keychain)
- Linux `machine-id` is the systemd-standard stable machine identifier; non-systemd
  systems fall back to `/var/lib/dbus/machine-id`
- No D-Bus dependency — Linux uses direct file I/O; macOS Keychain API does not
  require a D-Bus session
- TPM / Secure Enclave hardware binding is a future enhancement (see §7)

### Top-Secret Default Key File

The top-secret tier uses a key file whose content is hashed to derive the
encryption key. The default key file path is `~/.config/keybox/top.key`.

Init flow:
1. **Interactive (default):** `keybox --top-secret init` prompts for the key
   file path. Press Enter to accept the default (`~/.config/keybox/top.key`).
2. **Non-interactive:** `keybox --top-secret init --file <path> --non-interactive`
   specifies the path directly.
3. Keybox hashes the file content with SHA-256, derives an AES-256-GCM key,
   encrypts the age identity, and writes `identity.private.enc` and `identity.pub`.
4. When starting the daemon (`keybox --top-secret serve`), the file must be
   present at the configured path.
5. **After** the daemon starts and unlocks, the user may remove the key file
   — the identity remains cached in daemon memory.
6. The key file path never appears on the command line after the daemon is running.

Custom key file path can be specified during `init`:
```bash
keybox --top-secret init --file /custom/path/my-key
```

---

## 4. Daemon Design

### Overview

Two independent daemon processes manage decrypted age identities in memory:

- **keyboxd** — serves the confidential tier (password-protected)
- **keyboxd-top** — serves the top-secret tier (file-hash-protected)
- Tier 1 (secret) has **no daemon** — identity is decrypted from system binding on each operation

### State Machine

```
                serve
                  │
                  ▼
             ┌──────────┐
             │  LOCKED  │──── get/add/etc (auto-unlock) ──→ ┌────────────┐
             └──────────┘     prompts for password/file      │  UNLOCKED  │
                  ▲                                          └────────────┘
                  │                                    unlock  │     │
                  │                                         └─────┘     │
                  │                                            │        │
                  │               lock                          │        │
                  └─────────────────────────────────────────────┘        │
                                                                         │
                                                          stop           │
                                               ┌─────────────────────────┘
                                               ▼
                                          process exits
```

### Commands

| Command | Behavior |
|---------|----------|
| `keybox --confidential serve` | Start daemon in LOCKED state. If already running, no-op. |
| `keybox --confidential unlock` | Pre-unlock: prompt for password, decrypt identity, cache in memory. Error if daemon not running. |
| `keybox --confidential lock` | Clear identity from memory, return to LOCKED state. Error if daemon not running. |
| `keybox --confidential stop` | Clear identity and exit daemon process. |

### Communication

- Linux/macOS: Unix domain socket at `~/.config/keybox/keyboxd.sock` (permissions: `0600`)
- Windows: Named pipe
- Protocol: simple request/response, binary framing
- No D-Bus or other IPC dependency

### Auto-Spawn

When a CLI command needs the daemon and it is not running, the CLI can
auto-spawn it (start in LOCKED state, then auto-trigger unlock prompt on
first credential operation).

### Security

- The decrypted age identity exists only in daemon process memory, never on disk
- Socket permissions restrict access to current user (0600)
- Future: configurable idle timeout for auto-lock (`--timeout 15m`)

---

## 5. Data Model

### Credential File

Each credential is a single file:

```
store/<domain>/<account>.enc   # age-encrypted blob containing the password/token
```

The directory structure is self-describing — `list` operations read the
filesystem directly. No metadata files are stored alongside credentials.

### Domain & Account Names

- Allowed characters: `[a-zA-Z0-9_-]`
- Case-sensitive
- Domain is the namespace (e.g., `gitea`, `ldap`, `openai`)
- Account is the identifier within that domain (e.g., `pat`, `admin`, `api-key`)

---

## 6. Error Handling

| Scenario | Behavior |
|----------|----------|
| Tier not initialized | Prompt to run `init` first. Secret tier auto-inits on first use. |
| Daemon not running (confidential/top-secret) | Auto-spawn daemon, then proceed. |
| Daemon in LOCKED state (get/add/update) | Auto-prompt for password/file, unlock, then proceed. |
| Wrong password on unlock | Error message, remain LOCKED. Allow retry. |
| Missing key file for top-secret tier | Error: key file not found at configured path. |
| `add` on existing credential | Error: "already exists, use `keybox update` to modify." |
| `update` on missing credential | Error: "not found, use `keybox add` to create." |
| Credential not found (get/delete) | Error: "no credential for <domain>/<account>." |
| Invalid domain/account name | Error: illegal characters. |
| Stdin not a TTY (subprocess mode) | Error with guidance: use `--non-interactive` or pre-unlock daemon. |
| `KEYBOX_LLM_CALLING=1` is set | Error with LLM-friendly guidance listing all resolution paths, including asking the human for help. |
| Platform mechanism unavailable | Error with details. |

---

## 7. Future Considerations (Out of v1 Scope)

- Git-based sync (`keybox sync --remote <url>`)
- TPM / Secure Enclave hardware binding for secret tier on Linux
- Idle timeout auto-lock for daemons
- Browser/desktop integration
- Team sharing via age recipients (`age::Encryptor::with_recipients`)
- TOTP code generation
- Import/export (Bitwarden JSON, pass store, CSV)
