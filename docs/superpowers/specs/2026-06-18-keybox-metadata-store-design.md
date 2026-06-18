# Design Spec: Keybox Metadata Store — Unified Encrypted Store

Date: 2026-06-18
Status: Draft — awaiting review

---

## 1. Overview

### 1.1 Problem

Keybox currently stores each credential as an independent age-encrypted file under
`store/<domain>/<account>.enc`, with zero metadata beyond the filesystem path.
This prevents:

- LLM-based credential selection (no descriptions, tags, or usage context)
- Advanced features (expiry tracking, usage statistics, tag filtering)
- Cross-credential integrity guarantees

### 1.2 Solution

Replace file-per-secret storage with a **single encrypted file** containing a
structured JSON payload that holds all credentials, metadata, key pairs, and
integrity verification data in one atomic unit.

### 1.3 Non-Goals

- The ROT design (Keychain, DPAPI, machine-id, passphrase, key file) is **unchanged**.
- The age encryption primitive for credential secrets is **preserved** (X25519 +
  ChaCha20-Poly1305).
- This is a breaking format change. No backward compatibility with the old
  file-per-secret format.

---

## 2. File Format

### 2.1 Outer Container: Binary Header + Encrypted JSON Body

```
┌─────────────────────────────────────────────────────────────┐
│ Offset  │ Size     │ Field              │ Description       │
├─────────┼──────────┼────────────────────┼───────────────────┤
│ 0       │ 4        │ magic              │ "KBOX" (0x4B424F58)│
│ 4       │ 2        │ version            │ 0x0001 (u16 BE)   │
│ 6       │ 8        │ key_ref            │ SHA-256 of outer  │
│         │          │                    │ AES key (first 8B)│
│ 14      │ 12       │ nonce              │ AES-256-GCM nonce │
│ 26      │ variable │ ciphertext (+ tag) │ AES-256-GCM       │
│         │          │                    │ encrypted JSON    │
│         │          │                    │ (16-byte GCM tag  │
│         │          │                    │  appended)        │
└─────────────────────────────────────────────────────────────┘
```

**Field explanations:**

- **Magic "KBOX"**: Identifies the file as a Keybox keystore. Enables clear error
  messages ("not a valid Keybox keystore file") on corrupted or wrong files.

- **Key ref (8 bytes)**: First 8 bytes of SHA-256(outer AES key). Allows
  pre-checking whether the system protector returned the correct key before
  attempting decryption. A mismatch means the key material has changed (e.g.,
  Keychain item deleted, machine-id rotated). Note: 8 bytes provides 64 bits of
  collision resistance — sufficient for single-user local use.

- **Nonce (12 bytes)**: Random 96-bit nonce for AES-GCM. MUST be freshly
  generated for every write operation. Nonce reuse with the same key would
  catastrophically break GCM security.

- **Ciphertext**: The JSON payload (Section 3) encrypted with AES-256-GCM.
  The 16-byte GCM authentication tag is appended to the ciphertext. GCM provides
  AEAD: confidentiality + integrity in one operation. Any tampering of the file
  causes GCM decryption to fail.

**Integrity note:** See Section 4.5 for the complete two-layer integrity model.

### 2.2 Outer Encryption

The outer layer uses the **system protector** (the same protector used for the
current `secret` tier):

| Platform | Protector | Cipher |
|----------|-----------|--------|
| macOS    | Keychain (Security Framework) | AES-256-GCM |
| Windows  | DPAPI (`CryptProtectData`) | AES-256-GCM (via DPAPI) |
| Linux    | machine-id derived key | AES-256-GCM |

The protector key is derived from the store file path for domain separation
(preventing key reuse across different store files).

### 2.3 File Path

```
~/.config/keybox/keybox.keystore
```

Single file, replacing the current directory-based `store/<domain>/<account>.enc`
structure. The daemon socket (`keyboxd.sock`) remains unchanged.

---

## 3. JSON Payload Schema

### 3.1 Top-Level Structure

```json
{
  "version": 1,
  "created_at": "2026-06-18T10:00:00Z",
  "updated_at": "2026-06-18T10:30:00Z",
  "key_pairs": {
    "secret": {
      "public_key": "age1xxxxxxxxxxxx...",
      "encrypted_private_key": "<base64>",
      "protector": "macos-keychain"
    },
    "con": {
      "public_key": "age1xxxxxxxxxxxx...",
      "encrypted_private_key": "<base64>",
      "protector": "age-passphrase"
    },
    "top": {
      "public_key": "age1xxxxxxxxxxxx...",
      "encrypted_private_key": "<base64>",
      "protector": "aes-gcm-keyfile"
    }
  },
  "credentials": {
    "github.com:brian": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "domain": "github.com",
      "account": "brian",
      "description": "Personal access token for keybox repo",
      "tags": ["git", "api"],
      "created_at": "2026-01-01T00:00:00Z",
      "updated_at": "2026-06-15T10:30:00Z",
      "last_access_at": "2026-06-18T09:00:00Z",
      "crypt_level": "secret",
      "secret": "<age encrypted ciphertext, base64>"
    }
  }
}
```

### 3.2 `key_pairs` — Per-Tier Key Material

Each tier that has been initialized has an entry under `key_pairs`. Tiers that
have NOT been initialized are simply absent from the map. This enables lazy
initialization: the presence or absence of a key determines what has been
initialized.

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string | Age X25519 public key (Bez32: `age1...`). Never secret. |
| `encrypted_private_key` | string (base64) | Age X25519 identity (private key), encrypted by the tier's ROT protector. |
| `protector` | string | Identifier: `macos-keychain`, `windows-dpapi`, `linux-machine-id`, `age-passphrase`, `aes-gcm-keyfile` |

### 3.3 `credentials` — Flat Map

Credentials are stored as a flat map keyed by `<domain>:<account>`. Each
credential record:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | UUID4 | yes | Stable identifier across renames |
| `domain` | string | yes | Service domain |
| `account` | string | yes | Account identifier |
| `description` | string | no | Human-readable description for LLM context |
| `tags` | string[] | no | Searchable tags |
| `created_at` | ISO 8601 | yes | When the credential was added |
| `updated_at` | ISO 8601 | yes | Last modification time |
| `last_access_at` | ISO 8601 | no | Last time the secret was retrieved (`get password`) |
| `crypt_level` | string | yes | `"secret"`, `"con"`, or `"top"` |
| `secret` | string (base64) | yes | Age-encrypted credential value, using the public_key from `key_pairs[<crypt_level>].public_key` |

**Why flat map?** O(1) lookup by `<domain>:<account>`. Filtering by `crypt_level`
for list operations is O(n) with <100 records, negligible cost.

---

## 4. Encryption Architecture

### 4.1 Two-Layer Model

```
Layer 1 (Outer): System Protector
  └── AES-256-GCM → decrypts → JSON payload
       ├── Provides: metadata confidentiality + integrity
       └── Auto-unlock: no user interaction needed (OS-bound trust)

Layer 2 (Inner): Age X25519 per crypt_level
  └── Each crypt_level has its own X25519 key pair
       ├── Public key (public_key): stored in plaintext in JSON → used for encryption
       ├── Private key (identity): encrypted by tier-specific ROT → used for decryption
       └── Secret field in each credential: age-encrypted ciphertext
```

### 4.2 Encryption Flow (add credential)

```
Input: plaintext secret, crypt_level, metadata

1. JSON is loaded (outer auto-decrypted)
2. public_key = key_pairs[<crypt_level>].public_key
3. secret_ciphertext = age_encrypt(public_key, plaintext)
4. credential record added to JSON
5. JSON serialized, outer-encrypted, written to temp file, renamed
```

**Key property:** Encryption (step 3) only needs the public key. No user
interaction, no passphrase entry, no key file needed. This works identically
for all crypt_levels.

### 4.3 Decryption Flow (get password)

```
Input: domain:account

1. JSON is loaded (outer auto-decrypted)
2. Record = credentials["<domain>:<account>"]
3. crypt_level = record.crypt_level
4. encrypted_private_key = key_pairs[<crypt_level>].encrypted_private_key
5. identity = protector_for(<crypt_level>).unprotect(encrypted_private_key)
   ├── secret level: system protector → auto (zero interaction)
   ├── con level:   age passphrase protector → user prompted (masked input)
   └── top level:   key file protector → user prompted for file path (masked input)
6. plaintext = age_decrypt(identity, record.secret)
7. Update last_access_at
```

### 4.4 Key Pair Lifecycle

**Creation (init):**
```
1. Generate age X25519 key pair
2. Store public_key in JSON (plaintext)
3. Store encrypted_private_key in JSON (protected by tier ROT)
```

**Rotation (future):**
```
1. Generate new key pair
2. Re-encrypt all credentials of that crypt_level with new public_key
3. Replace old key pair in JSON
```

### 4.5 Integrity Model

Two independent layers protect the keystore at different granularities:

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: Outer AES-256-GCM (file-level)                     │
│  ───────────────────────────────────                         │
│  Scope:   the entire keybox.keystore file                    │
│  When:    verified on every file read (decryption)           │
│  Catches: any bit flip or tampering anywhere in the file     │
│  Failure: "Keystore file corrupted or tampered"              │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Layer 2: age AEAD (credential-level)                 │   │
│  │ ────────────────────                                 │   │
│  │ Scope:   each credential's `secret` field            │   │
│  │ When:    verified on inner decryption                │   │
│  │ Catches: tampering with a single credential's        │   │
│  │          ciphertext                                  │   │
│  │ Failure: age decryption error                        │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

**Why two layers?**

- **Layer 1** (AES-GCM): The entire file is one AEAD blob. Any on-disk
  tampering — bit flips, truncation, replacement — fails GCM decryption.
- **Layer 2** (age): Each credential's secret is independently encrypted with
  age's ChaCha20-Poly1305 AEAD. Even if the outer layer were somehow
  compromised, individual secrets remain protected under their respective
  identities.

**Computation order (write):**
```
1. Update key_pairs or credentials in memory
2. Serialize JSON
3. Encrypt with AES-256-GCM (new random nonce)
4. Write to keybox.keystore.tmp → fsync → rename
```

**Verification order (read):**
```
1. Read file, verify magic + version
2. Verify key_ref matches outer AES key
3. Decrypt with AES-256-GCM → GCM tag verified during decryption
4. Parse JSON
5. (On credential access) Decrypt secret with age → age AEAD verified
```

---

## 5. CLI Interface

### 5.1 Command Hierarchy

```
keybox
├── init          Initialize store and/or crypt levels
├── add           Add a new credential
├── get           Retrieve fields from a credential
├── list          List credentials with metadata
├── edit          Modify credential metadata
├── delete        Remove a credential
├── generate      Generate random passwords/passphrases
├── serve         Start daemon
├── unlock        Unlock the daemon for a crypt level
├── lock          Lock the daemon (revoke all tokens)
```

### 5.2 `keybox init`

```
keybox init [--level <secret|con|top>]
```

#### New Store (keybox.keystore does not exist)

If `--level` is specified, initialize only that tier. If `--level` is NOT specified,
initialize sequentially in order:

1. **Auto-init secret tier** (system protector, zero interaction)
2. **Prompt: "Initialize confidential level? (y/N)"**
   - If yes: prompt for master passphrase (masked + confirmation)
   - Warning: "This passphrase cannot be recovered if forgotten. Keep it safe and
     do not share it with anyone."
3. **Prompt: "Initialize top-secret level? (y/N)"**
   - If yes: prompt for key file path (masked input, no echo)
   - Validation: file must exist, must be non-empty
   - Warning: "The CONTENT of this file is your encryption key — not its path.
     If the file content changes, credentials encrypted at this level will be
     irrecoverable. Keep this file safe and do not share it."
   - Reminder: "You are entering the file PATH — it will not be echoed on screen."

#### Existing Store (keybox.keystore exists)

- Check which `key_pairs` entries are missing
- If `--level` specified:
    - If that tier already initialized: error, refuse
    - If not initialized: initialize only that tier
- If `--level` NOT specified:
    - Show status (which tiers initialized)
    - Sequentially prompt to initialize each missing tier (same flow as new store)
- If all tiers already initialized: error, refuse

All ROT input is always masked (hidden input, no echo).

### 5.3 `keybox add`

```
keybox add <domain:account> [--level <secret|con|top>] [--description "..."] [--tags "a,b"]
       [--stdin] [--no-interactive]

<domain:account> can use "default" as domain:
  keybox add :myaccount           → stored as "default:myaccount"
  keybox add github.com:brian     → stored as "github.com:brian"

Behavior:
1. If the store has no key_pairs at all:
    → Error: "No crypt levels initialized. Run 'keybox init' first."

2. If --level not specified: defaults to "secret" tier.

3. If --level specified and key_pairs[<level>] is missing:
    → Warning: "<level> level not initialized."
    → Automatically trigger initialization for that tier (same flow as init),
      then proceed to add.

4. Secret input:
    → Interactive: Prompt (masked) for the credential value
    → Or read from stdin: echo "token" | keybox add github:token --stdin
    → Non-interactive (--no-interactive):
        Reads password from KEYBOX_SET_PASSWORD_ONESHOT env var
        After reading, the env var is SET TO EMPTY to prevent persistence

5. Encrypt credential value with key_pairs[<level>].public_key

6. Add record to in-memory JSON, write to disk atomically

Note: Operations are performed in memory. The file is only written once the
operation completes successfully. If the process is interrupted (Ctrl+C), the
file remains unchanged.

### 5.4 `keybox get`

```
keybox get [<field>] -u <domain:account> [options]

If <field> is omitted, defaults to "all" behavior (see below).

Fields:
  password | secret    → the decrypted credential value
  description           → human-readable description (from metadata, no decryption)
  domain, account       → identifiers (from metadata)
  tags                  → comma-separated tag list (from metadata)
  metadata              → all metadata fields as JSON (no secret)
  all                   → all fields EXCEPT secret (secret shown as <masked>)

Options:
  --clipboard, -c       → Copy to clipboard (default for password)
  --env, -e <VAR1>[:<VAR2>]
                        → Inject as environment variables. If one name given:
                          injects password only. If two names given (colon-separated):
                          first=account, second=password.
                          Example: --env OA_ACCOUNT:OA_PASSWORD
  --force, -f           → Force display password to stdout
  --access-token <t>    → Use daemon token instead of interactive ROT entry
  --no-interactive      → Non-interactive mode (for scripts/automation)
  --user, -u            → Credential key <domain:account>
```

#### Default Behavior (get password)

```
keybox get password -u github:brian

1. ⚠ WARNING displayed:
   "For security, passwords are NOT displayed in plaintext by default.
    Use --clipboard to copy or --env to inject. Use --force to force display
    password to stdout."

2. Then:
   → secret level: auto-decrypt → copy to clipboard
   → con level: prompt for passphrase (masked) → decrypt → copy to clipboard
   → top level: prompt for key file path (masked) → decrypt → copy to clipboard

3. The secret is NEVER printed to stdout unless --force is specified.
```

#### get all (default when no field specified)

```
keybox get -u github:brian          (same as `keybox get all -u github:brian`)

Returns all metadata fields. The `secret` field is replaced with "<masked>"
since it is stored encrypted and meaningless to display.

Output:
  {
    "domain": "github.com",
    "account": "brian",
    "description": "...",
    "tags": ["git"],
    "crypt_level": "secret",
    "created_at": "...",
    "secret": "<masked>"
  }
```

Only `keybox get password` (or `keybox get secret`) decrypts and returns the
actual credential value.

#### --env Injection

```
keybox get password -u github:brian --env OA_ACCOUNT:OA_PASSWORD
  → Injects: OA_ACCOUNT=brian, OA_PASSWORD=<decrypted password>

keybox get password -u github:brian --env MY_TOKEN
  → Injects: MY_TOKEN=<decrypted password>  (password only)
```

#### Default Domain

If domain is omitted, `default` is used:

```
keybox add :my-root-account    → stored as "default:my-root-account"
keybox get password -u :my-root-account   → looks up "default:my-root-account"
```

#### Non-Interactive Mode

For scripted/automated access, use `--no-interactive`. ROT material must be
provided via environment variables:

```
# Environment variables for ROT injection:
KEYBOX_MASTER_PASSPHRASE    → con level passphrase
KEYBOX_MASTER_KEYFILE       → top level key file path

# Environment variables for daemon token:
KEYBOX_CON_ACCESS_TOKEN     → token for con level access
KEYBOX_TOP_ACCESS_TOKEN     → token for top level access

# Precedence: --access-token > env var token > env var ROT
```

```
# Non-interactive with token (requires keybox serve to be running):
keybox get password -u github:brian --access-token <token> --no-interactive

# Non-interactive with passphrase env:
KEYBOX_MASTER_PASSPHRASE=mysecret keybox get password -u aws:admin --no-interactive

# Non-interactive with token env:
KEYBOX_CON_ACCESS_TOKEN=abc123 keybox get password -u aws:admin --no-interactive
```

**Non-interactive restrictions:**
- Plaintext output to stdout is NOT supported in non-interactive mode.
  If neither `--env` nor `--clipboard` is specified, error:
  "Non-interactive mode requires --env or --clipboard."
- `--access-token` and token env vars only work when `keybox serve` is running.
  If the daemon is not running, error:
  "Daemon not running. Token-based access requires 'keybox serve'."
- Secret level credentials do NOT require unlock or token — they auto-decrypt
  and can be accessed directly without the daemon.
- All sensitive env vars (`KEYBOX_MASTER_PASSPHRASE`, `KEYBOX_MASTER_KEYFILE`,
  `KEYBOX_CON_ACCESS_TOKEN`, `KEYBOX_TOP_ACCESS_TOKEN`) are cleared (set to empty)
  after being read, to prevent accidental persistence.

### 5.5 `keybox list` / `keybox ls`

```
keybox list [--level <level>] [--tag <tag>] [--format|--fmt json|table]

Default output format: json
Use --fmt table for human-readable table output.

Output (table format, --fmt table):
  DOMAIN:ACCOUNT      LEVEL    TAGS         DESCRIPTION
  github.com:brian    secret   git, api     Personal access token for keybox repo
  aws:admin           con      infra        AWS root account

Output (json format, for LLM consumption):
  [
    {
      "id": "...",
      "key": "github.com:brian",
      "domain": "github.com",
      "account": "brian",
      "description": "...",
      "tags": ["git", "api"],
      "crypt_level": "secret",
      "created_at": "...",
      "last_access_at": "...",
      "secret": "<masked>"
    }
  ]

The `secret` field is always shown as `<masked>` — it is stored encrypted and
displaying the ciphertext serves no purpose and could aid brute-force attempts.
Metadata is read directly from the outer JSON layer; no inner decryption needed.
`keybox list` works even when con/top tiers are locked.

### 5.6 `keybox edit`

```
keybox edit <domain:account> --description "..." --tags "a,b,c"
       [--no-interactive]

Modifies metadata fields only (description, tags). Does NOT touch the secret.

Security: For con/top credentials, editing requires ROT verification (same flow
as get password for that tier). This prevents unauthorized modification of
credentials protected by a passphrase or key file. For secret level, no
verification needed (auto-decrypt).

The operation is in-memory: modifications are applied to the in-memory JSON,
then written atomically to disk.
```

### 5.7 `keybox update`

```
keybox update password <domain:account>

Updates the credential value (secret) for an existing credential.

Behavior:
1. Verify ROT for the credential's crypt_level (same flow as get password):
   - secret: auto
   - con: prompt for passphrase (masked)
   - top: prompt for key file path (masked)

2. Prompt for current password (masked):
   → Decrypt existing secret and compare
   → If mismatch: "Current password is incorrect." Abort.

3. Prompt for new password (masked + confirmation):
   → "Enter new password: " (masked)
   → "Confirm new password: " (masked)
   → If mismatch: "Passwords do not match." Abort.

4. Re-encrypt with key_pairs[<crypt_level>].public_key

5. Update record in-memory, write atomically

Non-interactive mode is NOT supported for `update password` initially.
```

### 5.8 `keybox delete`

```
keybox delete <domain:account> [--no-interactive]

Removes the record from JSON, rewrites file.
Prompts for confirmation.

Security: For con/top credentials, deletion requires ROT verification (same flow
as get password for that tier). This prevents unauthorized deletion of protected
credentials. For secret level, no verification needed (auto-decrypt).

### 5.9 `keybox serve`, `keybox unlock`, `keybox lock`

See Section 6 (Daemon & Unlock/Token).

### 5.10 `keybox generate` / `keybox gen`

```
keybox generate [--length <n>] [--passphrase] [--clipboard] [--env <VAR>]
       [--lowercase] [--uppercase] [--digits] [--symbols] [--chinese]
       [--exclude-similar]
       [--save <domain:account>] [--description "..."] [--tags "a,b"] [--level <level>]

Generates a random password or passphrase.

Generation options:
  --length, -l <n>     → Password length in characters (default: 16)
                          Passphrase word count (default: 4)
                          Max password length: 256 bytes
                          Max passphrase words: 128

  --passphrase          → Generate a memorable passphrase (EFF wordlist)
  --wordlist <PATH>     → Custom wordlist file (one word per line)

  --lowercase           → Include lowercase (a-z)
  --uppercase           → Include uppercase (A-Z)
  --digits              → Include digits (0-9)
  --symbols             → Include symbols
  --chinese             → Include CJK Unified Ideographs
  --exclude-similar     → Exclude ambiguous chars (0, O, I, l, 1)

  --clipboard, -c       → Copy to clipboard
  --env, -e <VAR>       → Inject into environment variable

Save options (only with --save):
  --save <domain:account>
                         → Save generated password as a credential.
                            If <domain:account> already exists: error,
                            "Credential already exists: <domain:account>"
  --description "..."    → Credential description
  --tags "a,b"           → Comma-separated tags
  --level <level>        → Crypt level (default: secret)

Default behavior (no charset flags):
  → Uses default charset: a-z, A-Z, 0-9, _
  → Length: 16 characters for password, 4 words for passphrase

Example:
  keybox gen --length 32 --clipboard
  keybox gen --passphrase --length 6
  keybox gen --symbols --digits --exclude-similar --length 24
  keybox gen --save github.com:new-token --description "CI bot" --tags "github,ci"
  keybox gen --save :my-password --tags "default"
```

**Compatibility note:** This preserves the existing `keybox generate` interface
from `src/cli.rs` and `src/generate.rs`. The only additions are explicit
default word count (4) and `--save` for direct credential creation.

---

## 6. Daemon & Unlock/Token Mechanism

### 6.1 Daemon (`keybox serve`)

Starts a background process (`keyboxd`) that holds the decrypted JSON store in
memory. The daemon communicates with the CLI via Unix domain socket (macOS/Linux)
or named pipe (Windows), same IPC mechanism as the current design.

**When the daemon is needed:**
- Token-based access (`--access-token`) for con/top credentials
- `keybox unlock` / `keybox lock` commands
- Secret level credentials and metadata access (`list`, `get description`, etc.)
  do NOT require the daemon — they work directly via the keystore file.

**Daemon states:**

```
LOCKED (initial)
  ├── JSON decrypted in memory (outer auto-decrypted on start)
  ├── Metadata accessible: list, get description, get tags
  ├── credential secrets: NOT accessible (inner decryption needs unlock)
  └── Tokens: none

UNLOCKED (after keybox unlock)
  ├── JSON + decrypted identities in memory for unlocked tier(s)
  ├── credential secrets: accessible for unlocked tiers
  └── Tokens: active tokens with scope and expiry
```

### 6.2 `keybox unlock`

```
keybox unlock --level <con|top>[,<con|top>...] [--timeout <minutes>]
       [--clipboard] [--env <VAR>]

Note: "secret" level does NOT need unlock — secret credentials auto-decrypt
via the system protector. Only "con" and "top" require unlock.

Behavior:
1. Daemon must be running (keybox serve)
2. For each requested level:
   a. Prompt for ROT (masked input, no echo):
      - con: passphrase → must match the passphrase used during init
        (verified by attempting to decrypt key_pairs["con"].encrypted_private_key)
      - top: key file path (masked — path is not shown on screen)
        → Validation: file must exist and be non-empty
        → Error if file not found: "Key file not found: <path>"
        → Error if file empty: "Key file is empty"
        → Reminder: "The file CONTENT is the encryption key, not its path.
          If the content changes, credentials at this level become irrecoverable."
   b. Decrypt key_pairs[<level>].encrypted_private_key → get age identity
   c. Store identity in daemon memory

3. For each requested level, generate a random access token:
   token = base64(random_bytes(32))   // 256-bit CSPRNG, NOT time-derived
   Store: {token, scope: <level>, expires_at: now + timeout}

4. Output token(s):
   → --clipboard: copy to clipboard
   → --env <VAR>: inject into environment variable
   → default: print to stdout
```

**Why random token, not time-derived?** Predictable tokens enable enumeration
attacks. A CSPRNG token is information-theoretically unpredictable.

### 6.3 `keybox get --access-token`

```
keybox get password -u github:brian --access-token <token>

Behavior:
1. CLI sends {action: "get", key: "github:brian", field: "password", token: "..."}
2. Daemon looks up token:
   → Not found: reject with "Invalid token"
   → Expired: reject with "Token expired. Run keybox unlock."
   → Scope insufficient (e.g., token scope=con, credential crypt_level=top):
     reject with "Token scope insufficient. Required: top, have: con"
   → Valid: proceed to decrypt and return credential value
```

### 6.4 `keybox lock`

```
keybox lock

Behavior:
1. Clears ALL tokens from daemon memory (all scopes, all expiry times)
2. Clears decrypted identities from daemon memory
3. Daemon returns to LOCKED state
   → Metadata still accessible (outer layer stays decrypted)
   → Secrets inaccessible until next unlock
   → Interactive get password still works (prompts for ROT each time)
```

### 6.5 Token Scope

Each token authorizes exactly **one** crypt level. No inheritance. Secret level
does not need a token (auto-decrypt). Only con and top use tokens:

```
Token scope = "top"    → can decrypt top credentials only
Token scope = "con"    → can decrypt con credentials only
```

To access credentials at multiple levels via token, run unlock for each level:

```
keybox unlock --level con,top --timeout 30
```

This generates two independent tokens (one for con, one for top), or one token
with multiple scopes if the CLI accepts comma-separated levels. The daemon
unlocks each tier's identity using its respective ROT (passphrase for con,
key file for top).

### 6.6 Multiple Unlocks

```
keybox unlock --level con --timeout 30 → token_1 (scope=con)
keybox unlock --level top --timeout 10 → token_2 (scope=top)
keybox lock                            → both token_1 and token_2 invalidated
```

Each unlock generates a new independent token. Multiple concurrent tokens with
different scopes and expiry times coexist. Lock invalidates all.

---

## 7. Initialization Flow

### 7.1 New Store Creation

```
keybox init  (no --level, no existing file)

Sequential flow:
1. Secret tier (auto, zero interaction):
   a. Generate random 256-bit AES key for outer encryption
   b. Protect AES key with system protector → Keychain/DPAPI/machine-id
   c. Generate age X25519 key pair for secret tier
   d. Protect private key with system protector
   e. Create keybox.keystore with initial JSON

2. Confidential tier (prompt):
   a. "Initialize confidential level keystore? (y/N)"
   b. If yes: prompt for master passphrase (masked + confirmation)
      Warning: "This passphrase cannot be recovered if forgotten. Keep it safe
      and do not share it with anyone."
   c. Generate age X25519 key pair for con tier
   d. Protect private key with age passphrase protector
   e. Add to key_pairs in JSON, rewrite file

3. Top-secret tier (prompt):
   a. "Initialize top-secret level keystore? (y/N)"
   b. If yes: prompt for key file path (masked input, no echo)
      Reminder: "The path will NOT be shown on screen."
      Warning: "The CONTENT of this file is your encryption key — not its path.
      Use a file with non-trivial content. If the content changes, credentials at
      this level become irrecoverable. Keep this file safe and do not share it."
   c. Validate: file must exist, must be non-empty
   d. SHA-256 the file content → AES-256 key
   e. Generate age X25519 key pair for top tier
   f. Protect private key with AES-GCM keyfile protector
   g. Add to key_pairs in JSON, rewrite file
```

### 7.2 Initializing Specific Tier on Existing Store

```
keybox init --level con  (store exists, con not yet initialized)

1. Check key_pairs: is "con" present? → No → proceed
2. Prompt for passphrase (masked + confirmation, with warnings)
3. Generate key pair, protect, add to JSON
4. Rewrite file
```

### 7.3 Lazy Initialization via `keybox add`

```
keybox add aws:admin --level con

1. key_pairs["con"] is missing
2. Warning: "con level not initialized. Initializing now..."
3. Trigger initialization flow for con tier (same as 7.2)
4. Continue with credential add
```

### 7.4 Atomic Writes & Interruption Safety

All write operations follow the same pattern:
```
1. Perform all computation in memory
2. Serialize JSON
3. Encrypt with outer AES key
4. Write to keybox.keystore.tmp
5. fsync(keybox.keystore.tmp)
6. rename(keybox.keystore.tmp, keybox.keystore)
```

**Crash safety:** The file is ONLY written after the operation completes. If
the process is interrupted (Ctrl+C, SIGTERM, shell window closed) during ROT
input or any in-memory operation, the original `keybox.keystore` is untouched.
The temp file may be left behind but is never used as the source of truth.

This applies to ALL keystore-modifying operations: init, add, edit, delete, update.

---

## 8. Error Handling

| Scenario | Error | Resolution |
|----------|-------|------------|
| File has wrong magic | "Not a valid Keybox keystore file" | Check file path |
| Version not supported | "Unsupported keystore version: {n}" | Upgrade Keybox |
| Key ref mismatch | "Keystore encryption key has changed" | Check system protector |
| GCM decryption fails | "Keystore file corrupted or tampered" | Restore from backup |
| crypt_level not initialized | "Level <x> not initialized. Run keybox init --level <x>" | Run init |
| All tiers already initialized | "All crypt levels already initialized" | No action needed |
| Key file not found (top init/unlock) | "Key file not found: <path>" | Provide valid file |
| Key file empty (top init/unlock) | "Key file is empty" | Use non-empty file |
| Token expired | "Token expired. Run keybox unlock." | Re-unlock |
| Token scope insufficient | "Token scope insufficient." | Unlock with correct level |
| Daemon not running | "Daemon not running. Run keybox serve first." | Start daemon |
| Password displayed without --force | Warning: "Use --clipboard, --env, or --force" | Use appropriate flag |
| Non-interactive without --env/--clipboard | "Non-interactive mode requires --env or --clipboard." | Specify output mode |
| Token used without daemon | "Daemon not running. Token-based access requires 'keybox serve'." | Start daemon |
| con/top edit/delete without ROT | Same flow as get password for that tier | Provide ROT or use secret level |
| con unlock wrong passphrase | "Incorrect passphrase" | Retry or reset |
| gen --save on existing credential | "Credential already exists: <domain:account>" | Use update instead |

---

## 9. Testing Strategy

### Unit Tests
- JSON serialization/deserialization round-trip
- key_ref derivation from outer key
- Token generation (uniqueness, entropy)
- Token scope check logic (exact match, no inheritance)
- Default domain handling (`:account` → `default:account`)
- `<masked>` replacement for secret field

### Integration Tests
- init → add → get cycle for each crypt_level
- Lazy init: add triggers auto-init for missing tier (with warning)
- Sequential init flow (secret auto → con prompt → top prompt)
- Existing store init (only missing tiers)
- daemon lock/unlock cycle
- token expiry behavior
- concurrent unlock (multiple tokens)
- corrupted file detection (tampered magic, wrong key_ref, GCM failure)
- atomic write: Ctrl+C during operation leaves original file intact
- Key file validation (missing file, empty file)
- Default domain add → get round-trip
- --env injection with single and dual variable names
- get password without --force shows warning, requires --clipboard or --force
- get all / get (default) shows `<masked>` for secret, never decrypts
- update password: correct old password → update succeeds
- update password: wrong old password → rejected
- update password: new password mismatch → rejected
- gen --save: generated password saved as credential correctly
- gen --save on existing domain:account: rejected with clear error
- gen without --save: output only, no keystore modification

### Security Tests
- Token unpredictability (statistical randomness test)
- Masked input verification (no plaintext echo for passphrase, key file path)
- --force flag enforcement (secret NOT leaked without --force)
- No secret in metadata operations (list, get description, get all)
- Environment variable injection (KEYBOX_MASTER_PASSPHRASE not logged)
- Non-interactive mode correctly reads from env vars
- Token takes precedence over env var ROT
- Env vars cleared after use (KEYBOX_MASTER_PASSPHRASE empty after read)
- Non-interactive without --env/--clipboard correctly rejected
- con/top edit/delete requires ROT verification
- Token rejected when daemon not running
- Wrong con passphrase fails unlock

---

## 11. Environment Variable Lifecycle

All sensitive environment variables are **single-use**: they are read once at
the start of the operation and immediately cleared (set to empty string in the
process environment). This prevents accidental leakage through:

- Shell history that captures environment variables
- `env` commands that dump all variables
- Long-lived shell sessions where the variable persists

**Affected env vars:**

| Variable | Used By | Cleared After |
|----------|---------|---------------|
| `KEYBOX_SET_PASSWORD_ONESHOT` | `keybox add --no-interactive` | Read once, cleared |
| `KEYBOX_MASTER_PASSPHRASE` | `keybox get --no-interactive` (con) | Read once, cleared |
| `KEYBOX_MASTER_KEYFILE` | `keybox get --no-interactive` (top) | Read once, cleared |
| `KEYBOX_CON_ACCESS_TOKEN` | `keybox get --no-interactive` (con) | Read once, cleared |
| `KEYBOX_TOP_ACCESS_TOKEN` | `keybox get --no-interactive` (top) | Read once, cleared |

**Implementation note:** Use `std::env::set_var("VAR", "")` or equivalent after
reading, before any further operation. Do NOT simply read from `env::var()` as
cached values may persist.

---

## 12. Open Questions

1. **Backup strategy**: Should `keybox` auto-create `keybox.keystore.bak` before writes?
   Suggested: yes, keep last N backups.
2. **Git integration**: Should `keybox` auto-commit to git like `pass`? Suggested: no
   — a single encrypted binary blob is not diff-friendly. Users who want versioning
   can wrap the file themselves.
3. **Multiple stores**: Should Keybox support multiple store files (like gopass mounts)?
   Suggested: out of scope for now. Single store, simple UX.
