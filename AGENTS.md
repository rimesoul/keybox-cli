# AGENTS.md — Keybox-CLI

## Build & Test

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

- CI skips platform-specific `protect_tests` on non-native platforms: `cargo test -- --skip protect_tests`
- Release is triggered by pushing a `v*` tag (e.g., `v0.2.0`); builds for linux-x86_64, macos-arm64, windows-x86_64
- Single binary crate — `cargo build --release` produces `target/release/keybox`

## Project Structure

```
src/
├── main.rs          # Entrypoint, all 12 command handlers (~1000 lines)
├── cli.rs           # Clap derive CLI definitions (Command enum, GenerateArgs)
├── keystore/        # Core: single-file encrypted credential store
│   ├── schema.rs    #   KeyStore, Credential, KeyPair, CryptLevel types (serde)
│   ├── format.rs    #   Binary container: magic "KBOX", AES-256-GCM enc/dec, atomic write
│   └── ops.rs       #   CRUD: init, add, get, list, edit, delete, update_password
├── daemon/          # Background process + IPC (Unix socket / Windows named pipe)
│   ├── token.rs     #   CSPRNG token generation, validation, expiry
│   ├── protocol.rs  #   Request/Response enums (serde)
│   ├── server.rs    #   Daemon state: KeyStore + TokenStore + identity cache
│   └── client.rs    #   IPC client
├── crypto/          # Low-level: age_ops (X25519 + ChaCha20-Poly1305)
├── protect/         # Platform protectors: macOS Keychain, Windows DPAPI, Linux machine-id
├── generate.rs      # Random password/passphrase generation (EFF wordlist)
├── interactive.rs   # TTY prompts (masked input, confirmation)
├── env_run.rs       # Inject secret as env var into child process
└── tier.rs          # Legacy tier path helpers (still referenced by store.rs)
```

## Key Architecture Facts

- **Two-layer encryption**: Outer AES-256-GCM protects the JSON keystore; inner age X25519 protects each `Credential.secret` field
- **Single keystore file**: `~/.config/keybox/keybox.keystore` — binary header (magic + key_ref + nonce) + AES-GCM encrypted JSON
- **Three crypt levels** share one keystore: `secret` (auto-decrypt), `confidential` (passphrase), `top-secret` (key file). Each has its own age key pair stored in `key_pairs`
- **CLI**: `--level` is per-command, not a global flag. Default is `secret`
- **Daemon**: Only needed for `confidential`/`top-secret` token-based access. `secret` level decrypts directly without daemon
- **Secrets never print to stdout** by default — `get password` shows warning, requires `--clipboard`, `--env`, or `--force`

## Spec / Plan Workflow (Superpowers)

This project uses the Superpowers methodology. Before touching code for any feature:

1. **drill-requirement** → validate the need
2. **brainstorming** → design, get user approval
3. **writing-plans** → implementable task list
4. **subagent-driven-development** → TDD implementation with two-stage review

Design docs in `docs/superpowers/specs/`, plans in `docs/superpowers/plans/`. Do NOT skip directly to code.

## Notable Conventions

- Error handling uses `Result<_, String>` throughout (custom error types flagged as future improvement)
- Sensitive env vars are cleared after single-use (`KEYBOX_MASTER_PASSPHRASE`, `KEYBOX_SET_PASSWORD_ONESHOT`, etc.)
- Atomotic writes: `write tmp → rename` (no `fsync` yet — flagged for future hardening)
- `#[allow(clippy::too_many_arguments)]` used on `add_credential` (8 args) and `handle_get` (8 args)
- `store.rs` and `tier.rs` are **legacy** — still exported but largely superseded by `keystore/` module
- Integration tests in `tests/integration/` use `assert_cmd` for CLI black-box testing; unit tests in `tests/unit/`
