# Design Spec: Multi-Level Daemon Unlock

Date: 2026-06-27
Status: ✅ Implemented (commit: 025c2f6)
Depends on: `docs/superpowers/specs/2026-06-18-keybox-metadata-store-design.md` (Section 6)

### Implementation Notes

- ROT retry (3 attempts, Section 3.6) is **deferred** — currently single attempt.
  Validation happens on the daemon side; if ROT is incorrect, daemon returns an error
  which is displayed to the user.
- ROT input validation (file exists, non-empty) was moved to daemon-side for consistency
  with passphrase validation.

---

## 1. Overview

### 1.1 Problem

`keybox unlock` currently only supports a single level (`--level con` or `--level top`).
The default behavior is a required argument error. Common usage needs to unlock both
confidential and top-secret tiers at once with a single token.

### 1.2 Solution

- `keybox unlock` with no `--level` defaults to unlock all initialized con/top tiers
- A single token carries multiple scopes (`scopes: Vec<String>` instead of `scope: String`)
- Both interactive and non-interactive modes require ALL ROTs to be verified for ALL
  initialized tiers, unless the user explicitly specifies a single `--level`
- Uninitialized tiers are silently skipped

### 1.3 Non-Goals

- Secret level (auto-decrypt, no unlock needed)
- Comma-separated level input was already supported in the original design (unused)

---

## 2. Data Model Changes

### 2.1 Token Scope (single → multiple)

`src/daemon/token.rs`:

```rust
// Before:
pub struct TokenData {
    pub scope: String,
    pub expires_at: SystemTime,
}

// After:
pub struct TokenData {
    pub scopes: Vec<String>,    // e.g. ["con"] or ["con", "top"]
    pub expires_at: SystemTime,
}
```

**Validation change:** `token.scopes.contains(&required_scope)` instead of `token.scope == required_scope`.

`TokenStore::generate` signature:
```rust
pub fn generate(&mut self, scopes: &[String], timeout_minutes: u64) -> String
```

### 2.2 Protocol Change

`src/daemon/protocol.rs`:

```rust
// Before:
Unlocked { token: String, level: String },

// After:
Unlocked { token: String, levels: Vec<String> },
```

---

## 3. CLI Behavior

### 3.0 Daemon Pre-Check

On `keybox serve` startup, the daemon checks key_pairs in the keystore:

| State | Action |
|-------|--------|
| Neither con nor top initialized | Print warning: `Warning: No unlockable levels found. Run 'keybox init --level confidential' or 'keybox init --level top-secret' to enable daemon unlock.` — daemon still starts, serves metadata |
| At least one initialized | Normal startup, no warning |

The same check applies in `keybox unlock` before prompting: if no levels are initialized, error immediately without generating a token.

### 3.1 `keybox unlock` (no `--level`)

Default target: all initialized con/top tiers.

**Interactive:**
```
$ keybox unlock

Enter master passphrase for confidential tier: ******
(top-secret not initialized — skipped)
Confidential tier verified. Token valid for 30 minutes.

Token: dGhpcyBpcyBhIHRva2Vu...
```

**Non-interactive:**
```
# both tiers initialized → both env vars required
KEYBOX_MASTER_PASSPHRASE=mypass KEYBOX_MASTER_KEYFILE=/path/key \
    keybox unlock --no-interactive

# top not initialized → passphrase only needed
KEYBOX_MASTER_PASSPHRASE=mypass keybox unlock --no-interactive

# both initialized but missing keyfile → error
KEYBOX_MASTER_PASSPHRASE=mypass keybox unlock --no-interactive
Error: top-secret tier requires KEYBOX_MASTER_KEYFILE
```

### 3.2 `keybox unlock --level <level>`

Single level only. Interactive prompts for that level's ROT only.
Non-interactive reads only that level's env var.

### 3.3 `keybox unlock --level con,top`

Same as default (no `--level`). Both tiers verified.

### 3.4 `--clipboard` / `--env`

| Mode | --clipboard | --env VAR |
|------|:---:|:---:|
| Single level | Token → clipboard | Token → VAR |
| Multi level | Token → clipboard | Error: `--env not supported with multi-level unlock` |
| Default (stdout) | — | Token printed to stdout |

### 3.5 Timeout

- `--timeout <minutes>` on the command line always takes precedence
- Default (no `--timeout`): 30 minutes
- Future: configurable default in `~/.config/keybox/keybox.toml` (not in this spec)

### 3.6 ROT Retry Behavior

Both passphrase and key file verification follow the same retry pattern:

```
Con passphrase:  prompt → incorrect → "Incorrect passphrase." → retry (up to 3 attempts)
Top key file:    prompt → decrypt fails → "Key file verification failed." → retry (up to 3 attempts)
```

After 3 failed attempts, abort without generating a token. If verifying multiple levels,
failures accumulate independently — if con passes but top fails 3 times, abort entirely
(no token generated for either level).

### 3.7 Non-interactive Mode — Shell Variable Expansion Risk

Using shell variables on the command line like `-p $PASSWORD` or `-p $env:PASSWORD`
creates a security risk: the shell expands the variable **before** keybox starts,
exposing the secret in shell history and process lists.

**Not supported.** Users must use environment variable injection:

```
# ✅ Correct
KEYBOX_MASTER_PASSPHRASE=mypass keybox unlock --no-interactive

# ❌ Not supported — variable expanded by shell before keybox runs
keybox unlock --no-interactive -p $PASSWORD
```

### 3.8 Error Cases

| Scenario | Error |
|----------|-------|
| No unlockable levels (both uninitialized) | `No unlockable levels found. Run 'keybox init --level con' or 'keybox init --level top'.` |
| Non-interactive, both initialized, missing env | `confidential tier requires KEYBOX_MASTER_PASSPHRASE` (or top tier requires KEYBOX_MASTER_KEYFILE) |
| Wrong passphrase | `Incorrect passphrase.` (retry, then abort) |
| Key file not found / empty | `Key file not found: <path>` / `Key file is empty` |

---

## 4. Env Var Lifecycle

`KEYBOX_MASTER_PASSPHRASE` and `KEYBOX_MASTER_KEYFILE` are **cleared** (set to empty) immediately after ROT verification — before token generation. Same as Section 11 of the main keystore spec.

---

## 5. Implementation Scope

| File | Change |
|------|--------|
| `cli.rs` | `level: String` → `level: Option<String>` |
| `main.rs` `handle_unlock` | Default `"con,top"`, split loop, single token with multi scopes, retry logic |
| `daemon/token.rs` | `scope: String` → `scopes: Vec<String>` |
| `daemon/protocol.rs` | `level: String` → `levels: Vec<String>` |
| `daemon/server.rs` | `handle_unlock` returns `levels: Vec<String>`; startup pre-check for no unlockable levels |
| `daemon/client.rs` | Update `unlock()` return type |
| `tests/integration/` | Add multi-level unlock tests, retry tests, daemon warning test |
