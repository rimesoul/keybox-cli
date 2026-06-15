# Keybox Generate — Design Spec

Date: 2026-06-14 | Status: Approved

## Overview

Add a `generate` subcommand to keybox that produces random passwords with
configurable character sets, length, and output targets. It is a pure
password generator — no domain/account binding by default. Optional
`--save` integrates with keybox storage.

---

## 1. Command Format

```
keybox generate [OPTIONS]
```

## 2. Character Sets

**Default (no flags specified):** lowercase + uppercase + digits + `_`, length 16.

When one or more character set flags are specified, only those sets are used:

| Flag | Character Pool |
|------|---------------|
| `--lowercase` | `a-z` (26) |
| `--uppercase` | `A-Z` (26) |
| `--digits` | `0-9` (10) |
| `--symbols` | `_!@#$%^&*()-+=[]{};:,.<>?/~` |
| `--chinese` | CJK Unified Ideographs (U+4E00–U+9FFF, ~20,992 chars) |

**Constraints:**
- At least one character set must be active
- If all sets are disabled (no flags + explicitly empty): error "at least one character set required"

## 3. Length

| Flag | Description | Default |
|------|-------------|---------|
| `--length <N>` | Password length (code points) | 16 |

Maximum length is 256. Values above 256 are clamped to 256 without error.

In `--passphrase` mode (see §5), `--length` controls word count instead
(maximum 128 words).

## 4. Output Options (mutually exclusive where noted)

| Flag | Description |
|------|-------------|
| *(default)* | Print to stdout |
| `--clipboard` | Copy to system clipboard (conflicts with `--env`) |
| `--env <VAR> -- <cmd>` | Inject as env var into child process (conflicts with `--clipboard`) |

`--save` (see §6) can be combined with any output option.

## 5. Passphrase Mode

```
keybox generate --passphrase --length 4
# → correct-horse-battery-staple
```

| Flag | Description | Default |
|------|-------------|---------|
| `--passphrase` | Generate word-based passphrase instead of character-based | — |
| `--wordlist <path>` | Custom word list file (one word per line) | Built-in EFF large wordlist |

- Words are joined with `-`
- `--length` controls word count (default 4)
- Character set flags (`--lowercase`, `--chinese`, etc.) are ignored in passphrase mode
- Built-in wordlist: EFF large wordlist (~7,776 words)

## 6. Storage Integration

| Flag | Description |
|------|-------------|
| `--save <domain> <account>` | Generate and store to keybox. Same as `keybox add` — rejects duplicates with "already exists, use `keybox update`" |

The `--save` flag routes through the existing `add` logic. Security tier
follows the same level flag rules as all other commands (default `--secret`).

## 7. Other Options

| Flag | Description |
|------|-------------|
| `--exclude-similar` | Exclude visually ambiguous characters: `0`, `O`, `I`, `l`, `1` |

## 8. Examples

```bash
# Default: 16-char mixed [a-z][A-Z][0-9]_
keybox generate

# 32-char strong password
keybox generate --lowercase --uppercase --digits --symbols --length 32

# 6-digit PIN
keybox generate --digits --length 6

# Lowercase only, 24 chars
keybox generate --lowercase --length 24

# Chinese + digits, store as gitea/token
keybox generate --chinese --digits --length 12 --save gitea token

# 4-word passphrase, save to confidential tier
keybox --confidential generate --passphrase --length 4 --save ldap workuser

# Generate and inject into child process, never printed
keybox generate --env DB_PASS -- ./init-db.sh

# Clipboard only
keybox generate --clipboard

# Strong password excluding ambiguous chars
keybox generate --lowercase --uppercase --digits --symbols --length 32 --exclude-similar
```

## 9. Error Handling

| Scenario | Behavior |
|----------|----------|
| No character set active | Error: "at least one character set required" |
| `--save` duplicate domain/account | Error: "already exists: <domain>/<account>. Use `keybox update`." |
| `--wordlist` file not found | Error: "wordlist not found: <path>" |
| `--wordlist` file empty | Error: "wordlist is empty" |
| `--env` without command | Error: "no command specified after -- separator" |
| `--length` = 0 | Error: "length must be at least 1" |
| `--length` > 256 | Silently clamped to 256 (128 in passphrase mode) |

## 10. Implementation Notes

- New file: `src/generate.rs` — pure generation logic (no I/O, no CLI)
- Modify `src/cli.rs` — add `Command::Generate` variant with flags
- Modify `src/main.rs` — add `handle_generate` dispatch
- Rust crate for randomness: already have `rand = "0.8"`
- Chinese character pool: compile-time generated from Unicode range
- EFF wordlist: embed via `include_str!()` at compile time
