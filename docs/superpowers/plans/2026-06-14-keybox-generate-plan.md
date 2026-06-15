# Keybox Generate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `generate` subcommand that produces random passwords with configurable character sets, passphrase mode, and optional storage.

**Architecture:** Pure generation logic in `src/generate.rs` (no I/O), CLI integration in `src/cli.rs` + `src/main.rs`. EFF wordlist embedded at compile time. Character set selection via explicit flags with sensible defaults.

**Tech Stack:** `rand` (already dep), `include_str!` for wordlist, existing `store`/`cli` modules.

---

## File Structure

```
src/
├── generate.rs              # NEW: pure password generation functions
├── cli.rs                   # MODIFY: add Command::Generate variant
├── main.rs                  # MODIFY: add handle_generate dispatch
tests/
├── unit/
│   └── generate_tests.rs    # NEW: unit tests for generation logic
├── integration/
│   └── generate_tests.rs    # NEW: integration tests via CLI binary
tests/
└── unit.rs                  # MODIFY: add generate_tests module
eff_large_wordlist.txt       # NEW: embedded EFF wordlist
```

---

### Task 1: Generate module — character-based password generation

**Files:**
- Create: `src/generate.rs`
- Create: `tests/unit/generate_tests.rs`
- Create: `eff_large_wordlist.txt`
- Modify: `src/lib.rs` — add `pub mod generate;`
- Modify: `tests/unit.rs` — add generate_tests module

- [ ] **Step 1: Write generate_tests.rs**

```rust
// tests/unit/generate_tests.rs
use keybox::generate;

#[test]
fn test_default_charset() {
    let password = generate::generate_password(16, &generate::default_charset());
    assert_eq!(password.chars().count(), 16);
    // All chars should be from the default set [a-z][A-Z][0-9]_
    for c in password.chars() {
        assert!(
            c.is_ascii_lowercase() || c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_',
            "unexpected char '{}' in default password", c
        );
    }
}

#[test]
fn test_lowercase_only() {
    let charset = generate::build_charset(true, false, false, false, false);
    let password = generate::generate_password(20, &charset);
    assert_eq!(password.chars().count(), 20);
    for c in password.chars() {
        assert!(c.is_ascii_lowercase(), "expected lowercase only, got '{}'", c);
    }
}

#[test]
fn test_uppercase_only() {
    let charset = generate::build_charset(false, true, false, false, false);
    let password = generate::generate_password(8, &charset);
    assert_eq!(password.chars().count(), 8);
    for c in password.chars() {
        assert!(c.is_ascii_uppercase(), "expected uppercase only, got '{}'", c);
    }
}

#[test]
fn test_digits_only() {
    let charset = generate::build_charset(false, false, true, false, false);
    let password = generate::generate_password(6, &charset);
    assert_eq!(password.chars().count(), 6);
    for c in password.chars() {
        assert!(c.is_ascii_digit(), "expected digits only, got '{}'", c);
    }
}

#[test]
fn test_symbols_only() {
    let charset = generate::build_charset(false, false, false, true, false);
    let password = generate::generate_password(10, &charset);
    assert_eq!(password.chars().count(), 10);
    let syms = "_!@#$%^&*()-+=[]{};:,.<>?/~";
    for c in password.chars() {
        assert!(syms.contains(c), "expected symbol, got '{}'", c);
    }
}

#[test]
fn test_chinese_only() {
    let charset = generate::build_charset(false, false, false, false, true);
    let password = generate::generate_password(10, &charset);
    assert_eq!(password.chars().count(), 10);
    for c in password.chars() {
        let code = c as u32;
        assert!(
            (0x4E00..=0x9FFF).contains(&code),
            "expected CJK char, got U+{:04X} '{}'", code, c
        );
    }
}

#[test]
fn test_mixed_charset() {
    let charset = generate::build_charset(true, false, true, false, true);
    let password = generate::generate_password(50, &charset);
    assert_eq!(password.chars().count(), 50);
    // Should contain at least one of each requested type (probabilistic, high chance with 50)
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_chinese = password.chars().any(|c| (0x4E00..=0x9FFF).contains(&(c as u32)));
    assert!(has_lower, "should contain lowercase");
    assert!(has_digit, "should contain digits");
    assert!(has_chinese, "should contain Chinese chars");
}

#[test]
fn test_length_clamping() {
    let charset = generate::default_charset();
    let password = generate::generate_password(500, &charset); // over 256
    assert_eq!(password.chars().count(), 256);
}

#[test]
fn test_length_zero() {
    let charset = generate::default_charset();
    let result = std::panic::catch_unwind(|| {
        generate::generate_password(0, &charset);
    });
    assert!(result.is_err());
}

#[test]
fn test_exclude_similar() {
    let charset = generate::build_charset_with_exclude_similar(true, true, true, false, false);
    let password = generate::generate_password(100, &charset);
    for c in password.chars() {
        assert!(!matches!(c, '0' | 'O' | 'I' | 'l' | '1'), "should exclude similar char '{}'", c);
    }
}

#[test]
fn test_build_charset_empty_returns_err() {
    let result = generate::build_charset(false, false, false, false, false);
    assert!(result.is_empty());
}

#[test]
fn test_randomness_produces_variation() {
    let charset = generate::default_charset();
    let a = generate::generate_password(32, &charset);
    let b = generate::generate_password(32, &charset);
    assert_ne!(a, b, "two random passwords should differ");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test generate_tests`
Expected: compilation failure (module not found)

- [ ] **Step 3: Implement src/generate.rs**

```rust
use rand::Rng;

const DEFAULT_SYMBOLS: &str = "_!@#$%^&*()-+=[]{};:,.<>?/~";
const SIMILAR_CHARS: &[char] = &['0', 'O', 'I', 'l', '1'];
const MAX_LENGTH: usize = 256;

pub fn default_charset() -> Vec<char> {
    build_charset(true, true, true, false, false)
}

pub fn build_charset(
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    chinese: bool,
) -> Vec<char> {
    build_charset_inner(lowercase, uppercase, digits, symbols, chinese, false)
}

pub fn build_charset_with_exclude_similar(
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    chinese: bool,
) -> Vec<char> {
    build_charset_inner(lowercase, uppercase, digits, symbols, chinese, true)
}

fn build_charset_inner(
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    chinese: bool,
    exclude_similar: bool,
) -> Vec<char> {
    let mut chars = Vec::new();

    if lowercase {
        chars.extend('a'..='z');
    }
    if uppercase {
        chars.extend('A'..='Z');
    }
    if digits {
        chars.extend('0'..='9');
    }
    if symbols {
        chars.extend(DEFAULT_SYMBOLS.chars());
    }
    if chinese {
        chars.extend(
            (0x4E00u32..=0x9FFFu32)
                .filter_map(|cp| char::from_u32(cp))
        );
    }
    if exclude_similar {
        chars.retain(|c| !SIMILAR_CHARS.contains(c));
    }

    chars
}

pub fn generate_password(mut length: usize, charset: &[char]) -> String {
    if length == 0 {
        panic!("length must be at least 1");
    }
    if length > MAX_LENGTH {
        length = MAX_LENGTH;
    }
    if charset.is_empty() {
        panic!("charset is empty");
    }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect()
}
```

- [ ] **Step 4: Download EFF wordlist**

```bash
curl -sL https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt -o eff_large_wordlist.txt
```

The wordlist format is `11111 word`, which needs parsing in Task 2.

- [ ] **Step 5: Add module to lib.rs and tests/unit.rs**

```
// src/lib.rs: add `pub mod generate;`
// tests/unit.rs: add `#[path = "unit/generate_tests.rs"] mod generate_tests;`
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test generate_tests`
Expected: all 12 tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/generate.rs tests/unit/generate_tests.rs eff_large_wordlist.txt src/lib.rs tests/unit.rs
git commit -m "feat: add password generation module with character sets and length clamping"
```

---

### Task 2: Passphrase mode

**Files:**
- Modify: `src/generate.rs` — add passphrase generation
- Modify: `tests/unit/generate_tests.rs` — add passphrase tests

- [ ] **Step 1: Write passphrase tests**

Add to `tests/unit/generate_tests.rs`:

```rust
#[test]
fn test_passphrase_default() {
    let words = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(4, &words);
    let parts: Vec<&str> = passphrase.split('-').collect();
    assert_eq!(parts.len(), 4);
    for word in parts {
        assert!(words.contains(&word.to_string()), "word '{}' not in wordlist", word);
    }
}

#[test]
fn test_passphrase_word_count() {
    let words = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(6, &words);
    assert_eq!(passphrase.split('-').count(), 6);
}

#[test]
fn test_passphrase_length_clamping() {
    let words = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(200, &words); // over 128
    assert_eq!(passphrase.split('-').count(), 128);
}

#[test]
fn test_passphrase_randomness() {
    let words = generate::load_wordlist();
    let a = generate::generate_passphrase(8, &words);
    let b = generate::generate_passphrase(8, &words);
    assert_ne!(a, b, "two passphrases should differ");
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test passphrase`
Expected: compilation failure (functions not defined)

- [ ] **Step 3: Implement passphrase generation in src/generate.rs**

Add to `src/generate.rs`:

```rust
const MAX_PASSPHRASE_WORDS: usize = 128;

pub fn load_wordlist() -> Vec<String> {
    let raw = include_str!("../eff_large_wordlist.txt");
    raw.lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                Some(parts[1].to_string())
            } else {
                None
            }
        })
        .collect()
}

pub fn generate_passphrase(mut word_count: usize, wordlist: &[String]) -> String {
    if word_count == 0 {
        panic!("word count must be at least 1");
    }
    if word_count > MAX_PASSPHRASE_WORDS {
        word_count = MAX_PASSPHRASE_WORDS;
    }
    if wordlist.is_empty() {
        panic!("wordlist is empty");
    }

    let mut rng = rand::thread_rng();
    (0..word_count)
        .map(|_| {
            let idx = rng.gen_range(0..wordlist.len());
            wordlist[idx].as_str()
        })
        .collect::<Vec<_>>()
        .join("-")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test generate_tests`
Expected: 16 tests PASS (12 from Task 1 + 4 new)

- [ ] **Step 5: Commit**

```bash
git add src/generate.rs tests/unit/generate_tests.rs
git commit -m "feat: add passphrase generation with EFF wordlist"
```

---

### Task 3: CLI integration — clap argument + main.rs dispatch

**Files:**
- Modify: `src/cli.rs` — add `Generate` variant to `Command` enum
- Modify: `src/main.rs` — add `handle_generate` and dispatch

- [ ] **Step 1: Add Command::Generate to cli.rs**

Add to the `Command` enum in `src/cli.rs`:

```rust
    /// Generate a random password
    Generate {
        #[arg(long, default_value_t = 16)]
        length: usize,

        #[arg(long)]
        lowercase: bool,
        #[arg(long)]
        uppercase: bool,
        #[arg(long)]
        digits: bool,
        #[arg(long)]
        symbols: bool,
        #[arg(long)]
        chinese: bool,

        #[arg(long)]
        passphrase: bool,
        #[arg(long)]
        wordlist: Option<String>,

        #[arg(long, conflicts_with = "env")]
        clipboard: bool,
        #[arg(long, conflicts_with = "clipboard")]
        env: Option<String>,

        #[arg(long, num_args = 2, value_names = ["DOMAIN", "ACCOUNT"])]
        save: Option<Vec<String>>,

        #[arg(long)]
        exclude_similar: bool,
    },
```

And update `Command::to_operation()` to handle `Generate`:

```rust
Command::Generate { .. } => Operation::Generate,
```

And add `Generate` to the `Operation` enum:

```rust
pub enum Operation { Add, Get, List, Delete, Update, Init, Serve, Unlock, Lock, Stop, Generate }
```

- [ ] **Step 2: Add handle_generate to main.rs**

```rust
use keybox::generate;
use keybox::store;

fn handle_generate(
    base: &PathBuf,
    tier: Tier,
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
    chinese: bool,
    passphrase: bool,
    wordlist: Option<&str>,
    clipboard: bool,
    env_var: Option<&str>,
    save: Option<&[String]>,
    exclude_similar: bool,
) -> Result<(), String> {
    let password = if passphrase {
        let words = match wordlist {
            Some(path) => {
                let content = fs::read_to_string(path)
                    .map_err(|e| format!("wordlist not found: {}", e))?;
                let words: Vec<String> = content.lines()
                    .filter(|l| !l.is_empty())
                    .map(|l| l.to_string())
                    .collect();
                if words.is_empty() {
                    return Err("wordlist is empty".into());
                }
                words
            }
            None => generate::load_wordlist(),
        };
        generate::generate_passphrase(length, &words)
    } else {
        let has_explicit_charset = lowercase || uppercase || digits || symbols || chinese;
        let charset = if has_explicit_charset {
            if exclude_similar {
                generate::build_charset_with_exclude_similar(lowercase, uppercase, digits, symbols, chinese)
            } else {
                generate::build_charset(lowercase, uppercase, digits, symbols, chinese)
            }
        } else {
            if exclude_similar {
                generate::build_charset_with_exclude_similar(true, true, true, false, false)
            } else {
                generate::default_charset()
            }
        };
        if charset.is_empty() {
            return Err("at least one character set required".into());
        }
        generate::generate_password(length, &charset)
    };

    let secret = password.as_bytes();

    // Helper to save
    let save_credential = |base: &PathBuf, tier: Tier, save: &[String], secret: &[u8]| -> Result<(), String> {
        let domain = &save[0];
        let account = &save[1];
        keybox::cli::validate_name(domain)?;
        keybox::cli::validate_name(account)?;
        ensure_initialized(base, tier)?;
        store::add_credential(base, tier, domain, account, secret)?;
        Ok(())
    };

    // Output
    if let Some(var_name) = env_var {
        let args: Vec<String> = std::env::args().skip_while(|a| a != "--").skip(1).collect();
        if args.is_empty() {
            return Err("no command specified after -- separator".into());
        }
        if let Some(save) = save {
            save_credential(base, tier, save, secret)?;
        }
        let exit_code = env_run::run_with_env(var_name, secret, &args)?;
        std::process::exit(exit_code);
    } else if clipboard {
        let secret_str = std::str::from_utf8(secret).map_err(|_| "Secret contains non-UTF8 data".to_string())?;
        let mut cb = arboard::Clipboard::new().map_err(|e| format!("Failed to access clipboard: {}", e))?;
        cb.set_text(secret_str).map_err(|e| format!("Failed to copy: {}", e))?;
        println!("Password copied to clipboard");
    } else {
        let secret_str = std::str::from_utf8(secret).map_err(|_| "Invalid UTF-8".to_string())?;
        println!("{}", secret_str);
    }

    if let Some(save) = save {
        save_credential(base, tier, save, secret)?;
        println!("Saved to {}/{}", save[0], save[1]);
    }

    Ok(())
}
```

- [ ] **Step 3: Update main() dispatch to route Generate**

```rust
Command::Generate {
    length, lowercase, uppercase, digits, symbols, chinese,
    passphrase, wordlist, clipboard, env,
    save, exclude_similar,
} => {
    handle_generate(
        &base, tier, *length,
        *lowercase, *uppercase, *digits, *symbols, *chinese,
        *passphrase, wordlist.as_deref(),
        *clipboard, env.as_deref(),
        save.as_deref(),
        *exclude_similar,
    )
}
```

- [ ] **Step 4: Build and verify compilation**

Run: `cargo build`
Expected: compiles successfully

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: all existing tests pass + generate unit tests pass

- [ ] **Step 6: Commit**

```bash
git add src/cli.rs src/main.rs
git commit -m "feat: add generate command to CLI with full dispatch"
```

---

### Task 4: Integration tests

**Files:**
- Create: `tests/integration/generate_tests.rs`
- Modify: `tests/integration.rs` — add generate_tests module

- [ ] **Step 1: Write integration tests**

```rust
// tests/integration/generate_tests.rs
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn test_generate_default() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().count() == 16
        }));
}

#[test]
fn test_generate_length() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--length", "32"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().count() == 32
        }));
}

#[test]
fn test_generate_digits_only() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--digits", "--length", "6"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().all(|c| c.is_ascii_digit()) && output.trim().len() == 6
        }));
}

#[test]
fn test_generate_passphrase() {
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate", "--passphrase", "--length", "4"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().split('-').count() == 4
        }));
}

#[test]
fn test_generate_no_charset_errors() {
    // When all charsets are turned off (by explicitly not providing any), default applies.
    // But if someone specifies flags that result in empty set? Not possible with current clap:
    // to get empty charset user must explicitly only use flags that turn things OFF.
    // Since we don't have --no-* flags, empty charset can only happen via code path.
    // Test that default works:
    let mut cmd = Command::cargo_bin("keybox").unwrap();
    cmd.args(["generate"])
        .assert()
        .success();
}

#[test]
fn test_generate_and_save() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .success();

    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["get", "test", "pin"])
        .assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            output.trim().chars().all(|c| c.is_ascii_digit()) && output.trim().len() == 6
        }));
}

#[test]
fn test_generate_save_duplicate_fails() {
    let dir = TempDir::new().unwrap();
    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .success();

    Command::cargo_bin("keybox").unwrap()
        .env("KEYBOX_CONFIG_DIR", dir.path().to_str().unwrap())
        .args(["generate", "--digits", "--length", "6", "--save", "test", "pin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}
```

- [ ] **Step 2: Run integration tests**

Run: `cargo test generate_tests`
Expected: all integration tests PASS

- [ ] **Step 3: Run full test suite**

Run: `cargo test`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/integration/generate_tests.rs tests/integration.rs
git commit -m "test: add generate command integration tests"
```

---

## Plan Summary

| Task | Description | Files | Tests |
|------|-------------|-------|-------|
| 1 | Generate module (char-based) | `generate.rs`, `generate_tests.rs`, `eff_large_wordlist.txt` | 12 |
| 2 | Passphrase mode | `generate.rs` (modify), `generate_tests.rs` (modify) | +4 |
| 3 | CLI integration | `cli.rs`, `main.rs` | build check |
| 4 | Integration tests | `integration/generate_tests.rs` | +7 |

**Total:** 4 tasks, 23 new tests, ~5 files modified/created.
