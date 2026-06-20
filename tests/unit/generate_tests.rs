use keybox::generate;

// ── charset tests ───────────────────────────────────────────────

#[test]
fn test_default_charset_includes_lower_upper_digits_underscore() {
    let chars = generate::default_charset();
    // lower
    assert!(chars.contains(&'a'));
    assert!(chars.contains(&'z'));
    // upper
    assert!(chars.contains(&'A'));
    assert!(chars.contains(&'Z'));
    // digits
    assert!(chars.contains(&'0'));
    assert!(chars.contains(&'9'));
    // underscore in default
    assert!(chars.contains(&'_'));
    // no other symbols, no chinese in default
    assert!(!chars.contains(&'!'));
    assert!(!chars.contains(&'\u{4E00}')); // CJK start
}

#[test]
fn test_lowercase_only_charset() {
    let chars = generate::build_charset(true, false, false, false, false);
    assert!(chars.iter().all(|c| c.is_ascii_lowercase()));
    assert_eq!(chars.len(), 26);
}

#[test]
fn test_uppercase_only_charset() {
    let chars = generate::build_charset(false, true, false, false, false);
    assert!(chars.iter().all(|c| c.is_ascii_uppercase()));
    assert_eq!(chars.len(), 26);
}

#[test]
fn test_digits_only_charset() {
    let chars = generate::build_charset(false, false, true, false, false);
    assert!(chars.iter().all(|c| c.is_ascii_digit()));
    assert_eq!(chars.len(), 10);
}

#[test]
fn test_symbols_only_charset() {
    let chars = generate::build_charset(false, false, false, true, false);
    assert!(!chars.is_empty());
    assert!(chars.iter().all(|c| !c.is_alphanumeric()));
    assert!(chars.contains(&'!'));
    assert!(chars.contains(&'~'));
}

#[test]
fn test_chinese_only_charset() {
    let chars = generate::build_charset(false, false, false, false, true);
    assert!(!chars.is_empty());
    // All chars should be in the CJK Unified Ideographs range
    assert!(chars.iter().all(|c| ('\u{4E00}'..='\u{9FFF}').contains(c)));
}

#[test]
fn test_mixed_charset() {
    let chars = generate::build_charset(true, true, true, true, false);
    assert!(chars.contains(&'a'));
    assert!(chars.contains(&'Z'));
    assert!(chars.contains(&'5'));
    assert!(chars.contains(&'!'));
    // no chinese
    assert!(!chars.contains(&'\u{4E00}'));
}

#[test]
fn test_exclude_similar_removes_ambiguous_chars() {
    let chars_without = generate::build_charset_with_exclude_similar(true, true, true, false, false);
    let chars_with = generate::build_charset(true, true, true, false, false);
    // With exclude_similar should be strictly smaller
    assert!(chars_without.len() < chars_with.len());
    // Specific ambiguous chars should be absent
    assert!(!chars_without.contains(&'0'));
    assert!(!chars_without.contains(&'O'));
    assert!(!chars_without.contains(&'I'));
    assert!(!chars_without.contains(&'l'));
    assert!(!chars_without.contains(&'1'));
}

// ── generation tests ────────────────────────────────────────────

#[test]
fn test_generate_password_length() {
    let chars = generate::build_charset(true, true, true, false, false);
    let pw = generate::generate_password(32, &chars).unwrap();
    assert_eq!(pw.len(), 32);
    assert!(pw.chars().all(|c| chars.contains(&c)));
}

#[test]
fn test_generate_password_length_clamps_to_max() {
    let chars = generate::build_charset(true, false, false, false, false);
    let pw = generate::generate_password(500, &chars).unwrap();
    // Length should be clamped to MAX_LENGTH (256)
    assert_eq!(pw.len(), 256);
    // All chars should be from the charset
    assert!(pw.chars().all(|c| chars.contains(&c)));
}

#[test]
fn test_generate_password_length_zero_error() {
    let chars = generate::build_charset(true, false, false, false, false);
    assert!(generate::generate_password(0, &chars).is_err());
}

#[test]
fn test_generate_password_empty_charset_error() {
    let chars: Vec<char> = vec![];
    assert!(generate::generate_password(1, &chars).is_err());
}

#[test]
fn test_randomness_produces_variation() {
    let chars = generate::build_charset(true, true, true, true, false);
    let pw1 = generate::generate_password(64, &chars).unwrap();
    let pw2 = generate::generate_password(64, &chars).unwrap();
    assert_ne!(pw1, pw2);
}

// ── passphrase tests ─────────────────────────────────────────────

/// Count words in a passphrase by greedily matching the longest
/// wordlist entry at each position. This correctly handles wordlist
/// entries that contain hyphens (e.g. "drop-down").
fn count_passphrase_words(passphrase: &str, wordlist: &[String]) -> usize {
    let mut remaining = passphrase;
    let mut count = 0;
    while !remaining.is_empty() {
        let matched = wordlist
            .iter()
            .filter(|w| remaining.starts_with(w.as_str()))
            .max_by_key(|w| w.len())
            .expect("passphrase contains a word not in the wordlist");
        count += 1;
        remaining = &remaining[matched.len()..];
        if remaining.starts_with('-') {
            remaining = &remaining[1..];
        }
    }
    count
}

#[test]
fn test_passphrase_zero_word_count_error() {
    let wordlist = generate::load_wordlist();
    assert!(generate::generate_passphrase(0, &wordlist).is_err());
}

#[test]
fn test_passphrase_empty_wordlist_error() {
    let wordlist: Vec<String> = vec![];
    assert!(generate::generate_passphrase(1, &wordlist).is_err());
}

#[test]
fn test_passphrase_default() {
    let wordlist = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(4, &wordlist).unwrap();
    assert_eq!(count_passphrase_words(&passphrase, &wordlist), 4);
}

#[test]
fn test_passphrase_word_count() {
    let wordlist = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(6, &wordlist).unwrap();
    assert_eq!(count_passphrase_words(&passphrase, &wordlist), 6);
}

#[test]
fn test_passphrase_length_clamping() {
    let wordlist = generate::load_wordlist();
    let passphrase = generate::generate_passphrase(200, &wordlist).unwrap();
    assert_eq!(count_passphrase_words(&passphrase, &wordlist), 128);
}

#[test]
fn test_passphrase_randomness() {
    let wordlist = generate::load_wordlist();
    let pw1 = generate::generate_passphrase(8, &wordlist).unwrap();
    let pw2 = generate::generate_passphrase(8, &wordlist).unwrap();
    assert_ne!(pw1, pw2);
}
