use rand::Rng;

const DEFAULT_SYMBOLS: &str = "_!@#$%^&*()-+=[]{};:,.<>?/~";
const SIMILAR_CHARS: &[char] = &['0', 'O', 'I', 'l', '1'];
const MAX_LENGTH: usize = 256;

pub fn default_charset() -> Vec<char> {
    let mut chars: Vec<char> = ('a'..='z').chain('A'..='Z').chain('0'..='9').collect();
    chars.push('_');
    chars
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
                .filter_map(char::from_u32),
        );
    }
    if exclude_similar {
        chars.retain(|c| !SIMILAR_CHARS.contains(c));
    }

    chars
}

pub fn generate_password(mut length: usize, charset: &[char]) -> Result<String, String> {
    if length == 0 {
        return Err("length must be at least 1".into());
    }
    if length > MAX_LENGTH {
        length = MAX_LENGTH;
    }
    if charset.is_empty() {
        return Err("charset is empty".into());
    }

    let mut rng = rand::thread_rng();
    Ok((0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx]
        })
        .collect())
}

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

pub fn generate_passphrase(mut word_count: usize, wordlist: &[String]) -> Result<String, String> {
    if word_count == 0 {
        return Err("word count must be at least 1".into());
    }
    if word_count > MAX_PASSPHRASE_WORDS {
        word_count = MAX_PASSPHRASE_WORDS;
    }
    if wordlist.is_empty() {
        return Err("wordlist is empty".into());
    }

    let mut rng = rand::thread_rng();
    Ok((0..word_count)
        .map(|_| {
            let idx = rng.gen_range(0..wordlist.len());
            wordlist[idx].as_str()
        })
        .collect::<Vec<_>>()
        .join("-"))
}
