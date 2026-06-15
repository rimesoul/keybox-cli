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
                .filter_map(|cp| char::from_u32(cp)),
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
