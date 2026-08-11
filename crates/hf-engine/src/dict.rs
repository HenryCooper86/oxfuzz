//! Fuzzing dictionary support.
//!
//! A dictionary is a list of interesting tokens (magic bytes, keywords, format
//! markers) the fuzzer splices into inputs. Seeding one with the string
//! literals a target compares against is one of the cheapest ways to get past
//! shallow `memcmp`/keyword gates and reach deeper code, so `oxfuzz` extracts
//! literals from the target source and hands them to the engine.
//!
//! Tokens are byte sequences (a literal like `"\x89PNG"` is binary, and those
//! magic-byte literals are exactly the high-value ones). The on-disk format is
//! the AFL++/libFuzzer dictionary format: one `"token"` per line, with
//! non-printable bytes escaped as `\xNN`.

use hf_core::engine::EngineKind;

/// The longest literal worth keeping in a dictionary. Very long strings are
/// almost never useful comparison tokens and just bloat the file.
const MAX_TOKEN_LEN: usize = 128;

/// Extract candidate dictionary tokens from C/C++ source: the decoded contents
/// of double-quoted string literals, plus multi-byte hexadecimal integer
/// constants (magic numbers). Duplicates, empty strings, and implausibly long
/// literals are dropped. Order is stable (first-seen).
///
/// Hex constants like `0xCAFEBABE` are exactly the values targets compare against
/// at numeric gates (`if (magic == 0xCAFEBABE)`); a dictionary token that carries
/// those bytes lets the fuzzer splice past the gate. Because the compared type's
/// endianness is unknown, each constant is emitted in both little- and big-endian
/// byte order at its natural width (2/4/8 bytes). One-byte constants (`<= 0xff`)
/// are skipped as noise -- the fuzzer reaches those trivially.
///
/// This is a deliberately simple lexical scan, not a full parse: it tolerates
/// the messy, possibly-invalid source of a target under test and never fails.
#[must_use]
pub fn extract_tokens(source: &str) -> Vec<Vec<u8>> {
    let mut tokens = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // Skip line comments so `// "not a token"` is ignored.
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            // Skip block comments.
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            b'"' => {
                let (literal, next) = scan_string_literal(bytes, i);
                i = next;
                if !literal.is_empty()
                    && literal.len() <= MAX_TOKEN_LEN
                    && seen.insert(literal.clone())
                {
                    tokens.push(literal);
                }
            }
            // Hex integer literal `0x..`/`0X..`, but only when it starts a token
            // (not embedded in an identifier like `var0x1`).
            b'0' if matches!(bytes.get(i + 1), Some(b'x' | b'X'))
                && (i == 0 || !is_ident_byte(bytes[i - 1])) =>
            {
                let (value, next) = scan_hex_literal(bytes, i);
                i = next;
                if let Some(value) = value.filter(|value| *value > 0xff) {
                    for token in int_tokens(value) {
                        if seen.insert(token.clone()) {
                            tokens.push(token);
                        }
                    }
                }
            }
            _ => i += 1,
        }
    }
    tokens
}

/// Whether `b` can appear inside a C identifier (so `0x` after it is not a
/// numeric literal).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Scan a `0x..`/`0X..` hex integer literal at `bytes[start]`, returning its
/// value and the index past the digits (and any `u`/`l` suffix). `None` when it
/// has no hex digits or overflows `u64`.
fn scan_hex_literal(bytes: &[u8], start: usize) -> (Option<u64>, usize) {
    let mut i = start + 2;
    let mut value: u64 = 0;
    let mut digits = 0usize;
    let mut overflow = false;
    while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
        if digits >= 16 {
            overflow = true;
        }
        value = value
            .wrapping_mul(16)
            .wrapping_add(u64::from(hex_val(bytes[i])));
        digits += 1;
        i += 1;
    }
    // Consume an integer suffix (uUlL) so it is not re-scanned as an identifier.
    while i < bytes.len() && matches!(bytes[i], b'u' | b'U' | b'l' | b'L') {
        i += 1;
    }
    if digits == 0 || overflow {
        (None, i)
    } else {
        (Some(value), i)
    }
}

/// Encode a magic constant as dictionary tokens: its bytes at the natural width
/// (2/4/8) in both little- and big-endian order (the compared type's endianness
/// is unknown). A palindromic encoding is emitted once.
fn int_tokens(value: u64) -> Vec<Vec<u8>> {
    let width = if value <= 0xffff {
        2
    } else if value <= 0xffff_ffff {
        4
    } else {
        8
    };
    let little = value.to_le_bytes()[..width].to_vec();
    let big = value.to_be_bytes()[8 - width..].to_vec();
    if little == big {
        vec![little]
    } else {
        vec![little, big]
    }
}

/// Scan a C string literal starting at the opening quote `bytes[start] == '"'`,
/// returning the decoded bytes (with `\n`, `\t`, `\r`, `\0`, `\"`, `\\`, and
/// `\xNN` handled) and the index just past the closing quote.
fn scan_string_literal(bytes: &[u8], start: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                break;
            }
            b'\\' if i + 1 < bytes.len() => {
                let esc = bytes[i + 1];
                match esc {
                    b'n' => {
                        out.push(b'\n');
                        i += 2;
                    }
                    b't' => {
                        out.push(b'\t');
                        i += 2;
                    }
                    b'r' => {
                        out.push(b'\r');
                        i += 2;
                    }
                    b'0' => {
                        out.push(0);
                        i += 2;
                    }
                    b'\\' => {
                        out.push(b'\\');
                        i += 2;
                    }
                    b'"' => {
                        out.push(b'"');
                        i += 2;
                    }
                    b'\'' => {
                        out.push(b'\'');
                        i += 2;
                    }
                    b'x' | b'X' => {
                        // Up to two hex digits.
                        let mut j = i + 2;
                        let mut val: u32 = 0;
                        let mut digits = 0;
                        while j < bytes.len() && digits < 2 && bytes[j].is_ascii_hexdigit() {
                            val = val * 16 + u32::from(hex_val(bytes[j]));
                            j += 1;
                            digits += 1;
                        }
                        if digits == 0 {
                            out.push(b'x');
                            i += 2;
                        } else {
                            out.push(val as u8);
                            i = j;
                        }
                    }
                    other => {
                        out.push(other);
                        i += 2;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    (out, i)
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Render tokens as an AFL++/libFuzzer dictionary file body.
#[must_use]
pub fn render_dict(tokens: &[Vec<u8>]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for token in tokens {
        out.push('"');
        for &b in token {
            match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                0x20..=0x7e => out.push(b as char),
                other => {
                    // Writing to a String is infallible.
                    let _ = write!(out, "\\x{other:02x}");
                }
            }
        }
        out.push_str("\"\n");
    }
    out
}

/// The engine-specific command-line arguments that point the fuzzer at a
/// dictionary file (`container_path` is the path inside the sandbox). Returns
/// an empty vec for engines with no dictionary concept (syzkaller).
#[must_use]
pub fn dict_run_args(engine: EngineKind, container_path: &str) -> Vec<String> {
    match engine {
        EngineKind::LibFuzzer => vec![format!("-dict={container_path}")],
        // afl-fuzz takes `-x <dir-or-file>`.
        EngineKind::AflPlusPlus => vec!["-x".to_owned(), container_path.to_owned()],
        // honggfuzz takes `-w <file>`.
        EngineKind::Honggfuzz => vec!["-w".to_owned(), container_path.to_owned()],
        EngineKind::Syzkaller => Vec::new(),
    }
}

/// Parse an AFL++/libFuzzer dictionary body back into tokens -- the inverse of
/// [`render_dict`]. Blank and `#`-comment lines are skipped; for any other line
/// the content between its first and last `"` is decoded (so a `name="token"`
/// level entry works, and a stray unquoted line is ignored). Decodes `\\`, `\"`,
/// and `\xNN`. Used to merge externally-produced tokens (e.g. LLM-proposed) into
/// an existing dictionary.
#[must_use]
pub fn parse_dict(text: &str) -> Vec<Vec<u8>> {
    let mut tokens = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (Some(start), Some(end)) = (line.find('"'), line.rfind('"')) else {
            continue;
        };
        if end <= start {
            continue;
        }
        let token = decode_dict_token(&line[start + 1..end]);
        if !token.is_empty() && token.len() <= MAX_TOKEN_LEN {
            tokens.push(token);
        }
    }
    tokens
}

/// Decode the escaped body of a dictionary token (`\\`, `\"`, `\xNN`).
fn decode_dict_token(body: &str) -> Vec<u8> {
    let bytes = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'\\' => {
                    out.push(b'\\');
                    i += 2;
                }
                b'"' => {
                    out.push(b'"');
                    i += 2;
                }
                b'x' | b'X'
                    if i + 3 < bytes.len()
                        && bytes[i + 2].is_ascii_hexdigit()
                        && bytes[i + 3].is_ascii_hexdigit() =>
                {
                    out.push(hex_val(bytes[i + 2]) * 16 + hex_val(bytes[i + 3]));
                    i += 4;
                }
                other => {
                    out.push(other);
                    i += 2;
                }
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn extracts_string_literals_deduped_in_order() {
        let src = r#"
            int f() {
                if (strcmp(s, "MAGIC") == 0) return 1;
                if (strcmp(s, "PNG") == 0) return 2;
                return strcmp(s, "MAGIC"); // duplicate, and a comment "IGNORED"
            }
        "#;
        let tokens = extract_tokens(src);
        assert_eq!(tokens, vec![b("MAGIC"), b("PNG")]);
    }

    #[test]
    fn skips_comment_and_block_comment_strings() {
        let src = "/* \"blockstr\" */ const char *k = \"real\"; // \"linestr\"";
        assert_eq!(extract_tokens(src), vec![b("real")]);
    }

    #[test]
    fn decodes_hex_escapes_to_raw_bytes() {
        let src = r#"char *m = "\x89PNG\n";"#;
        let tokens = extract_tokens(src);
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0], vec![0x89, b'P', b'N', b'G', b'\n']);
    }

    #[test]
    fn extracts_hex_magic_constants_in_both_endiannesses() {
        let tokens = extract_tokens("if (magic == 0xCAFEBABE) {}");
        // 4-byte magic, little- and big-endian.
        assert!(tokens.contains(&vec![0xbe, 0xba, 0xfe, 0xca]));
        assert!(tokens.contains(&vec![0xca, 0xfe, 0xba, 0xbe]));
    }

    #[test]
    fn hex_constant_width_follows_magnitude() {
        // 2-byte value.
        let tokens = extract_tokens("x = 0x8950;");
        assert!(tokens.contains(&vec![0x50, 0x89]));
        assert!(tokens.contains(&vec![0x89, 0x50]));
        assert!(tokens.iter().all(|t| t.len() == 2));
    }

    #[test]
    fn skips_trivial_and_embedded_hex() {
        // <= 0xff is noise; an identifier-embedded 0x is not a literal.
        assert!(extract_tokens("y = 0x05; z = var0x1234;").is_empty());
    }

    #[test]
    fn hex_suffix_is_consumed_and_value_parsed() {
        let tokens = extract_tokens("u32 v = 0xDEADu;");
        assert!(tokens.contains(&vec![0xde, 0xad]));
        assert!(tokens.contains(&vec![0xad, 0xde]));
    }

    #[test]
    fn render_escapes_nonprintable_and_quotes() {
        let rendered = render_dict(&[vec![0x89, b'P', b'N', b'"', b'G']]);
        assert_eq!(rendered, "\"\\x89PN\\\"G\"\n");
    }

    #[test]
    fn parse_dict_round_trips_render_dict() {
        let tokens = vec![
            vec![0x89u8, b'P', b'N', b'G'],
            b("MAGIC"),
            vec![b'"', b'\\', 0x0a],
        ];
        let rendered = render_dict(&tokens);
        assert_eq!(
            parse_dict(&rendered),
            tokens,
            "render -> parse must be lossless"
        );
    }

    #[test]
    fn parse_dict_skips_comments_and_level_prefix() {
        let text = "# a comment\n\
                    \n\
                    \"plain\"\n\
                    kw=\"leveled\"\n\
                    not a token line\n";
        assert_eq!(parse_dict(text), vec![b("plain"), b("leveled")]);
    }

    #[test]
    fn dict_run_args_are_engine_specific() {
        assert_eq!(
            dict_run_args(EngineKind::LibFuzzer, "/work/t.dict"),
            vec!["-dict=/work/t.dict".to_owned()]
        );
        assert_eq!(
            dict_run_args(EngineKind::AflPlusPlus, "/work/t.dict"),
            vec!["-x".to_owned(), "/work/t.dict".to_owned()]
        );
        assert_eq!(
            dict_run_args(EngineKind::Honggfuzz, "/work/t.dict"),
            vec!["-w".to_owned(), "/work/t.dict".to_owned()]
        );
        assert!(dict_run_args(EngineKind::Syzkaller, "/work/t.dict").is_empty());
    }
}
