//! Fuzzing dictionary support.
//!
//! A dictionary is a list of interesting tokens (magic bytes, keywords, format
//! markers) the fuzzer splices into inputs. Seeding one with the string
//! literals a target compares against is one of the cheapest ways to get past
//! shallow `memcmp`/keyword gates and reach deeper code, so `hobot_fuzz` extracts
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
/// of double-quoted string literals (as raw bytes). Duplicates, empty strings,
/// and implausibly long literals are dropped. Order is stable (first-seen).
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
            _ => i += 1,
        }
    }
    tokens
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
        EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite => {
            vec![format!("-dict={container_path}")]
        }
        // afl-fuzz takes `-x <dir-or-file>`.
        EngineKind::AflPlusPlus => vec!["-x".to_owned(), container_path.to_owned()],
        // honggfuzz takes `-w <file>`.
        EngineKind::Honggfuzz => vec!["-w".to_owned(), container_path.to_owned()],
        EngineKind::Syzkaller => Vec::new(),
    }
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
    fn render_escapes_nonprintable_and_quotes() {
        let rendered = render_dict(&[vec![0x89, b'P', b'N', b'"', b'G']]);
        assert_eq!(rendered, "\"\\x89PN\\\"G\"\n");
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
