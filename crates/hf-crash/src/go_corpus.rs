//! Go native fuzzing corpus files (encoding version 1).
//!
//! `go test` stores a corpus entry, and every failing input it reports, as a
//! small text file: a version line followed by one Go literal per fuzz
//! argument. This module reads and writes the one shape the Go harness path
//! supports -- a single `[]byte` or `string` argument -- so a failing input
//! can be shown and deduplicated as bytes, and a byte seed can be handed to
//! the Go fuzzer. See `docs/design/go-native-fuzzing-design.md`.
//!
//! The format is defined by `internal/fuzz/encoding.go` of the pinned Go
//! toolchain. Files come from an untrusted process: decoding is total, never
//! panics, and the caller bounds the file size before reading it.

/// The first line of every version 1 corpus file.
pub const HEADER: &str = "go test fuzz v1";

/// The Go type of the single fuzz argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoInputKind {
    /// `[]byte`.
    Bytes,
    /// `string`.
    String,
}

impl GoInputKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Bytes => "[]byte(",
            Self::String => "string(",
        }
    }
}

/// Why a corpus file was not decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoCorpusError {
    /// The first line is not the version 1 header.
    MissingHeader,
    /// The file carries no value line, or more than one: the harness path
    /// supports exactly one fuzz argument.
    NotOneValue { values: usize },
    /// The value is not a `[]byte(...)` or `string(...)` literal.
    UnsupportedType,
    /// The literal inside the parentheses is not a Go string literal.
    BadLiteral,
}

impl std::fmt::Display for GoCorpusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHeader => write!(f, "not a Go corpus file (no '{HEADER}' header)"),
            Self::NotOneValue { values } => write!(
                f,
                "the Go corpus file carries {values} values; exactly one is supported"
            ),
            Self::UnsupportedType => {
                write!(f, "the Go corpus value is neither []byte nor string")
            }
            Self::BadLiteral => write!(f, "the Go corpus value is not a valid string literal"),
        }
    }
}

impl std::error::Error for GoCorpusError {}

/// Decode a version 1 corpus file with one `[]byte` or `string` value into
/// its raw bytes.
///
/// # Errors
/// Returns a [`GoCorpusError`] naming the first reason the file is not that
/// shape.
pub fn decode(file: &[u8]) -> Result<(GoInputKind, Vec<u8>), GoCorpusError> {
    let mut lines = file
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    if lines.next() != Some(HEADER.as_bytes()) {
        return Err(GoCorpusError::MissingHeader);
    }
    let values: Vec<&[u8]> = lines
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .collect();
    let [value] = values.as_slice() else {
        return Err(GoCorpusError::NotOneValue {
            values: values.len(),
        });
    };
    let value = trim_ascii(value);
    for kind in [GoInputKind::Bytes, GoInputKind::String] {
        if let Some(rest) = value.strip_prefix(kind.prefix().as_bytes()) {
            let literal = rest.strip_suffix(b")").ok_or(GoCorpusError::BadLiteral)?;
            return unquote(trim_ascii(literal))
                .map(|bytes| (kind, bytes))
                .ok_or(GoCorpusError::BadLiteral);
        }
    }
    Err(GoCorpusError::UnsupportedType)
}

/// Encode raw bytes as a version 1 corpus file for a harness whose single
/// fuzz argument is `kind`.
///
/// Every byte outside printable ASCII is written as a `\xNN` escape, so the
/// file is plain ASCII and decodes to exactly `data` for both kinds (a Go
/// string holds arbitrary bytes).
#[must_use]
pub fn encode(kind: GoInputKind, data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(HEADER.len() + data.len() + 16);
    out.push_str(HEADER);
    out.push('\n');
    out.push_str(kind.prefix());
    out.push('"');
    for &byte in data {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push_str("\")\n");
    out
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |last| last + 1);
    &bytes[start..end]
}

/// Decode one Go string literal: interpreted (`"..."`) or raw (`` `...` ``).
fn unquote(literal: &[u8]) -> Option<Vec<u8>> {
    match literal {
        [b'`', body @ .., b'`'] => {
            if body.contains(&b'`') {
                return None;
            }
            // A raw literal drops carriage returns and keeps everything else.
            Some(body.iter().copied().filter(|byte| *byte != b'\r').collect())
        }
        [b'"', body @ .., b'"'] => unquote_interpreted(body),
        _ => None,
    }
}

fn unquote_interpreted(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut rest = body;
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b'"' | b'\n' => return None,
            b'\\' => {
                let (&escape, tail) = rest.split_first()?;
                rest = tail;
                match escape {
                    b'a' => out.push(0x07),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'v' => out.push(0x0b),
                    b'\\' => out.push(b'\\'),
                    b'"' => out.push(b'"'),
                    b'x' => {
                        let (value, tail) = take_radix(rest, 2, 16)?;
                        out.push(u8::try_from(value).ok()?);
                        rest = tail;
                    }
                    b'0'..=b'7' => {
                        // Three octal digits, the first already consumed.
                        let (low, tail) = take_radix(rest, 2, 8)?;
                        let value = u32::from(escape - b'0') * 64 + low;
                        out.push(u8::try_from(value).ok()?);
                        rest = tail;
                    }
                    b'u' | b'U' => {
                        let digits = if escape == b'u' { 4 } else { 8 };
                        let (value, tail) = take_radix(rest, digits, 16)?;
                        let rune = char::from_u32(value)?;
                        let mut buffer = [0_u8; 4];
                        out.extend_from_slice(rune.encode_utf8(&mut buffer).as_bytes());
                        rest = tail;
                    }
                    _ => return None,
                }
            }
            other => out.push(other),
        }
    }
    Some(out)
}

/// Read exactly `digits` digits of `radix` from the front of `bytes`.
fn take_radix(bytes: &[u8], digits: usize, radix: u32) -> Option<(u32, &[u8])> {
    if bytes.len() < digits {
        return None;
    }
    let (head, tail) = bytes.split_at(digits);
    let mut value = 0_u32;
    for &byte in head {
        value = value * radix + char::from(byte).to_digit(radix)?;
    }
    Some((value, tail))
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, GoCorpusError, GoInputKind};

    #[test]
    fn a_failing_input_written_by_go_decodes_to_its_bytes() {
        // Written by Go 1.26.5 in the sandbox image for a planted
        // out-of-range read: valid UTF-8 is literal, the rest is `\x` escaped.
        let file = "go test fuzz v1\n[]byte(\"FUZ\\xe7\\x1d\\x12\\xfb<\\x89\\xb8\u{63d}\\xa7\\xc1\\x06h\\xff\\xff\\xff\\x80d\")\n";
        let (kind, bytes) = decode(file.as_bytes()).unwrap();
        assert_eq!(kind, GoInputKind::Bytes);
        assert_eq!(
            bytes,
            b"FUZ\xe7\x1d\x12\xfb<\x89\xb8\xd8\xbd\xa7\xc1\x06h\xff\xff\xff\x80d"
        );
    }

    #[test]
    fn every_byte_value_survives_a_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        for kind in [GoInputKind::Bytes, GoInputKind::String] {
            let file = encode(kind, &all);
            assert!(file.is_ascii());
            assert_eq!(decode(file.as_bytes()).unwrap(), (kind, all.clone()));
        }
        assert_eq!(
            encode(GoInputKind::String, b"a\"b\\c\n"),
            "go test fuzz v1\nstring(\"a\\\"b\\\\c\\x0a\")\n"
        );
        assert_eq!(
            decode(encode(GoInputKind::Bytes, b"").as_bytes()).unwrap(),
            (GoInputKind::Bytes, Vec::new())
        );
    }

    #[test]
    fn go_escapes_and_raw_literals_are_decoded() {
        let cases: [(&str, &[u8]); 5] = [
            (
                r#"string("\a\b\f\n\r\t\v\\\"")"#,
                b"\x07\x08\x0c\n\r\t\x0b\\\"",
            ),
            (r#"[]byte("\000\101\377")"#, b"\x00A\xff"),
            (
                r#"string("\u00e9\U0001f600")"#,
                "\u{e9}\u{1f600}".as_bytes(),
            ),
            ("[]byte(`raw \\x41 \"q\"`)", b"raw \\x41 \"q\""),
            ("  string( \"padded\" )  ", b"padded"),
        ];
        for (value, expected) in cases {
            let file = format!("go test fuzz v1\r\n{value}\r\n");
            assert_eq!(decode(file.as_bytes()).unwrap().1, expected, "{value}");
        }
    }

    #[test]
    fn files_of_another_shape_are_refused() {
        let refused = |text: &str| decode(text.as_bytes()).unwrap_err();
        assert_eq!(refused("[]byte(\"x\")\n"), GoCorpusError::MissingHeader);
        assert_eq!(refused(""), GoCorpusError::MissingHeader);
        assert_eq!(
            refused("go test fuzz v1\n"),
            GoCorpusError::NotOneValue { values: 0 }
        );
        assert_eq!(
            refused("go test fuzz v1\n[]byte(\"a\")\nint(5)\n"),
            GoCorpusError::NotOneValue { values: 2 }
        );
        assert_eq!(
            refused("go test fuzz v1\nint(5)\n"),
            GoCorpusError::UnsupportedType
        );
        for literal in [
            "[]byte(\"open)",
            "[]byte(\"a\"",
            "[]byte(\"\\q\")",
            "[]byte(\"\\x4\")",
            "[]byte(\"\\400\")",
            "[]byte(\"\\ud800\")",
            "[]byte(\"a\"b\")",
            "[]byte(`a`b`)",
            "[]byte(x)",
            "[]byte()",
        ] {
            assert_eq!(
                refused(&format!("go test fuzz v1\n{literal}\n")),
                GoCorpusError::BadLiteral,
                "{literal}"
            );
        }
    }
}
