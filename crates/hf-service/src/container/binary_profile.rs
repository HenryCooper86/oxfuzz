//! A static profile of a Linux ELF binary: how it is linked, what it imports,
//! which input channel it most likely reads, and a heuristic dictionary built
//! from its printable strings.
//!
//! Every function here is pure over bytes: no file access, no process
//! execution. The parsers are total over hostile input: each offset is
//! checked against the image before it is read.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};

use super::binary_only::{elf_machine, BinaryInput, ElfMachine};
use super::harness::sha256_hex;

/// Most dynamic imports a profile lists.
pub const MAX_IMPORTS: usize = 512;
/// Most interesting strings a profile lists.
pub const MAX_STRINGS: usize = 200;
/// Longest string a profile keeps, in bytes.
pub const MAX_STRING_LEN: usize = 80;
/// Most tokens in one dictionary.
pub const MAX_DICTIONARY_TOKENS: usize = 256;
/// Longest dictionary token AFL++ accepts, in bytes.
pub const MAX_TOKEN_BYTES: usize = 128;
/// Largest dictionary text `parse_dictionary` reads.
pub const MAX_DICTIONARY_TEXT_BYTES: usize = 64 * 1024;

const MAX_SYMBOLS: u64 = 65_536;
const MAX_SYMBOL_NAME: usize = 256;
const ELF_HEADER_LEN: u64 = 64;
const PHDR_MIN: u64 = 56;
const SHDR_MIN: u64 = 64;
const SYM_SIZE: u64 = 24;
const PT_INTERP: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHT_SYMTAB: u32 = 2;

fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

/// How the binary is linked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Linking {
    /// The binary loads shared libraries: it has an interpreter or a
    /// dynamic symbol table.
    Dynamic,
    /// The binary carries everything it needs.
    Static,
}

/// What a static look at a binary shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryProfile {
    pub machine: ElfMachine,
    pub size: u64,
    pub sha256: String,
    pub linking: Linking,
    /// Undefined dynamic symbols, version suffix stripped, sorted, unique.
    pub imports: Vec<String>,
    pub suggested_input: BinaryInput,
    /// Plain English reasons for the suggestion.
    pub suggestion_reasons: Vec<String>,
    /// Printable strings likely to be input vocabulary.
    pub strings: Vec<String>,
    /// Heuristic dictionary tokens in AFL escaped form, without quotes.
    pub dictionary: Vec<String>,
    pub notes: Vec<String>,
}

/// Profile an ELF image.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the bytes are not a supported
/// ELF binary or a header points outside the image.
pub fn profile_binary(image: &[u8]) -> Result<BinaryProfile, ClassifiedError> {
    let machine = elf_machine(image)?;
    let linking = linking(image)?;
    let imports = dynamic_imports(image)?;
    let (suggested_input, suggestion_reasons) = suggest_input(&imports, linking);
    let symbols = symbol_names(image)?;
    let strings = interesting_strings(&printable_strings(image, usize::MAX), &imports, &symbols);
    let dictionary = dictionary_tokens(&strings, &imports);
    let mut notes = Vec::new();
    if linking == Linking::Static {
        notes.push(
            "Statically linked: the crash reporter and the socket shim are preloads and do not \
             load into this binary, so findings have no frames and socket modes will not work."
                .to_string(),
        );
    } else if imports.is_empty() {
        notes.push("No dynamic imports were found.".to_string());
    }
    Ok(BinaryProfile {
        machine,
        size: image.len() as u64,
        sha256: sha256_hex(image),
        linking,
        imports,
        suggested_input,
        suggestion_reasons,
        strings,
        dictionary,
        notes,
    })
}

fn bytes_at<'a>(
    image: &'a [u8],
    offset: u64,
    len: u64,
    what: &str,
) -> Result<&'a [u8], ClassifiedError> {
    let out_of_range = || invalid(format!("the ELF {what} points outside the file"));
    let end = offset.checked_add(len).ok_or_else(out_of_range)?;
    let start = usize::try_from(offset).map_err(|_| out_of_range())?;
    let end = usize::try_from(end).map_err(|_| out_of_range())?;
    image.get(start..end).ok_or_else(out_of_range)
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn header_field<T>(value: Option<T>) -> Result<T, ClassifiedError> {
    value.ok_or_else(|| invalid("the ELF header is truncated"))
}

/// The ELF table described by an (offset, entry size, count) triple, checked
/// to lie inside the image. `None` when the table is absent.
fn table<'a>(
    image: &'a [u8],
    (offset, entry_size, count): (u64, u64, u64),
    minimum: u64,
    what: &str,
) -> Result<Option<(&'a [u8], usize)>, ClassifiedError> {
    if offset == 0 || count == 0 {
        return Ok(None);
    }
    if entry_size < minimum {
        return Err(invalid(format!("the ELF {what} entries are too small")));
    }
    let len = entry_size
        .checked_mul(count)
        .ok_or_else(|| invalid(format!("the ELF {what} table is too large")))?;
    let bytes = bytes_at(image, offset, len, what)?;
    let step = usize::try_from(entry_size)
        .map_err(|_| invalid(format!("the ELF {what} entries are too large")))?;
    Ok(Some((bytes, step)))
}

fn program_headers(image: &[u8]) -> Result<Option<(&[u8], usize)>, ClassifiedError> {
    let offset = header_field(u64_at(image, 0x20))?;
    let size = u64::from(header_field(u16_at(image, 0x36))?);
    let count = u64::from(header_field(u16_at(image, 0x38))?);
    table(
        image,
        (offset, size, count),
        PHDR_MIN,
        "program header table",
    )
}

fn section_headers(image: &[u8]) -> Result<Option<(&[u8], usize)>, ClassifiedError> {
    let offset = header_field(u64_at(image, 0x28))?;
    let size = u64::from(header_field(u16_at(image, 0x3A))?);
    let count = u64::from(header_field(u16_at(image, 0x3C))?);
    table(
        image,
        (offset, size, count),
        SHDR_MIN,
        "section header table",
    )
}

/// The dynamic symbol table and its string table, when the image has one.
type DynsymTables<'a> = (&'a [u8], &'a [u8]);

fn dynsym(image: &[u8]) -> Result<Option<DynsymTables<'_>>, ClassifiedError> {
    symbol_table(image, SHT_DYNSYM)
}

/// The symbol table of section type `kind` and its string table.
fn symbol_table(image: &[u8], kind: u32) -> Result<Option<DynsymTables<'_>>, ClassifiedError> {
    let Some((sections, step)) = section_headers(image)? else {
        return Ok(None);
    };
    let section = |index: usize| sections.get(index * step..(index + 1) * step);
    let mut index = 0;
    while let Some(header) = section(index) {
        index += 1;
        if u32_at(header, 4) != Some(kind) {
            continue;
        }
        let field = |at| header_field(u64_at(header, at));
        let (offset, size) = (field(0x18)?, field(0x20)?);
        let link = usize::try_from(header_field(u32_at(header, 0x28))?)
            .map_err(|_| invalid("the ELF symbol table link is out of range"))?;
        let strtab = section(link)
            .ok_or_else(|| invalid("the ELF symbol table names a missing string table"))?;
        let str_field = |at| header_field(u64_at(strtab, at));
        let (str_offset, str_size) = (str_field(0x18)?, str_field(0x20)?);
        let symbols = bytes_at(image, offset, size, "symbol table")?;
        let names = bytes_at(image, str_offset, str_size, "string table")?;
        return Ok(Some((symbols, names)));
    }
    Ok(None)
}

fn symbol_name(strtab: &[u8], offset: u32) -> Option<String> {
    let rest = strtab.get(usize::try_from(offset).ok()?..)?;
    let rest = rest.get(..rest.len().min(MAX_SYMBOL_NAME))?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let name = String::from_utf8_lossy(&rest[..end]);
    // "read@GLIBC_2.17" and "read@@GLIBC_2.17" both name `read`.
    let name = name.split('@').next().unwrap_or_default();
    (!name.is_empty()).then(|| name.to_string())
}

/// Every name in the image's static and dynamic symbol tables. These are the
/// toolchain's names for functions, objects and source files, never part of
/// an input format, so strings equal to one are left out of the profile.
fn symbol_names(image: &[u8]) -> Result<HashSet<String>, ClassifiedError> {
    let limit = usize::try_from(MAX_SYMBOLS).unwrap_or(usize::MAX);
    let step = usize::try_from(SYM_SIZE).unwrap_or(24);
    let mut names = HashSet::new();
    for kind in [SHT_SYMTAB, SHT_DYNSYM] {
        let Some((symbols, strtab)) = symbol_table(image, kind)? else {
            continue;
        };
        names.extend(
            symbols
                .chunks_exact(step)
                .take(limit)
                .filter_map(|sym| u32_at(sym, 0).filter(|&name| name != 0))
                .filter_map(|name| symbol_name(strtab, name)),
        );
    }
    Ok(names)
}

/// The undefined dynamic symbols of the image, version suffix stripped,
/// sorted and unique, at most [`MAX_IMPORTS`].
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when a header points outside the
/// image.
pub fn dynamic_imports(image: &[u8]) -> Result<Vec<String>, ClassifiedError> {
    let Some((symbols, strtab)) = dynsym(image)? else {
        return Ok(Vec::new());
    };
    let limit = usize::try_from(MAX_SYMBOLS).unwrap_or(usize::MAX);
    let step = usize::try_from(SYM_SIZE).unwrap_or(24);
    let names: BTreeSet<String> = symbols
        .chunks_exact(step)
        .take(limit)
        .filter(|sym| u16_at(sym, 6) == Some(0))
        .filter_map(|sym| u32_at(sym, 0).filter(|&name| name != 0))
        .filter_map(|name| symbol_name(strtab, name))
        .collect();
    Ok(names.into_iter().take(MAX_IMPORTS).collect())
}

const PT_LOAD: u32 = 1;

/// The address the image's file offset 0 is loaded at: the lowest
/// `p_vaddr - p_offset` over its `PT_LOAD` segments. 0 for a position-
/// independent executable, the link base for a fixed-address one. A module
/// offset from a crash report plus this is the address objdump shows.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when the header table points
/// outside the image.
pub fn load_base(image: &[u8]) -> Result<u64, ClassifiedError> {
    let Some((headers, step)) = program_headers(image)? else {
        return Ok(0);
    };
    Ok(headers
        .chunks_exact(step)
        .filter(|header| u32_at(header, 0) == Some(PT_LOAD))
        .filter_map(|header| Some(u64_at(header, 0x10)?.saturating_sub(u64_at(header, 0x08)?)))
        .min()
        .unwrap_or(0))
}

/// Whether the image loads shared libraries.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when a header points outside the
/// image.
pub fn linking(image: &[u8]) -> Result<Linking, ClassifiedError> {
    if image.len() < usize::try_from(ELF_HEADER_LEN).unwrap_or(64) {
        return Err(invalid("the file is too short to be an ELF binary"));
    }
    if let Some((headers, step)) = program_headers(image)? {
        if headers
            .chunks_exact(step)
            .any(|header| u32_at(header, 0) == Some(PT_INTERP))
        {
            return Ok(Linking::Dynamic);
        }
    }
    Ok(if dynsym(image)?.is_some() {
        Linking::Dynamic
    } else {
        Linking::Static
    })
}

/// Runs of printable ASCII (and tab) of 4 or more bytes, in file order,
/// unique, each cut to [`MAX_STRING_LEN`] bytes, at most `limit` of them.
#[must_use]
pub fn printable_strings(image: &[u8], limit: usize) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for run in image.split(|&b| !(b == b'\t' || (0x20..=0x7e).contains(&b))) {
        if out.len() >= limit {
            break;
        }
        if run.len() < 4 {
            continue;
        }
        let text: String = run[..run.len().min(MAX_STRING_LEN)]
            .iter()
            .map(|&b| char::from(b))
            .collect();
        if seen.insert(text.clone()) {
            out.push(text);
        }
    }
    out
}

/// Whether a string is a source or object file name (`crtstuff.c`, `Scrt1.o`).
fn is_file_name(text: &str) -> bool {
    const EXTENSIONS: [&str; 7] = [".o", ".c", ".h", ".S", ".s", ".cc", ".cpp"];
    !text.contains(char::is_whitespace) && EXTENSIONS.iter().any(|ext| text.ends_with(ext))
}

/// Whether a string is mostly punctuation, as machine code bytes that happen
/// to be printable usually are (`` `B@9@ ``).
fn is_code_noise(text: &str) -> bool {
    let alphanumeric = text.chars().filter(char::is_ascii_alphanumeric).count();
    alphanumeric * 2 < text.chars().count()
}

/// Whether a token holds a printf conversion (`%u`, `%5.2lf`).
fn has_printf_conversion(text: &str) -> bool {
    text.split('%').skip(1).any(|rest| {
        rest.trim_start_matches(|c: char| c.is_ascii_digit() || ".-+ #lhzjt".contains(c))
            .starts_with(|c: char| "diouxXeEfFgGaAcspn".contains(c))
    })
}

fn is_boilerplate(text: &str, imports: &[String]) -> bool {
    const PREFIXES: [&str; 8] = [
        "GLIBC_", "GCC:", "_", ".", "/lib", "/usr/lib", "ld-linux", "GCC_",
    ];
    const FRAGMENTS: [&str; 3] = ["glibc", "libc.so", "gnu c"];
    let lower = text.to_ascii_lowercase();
    imports.iter().any(|import| import == text)
        || PREFIXES.iter().any(|prefix| text.starts_with(prefix))
        || FRAGMENTS.iter().any(|fragment| lower.contains(fragment))
        || is_file_name(text)
}

/// The strings worth showing: those that are not loader, compiler or libc
/// boilerplate, at most [`MAX_STRINGS`].
fn interesting_strings(
    strings: &[String],
    imports: &[String],
    symbols: &HashSet<String>,
) -> Vec<String> {
    strings
        .iter()
        .filter(|text| !is_boilerplate(text, imports) && !symbols.contains(text.as_str()))
        .filter(|text| !is_code_noise(text))
        .take(MAX_STRINGS)
        .cloned()
        .collect()
}

/// Which input channel the binary most likely reads, with the reasons.
#[must_use]
pub fn suggest_input(imports: &[String], linking: Linking) -> (BinaryInput, Vec<String>) {
    let has = |names: &[&str]| imports.iter().any(|i| names.contains(&i.as_str()));
    if linking == Linking::Static && imports.is_empty() {
        return (
            BinaryInput::File,
            vec![
                "statically linked: the imports cannot be read, so a file argument is assumed"
                    .to_string(),
            ],
        );
    }
    let (input, reason) = if has(&["accept", "accept4"]) {
        (
            BinaryInput::Socket,
            "imports accept: it serves stream connections",
        )
    } else if has(&["bind"]) && has(&["recvfrom", "recvmsg", "recvmmsg"]) {
        (BinaryInput::Socket, "binds a socket and reads datagrams")
    } else if has(&[
        "fopen", "fopen64", "open", "open64", "openat", "openat64", "freopen",
    ]) {
        (
            BinaryInput::File,
            "opens files: input is most likely a file named on the command line",
        )
    } else if has(&[
        "read",
        "fread",
        "fgets",
        "getline",
        "getchar",
        "fgetc",
        "scanf",
        "__isoc99_scanf",
        "getc",
    ]) {
        (
            BinaryInput::Stdin,
            "reads with standard-input calls and opens no files",
        )
    } else {
        (
            BinaryInput::File,
            "no input calls were found among the imports; a file argument is the common case",
        )
    };
    (input, vec![reason.to_string()])
}

/// Whether the token is only printf conversions such as `%d` or `%5.2lf`.
fn is_printf_only(token: &str) -> bool {
    let mut chars = token.chars().peekable();
    let mut seen = false;
    while let Some(c) = chars.next() {
        if c != '%' {
            return false;
        }
        seen = true;
        if chars.peek() == Some(&'%') {
            chars.next();
            continue;
        }
        let mut converted = false;
        for next in chars.by_ref() {
            if next.is_ascii_alphabetic() && !matches!(next, 'l' | 'h' | 'z' | 'j' | 't' | 'L') {
                converted = true;
                break;
            }
            if !(next.is_ascii_digit() || "-+ #.lhzjtL*".contains(next)) {
                return false;
            }
        }
        if !converted {
            return false;
        }
    }
    seen
}

/// Heuristic dictionary tokens, in AFL escaped form without quotes.
#[must_use]
pub fn dictionary_tokens(strings: &[String], imports: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut offer = |candidate: &str, out: &mut Vec<String>| {
        let keep = !is_printf_only(candidate)
            && !has_printf_conversion(candidate)
            && !is_code_noise(candidate)
            && !imports.iter().any(|import| import == candidate)
            && seen.insert(candidate.to_string());
        if keep && out.len() < MAX_DICTIONARY_TOKENS {
            out.push(escape_token(candidate.as_bytes()));
        }
    };
    for text in strings {
        if text.chars().any(char::is_whitespace) {
            for word in text.split_whitespace() {
                let long_enough = (3..=24).contains(&word.len());
                let keyword = word.chars().any(|c| !c.is_ascii_lowercase())
                    || word.chars().all(|c| c.is_ascii_uppercase());
                if long_enough && keyword {
                    offer(word, &mut out);
                }
            }
        } else if (2..=32).contains(&text.len()) {
            offer(text, &mut out);
        }
    }
    out
}

/// AFL dictionary escaping: printable ASCII is verbatim except `"` and `\`,
/// which are backslash-escaped; every other byte is `\xNN`.
#[must_use]
pub fn escape_token(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out
}

/// Decode an escaped token back to bytes.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] for a bad escape, a bare quote or
/// a character outside printable ASCII.
pub fn unescape_token(text: &str) -> Result<Vec<u8>, ClassifiedError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&byte) = bytes.get(i) {
        i += 1;
        match byte {
            b'\\' => {
                let escape = bytes.get(i).copied();
                i += 1;
                match escape {
                    Some(b'\\') => out.push(b'\\'),
                    Some(b'"') => out.push(b'"'),
                    Some(b'x') => {
                        let digits = bytes
                            .get(i..i + 2)
                            .and_then(|pair| {
                                let hi = char::from(pair[0]).to_digit(16)?;
                                let lo = char::from(pair[1]).to_digit(16)?;
                                u8::try_from(hi * 16 + lo).ok()
                            })
                            .ok_or_else(|| invalid("a \\x escape needs two hex digits"))?;
                        i += 2;
                        out.push(digits);
                    }
                    _ => return Err(invalid("unknown escape (use \\\\, \\\" or \\xNN)")),
                }
            }
            b'"' => return Err(invalid("a quote inside a token must be escaped")),
            0x20..=0x7e => out.push(byte),
            _ => {
                return Err(invalid(
                    "a token holds only printable ASCII or \\xNN escapes",
                ))
            }
        }
    }
    Ok(out)
}

fn checked_token(token: &str) -> Result<Vec<u8>, ClassifiedError> {
    let bytes = unescape_token(token)?;
    if bytes.is_empty() {
        return Err(invalid("a dictionary token cannot be empty"));
    }
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(invalid(format!(
            "a dictionary token is longer than {MAX_TOKEN_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// Render tokens as AFL dictionary text, one `token_0001="..."` per line.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] for a malformed, empty or
/// overlong token, or more than [`MAX_DICTIONARY_TOKENS`] tokens.
pub fn render_dictionary(tokens: &[String]) -> Result<String, ClassifiedError> {
    if tokens.len() > MAX_DICTIONARY_TOKENS {
        return Err(invalid(format!(
            "a dictionary holds at most {MAX_DICTIONARY_TOKENS} tokens"
        )));
    }
    let mut out = String::new();
    for (index, token) in tokens.iter().enumerate() {
        let bytes =
            checked_token(token).map_err(|e| invalid(format!("token {}: {e}", index + 1)))?;
        // Writing to a String cannot fail.
        let _ = writeln!(out, "token_{:04}=\"{}\"", index + 1, escape_token(&bytes));
    }
    Ok(out)
}

/// Read AFL dictionary text into escaped token texts. Lines are
/// `name="..."` or `"..."`; `#` comments and blank lines are skipped.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] naming the first malformed line,
/// or when the text or token count exceeds the bounds.
pub fn parse_dictionary(text: &str) -> Result<Vec<String>, ClassifiedError> {
    if text.len() > MAX_DICTIONARY_TEXT_BYTES {
        return Err(invalid(format!(
            "the dictionary is larger than {} KiB",
            MAX_DICTIONARY_TEXT_BYTES / 1024
        )));
    }
    let mut tokens = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |message: &str| invalid(format!("dictionary line {}: {message}", index + 1));
        let first = line
            .find('"')
            .ok_or_else(|| at("expected a quoted token"))?;
        let name = line[..first].trim();
        let name_ok = name.is_empty()
            || name.strip_suffix('=').is_some_and(|n| {
                let n = n.trim_end();
                !n.is_empty()
                    && n.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '@'))
            });
        if !name_ok {
            return Err(at("expected name=\"token\" or \"token\""));
        }
        let inner = line[first + 1..]
            .strip_suffix('"')
            .ok_or_else(|| at("the token must end with a quote"))?;
        let bytes = checked_token(inner).map_err(|e| at(&e.to_string()))?;
        if tokens.len() >= MAX_DICTIONARY_TOKENS {
            return Err(at(&format!(
                "a dictionary holds at most {MAX_DICTIONARY_TOKENS} tokens"
            )));
        }
        tokens.push(escape_token(&bytes));
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF64 LE `x86_64` executable with an optional `PT_INTERP` and a
    /// .dynsym/.dynstr pair. Symbols are (name, defined).
    fn elf(interp: bool, symbols: &[(&str, bool)], extra: &[u8]) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut syms = vec![0u8; 24];
        for (name, defined) in symbols {
            let at = u32::try_from(strtab.len()).unwrap();
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            let mut sym = vec![0u8; 24];
            sym[0..4].copy_from_slice(&at.to_le_bytes());
            let shndx: u16 = u16::from(*defined);
            sym[6..8].copy_from_slice(&shndx.to_le_bytes());
            syms.extend_from_slice(&sym);
        }
        let phnum: u16 = u16::from(interp);
        let mut image = vec![0u8; 64];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&3u16.to_le_bytes());
        image[18..20].copy_from_slice(&62u16.to_le_bytes());
        if interp {
            image[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
            let mut ph = vec![0u8; 56];
            ph[0..4].copy_from_slice(&3u32.to_le_bytes());
            image.extend_from_slice(&ph);
        }
        image[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        image[0x38..0x3a].copy_from_slice(&phnum.to_le_bytes());
        let strtab_off = image.len() as u64;
        image.extend_from_slice(&strtab);
        while !image.len().is_multiple_of(8) {
            image.push(0);
        }
        let symtab_off = image.len() as u64;
        image.extend_from_slice(&syms);
        image.extend_from_slice(extra);
        while !image.len().is_multiple_of(8) {
            image.push(0);
        }
        let shoff = image.len() as u64;
        let mut section = |kind: u32, off: u64, size: u64, link: u32| {
            let mut sh = vec![0u8; 64];
            sh[4..8].copy_from_slice(&kind.to_le_bytes());
            sh[0x18..0x20].copy_from_slice(&off.to_le_bytes());
            sh[0x20..0x28].copy_from_slice(&size.to_le_bytes());
            sh[0x28..0x2c].copy_from_slice(&link.to_le_bytes());
            image.extend_from_slice(&sh);
        };
        section(0, 0, 0, 0);
        section(11, symtab_off, syms.len() as u64, 2);
        section(3, strtab_off, strtab.len() as u64, 0);
        image[0x28..0x30].copy_from_slice(&shoff.to_le_bytes());
        image[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        image[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        image
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn the_load_base_is_the_lowest_loaded_address_less_its_offset() {
        let with_loads = |loads: &[(u64, u64)]| {
            let mut image = elf(false, &[], b"");
            let phoff = image.len() as u64;
            for (offset, vaddr) in loads {
                let mut ph = vec![0u8; 56];
                ph[0..4].copy_from_slice(&1u32.to_le_bytes());
                ph[0x08..0x10].copy_from_slice(&offset.to_le_bytes());
                ph[0x10..0x18].copy_from_slice(&vaddr.to_le_bytes());
                image.extend_from_slice(&ph);
            }
            image[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
            image[0x38..0x3a].copy_from_slice(&u16::try_from(loads.len()).unwrap().to_le_bytes());
            image
        };
        assert_eq!(
            load_base(&with_loads(&[(0, 0), (0x10db8, 0x20db8)])).unwrap(),
            0
        );
        assert_eq!(
            load_base(&with_loads(&[(0x1000, 0x40_1000), (0, 0x40_0000)])).unwrap(),
            0x40_0000
        );
        assert_eq!(load_base(&elf(false, &[], b"")).unwrap(), 0);
    }

    #[test]
    fn symbol_names_and_code_noise_stay_out_of_strings_and_the_dictionary() {
        // A non-stripped static binary: its .symtab names toolchain objects
        // and functions, which are not part of any input format.
        let mut image = elf(
            false,
            &[("frame_dummy", true), ("crtstuff.c", true), ("main", true)],
            b"\0PIC1\0usage: picinfo FILE\0%ux%u,\0`B@9@\0Scrt1.o\0helper.c\0",
        );
        let shoff =
            usize::try_from(u64::from_le_bytes(image[0x28..0x30].try_into().unwrap())).unwrap();
        image[shoff + 64 + 4..shoff + 64 + 8].copy_from_slice(&2u32.to_le_bytes());
        let profile = profile_binary(&image).unwrap();
        for noise in [
            "frame_dummy",
            "crtstuff.c",
            "main",
            "Scrt1.o",
            "helper.c",
            "`B@9@",
        ] {
            assert!(
                !profile.strings.iter().any(|text| text == noise),
                "{noise}: {:?}",
                profile.strings
            );
        }
        assert!(profile.strings.iter().any(|text| text == "PIC1"));
        assert_eq!(profile.dictionary, names(&["PIC1", "usage:", "FILE"]));
    }

    #[test]
    fn imports_are_version_stripped_sorted_and_skip_defined() {
        let image = elf(
            true,
            &[
                ("write@GLIBC_2.2.5", false),
                ("read@GLIBC_2.17", false),
                ("main", true),
                ("read@@GLIBC_2.17", false),
            ],
            b"",
        );
        assert_eq!(dynamic_imports(&image).unwrap(), names(&["read", "write"]));
    }

    #[test]
    fn imports_are_capped() {
        let owned: Vec<String> = (0..600).map(|i| format!("sym{i:04}")).collect();
        let syms: Vec<(&str, bool)> = owned.iter().map(|s| (s.as_str(), false)).collect();
        let image = elf(true, &syms, b"");
        assert_eq!(dynamic_imports(&image).unwrap().len(), MAX_IMPORTS);
    }

    #[test]
    fn linking_detects_interp_dynsym_and_static() {
        assert_eq!(linking(&elf(true, &[], b"")).unwrap(), Linking::Dynamic);
        assert_eq!(
            linking(&elf(false, &[("read", false)], b"")).unwrap(),
            Linking::Dynamic
        );
        let mut image = elf(false, &[], b"");
        // Turn the dynsym section into a plain one: no PT_INTERP, no SHT_DYNSYM.
        let shoff =
            usize::try_from(u64::from_le_bytes(image[0x28..0x30].try_into().unwrap())).unwrap();
        image[shoff + 64 + 4..shoff + 64 + 8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(linking(&image).unwrap(), Linking::Static);
        image[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(linking(&image).unwrap(), Linking::Static);
        assert!(dynamic_imports(&image).unwrap().is_empty());
    }

    #[test]
    fn out_of_range_headers_are_validation_errors() {
        let mut image = elf(true, &[("read", false)], b"");
        let good = image.clone();
        image[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            dynamic_imports(&image),
            Err(ClassifiedError::Validation(_))
        ));
        let mut image = good.clone();
        image[0x20..0x28].copy_from_slice(&(1u64 << 40).to_le_bytes());
        assert!(matches!(
            linking(&image),
            Err(ClassifiedError::Validation(_))
        ));
        let mut image = good.clone();
        let shoff =
            usize::try_from(u64::from_le_bytes(image[0x28..0x30].try_into().unwrap())).unwrap();
        // dynsym size beyond the file
        image[shoff + 64 + 0x20..shoff + 64 + 0x28].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            dynamic_imports(&image),
            Err(ClassifiedError::Validation(_))
        ));
        // sh_link beyond the section count
        let mut image = good;
        image[shoff + 64 + 0x28..shoff + 64 + 0x2c].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            dynamic_imports(&image),
            Err(ClassifiedError::Validation(_))
        ));
    }

    #[test]
    fn truncated_images_error_without_panicking() {
        let image = elf(true, &[("read", false)], b"");
        for len in 0..image.len() {
            let _ = profile_binary(&image[..len]);
            let _ = linking(&image[..len]);
            let _ = dynamic_imports(&image[..len]);
        }
        assert!(profile_binary(&image[..30]).is_err());
    }

    #[test]
    fn strings_are_extracted_truncated_deduped_and_limited() {
        let mut data = b"\x00ab\x00hello world\x00\x01hello world\x00tab\there\x00".to_vec();
        data.extend(std::iter::repeat_n(b'x', 100));
        data.push(0);
        data.extend_from_slice(b"WIDTH\x00");
        let strings = printable_strings(&data, 100);
        assert_eq!(strings[0], "hello world");
        assert_eq!(strings[1], "tab\there");
        assert_eq!(strings[2].len(), MAX_STRING_LEN);
        assert_eq!(strings[3], "WIDTH");
        assert_eq!(strings.len(), 4);
        assert_eq!(printable_strings(&data, 2).len(), 2);
    }

    #[test]
    fn interesting_filter_drops_boilerplate() {
        let strings = names(&[
            "GLIBC_2.2.5",
            "GCC: (GNU) 13.2.0",
            "_init",
            ".text",
            "/lib64/ld-linux-x86-64.so.2",
            "/usr/lib/x",
            "ld-linux-aarch64.so.1",
            "libc.so.6",
            "GNU C17 13.2",
            "glibc thing",
            "printf",
            "PIC1",
        ]);
        let kept = interesting_strings(&strings, &names(&["printf"]), &HashSet::new());
        assert_eq!(kept, names(&["PIC1"]));
    }

    #[test]
    fn interesting_strings_are_capped() {
        let strings: Vec<String> = (0..500).map(|i| format!("word{i}")).collect();
        assert_eq!(
            interesting_strings(&strings, &[], &HashSet::new()).len(),
            MAX_STRINGS
        );
    }

    #[test]
    fn suggest_input_rules_and_order() {
        let s = |list: &[&str], link| suggest_input(&names(list), link);
        let d = Linking::Dynamic;
        assert_eq!(s(&["accept", "fopen"], d).0, BinaryInput::Socket);
        assert_eq!(s(&["accept4"], d).0, BinaryInput::Socket);
        assert_eq!(s(&["bind", "recvfrom", "fopen"], d).0, BinaryInput::Socket);
        assert_eq!(s(&["bind", "recvmsg"], d).0, BinaryInput::Socket);
        assert_eq!(s(&["bind", "fopen"], d).0, BinaryInput::File);
        assert_eq!(s(&["fopen", "read"], d).0, BinaryInput::File);
        assert_eq!(s(&["openat64", "read"], d).0, BinaryInput::File);
        assert_eq!(s(&["fgets"], d).0, BinaryInput::Stdin);
        assert_eq!(s(&["__isoc99_scanf"], d).0, BinaryInput::Stdin);
        let (input, reasons) = s(&["printf"], d);
        assert_eq!(input, BinaryInput::File);
        assert!(reasons[0].starts_with("no input calls"));
        let (input, reasons) = s(&[], Linking::Static);
        assert_eq!(input, BinaryInput::File);
        assert!(reasons[0].starts_with("statically linked"));
        assert_eq!(
            s(&["accept"], d).1[0],
            "imports accept: it serves stream connections"
        );
    }

    #[test]
    fn dictionary_tokens_follow_the_rules() {
        let strings = names(&[
            "PIC1",
            "%d",
            "%5.2lf%s",
            "Content-Length:",
            "read the WIDTH value",
            "a",
            "send",
            "<html>",
            &"z".repeat(40),
        ]);
        let tokens = dictionary_tokens(&strings, &names(&["send"]));
        assert_eq!(
            tokens,
            names(&["PIC1", "Content-Length:", "WIDTH", "<html>"])
        );
    }

    #[test]
    fn dictionary_tokens_dedupe_and_cap() {
        let strings: Vec<String> = (0..400).map(|i| format!("tok{i}")).collect();
        assert_eq!(
            dictionary_tokens(&strings, &[]).len(),
            MAX_DICTIONARY_TOKENS
        );
        assert_eq!(dictionary_tokens(&names(&["abc", "abc"]), &[]).len(), 1);
    }

    #[test]
    fn escape_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        let text = escape_token(&all);
        assert_eq!(unescape_token(&text).unwrap(), all);
        assert_eq!(escape_token(b"a\"b\\c\n"), "a\\\"b\\\\c\\x0a");
        assert_eq!(escape_token(&[0xff]), "\\xff");
    }

    #[test]
    fn unescape_rejects_malformed_text() {
        for bad in [
            "\\",
            "\\q",
            "\\x",
            "\\x1",
            "\\xzz",
            "a\"b",
            "caf\u{e9}",
            "\u{7f}",
        ] {
            assert!(
                matches!(unescape_token(bad), Err(ClassifiedError::Validation(_))),
                "{bad:?}"
            );
        }
        assert_eq!(unescape_token("\\xFF").unwrap(), vec![0xff]);
    }

    #[test]
    fn dictionary_round_trips() {
        let tokens = names(&["PIC1", "a\\\"b", "\\xff\\x00"]);
        let text = render_dictionary(&tokens).unwrap();
        assert!(text.starts_with("token_0001=\"PIC1\"\n"));
        assert!(text.contains("token_0003=\"\\xff\\x00\"\n"));
        assert_eq!(parse_dictionary(&text).unwrap(), tokens);
    }

    #[test]
    fn parse_dictionary_skips_comments_and_accepts_bare_tokens() {
        let text = "# header\n\n  \nname@2=\"AB\"\n\"CD\"\n";
        assert_eq!(parse_dictionary(text).unwrap(), names(&["AB", "CD"]));
        assert_eq!(parse_dictionary("t=\"\\x41\"").unwrap(), names(&["A"]));
    }

    #[test]
    fn parse_dictionary_names_the_bad_line() {
        for (text, line) in [
            ("\"ok\"\nnoquote\n", "line 2"),
            ("# c\n\n\"ok\nx\"\n", "line 3"),
            ("a b=\"x\"\n", "line 1"),
            ("\"\"\n", "line 1"),
            ("\"ok\"\n\"bad\\q\"\n", "line 2"),
        ] {
            match parse_dictionary(text) {
                Err(ClassifiedError::Validation(m)) => {
                    assert!(m.contains(line), "{m} should name {line}");
                }
                other => panic!("{text:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn dictionary_bounds_are_enforced() {
        let long = "a".repeat(MAX_TOKEN_BYTES + 1);
        assert!(render_dictionary(std::slice::from_ref(&long)).is_err());
        assert!(parse_dictionary(&format!("\"{long}\"")).is_err());
        assert!(render_dictionary(&[String::new()]).is_err());
        assert!(render_dictionary(&["a".repeat(MAX_TOKEN_BYTES)]).is_ok());
        let many = vec!["a".to_string(); MAX_DICTIONARY_TOKENS + 1];
        assert!(render_dictionary(&many).is_err());
        let text = "\"a\"\n".repeat(MAX_DICTIONARY_TOKENS + 1);
        assert!(parse_dictionary(&text).is_err());
        assert!(parse_dictionary(&" ".repeat(MAX_DICTIONARY_TEXT_BYTES + 1)).is_err());
        assert!(render_dictionary(&["\\q".to_string()]).is_err());
    }

    #[test]
    fn profile_of_a_synthetic_image() {
        let image = elf(
            true,
            &[("fopen", false), ("read", false), ("main", true)],
            b"\x00PIC1\x00GLIBC_2.2.5\x00WIDTH %d\x00",
        );
        let profile = profile_binary(&image).unwrap();
        assert_eq!(profile.machine, ElfMachine::X86_64);
        assert_eq!(profile.size, image.len() as u64);
        assert_eq!(profile.sha256, sha256_hex(&image));
        assert_eq!(profile.linking, Linking::Dynamic);
        assert_eq!(profile.imports, names(&["fopen", "read"]));
        assert_eq!(profile.suggested_input, BinaryInput::File);
        assert_eq!(profile.suggestion_reasons.len(), 1);
        assert!(profile.strings.contains(&"PIC1".to_string()));
        assert!(!profile.strings.iter().any(|s| s.starts_with("GLIBC_")));
        assert!(profile.dictionary.contains(&"PIC1".to_string()));
        assert!(profile.dictionary.contains(&"WIDTH".to_string()));
        assert!(profile.notes.is_empty());
    }

    #[test]
    fn profile_notes_for_static_and_empty_dynamic() {
        let empty = profile_binary(&elf(true, &[], b"")).unwrap();
        assert_eq!(empty.notes, names(&["No dynamic imports were found."]));
        let mut image = elf(false, &[], b"");
        image[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let profile = profile_binary(&image).unwrap();
        assert_eq!(profile.linking, Linking::Static);
        assert!(profile.notes[0].starts_with("Statically linked"));
        assert_eq!(profile.suggested_input, BinaryInput::File);
    }

    #[test]
    fn profile_rejects_non_elf_like_elf_machine() {
        let bytes = b"#!/bin/sh\necho hi\n";
        let expected = elf_machine(bytes).unwrap_err().to_string();
        let actual = profile_binary(bytes).unwrap_err().to_string();
        assert_eq!(actual, expected);
    }

    #[test]
    #[ignore = "profiles /Users/Shared/oxfuzz-demo/picinfo/picinfo when present"]
    fn profile_of_the_picinfo_demo() {
        let path = "/Users/Shared/oxfuzz-demo/picinfo/picinfo";
        let Ok(image) = std::fs::read(path) else {
            eprintln!("{path} is absent; skipping");
            return;
        };
        let profile = profile_binary(&image).unwrap();
        eprintln!("{profile:#?}");
        assert_eq!(profile.linking, Linking::Dynamic);
        assert!(!profile.imports.is_empty());
        assert_eq!(profile.suggested_input, BinaryInput::File);
    }
}
