//! Releasing the object a constructor-style target returns, in the model-free
//! C and C++ template.
//!
//! A target such as `exif_data_new_from_data` allocates what it returns. A
//! harness that drops it leaks on every input, and under `AddressSanitizer`
//! libFuzzer reports that leak as a crash on the first input: the smoke run
//! stops at once on a finding that is not a bug, and the harness never
//! qualifies. The template therefore keeps the result and hands it to the
//! project's own release function, when the project declares one.

use std::path::Path;

use hf_core::target::TargetCandidate;

/// Suffixes of the release functions C libraries name after their type.
const RELEASE_SUFFIXES: [&str; 5] = ["_unref", "_free", "_destroy", "_delete", "_release"];

/// Constructor-style infixes that end the type prefix of a symbol.
const CONSTRUCTOR_INFIXES: [&str; 5] = ["_new", "_create", "_alloc", "_load", "_open"];

/// Headers scanned for a release declaration, at most, and bytes per header.
const MAX_SCANNED_HEADERS: usize = 2_000;
const MAX_HEADER_BYTES: u64 = 1_024 * 1_024;

/// How to keep and release a target's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Release {
    /// The declared return type, such as `ExifData *`.
    pub return_type: String,
    /// The project function that releases it, such as `exif_data_unref`.
    pub function: String,
}

/// The release of what `candidate` returns, when it returns a pointer to a
/// named type and a project header declares a matching release function.
///
/// A `char` or `void` pointer is never released: it may be static storage,
/// and freeing it would be the harness's own bug.
pub(super) fn release_for(candidate: &TargetCandidate) -> Option<Release> {
    let signature = candidate.signature.as_deref()?;
    let return_type = signature
        .find(candidate.symbol.as_str())
        .map(|end| signature[..end].trim())?;
    if !return_type.ends_with('*') || return_type.matches('*').count() != 1 {
        return None;
    }
    let base = return_type
        .trim_end_matches('*')
        .trim()
        .trim_start_matches("const ")
        .trim_start_matches("struct ")
        .trim();
    if base.is_empty()
        || matches!(
            base,
            "char" | "void" | "unsigned char" | "signed char" | "uint8_t" | "int8_t"
        )
        || !base.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let mut prefixes = vec![snake_case(base)];
    if let Some(prefix) = CONSTRUCTOR_INFIXES
        .iter()
        .filter_map(|infix| {
            candidate
                .symbol
                .find(infix)
                .map(|at| &candidate.symbol[..at])
        })
        .find(|prefix| !prefix.is_empty())
    {
        prefixes.push(prefix.to_owned());
    }
    let wanted: Vec<String> = prefixes
        .iter()
        .flat_map(|prefix| {
            RELEASE_SUFFIXES
                .iter()
                .map(move |suffix| format!("{prefix}{suffix}"))
        })
        .collect();
    let declared = declared_functions(&candidate.project_root, &wanted);
    wanted
        .into_iter()
        .find(|name| declared.contains(name))
        .map(|function| Release {
            return_type: return_type.to_owned(),
            function,
        })
}

/// `body` with its final target call kept in `_result` and released.
pub(super) fn keep_and_release(body: &str, symbol: &str, release: &Release) -> String {
    let call = format!("    {symbol}(");
    let Some(at) = body.rfind(&call) else {
        return body.to_owned();
    };
    format!(
        "{before}    {ty} _result = {symbol}({rest}\n    if (_result) {function}(_result);",
        before = &body[..at],
        ty = release.return_type,
        rest = &body[at + call.len()..],
        function = release.function,
    )
}

/// `ExifData` -> `exif_data`; an already snake-cased name is unchanged.
fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let mut previous_lower = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() {
            if previous_lower {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
            previous_lower = false;
        } else {
            out.push(character);
            previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        }
    }
    out
}

/// Which of `wanted` some header under `root` declares (`name (`), bounded.
fn declared_functions(root: &Path, wanted: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut scanned = 0usize;
    scan(root, wanted, &mut found, &mut scanned);
    found
}

fn scan(directory: &Path, wanted: &[String], found: &mut Vec<String>, scanned: &mut usize) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if *scanned >= MAX_SCANNED_HEADERS || found.len() == wanted.len() {
            return;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            let hidden = entry.file_name().to_string_lossy().starts_with('.');
            if !hidden {
                scan(&path, wanted, found, scanned);
            }
            continue;
        }
        let header = kind.is_file()
            && path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| matches!(extension, "h" | "hh" | "hpp" | "hxx"));
        if !header
            || entry
                .metadata()
                .map_or(true, |m| m.len() > MAX_HEADER_BYTES)
        {
            continue;
        }
        *scanned += 1;
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for name in wanted {
            if !found.contains(name) && declares(&text, name) {
                found.push(name.clone());
            }
        }
    }
}

/// Whether `text` holds `name` as a whole identifier followed by `(`.
fn declares(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let boundary = before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        boundary && text[at + name.len()..].trim_start().starts_with('(')
    })
}
