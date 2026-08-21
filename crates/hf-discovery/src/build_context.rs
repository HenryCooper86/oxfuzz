//! Extract a project's real compile context from its compile database.
//!
//! A `compile_commands.json` is a file inside the untrusted project under test,
//! and the values taken from it end up in a compiler invocation. Nothing here
//! passes a token through: every accepted argument matched an allowlisted form
//! and every include directory resolved to somewhere inside the project root.
//! Rejected tokens are recorded rather than discarded silently, so an operator
//! can see why a build lacks a flag the project's own build has.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use hf_core::build::{BuildContext, CompileEntry};
use serde::Deserialize;

/// Cap on accepted translation units. A database past this is not something we
/// can extract a single coherent compile context from.
pub const MAX_COMPILE_ENTRIES: usize = 50_000;

/// Cap on distinct rejected tokens retained for the operator. The list explains
/// a gap; it does not need to be exhaustive.
const MAX_DROPPED_FLAGS: usize = 32;

/// No-argument flags that change code generation and are safe to replay against
/// a harness build. Optimization levels, warning flags, and output selection are
/// deliberately absent: oxfuzz supplies its own, and a project's `-O2` or
/// `-Werror` must not override the sanitizer build it needs.
const ALLOWED_CODEGEN_FLAGS: [&str; 8] = [
    "-fno-strict-aliasing",
    "-fno-omit-frame-pointer",
    "-fPIC",
    "-fPIE",
    "-pthread",
    "-fwrapv",
    "-funsigned-char",
    "-fno-common",
];

/// Why a compile database could not be read.
#[derive(Debug, thiserror::Error)]
pub enum BuildContextError {
    /// The file is not a well-formed JSON Compilation Database.
    #[error("compile database is malformed: {0}")]
    Parse(String),
    /// The database records more translation units than are accepted.
    #[error("compile database has {0} entries, over the {1} limit")]
    TooLarge(usize, usize),
}

/// One entry as the JSON Compilation Database format records it. The format
/// admits either an `arguments` array or a single `command` string.
#[derive(Deserialize)]
struct RawEntry {
    directory: PathBuf,
    file: PathBuf,
    #[serde(default)]
    arguments: Option<Vec<String>>,
    #[serde(default)]
    command: Option<String>,
}

/// Parse a JSON Compilation Database.
///
/// The `command` form is split on whitespace. That loses shell quoting, so an
/// argument containing a space arrives as two tokens; both halves then fail the
/// allowlist and are dropped, which is the safe direction to be wrong in.
///
/// # Errors
/// Returns [`BuildContextError::Parse`] for malformed JSON or an entry carrying
/// neither `arguments` nor `command`, and [`BuildContextError::TooLarge`] past
/// [`MAX_COMPILE_ENTRIES`].
pub fn parse_compile_database(json: &str) -> Result<Vec<CompileEntry>, BuildContextError> {
    let raw: Vec<RawEntry> =
        serde_json::from_str(json).map_err(|error| BuildContextError::Parse(error.to_string()))?;
    if raw.len() > MAX_COMPILE_ENTRIES {
        return Err(BuildContextError::TooLarge(raw.len(), MAX_COMPILE_ENTRIES));
    }
    raw.into_iter()
        .map(|entry| {
            let arguments = match (entry.arguments, entry.command) {
                (Some(arguments), _) => arguments,
                (None, Some(command)) => command.split_whitespace().map(str::to_owned).collect(),
                (None, None) => {
                    return Err(BuildContextError::Parse(format!(
                        "entry for {} has neither arguments nor command",
                        entry.file.display()
                    )))
                }
            };
            Ok(CompileEntry {
                file: entry.file,
                directory: entry.directory,
                arguments,
            })
        })
        .collect()
}

/// Extract the portable, validated compile context from parsed entries.
///
/// Values are deduplicated in first-seen order, so the same project always
/// yields the same context and the same compile command.
#[must_use]
pub fn extract_build_context(entries: &[CompileEntry], project_root: &Path) -> BuildContext {
    let mut context = BuildContext {
        entry_count: entries.len(),
        ..BuildContext::default()
    };
    let mut seen_includes = HashSet::new();
    let mut seen_defines = HashSet::new();
    let mut seen_flags = HashSet::new();
    let mut seen_dropped = HashSet::new();

    for entry in entries {
        // Skip the compiler driver itself: it is argv[0], never a flag.
        let mut arguments = entry.arguments.iter().skip(1).peekable();
        while let Some(token) = arguments.next() {
            // `-I dir` splits the directory into the following token; `-Idir`
            // carries it inline.
            let include = if token == "-I" {
                arguments.next().map(String::as_str)
            } else {
                token.strip_prefix("-I").filter(|rest| !rest.is_empty())
            };
            if let Some(raw) = include {
                if let Some(directory) =
                    confined_include_dir(Path::new(raw), &entry.directory, project_root)
                {
                    if seen_includes.insert(directory.clone()) {
                        context.include_dirs.push(directory);
                    }
                } else {
                    record_dropped(&mut context, &mut seen_dropped, token);
                }
                continue;
            }
            if token.starts_with("-D") {
                if accepted_define(token) {
                    if seen_defines.insert(token.clone()) {
                        context.defines.push(token.clone());
                    }
                } else {
                    record_dropped(&mut context, &mut seen_dropped, token);
                }
                continue;
            }
            if token.starts_with("-std=") {
                if accepted_std(token) {
                    // First entry with a standard wins. Entries disagreeing on
                    // the standard is a property of the project's own build, and
                    // one harness compiles with one standard either way.
                    if context.std_flag.is_none() {
                        context.std_flag = Some(token.clone());
                    }
                } else {
                    record_dropped(&mut context, &mut seen_dropped, token);
                }
                continue;
            }
            if ALLOWED_CODEGEN_FLAGS.contains(&token.as_str()) {
                if seen_flags.insert(token.clone()) {
                    context.extra_flags.push(token.clone());
                }
                continue;
            }
            // Only flags are recorded as dropped. Source paths, object outputs,
            // and the values of value-taking flags are ordinary parts of a
            // compile line and listing them would bury the useful entries.
            if token.starts_with('-') {
                record_dropped(&mut context, &mut seen_dropped, token);
            }
        }
    }
    context
}

/// Record a rejected flag once, up to [`MAX_DROPPED_FLAGS`].
fn record_dropped(context: &mut BuildContext, seen: &mut HashSet<String>, token: &str) {
    if context.dropped.len() >= MAX_DROPPED_FLAGS {
        return;
    }
    if seen.insert(token.to_owned()) {
        context.dropped.push(token.to_owned());
    }
}

/// Resolve an include directory and keep it only if it lies inside the project.
///
/// The returned path is always expressed under the caller's `project_root`, so
/// a later `strip_prefix(project_root)` succeeds even when the database recorded
/// the directory through a different real path (a symlinked temporary directory
/// is the usual case).
fn confined_include_dir(raw: &Path, directory: &Path, project_root: &Path) -> Option<PathBuf> {
    let joined = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        directory.join(raw)
    };
    let candidate = lexically_normalize(&joined);
    let root = lexically_normalize(project_root);
    if candidate.starts_with(&root) {
        return Some(candidate);
    }
    // Lexical comparison is the primary rule because a compile database records
    // paths from the machine that built it, which need not exist here. When both
    // sides do exist, compare what the filesystem resolves them to as well, so a
    // symlinked project root does not reject its own include directories.
    let real_candidate = std::fs::canonicalize(&candidate).ok()?;
    let real_root = std::fs::canonicalize(&root).ok()?;
    let relative = real_candidate.strip_prefix(&real_root).ok()?;
    Some(root.join(relative))
}

/// Resolve `.` and `..` without consulting the filesystem.
fn lexically_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Whether a `-D` token names a C identifier and carries no control character.
///
/// The value half is otherwise unconstrained: a define may legitimately contain
/// punctuation, and every emitted token is shell-quoted at the one place the
/// compile command is built.
fn accepted_define(token: &str) -> bool {
    let Some(body) = token.strip_prefix("-D") else {
        return false;
    };
    if body.is_empty() || body.chars().any(char::is_control) {
        return false;
    }
    let name = body.split('=').next().unwrap_or_default();
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Whether a `-std=` token names a language standard and nothing else.
fn accepted_std(token: &str) -> bool {
    let Some(value) = token.strip_prefix("-std=") else {
        return false;
    };
    // Longest prefix first: `gnu++20` must not match the `gnu` arm and leave
    // `++20` as the version.
    let Some(version) = ["gnu++", "c++", "gnu", "c"]
        .into_iter()
        .find_map(|dialect| value.strip_prefix(dialect))
    else {
        return false;
    };
    !version.is_empty()
        && version.len() <= 4
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character.is_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const DB: &str = r#"[
      {"directory":"/proj","file":"/proj/src/dns.c",
       "arguments":["cc","-I/proj/include","-DHAVE_CONFIG_H=1","-std=c11",
                    "-Wall","-c","/proj/src/dns.c","-o","dns.o"]}
    ]"#;

    #[test]
    fn parses_arguments_form_entries() {
        let entries = parse_compile_database(DB).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file, PathBuf::from("/proj/src/dns.c"));
        assert_eq!(entries[0].arguments[0], "cc");
    }

    #[test]
    fn parses_command_string_form_entries() {
        // The other half of the JSON Compilation Database format records a
        // single `command` string instead of an `arguments` array.
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "command":"cc -I/proj/include -DA=1 -c /proj/a.c"}]"#;
        let entries = parse_compile_database(db).unwrap();
        assert_eq!(
            entries[0].arguments,
            vec!["cc", "-I/proj/include", "-DA=1", "-c", "/proj/a.c"]
        );
    }

    #[test]
    fn extracts_includes_defines_and_standard() {
        let entries = parse_compile_database(DB).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert_eq!(ctx.include_dirs, vec![PathBuf::from("/proj/include")]);
        assert_eq!(ctx.defines, vec!["-DHAVE_CONFIG_H=1"]);
        assert_eq!(ctx.std_flag.as_deref(), Some("-std=c11"));
        assert_eq!(ctx.entry_count, 1);
    }

    #[test]
    fn accepts_the_two_token_include_form() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-I","/proj/include","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert_eq!(ctx.include_dirs, vec![PathBuf::from("/proj/include")]);
    }

    #[test]
    fn rejects_include_directories_outside_the_project_root() {
        // A compile database is a file in the untrusted project. An include
        // directory pointing at the host filesystem must never be honored.
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-I/etc","-I../../../root/.ssh","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(
            ctx.include_dirs.is_empty(),
            "escaped include dirs: {:?}",
            ctx.include_dirs
        );
    }

    #[test]
    fn rejects_flags_outside_the_allowlist() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-Wall","-include","/etc/passwd","-fplugin=evil.so",
                                   "-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(ctx.extra_flags.is_empty());
        assert!(ctx.dropped.iter().any(|flag| flag == "-fplugin=evil.so"));
    }

    #[test]
    fn accepts_allowlisted_code_generation_flags() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-fno-strict-aliasing","-fPIC","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert_eq!(ctx.extra_flags, vec!["-fno-strict-aliasing", "-fPIC"]);
    }

    #[test]
    fn rejects_a_define_carrying_a_newline() {
        let db = "[{\"directory\":\"/proj\",\"file\":\"/proj/a.c\",\
                    \"arguments\":[\"cc\",\"-DA=1\\nrm -rf /\",\"-c\",\"/proj/a.c\"]}]";
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(ctx.defines.is_empty());
    }

    #[test]
    fn rejects_a_define_with_a_non_identifier_name() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-D9lives=1","-D$(evil)","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(ctx.defines.is_empty(), "{:?}", ctx.defines);
    }

    #[test]
    fn rejects_a_bogus_language_standard() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-std=c11;rm -rf /","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(ctx.std_flag.is_none());
    }

    #[test]
    fn deduplicates_repeated_values_across_entries() {
        let db = r#"[
          {"directory":"/proj","file":"/proj/a.c",
           "arguments":["cc","-I/proj/include","-DA=1","-c","/proj/a.c"]},
          {"directory":"/proj","file":"/proj/b.c",
           "arguments":["cc","-I/proj/include","-DA=1","-c","/proj/b.c"]}
        ]"#;
        let entries = parse_compile_database(db).unwrap();
        let ctx = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert_eq!(ctx.include_dirs.len(), 1);
        assert_eq!(ctx.defines.len(), 1);
        assert_eq!(ctx.entry_count, 2);
    }

    #[test]
    fn malformed_json_is_an_error_not_an_empty_context() {
        assert!(parse_compile_database("{not json").is_err());
    }

    #[test]
    fn an_entry_with_neither_arguments_nor_command_is_an_error() {
        assert!(parse_compile_database(r#"[{"directory":"/proj","file":"/proj/a.c"}]"#).is_err());
    }
}
