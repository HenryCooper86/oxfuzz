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

use hf_core::{
    build::{BuildContext, CompileEntry},
    runtime::{
        classify_fixed_sandbox_include_path, portable_define_value, FixedSandboxIncludePath,
        MAX_PORTABLE_DEFINE_BYTES,
    },
};
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
/// The `command` form decodes quotes and escapes without shell execution or
/// expansion. An `arguments` array takes precedence. Empty compiler invocations
/// and malformed quoting are rejected before flag extraction.
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
                (None, Some(command)) => shlex::split(&command).ok_or_else(|| {
                    BuildContextError::Parse(format!(
                        "entry for {} has malformed command quoting",
                        entry.file.display()
                    ))
                })?,
                (None, None) => {
                    return Err(BuildContextError::Parse(format!(
                        "entry for {} has neither arguments nor command",
                        entry.file.display()
                    )))
                }
            };
            if arguments
                .first()
                .is_none_or(|compiler| compiler.trim().is_empty())
            {
                return Err(BuildContextError::Parse(format!(
                    "entry for {} has an empty compiler invocation",
                    entry.file.display()
                )));
            }
            Ok(CompileEntry {
                file: entry.file,
                directory: entry.directory,
                arguments,
            })
        })
        .collect()
}

/// Directories whose sources build programs around a library -- its tests,
/// examples, benchmarks, fuzzers, demos -- rather than the library itself.
const AUXILIARY_DIRS: [&str; 17] = [
    "test",
    "tests",
    "testing",
    "unittest",
    "unittests",
    "example",
    "examples",
    "bench",
    "benches",
    "benchmark",
    "benchmarks",
    "fuzz",
    "fuzzing",
    "demo",
    "demos",
    "sample",
    "samples",
];

/// Whether `entry` compiles for one of the project's auxiliary programs: its
/// source, or the object it writes, lies under a directory such as `tests`,
/// `examples`, `bench` or `fuzz`. The object path counts because build systems compile library
/// sources again for each test program (Meson writes inih's
/// `tests/unittest_heap.p/.._ini.c.o` from `ini.c` with that test's settings).
#[must_use]
pub fn is_auxiliary_entry(entry: &CompileEntry, project_root: &Path) -> bool {
    let auxiliary = |path: &Path| {
        path.components().any(|component| match component {
            Component::Normal(name) => name
                .to_str()
                .is_some_and(|name| AUXILIARY_DIRS.contains(&name.to_ascii_lowercase().as_str())),
            _ => false,
        })
    };
    let source = lexically_normal(&entry.directory.join(&entry.file));
    if source
        .strip_prefix(project_root)
        .is_ok_and(&auxiliary)
    {
        return true;
    }
    let mut arguments = entry.arguments.iter();
    let output = loop {
        let Some(token) = arguments.next() else {
            break None;
        };
        if token == "-o" {
            break arguments.next().map(PathBuf::from);
        }
        if let Some(path) = token.strip_prefix("-o").filter(|rest| !rest.is_empty()) {
            break Some(PathBuf::from(path));
        }
    };
    output.is_some_and(|output| {
        let relative_to_build = if output.is_absolute() {
            lexically_normal(&output)
                .strip_prefix(&entry.directory)
                .map(Path::to_path_buf)
                .unwrap_or_default()
        } else {
            output
        };
        auxiliary(&relative_to_build)
    })
}

/// `path` with `.` and `..` components resolved lexically, without touching
/// the filesystem.
#[must_use]
pub fn lexically_normal(path: &Path) -> PathBuf {
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other.as_os_str()),
        }
    }
    normal
}

/// Extract the portable, validated compile context from parsed entries.
///
/// Values are deduplicated in first-seen order, so the same project always
/// yields the same context and the same compile command.
///
/// Only the library's own compiles shape the context when it has any: the
/// entries of tests, examples and other auxiliary programs
/// ([`is_auxiliary_entry`]) carry their own settings, and a harness built
/// with them fuzzes a configuration the library never ships. A macro that
/// the remaining entries still define with different values is dropped, as
/// one harness cannot honour them all.
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

    let library: Vec<&CompileEntry> = entries
        .iter()
        .filter(|entry| !is_auxiliary_entry(entry, project_root))
        .collect();
    let considered: Vec<&CompileEntry> = if library.is_empty() {
        entries.iter().collect()
    } else {
        library
    };

    for entry in considered {
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
    drop_conflicting_defines(&mut context, &mut seen_dropped);
    context
}

/// Drop every value of a macro the library's entries define more than one
/// way (`-DMODE=1` in one unit, `-DMODE=2` in another).
fn drop_conflicting_defines(context: &mut BuildContext, seen_dropped: &mut HashSet<String>) {
    let name = |define: &str| {
        define
            .trim_start_matches("-D")
            .split('=')
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let mut values: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for define in &context.defines {
        *values.entry(name(define)).or_default() += 1;
    }
    let (kept, conflicting): (Vec<String>, Vec<String>) = std::mem::take(&mut context.defines)
        .into_iter()
        .partition(|define| values.get(&name(define)).copied().unwrap_or(0) <= 1);
    context.defines = kept;
    for define in conflicting {
        record_dropped(context, seen_dropped, &define);
    }
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
    match raw.to_str().map(classify_fixed_sandbox_include_path) {
        Some(FixedSandboxIncludePath::Canonical) => return Some(raw.to_path_buf()),
        Some(FixedSandboxIncludePath::Invalid) => return None,
        Some(FixedSandboxIncludePath::Outside) | None => {}
    }
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
    if body.len() > MAX_PORTABLE_DEFINE_BYTES
        || body
            .split_once('=')
            .is_some_and(|(_, value)| !portable_define_value(value))
    {
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

/// Render a build context as compiler tokens valid inside the sandbox, where
/// the project is staged at `container_root` (`/work`).
///
/// Include directories are rewritten from host paths to their staged
/// equivalents. `copy_project_sources` preserves the project's directory layout,
/// so a directory at `<project>/include` is staged at `<container_root>/include`.
/// A directory that does not lie under `project_root` is dropped rather than
/// passed through: `extract_build_context` already confined them, and a second
/// check here costs nothing.
///
/// Tokens are returned unquoted. Quoting belongs to the single place that builds
/// the compile command, so it happens exactly once.
#[must_use]
pub fn staged_compile_flags(
    ctx: &BuildContext,
    project_root: &Path,
    container_root: &str,
) -> Vec<String> {
    let mut flags = Vec::new();
    for directory in &ctx.include_dirs {
        match directory.to_str().map(classify_fixed_sandbox_include_path) {
            Some(FixedSandboxIncludePath::Canonical) => {
                flags.push(format!("-I{}", directory.display()));
                continue;
            }
            Some(FixedSandboxIncludePath::Invalid) => continue,
            Some(FixedSandboxIncludePath::Outside) | None => {}
        }
        let Ok(relative) = directory.strip_prefix(project_root) else {
            continue;
        };
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            continue;
        }
        let posix = hf_core::runtime::posix_relative(relative);
        if posix.is_empty() {
            flags.push(format!("-I{container_root}"));
        } else {
            flags.push(format!("-I{container_root}/{posix}"));
        }
    }
    flags.extend(ctx.defines.iter().cloned());
    flags.extend(ctx.std_flag.iter().cloned());
    flags.extend(ctx.extra_flags.iter().cloned());
    flags
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
    fn include_dirs_are_rewritten_to_staged_container_paths() {
        let ctx = BuildContext {
            include_dirs: vec![PathBuf::from("/proj/include"), PathBuf::from("/proj/src")],
            defines: vec!["-DA=1".to_owned()],
            std_flag: Some("-std=c11".to_owned()),
            extra_flags: vec!["-fno-strict-aliasing".to_owned()],
            entry_count: 1,
            dropped: Vec::new(),
        };
        let flags = staged_compile_flags(&ctx, &PathBuf::from("/proj"), "/work");
        assert_eq!(
            flags,
            vec![
                "-I/work/include",
                "-I/work/src",
                "-DA=1",
                "-std=c11",
                "-fno-strict-aliasing",
            ]
        );
    }

    #[test]
    fn the_project_root_itself_maps_to_the_container_root() {
        let ctx = BuildContext {
            include_dirs: vec![PathBuf::from("/proj")],
            ..BuildContext::default()
        };
        assert_eq!(
            staged_compile_flags(&ctx, &PathBuf::from("/proj"), "/work"),
            vec!["-I/work"]
        );
    }

    #[test]
    fn an_include_dir_outside_the_project_is_not_rendered() {
        let ctx = BuildContext {
            include_dirs: vec![PathBuf::from("/elsewhere/include")],
            ..BuildContext::default()
        };
        assert!(staged_compile_flags(&ctx, &PathBuf::from("/proj"), "/work").is_empty());
    }

    #[test]
    fn fixed_sandbox_include_paths_reject_noncanonical_descendants() {
        let db = r#"[{"directory":"/proj","file":"/proj/a.c",
                      "arguments":["cc","-I/work/../etc","-I/work/./include",
                                   "-I/work//include","-I/work/include/","-c","/proj/a.c"]}]"#;
        let entries = parse_compile_database(db).expect("parse compile database");
        let context = extract_build_context(&entries, &PathBuf::from("/proj"));
        assert!(
            context.include_dirs.is_empty(),
            "{:?}",
            context.include_dirs
        );
    }

    #[test]
    fn staging_never_replays_noncanonical_fixed_sandbox_paths() {
        let context = BuildContext {
            include_dirs: vec![
                PathBuf::from("/work/../etc"),
                PathBuf::from("/work/include"),
            ],
            ..BuildContext::default()
        };
        assert_eq!(
            staged_compile_flags(&context, &PathBuf::from("/project"), "/work"),
            vec!["-I/work/include"]
        );
    }

    #[test]
    fn invalid_fixed_sandbox_paths_do_not_fall_back_under_a_work_project_root() {
        let db = r#"[{"directory":"/work","file":"/work/a.c",
                      "arguments":["cc","-I/work/./include","-c","/work/a.c"]}]"#;
        let entries = parse_compile_database(db).expect("parse compile database");
        assert!(extract_build_context(&entries, &PathBuf::from("/work"))
            .include_dirs
            .is_empty());
        let direct = BuildContext {
            include_dirs: vec![PathBuf::from("//work/include")],
            ..BuildContext::default()
        };
        assert!(staged_compile_flags(&direct, &PathBuf::from("/work"), "/work").is_empty());
    }

    #[test]
    fn an_empty_context_renders_no_flags() {
        assert!(
            staged_compile_flags(&BuildContext::default(), &PathBuf::from("/proj"), "/work")
                .is_empty()
        );
    }

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
    fn command_quoting_preserves_tokens_without_shell_expansion() {
        let command = r#"cc -I"/work/my include" -I/work/escaped\ include '-DNAME=$HOME' -c a.c"#;
        let database = serde_json::json!([{"directory":"/work", "file":"a.c", "command":command}]);
        let entries = parse_compile_database(&database.to_string()).unwrap();
        assert_eq!(
            entries[0].arguments,
            [
                "cc",
                "-I/work/my include",
                "-I/work/escaped include",
                "-DNAME=$HOME",
                "-c",
                "a.c"
            ]
        );
    }

    #[test]
    fn command_quoting_and_empty_invocations_are_validated() {
        for command in ["cc \"unterminated", "", "   "] {
            let database =
                serde_json::json!([{"directory":"/work", "file":"a.c", "command":command}]);
            assert!(
                parse_compile_database(&database.to_string()).is_err(),
                "{command:?}"
            );
        }
        for arguments in [vec![], vec![""], vec!["  "]] {
            let database =
                serde_json::json!([{"directory":"/work", "file":"a.c", "arguments":arguments}]);
            assert!(parse_compile_database(&database.to_string()).is_err());
        }
    }

    #[test]
    fn command_quoting_does_not_override_arguments_array_precedence() {
        let database = serde_json::json!([{"directory":"/work", "file":"a.c", "command":"cc \"unterminated", "arguments":["cc", "-I/work/my include", "-c", "a.c"]}]);
        let entries = parse_compile_database(&database.to_string()).unwrap();
        assert_eq!(entries[0].arguments[1], "-I/work/my include");
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
    fn rejects_embedded_absolute_paths_but_keeps_portable_define_values() {
        let database = serde_json::json!([{
            "directory": "/proj",
            "file": "/proj/a.c",
            "arguments": [
                "cc",
                "-DURI=file:///Users/alice/project",
                "-DPREFIX=prefix:/Users/alice/project",
                r"-DWINDOWS=C:\Users\alice\project",
                r"-DPREFIXED_WINDOWS=value:C:\Users\alice\project",
                "-DVERSION=1.2.3",
                "-DRATIO=1/2",
                "-DURL=https://example.test/api",
                "-DRELATIVE=src/parser.c",
                "-c",
                "/proj/a.c"
            ]
        }])
        .to_string();
        let entries = parse_compile_database(&database).expect("parse compile database");

        let context = extract_build_context(&entries, &PathBuf::from("/proj"));

        assert_eq!(
            context.defines,
            vec![
                "-DVERSION=1.2.3",
                "-DRATIO=1/2",
                "-DURL=https://example.test/api",
                "-DRELATIVE=src/parser.c",
            ]
        );
        assert!(context
            .dropped
            .contains(&"-DURI=file:///Users/alice/project".to_owned()));
        assert!(context
            .dropped
            .contains(&"-DPREFIX=prefix:/Users/alice/project".to_owned()));
    }

    #[test]
    fn test_program_variants_do_not_shape_the_library_context() {
        // inih compiles `ini.c` once for the library with no `INI_*` settings
        // and again for each unit-test program with that test's settings.
        // The union gave the harness `INI_INITIAL_ALLOC` three values and the
        // test-only `INI_CUSTOM_ALLOCATOR=1`.
        let database = serde_json::json!([
            {"directory": "/proj/build", "file": "../ini.c",
             "arguments": ["cc", "-I.", "-I..", "-D_FILE_OFFSET_BITS=64", "-o", "libinih.so.0.p/.._ini.c.o", "-c", "../ini.c"]},
            {"directory": "/proj/build", "file": "../ini.c",
             "arguments": ["cc", "-D_FILE_OFFSET_BITS=64", "-DINI_MAX_LINE=20", "-DINI_INITIAL_ALLOC=20",
                           "-o", "tests/unittest_heap.p/.._ini.c.o", "-c", "../ini.c"]},
            {"directory": "/proj/build", "file": "../tests/unittest_alloc.c",
             "arguments": ["cc", "-I../tests", "-DINI_CUSTOM_ALLOCATOR=1", "-DINI_INITIAL_ALLOC=12",
                           "-o", "tests/unittest_alloc.p/unittest_alloc.c.o", "-c", "../tests/unittest_alloc.c"]},
            {"directory": "/proj/build", "file": "../src/a.c",
             "arguments": ["cc", "-DMODE=1", "-o", "a.o", "-c", "../src/a.c"]},
            {"directory": "/proj/build", "file": "../src/b.c",
             "arguments": ["cc", "-DMODE=2", "-o", "b.o", "-c", "../src/b.c"]}
        ])
        .to_string();
        let entries = parse_compile_database(&database).expect("parse compile database");

        let context = extract_build_context(&entries, &PathBuf::from("/proj"));

        assert_eq!(context.defines, vec!["-D_FILE_OFFSET_BITS=64"]);
        assert!(
            context.dropped.contains(&"-DMODE=1".to_owned()),
            "{:?}",
            context.dropped
        );
        assert!(!context
            .include_dirs
            .iter()
            .any(|dir| dir.ends_with("tests")));
        assert!(is_auxiliary_entry(&entries[1], Path::new("/proj")));
        assert!(is_auxiliary_entry(&entries[2], Path::new("/proj")));
        assert!(!is_auxiliary_entry(&entries[0], Path::new("/proj")));
    }

    #[test]
    fn keeps_a_define_naming_a_standard_system_path() {
        // Every libexif unit is compiled with `-DLOCALEDIR=".../locale"`; with
        // it dropped the harness build failed on an undeclared identifier. A
        // standard system location identifies no host and exists in the
        // sandbox's own namespace.
        let database = serde_json::json!([{
            "directory": "/proj",
            "file": "/proj/a.c",
            "arguments": [
                "cc",
                "-DLOCALEDIR=\"/usr/local/share/locale\"",
                "-DSYSCONFDIR=/etc",
                "-DDATADIR='/usr/share/app'",
                "-DSEARCH=\"/usr/lib:/Users/alice/lib\"",
                "-DESCAPE=\"/usr/../Users/alice\"",
                "-DHOMEDIR=\"/home/alice/.config\"",
                "-c",
                "/proj/a.c"
            ]
        }])
        .to_string();
        let entries = parse_compile_database(&database).expect("parse compile database");

        let context = extract_build_context(&entries, &PathBuf::from("/proj"));

        assert_eq!(
            context.defines,
            vec![
                "-DLOCALEDIR=\"/usr/local/share/locale\"",
                "-DSYSCONFDIR=/etc",
                "-DDATADIR='/usr/share/app'",
            ]
        );
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
