//! Infer include directories from the project's own `#include` lines.
//!
//! A project without a compile database still states where its headers live:
//! `src/tlv_decode.c` writes `#include "tlv/tlv.h"` and the file sits at
//! `include/tlv/tlv.h`, so `include` is an include directory. Without it the
//! project's own sources fail to compile next to the harness, and no model
//! repair can fix a flag the compiler never received.
//!
//! This reads project files only and executes nothing. It is a fallback for a
//! project with no compile database: a database states the real flags and
//! always wins.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use hf_core::build::BuildContext;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;

/// Inferred include directories kept. A project needing more than this has a
/// build that only its own build system can describe.
pub const MAX_INFERRED_INCLUDE_DIRS: usize = 16;

/// Bytes of one source file scanned for `#include` lines. Includes sit at the
/// top of a file; a generated megabyte-sized table does not add any.
const MAX_SCANNED_BYTES: usize = 256 * 1024;

/// Source files scanned. Past this the walk is no longer a cheap fallback.
const MAX_SCANNED_FILES: usize = 20_000;

/// Infer the include directories of the project at `canonical_root`.
///
/// Returns `None` when every project include already resolves from the
/// including file's directory or the project root, which the harness build
/// searches without any flag.
///
/// # Errors
/// Returns the walker's validation errors for a non-canonical root or a source
/// path that escapes it.
pub fn infer_include_context(
    canonical_root: &Path,
) -> Result<Option<BuildContext>, ClassifiedError> {
    let mut files = BTreeSet::new();
    for language in [TargetLanguage::C, TargetLanguage::Cpp] {
        files.extend(crate::scanner::discoverable_source_files(
            canonical_root,
            language,
        )?);
    }
    if files.len() > MAX_SCANNED_FILES {
        return Ok(None);
    }
    let sources: Vec<(PathBuf, String)> = files
        .iter()
        .filter_map(|relative| {
            // An unreadable or non-UTF-8 file contributes no include lines;
            // the compiler reports it if it matters to the build.
            let bytes = std::fs::read(canonical_root.join(relative)).ok()?;
            let head = &bytes[..bytes.len().min(MAX_SCANNED_BYTES)];
            Some((relative.clone(), String::from_utf8_lossy(head).into_owned()))
        })
        .collect();
    let roots = infer_include_roots(&files, &sources);
    if roots.is_empty() {
        return Ok(None);
    }
    Ok(Some(BuildContext {
        include_dirs: roots
            .into_iter()
            .map(|relative| canonical_root.join(relative))
            .collect(),
        ..BuildContext::default()
    }))
}

/// The project-relative directories that make unresolved includes resolve.
///
/// `files` is every project source and header, project-relative. `sources`
/// pairs a file with its text. A spelling several directories could satisfy is
/// given to the directory most other includes also need; ties go to the
/// lexicographically first, so the result is deterministic.
#[must_use]
pub fn infer_include_roots(
    files: &BTreeSet<PathBuf>,
    sources: &[(PathBuf, String)],
) -> Vec<PathBuf> {
    let mut unresolved: Vec<BTreeSet<PathBuf>> = Vec::new();
    for (file, text) in sources {
        let directory = file.parent().unwrap_or_else(|| Path::new(""));
        for spelling in include_spellings(text) {
            let Some(spelling) = normalized_relative(Path::new(spelling)) else {
                continue;
            };
            let beside = normalized_relative(&directory.join(&spelling));
            if beside.is_some_and(|path| files.contains(&path)) || files.contains(&spelling) {
                continue;
            }
            let candidates: BTreeSet<PathBuf> = files
                .iter()
                .filter_map(|path| root_for(path, &spelling))
                .collect();
            if !candidates.is_empty() {
                unresolved.push(candidates);
            }
        }
    }

    let mut votes: BTreeMap<&PathBuf, usize> = BTreeMap::new();
    for candidates in &unresolved {
        for candidate in candidates {
            *votes.entry(candidate).or_default() += 1;
        }
    }
    let mut chosen: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for candidates in &unresolved {
        // BTreeSet iteration is ascending, and `max_by_key` keeps the last
        // maximum, so reverse to let the lexicographically first win a tie.
        if let Some(best) = candidates
            .iter()
            .rev()
            .max_by_key(|candidate| votes[candidate])
        {
            *chosen.entry(best.clone()).or_default() += 1;
        }
    }
    let mut roots: Vec<(PathBuf, usize)> = chosen.into_iter().collect();
    roots.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    roots.truncate(MAX_INFERRED_INCLUDE_DIRS);
    roots.into_iter().map(|(root, _)| root).collect()
}

/// The directory that makes `spelling` name `path`: `path` minus the
/// component-wise suffix `spelling`. `None` when it is not such a suffix or the
/// directory would be the project root, which is always searched.
fn root_for(path: &Path, spelling: &Path) -> Option<PathBuf> {
    let path_parts: Vec<Component<'_>> = path.components().collect();
    let spelling_parts: Vec<Component<'_>> = spelling.components().collect();
    let keep = path_parts.len().checked_sub(spelling_parts.len())?;
    if keep == 0 || path_parts[keep..] != spelling_parts[..] {
        return None;
    }
    Some(path_parts[..keep].iter().collect())
}

/// Resolve `.` and `..` lexically; `None` for an absolute path or one that
/// climbs out of the project.
fn normalized_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// The header spellings of every `#include "..."` line, and of every
/// `#include <...>` line that names a directory.
///
/// A bare `<string.h>` is a system header even when the project carries a file
/// of that name somewhere: adding that directory would shadow the system
/// header in every translation unit.
fn include_spellings(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter_map(|line| {
        let rest = line.trim_start().strip_prefix('#')?.trim_start();
        let rest = rest.strip_prefix("include")?.trim_start();
        let (close, body) = match rest.as_bytes().first()? {
            b'"' => ('"', &rest[1..]),
            b'<' => ('>', &rest[1..]),
            _ => return None,
        };
        let spelling = &body[..body.find(close)?];
        (close == '"' || spelling.contains('/')).then_some(spelling)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(entries: &[(&str, &str)]) -> (BTreeSet<PathBuf>, Vec<(PathBuf, String)>) {
        let files = entries
            .iter()
            .map(|(path, _)| PathBuf::from(path))
            .collect();
        let sources = entries
            .iter()
            .map(|(path, text)| (PathBuf::from(path), (*text).to_owned()))
            .collect();
        (files, sources)
    }

    fn roots(entries: &[(&str, &str)]) -> Vec<PathBuf> {
        let (files, sources) = project(entries);
        infer_include_roots(&files, &sources)
    }

    #[test]
    fn a_conventional_include_directory_is_inferred() {
        // The layout of the bundled `cmake_tlv_lib` example.
        assert_eq!(
            roots(&[
                ("include/tlv/tlv.h", ""),
                ("src/tlv_internal.h", "#include \"tlv/tlv.h\"\n"),
                (
                    "src/tlv_decode.c",
                    "#include <string.h>\n#include \"tlv_internal.h\"\n"
                ),
            ]),
            [PathBuf::from("include")]
        );
    }

    #[test]
    fn includes_that_already_resolve_need_no_directory() {
        // Beside the includer, relative to the project root, or through `..`.
        assert!(roots(&[
            ("utf8.h", ""),
            ("utf8.c", "#include \"utf8.h\"\n"),
            ("lib/a.h", ""),
            (
                "lib/a.c",
                "#  include \"a.h\"\n#include \"lib/a.h\"\n#include \"../utf8.h\"\n"
            ),
        ])
        .is_empty());
    }

    #[test]
    fn system_headers_and_escaping_paths_are_ignored() {
        assert!(roots(&[
            (
                "a.c",
                "#include <stdio.h>\n#include \"/etc/passwd\"\n#include \"../../outside.h\"\n"
            ),
            // A project file that happens to share a system header's name.
            ("compat/stdio.h", ""),
        ])
        .is_empty());
    }

    #[test]
    fn angle_bracket_project_includes_are_resolved_too() {
        assert_eq!(
            roots(&[
                ("api/proj/config.hpp", ""),
                ("src/main.cpp", "#include <proj/config.hpp>\n"),
            ]),
            [PathBuf::from("api")]
        );
    }

    #[test]
    fn an_ambiguous_spelling_follows_the_directory_other_includes_need() {
        // `util.h` exists under both trees; `core/` is the one the rest of the
        // project includes from, and the choice does not depend on file order.
        assert_eq!(
            roots(&[
                ("core/util.h", ""),
                ("core/types.h", ""),
                ("vendor/util.h", ""),
                ("app/a.c", "#include \"util.h\"\n#include \"types.h\"\n"),
            ]),
            [PathBuf::from("core")]
        );
    }

    #[test]
    fn several_directories_are_ordered_by_use_then_name() {
        assert_eq!(
            roots(&[
                ("inc/a.h", ""),
                ("inc/b.h", ""),
                ("gen/c.h", ""),
                (
                    "src/x.c",
                    "#include \"a.h\"\n#include \"b.h\"\n#include \"c.h\"\n"
                ),
            ]),
            [PathBuf::from("inc"), PathBuf::from("gen")]
        );
    }

    #[test]
    fn the_filesystem_entry_point_returns_absolute_directories_under_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("include/tlv")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("include/tlv/tlv.h"), "int tlv(void);\n").unwrap();
        std::fs::write(root.join("src/tlv.c"), "#include \"tlv/tlv.h\"\n").unwrap();

        let context = infer_include_context(&root).unwrap().unwrap();

        assert_eq!(context.include_dirs, [root.join("include")]);
        assert!(context.defines.is_empty());
        assert_eq!(context.std_flag, None);

        std::fs::remove_file(root.join("src/tlv.c")).unwrap();
        assert_eq!(infer_include_context(&root).unwrap(), None);
    }
}
