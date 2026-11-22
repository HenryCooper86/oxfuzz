//! The target's own definition as harness draft context.
//!
//! The draft prompt otherwise carries only the target's signature, which hides
//! how the target consumes its input (a `char *filename` handed to `fopen`, a
//! length that must match a header field). The definition is read from the
//! project, rendered by `hf_prompt::render_target_source_section`, and retained
//! in `harness_target_sources` before dispatch (Engineering Protocol 2.13).

use std::io::Read as _;
use std::path::Path;

use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;
use sha2::{Digest as _, Sha256};

use super::project_identity::canonical_project_root;
use super::ServiceContainer;

/// Largest source file a definition is read from. Discovery parsed the same
/// file, so a larger one is unusual; refusing it keeps the read bounded.
const MAX_TARGET_SOURCE_FILE_BYTES: u64 = 1024 * 1024;

/// Lines shown when discovery recorded no end line for the definition.
const DEFAULT_DEFINITION_LINES: u32 = 120;

/// The definition text of one target, cut from a project file.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TargetDefinition {
    /// Source file relative to the canonical project root.
    pub(super) relative_file: String,
    /// SHA-256 of the complete file the excerpt was cut from.
    pub(super) source_sha256: String,
    /// The definition lines, `location.line` through `location.end_line`.
    pub(super) excerpt: String,
}

/// One project file read for prompt context.
struct ProjectFile {
    /// Path relative to the canonical project root.
    relative_file: String,
    /// SHA-256 of the complete file.
    sha256: String,
    /// The file as text (invalid UTF-8 replaced).
    text: String,
}

/// Read `path` (relative to `canonical_root`, or absolute) as prompt context.
///
/// Returns `None` when the file resolves outside the project (including
/// through a symlink or `..`), is not a regular file, exceeds
/// [`MAX_TARGET_SOURCE_FILE_BYTES`], or cannot be read.
fn read_project_file(canonical_root: &Path, path: &Path) -> Option<ProjectFile> {
    let path = canonical_root.join(path);
    let resolved = std::fs::canonicalize(&path).ok()?;
    if !resolved.starts_with(canonical_root) {
        tracing::warn!(
            path = %path.display(),
            "prompt source resolves outside the project; omitted"
        );
        return None;
    }
    let metadata = std::fs::symlink_metadata(&resolved).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_TARGET_SOURCE_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&resolved)
        .ok()?
        .take(MAX_TARGET_SOURCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if u64::try_from(bytes.len()).ok()? > MAX_TARGET_SOURCE_FILE_BYTES {
        return None;
    }
    Some(ProjectFile {
        // `/`-separated on every host: the path reaches prompts and durable
        // records, which must name the same file on any machine.
        relative_file: hf_core::runtime::posix_relative(
            resolved.strip_prefix(canonical_root).ok()?,
        ),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        text: String::from_utf8_lossy(&bytes).into_owned(),
    })
}

/// Lines `first..=last` (1-based) of `text`, joined; `None` when empty.
fn line_window(text: &str, first: u32, last: u32) -> Option<String> {
    let skip = usize::try_from(first.checked_sub(1)?).ok()?;
    let take = usize::try_from(last.checked_sub(first)?.checked_add(1)?).ok()?;
    let excerpt = text
        .lines()
        .skip(skip)
        .take(take)
        .collect::<Vec<_>>()
        .join("\n");
    (!excerpt.trim().is_empty()).then_some(excerpt)
}

/// Read `candidate`'s definition from inside `canonical_root`.
///
/// Returns `None` when the file cannot be read as prompt context (see
/// [`read_project_file`]) or the recorded line range is empty. The section is
/// optional context: each of these renders the draft prompt without it rather
/// than failing the draft.
pub(super) fn read_target_definition(
    canonical_root: &Path,
    candidate: &TargetCandidate,
) -> Option<TargetDefinition> {
    let file = read_project_file(canonical_root, Path::new(&candidate.relative_file()))?;
    let first = candidate.location.line.max(1);
    let last = candidate
        .location
        .end_line
        .filter(|end| *end >= first)
        .unwrap_or_else(|| first.saturating_add(DEFAULT_DEFINITION_LINES - 1));
    Some(TargetDefinition {
        excerpt: line_window(&file.text, first, last)?,
        relative_file: file.relative_file,
        source_sha256: file.sha256,
    })
}

/// Header files examined for the target's declaration.
const MAX_DECLARATION_HEADERS: usize = 4000;

/// The project header that declares a target, and how the build finds it.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DeclaringHeader {
    /// Header path relative to the canonical project root, `/`-separated.
    pub(super) relative_file: String,
    /// The path to write in `#include "..."`: relative to the include
    /// directory that contains the header, else to the project root, which
    /// the harness build always searches.
    pub(super) include_spelling: String,
}

/// Whether `extension` names a C or C++ header.
fn is_header_extension(extension: &str) -> bool {
    matches!(extension, "h" | "hh" | "hpp" | "hxx")
}

/// Whether `text` declares or calls `symbol`: the identifier, bounded on both
/// sides, followed by an opening parenthesis.
fn mentions_function(text: &str, symbol: &str) -> bool {
    let is_identifier = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices(symbol).any(|(at, _)| {
        let before = at.checked_sub(1).map(|index| text.as_bytes()[index]);
        let after = text[at + symbol.len()..].trim_start().as_bytes().first();
        !before.is_some_and(is_identifier) && after == Some(&b'(')
    })
}

/// Find the header that declares `candidate` inside `canonical_root`.
///
/// `include_dirs` are the absolute include directories the harness build
/// searches. Of several headers that mention the target, the one nearest the
/// project root is chosen, then the lexicographically first, so the result
/// does not depend on walk order. `None` for a language without headers, when
/// no header mentions the target, or when the project cannot be walked.
pub(super) fn find_declaring_header(
    canonical_root: &Path,
    candidate: &TargetCandidate,
    include_dirs: &[std::path::PathBuf],
) -> Option<DeclaringHeader> {
    use hf_core::target::TargetLanguage;
    if !matches!(candidate.language, TargetLanguage::C | TargetLanguage::Cpp) {
        return None;
    }
    let mut headers = Vec::new();
    for language in [TargetLanguage::C, TargetLanguage::Cpp] {
        // A project that cannot be walked gets no header note; the draft
        // still carries the target's signature.
        let files = hf_discovery::discoverable_source_files(canonical_root, language).ok()?;
        headers.extend(files.into_iter().filter(|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(is_header_extension)
        }));
    }
    headers.sort_by(|a, b| {
        a.components()
            .count()
            .cmp(&b.components().count())
            .then_with(|| a.cmp(b))
    });
    headers.truncate(MAX_DECLARATION_HEADERS);
    let header = headers.into_iter().find(|relative| {
        read_project_file(canonical_root, relative)
            .is_some_and(|file| mentions_function(&file.text, &candidate.symbol))
    })?;
    let absolute = canonical_root.join(&header);
    let spelling = include_dirs
        .iter()
        .filter_map(|directory| absolute.strip_prefix(directory).ok())
        .min_by_key(|relative| relative.components().count())
        .unwrap_or(&header);
    Some(DeclaringHeader {
        relative_file: hf_core::runtime::posix_relative(&header),
        include_spelling: hf_core::runtime::posix_relative(spelling),
    })
}

/// The identifier a Rust target's crate is linked into the harness as: the
/// root `Cargo.toml` package name, which the cargo-fuzz build depends on, with
/// `-` written as `_`. `None` for another language or a project whose root
/// manifest names no package.
pub(super) fn rust_crate_ident(
    canonical_root: &Path,
    candidate: &TargetCandidate,
) -> Option<String> {
    if candidate.language != hf_core::target::TargetLanguage::Rust {
        return None;
    }
    let manifest = read_project_file(canonical_root, Path::new("Cargo.toml"))?;
    let name = hf_harness::cargo_fuzz::crate_name_from_cargo_toml(&manifest.text)?;
    Some(name.replace('-', "_"))
}

/// The text of a target's defining file, read from inside its project root,
/// for the template drafts that take a clause from it (the Go package, the
/// Java package). `None` for a file that is outside the project, not
/// regular, or larger than the prompt-source bound.
pub(super) fn target_file_text(candidate: &TargetCandidate) -> Option<String> {
    let canonical_root = std::fs::canonicalize(&candidate.project_root).ok()?;
    read_project_file(&canonical_root, Path::new(&candidate.relative_file())).map(|file| file.text)
}

/// Lines shown on each side of a faulting line.
const CRASH_SITE_RADIUS: u32 = 20;

/// The sandbox mount point of the staged project: a report's `/work/src/a.c`
/// is the project's `src/a.c`.
const SANDBOX_PROJECT_PREFIX: &str = "/work/";

/// The source lines around a faulting line.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CrashSite {
    /// Source file relative to the canonical project root.
    pub(super) relative_file: String,
    /// Line number of the excerpt's first line.
    pub(super) first_line: u32,
    /// The faulting line.
    pub(super) crash_line: u32,
    /// Lines `first_line` through `crash_line + CRASH_SITE_RADIUS`.
    pub(super) excerpt: String,
}

/// Read the lines around `line` of `file`, a path as a crash report printed
/// it (sandbox `/work/...`, project-relative, or absolute), from inside
/// `canonical_root`. `None` when the file is outside the project, unreadable,
/// or shorter than `line`.
pub(super) fn read_crash_site(canonical_root: &Path, file: &str, line: u32) -> Option<CrashSite> {
    let path = file.strip_prefix(SANDBOX_PROJECT_PREFIX).unwrap_or(file);
    let project_file = read_project_file(canonical_root, Path::new(path))?;
    if usize::try_from(line).ok()? > project_file.text.lines().count() {
        return None;
    }
    let first = line.saturating_sub(CRASH_SITE_RADIUS).max(1);
    let last = line.saturating_add(CRASH_SITE_RADIUS);
    Some(CrashSite {
        excerpt: line_window(&project_file.text, first, last)?,
        relative_file: project_file.relative_file,
        first_line: first,
        crash_line: line,
    })
}

impl ServiceContainer {
    /// The rendered target-definition section for one draft, retained before
    /// it is returned.
    ///
    /// `Ok(None)` without a store (the section could not be reconstructed
    /// later), when the definition cannot be read, or when the rendered section
    /// exceeds the retained size. A storage failure is an error: it stops
    /// dispatch, so an unretained section never reaches a provider.
    pub(super) async fn retained_target_source(
        &self,
        project: &Path,
        candidate: &TargetCandidate,
        include_dirs: &[std::path::PathBuf],
    ) -> Result<Option<String>, ClassifiedError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        let root = canonical_project_root(project)?;
        let Some(definition) = read_target_definition(&root, candidate) else {
            return Ok(None);
        };
        let mut rendered = hf_prompt::render_target_source_section(
            &definition.relative_file,
            candidate.location.line,
            &definition.excerpt,
        );
        // The note is part of the retained section, so the exact text the
        // model saw stays reconstructable (Engineering Protocol 2.13).
        if !rendered.is_empty() {
            if let Some(header) = find_declaring_header(&root, candidate, include_dirs) {
                rendered.push_str(&hf_prompt::render_target_header_note(
                    &header.relative_file,
                    &header.include_spelling,
                ));
            }
            if let Some(crate_ident) = rust_crate_ident(&root, candidate) {
                rendered.push_str(&hf_prompt::render_target_crate_note(
                    &crate_ident,
                    &definition.relative_file,
                ));
            }
        }
        if rendered.is_empty() || rendered.len() > hf_storage::MAX_TARGET_SOURCE_SECTION_BYTES {
            return Ok(None);
        }
        let record = hf_storage::HarnessTargetSourceRecord {
            id: uuid::Uuid::new_v4(),
            project_root: root.to_string_lossy().into_owned(),
            target_id: candidate.id,
            source_file: definition.relative_file,
            source_sha256: definition.source_sha256,
            rendered,
            created_at: chrono::Utc::now(),
        };
        store
            .append_harness_target_source(&record)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(Some(record.rendered))
    }
}

#[cfg(test)]
mod tests {
    use super::{find_declaring_header, read_crash_site, read_target_definition, rust_crate_ident};
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use std::path::{Path, PathBuf};

    fn candidate(root: &Path, file: &str, line: u32, end_line: Option<u32>) -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: root.to_path_buf(),
            language: TargetLanguage::C,
            symbol: "parse".to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from(file),
                line,
                col: 1,
                end_line,
                end_col: None,
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: 0.5,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    fn project(source: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/parse.c"), source).unwrap();
        (dir, root)
    }

    #[test]
    fn the_recorded_span_is_read_and_digested() {
        let (_dir, root) = project("// header\nint parse(void) {\n  return 1;\n}\nint other;\n");
        let definition =
            read_target_definition(&root, &candidate(&root, "src/parse.c", 2, Some(4))).unwrap();
        assert_eq!(definition.excerpt, "int parse(void) {\n  return 1;\n}");
        assert_eq!(definition.relative_file, "src/parse.c");
        assert_eq!(definition.source_sha256.len(), 64);
    }

    #[test]
    fn an_absolute_location_inside_the_project_is_read() {
        let (_dir, root) = project("int parse(void) { return 1; }\n");
        let absolute = root.join("src/parse.c");
        let definition = read_target_definition(
            &root,
            &candidate(&root, &absolute.to_string_lossy(), 1, Some(1)),
        )
        .unwrap();
        assert_eq!(definition.relative_file, "src/parse.c");
    }

    #[test]
    fn a_missing_end_line_reads_a_bounded_window() {
        let source = (1..=500)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let (_dir, root) = project(&source);
        let definition =
            read_target_definition(&root, &candidate(&root, "src/parse.c", 10, None)).unwrap();
        assert_eq!(definition.excerpt.lines().count(), 120);
        assert!(definition.excerpt.starts_with("line 10"));
    }

    #[test]
    fn a_path_outside_the_project_is_not_read() {
        let (_dir, root) = project("int parse(void) { return 1; }\n");
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.c"), "int secret;\n").unwrap();
        let escape = std::fs::canonicalize(outside.path())
            .unwrap()
            .join("secret.c");
        assert!(read_target_definition(
            &root,
            &candidate(&root, &escape.to_string_lossy(), 1, Some(1))
        )
        .is_none());
        assert!(
            read_target_definition(&root, &candidate(&root, "../secret.c", 1, Some(1))).is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_project_is_not_followed() {
        let (_dir, root) = project("int parse(void) { return 1; }\n");
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.c"), "int secret;\n").unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.c"), root.join("src/link.c"))
            .unwrap();
        assert!(
            read_target_definition(&root, &candidate(&root, "src/link.c", 1, Some(1))).is_none()
        );
    }

    #[test]
    fn an_oversized_file_is_not_read() {
        let (_dir, root) = project("");
        let big = vec![b'x'; usize::try_from(super::MAX_TARGET_SOURCE_FILE_BYTES).unwrap() + 1];
        std::fs::write(root.join("src/parse.c"), big).unwrap();
        assert!(
            read_target_definition(&root, &candidate(&root, "src/parse.c", 1, Some(1))).is_none()
        );
    }

    #[test]
    fn an_empty_span_is_not_a_definition() {
        let (_dir, root) = project("int parse(void);\n");
        assert!(
            read_target_definition(&root, &candidate(&root, "src/parse.c", 40, Some(41))).is_none()
        );
    }

    #[test]
    fn a_sandbox_crash_path_maps_into_the_project() {
        let source = (1..=100)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let (_dir, root) = project(&source);
        let site = read_crash_site(&root, "/work/src/parse.c", 50).unwrap();
        assert_eq!(site.relative_file, "src/parse.c");
        assert_eq!(site.first_line, 30);
        assert_eq!(site.crash_line, 50);
        assert!(site.excerpt.starts_with("line 30\n"));
        assert!(site.excerpt.ends_with("line 70"));
    }

    #[test]
    fn a_crash_near_the_file_start_clamps_the_window() {
        let (_dir, root) = project("a\nb\nc\n");
        let site = read_crash_site(&root, "src/parse.c", 2).unwrap();
        assert_eq!(site.first_line, 1);
        assert_eq!(site.excerpt, "a\nb\nc");
    }

    #[test]
    fn a_crash_outside_the_project_is_not_read() {
        let (_dir, root) = project("a\n");
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("libc.c"), "x\n").unwrap();
        let path = std::fs::canonicalize(outside.path())
            .unwrap()
            .join("libc.c");
        assert!(read_crash_site(&root, &path.to_string_lossy(), 1).is_none());
        assert!(read_crash_site(&root, "/work/../../etc/passwd", 1).is_none());
        assert!(read_crash_site(&root, "src/parse.c", 99).is_none());
    }
    #[test]
    fn the_declaring_header_is_spelled_relative_to_its_include_directory() {
        // The bundled `cmake_tlv_lib` layout: the model wrote `"tlv.h"`.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("include/tlv")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("include/tlv/tlv.h"),
            "int parse (const unsigned char *data, unsigned long len);\n",
        )
        .unwrap();
        // Mentions a longer identifier only, and a source file is not a header.
        std::fs::write(
            root.join("a.h"),
            "int parse_all(void);\nint reparse(void);\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/parse.c"),
            "int parse(const unsigned char *d, unsigned long n) { return 0; }\n",
        )
        .unwrap();
        let target = candidate(&root, "src/parse.c", 1, Some(1));

        let header = find_declaring_header(&root, &target, &[root.join("include")]).unwrap();
        assert_eq!(header.relative_file, "include/tlv/tlv.h");
        assert_eq!(header.include_spelling, "tlv/tlv.h");

        // Without an include directory the project root is what the build searches.
        let header = find_declaring_header(&root, &target, &[]).unwrap();
        assert_eq!(header.include_spelling, "include/tlv/tlv.h");
    }

    #[test]
    fn a_rust_target_is_named_through_its_package_not_its_directory() {
        // The bundled `rust_varint` example is the package
        // `oxfuzz_example_varint`; every first draft called
        // `rust_varint::decode` and failed to compile.
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"example-varint\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn decode(d: &[u8]) -> usize { d.len() }\n",
        )
        .unwrap();
        let mut target = candidate(&root, "src/lib.rs", 1, Some(1));
        assert_eq!(
            rust_crate_ident(&root, &target),
            None,
            "a C target has no crate"
        );
        target.language = TargetLanguage::Rust;
        assert_eq!(
            rust_crate_ident(&root, &target).as_deref(),
            Some("example_varint")
        );
    }

    #[test]
    fn a_target_no_header_declares_has_no_header_note() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("other.h"), "int unrelated(int);\n").unwrap();
        std::fs::write(
            root.join("parse.c"),
            "int parse(const char *s) { return s[0]; }\n",
        )
        .unwrap();
        let target = candidate(&root, "parse.c", 1, Some(1));
        assert_eq!(find_declaring_header(&root, &target, &[]), None);
    }
}
