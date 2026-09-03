//! On-disk harness state inside a target workspace.
//!
//! The workspace holds the harness revision currently staged for a target: its
//! source, its id marker, its compiled binary, and the dictionary and seeds
//! derived from it. Reading and writing that state is separated here so the
//! marker-versus-source resolution rules live in one place.

use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;
use uuid::Uuid;

use super::crash_inputs::is_regular_file;

/// Reduce an untrusted `target` to the single directory component that names
/// its workspace.
///
/// The target string is foreign data at the service boundary (`--target`, the
/// REST wire, the desktop IPC), and the documented `file.c::symbol` syntax plus
/// C++ qualified names routinely carry `/`, `:`, `<`, and `>`. Returning a
/// multi-component path from those would nest one target's workspace inside
/// another's (target `a/corpus` landing in target `a`'s corpus directory) and
/// would produce NTFS-illegal names on a Windows host, so the result is always
/// one portable component. Shares [`target_artifact_stem`] with
/// [`harness_binary_name`] so a workspace and the binary inside it are named by
/// the same rule: plain identifiers -- everything the scanners emit -- are kept
/// verbatim, and anything else is folded to `[A-Za-z0-9_-]` plus a hash of the
/// original that keeps distinct targets apart.
pub(super) fn sanitize_target(target: &str) -> PathBuf {
    PathBuf::from(target_artifact_stem(target))
}

/// Stable single-component stem for target-derived artifact filenames.
///
/// Injective up to the appended hash: the hash is added whenever the stem is
/// not the target verbatim, *including* when it is truncated, so two targets
/// sharing the retained prefix never collapse onto one name.
fn target_artifact_stem(target: &str) -> String {
    use sha2::{Digest, Sha256};

    /// Retained prefix length; the hash disambiguates anything cut here.
    const MAX_STEM_CHARS: usize = 64;

    // Every mapped character is ASCII, so the byte truncation below always
    // lands on a character boundary.
    let mut safe: String = target
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect();
    let changed = safe != target || safe.is_empty() || safe.len() > MAX_STEM_CHARS;
    if safe.is_empty() {
        safe.push_str("default");
    }
    safe.truncate(MAX_STEM_CHARS);
    if changed {
        let digest = format!("{:x}", Sha256::digest(target.as_bytes()));
        safe.push('-');
        safe.push_str(&digest[..8]);
    }
    safe
}

pub(super) fn harness_binary_name(target: &str) -> String {
    format!("fuzz_{}", target_artifact_stem(target))
}

// ---------------------------------------------------------------------------
// Seed generation
// ---------------------------------------------------------------------------

/// Whether a corpus entry name belongs to the reserved generated-seed
/// namespace: the `seed_` (heuristic), `llmseed_` (provider), and `regen_`
/// (survival-driven regeneration) prefixes oxfuzz's seed writers use.
///
/// A filesystem listing cannot carry a durable source tag -- every re-list
/// re-tags entries -- so the name is the marker. Only generated seeds are
/// eligible for survival-driven regeneration; every other entry is an input
/// a fuzzer or a human earned.
#[must_use]
pub fn is_generated_seed_name(name: &str) -> bool {
    name.starts_with("seed_") || name.starts_with("llmseed_") || name.starts_with("regen_")
}

/// Generate target-aware seed inputs for a corpus.
#[must_use]
pub fn generate_target_seeds(target: &str) -> Vec<(Vec<u8>, String)> {
    let lower = target.to_ascii_lowercase();
    if lower.contains("json") || lower.contains("parse") {
        vec![
            (b"{}".to_vec(), "seed_empty_obj".to_owned()),
            (b"[]".to_vec(), "seed_empty_arr".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
            (b"\"hello\"".to_vec(), "seed_string".to_owned()),
            (b"true".to_vec(), "seed_bool".to_owned()),
            (b"null".to_vec(), "seed_null".to_owned()),
            (b"42".to_vec(), "seed_number".to_owned()),
            (b"{\"key\":\"value\"}".to_vec(), "seed_object".to_owned()),
            (b"{\"nested\":{\"a\":1}}".to_vec(), "seed_nested".to_owned()),
            (b"\"".to_vec(), "seed_truncated_string".to_owned()),
            (b"[".to_vec(), "seed_truncated_array".to_owned()),
            (b"{".to_vec(), "seed_truncated_object".to_owned()),
        ]
    } else if lower.contains("xml") {
        vec![
            (b"<root/>".to_vec(), "seed_empty_xml".to_owned()),
            (b"<root>text</root>".to_vec(), "seed_simple_xml".to_owned()),
            (b"<a><b/></a>".to_vec(), "seed_nested_xml".to_owned()),
        ]
    } else if lower.contains("csv") {
        vec![
            (b"a,b,c\n1,2,3\n".to_vec(), "seed_simple_csv".to_owned()),
            (
                b"\"quoted\",\"fields\"\n".to_vec(),
                "seed_quoted_csv".to_owned(),
            ),
        ]
    } else {
        vec![
            (b"\x00".to_vec(), "seed_null_byte".to_owned()),
            (b"\xff".to_vec(), "seed_high_byte".to_owned()),
            (b"AAAA".to_vec(), "seed_repeated".to_owned()),
            ("".as_bytes().to_vec(), "seed_empty".to_owned()),
            (b"test".to_vec(), "seed_ascii".to_owned()),
        ]
    }
}

/// Build a fuzzing dictionary from the C/C++ sources in `workspace`, writing it
/// to `<workspace>/<dict_name>` and returning that path.
///
/// The literals a target compares against (magic bytes, format keywords) are
/// among the cheapest ways to get a fuzzer past shallow `memcmp`/keyword gates,
/// so seeding the engine dictionary with them measurably deepens coverage.
/// Returns `None` when no usable literals were found (so the caller adds no
/// dictionary flag) or the file cannot be written.
pub(super) fn build_workspace_dictionary(workspace: &Path, dict_name: &str) -> Option<PathBuf> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let entries = std::fs::read_dir(workspace).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh") {
            continue;
        }
        // Skip the generated harness itself -- its literals are oxfuzz's, not
        // the target's, and add noise.
        if path.file_stem().and_then(|s| s.to_str()) == Some("harness") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&path) {
            for token in hf_engine::dict::extract_tokens(&src) {
                if seen.insert(token.clone()) {
                    tokens.push(token);
                }
            }
        }
    }
    if tokens.is_empty() {
        return None;
    }
    let dict_path = workspace.join(dict_name);
    std::fs::write(&dict_path, hf_engine::dict::render_dict(&tokens)).ok()?;
    Some(dict_path)
}

/// A bounded excerpt of the target's non-harness C/C++ sources, for the LLM
/// dictionary author. Capped so a large target cannot blow the prompt budget.
pub(super) fn read_dictionary_source_excerpt(workspace: &Path, max_bytes: usize) -> String {
    let mut excerpt = String::new();
    let Ok(entries) = std::fs::read_dir(workspace) else {
        return excerpt;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh") {
            continue;
        }
        if path.file_stem().and_then(|s| s.to_str()) == Some("harness") {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(&path) {
            excerpt.push_str(&src);
            excerpt.push('\n');
            if excerpt.len() >= max_bytes {
                excerpt.truncate(max_bytes);
                break;
            }
        }
    }
    excerpt
}

/// Cache of LLM-proposed dictionary tokens, keyed by `project::target` and
/// tagged with the static dictionary's content hash, so the LLM is queried at
/// most once per source version.
pub(super) type DictLlmCache =
    std::sync::Mutex<std::collections::HashMap<String, (u64, Vec<Vec<u8>>)>>;

pub(super) fn dict_llm_cache() -> &'static DictLlmCache {
    static CACHE: std::sync::OnceLock<DictLlmCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Read the current harness source from a target workspace, trying the known
/// per-language harness filenames. Returns `None` when none exists yet.
pub(super) fn read_current_harness_source(workspace: &Path) -> Option<String> {
    let canonical = workspace.join("harness.source");
    if is_regular_file(&canonical) {
        if let Ok(src) = std::fs::read_to_string(canonical) {
            if !src.trim().is_empty() {
                return Some(src);
            }
        }
    }
    for name in [
        "harness.c",
        "harness.cc",
        "harness.cpp",
        "harness.cxx",
        "harness.rs",
        "harness.go",
    ] {
        let path = workspace.join(name);
        if is_regular_file(&path) {
            if let Ok(src) = std::fs::read_to_string(path) {
                if !src.trim().is_empty() {
                    return Some(src);
                }
            }
        }
    }
    None
}

/// Read the persisted id of the harness revision that produced the active
/// binary. Older workspaces predate this marker and are resolved by source.
pub(super) fn read_current_harness_id(workspace: &Path) -> Option<Uuid> {
    let path = workspace.join("harness.active");
    is_regular_file(&path)
        .then(|| std::fs::read_to_string(path).ok())
        .flatten()
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
}

/// Commit the source corresponding to the active harness binary.
///
/// Compiler input files are attempt-local: a failed compile may overwrite one,
/// while the previously built binary remains active. Keeping a separate
/// canonical source and replacing it only after a successful sandbox build
/// prevents run revision hashes and rollback decisions from describing source
/// that the active binary does not contain.
pub(super) fn write_current_harness_source(
    workspace: &Path,
    source: &str,
) -> Result<(), ClassifiedError> {
    std::fs::create_dir_all(workspace)
        .map_err(|e| ClassifiedError::Internal(format!("mkdir harness workspace: {e}")))?;
    let destination = workspace.join("harness.source");
    let temporary = workspace.join(format!("harness.source.{}.tmp", Uuid::new_v4()));
    std::fs::write(&temporary, source)
        .map_err(|e| ClassifiedError::Internal(format!("stage harness source: {e}")))?;
    if let Err(first) = std::fs::rename(&temporary, &destination) {
        // Windows does not replace an existing destination with `rename`; the
        // retry keeps the same behavior there. POSIX takes the atomic path above.
        if destination.exists() {
            std::fs::remove_file(&destination).map_err(|e| {
                let _ = std::fs::remove_file(&temporary);
                ClassifiedError::Internal(format!(
                    "replace harness source after rename failed ({first}): {e}"
                ))
            })?;
            std::fs::rename(&temporary, &destination).map_err(|e| {
                let _ = std::fs::remove_file(&temporary);
                ClassifiedError::Internal(format!("commit harness source: {e}"))
            })?;
        } else {
            let _ = std::fs::remove_file(&temporary);
            return Err(ClassifiedError::Internal(format!(
                "commit harness source: {first}"
            )));
        }
    }
    Ok(())
}

/// Link the active binary/source pair to its persisted qualification record.
pub(super) fn write_current_harness_id(workspace: &Path, id: Uuid) -> Result<(), ClassifiedError> {
    std::fs::write(workspace.join("harness.active"), id.to_string())
        .map_err(|e| ClassifiedError::Internal(format!("write active harness id: {e}")))
}

/// Atomically reactivate an already-verified historical executable.
pub(super) fn write_current_harness_binary(
    workspace: &Path,
    target: &str,
    source: &Path,
) -> Result<PathBuf, ClassifiedError> {
    if !is_regular_file(source) {
        return Err(ClassifiedError::Validation(format!(
            "historical harness binary is not a regular file: {}",
            source.display()
        )));
    }
    let destination = workspace.join(harness_binary_name(target));
    if std::fs::symlink_metadata(&destination).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(ClassifiedError::Validation(format!(
            "active harness destination is a symlink: {}",
            destination.display()
        )));
    }
    let temporary = workspace.join(format!("harness.restore.{}.tmp", Uuid::new_v4()));
    std::fs::copy(source, &temporary).map_err(|error| {
        ClassifiedError::Internal(format!(
            "stage historical harness binary {}: {error}",
            source.display()
        ))
    })?;
    if let Err(first) = std::fs::rename(&temporary, &destination) {
        if is_regular_file(&destination) {
            std::fs::remove_file(&destination).map_err(|error| {
                let _ = std::fs::remove_file(&temporary);
                ClassifiedError::Internal(format!(
                    "replace active harness after rename failed ({first}): {error}"
                ))
            })?;
            std::fs::rename(&temporary, &destination).map_err(|error| {
                let _ = std::fs::remove_file(&temporary);
                ClassifiedError::Internal(format!("commit historical harness binary: {error}"))
            })?;
        } else {
            let _ = std::fs::remove_file(&temporary);
            return Err(ClassifiedError::Internal(format!(
                "commit historical harness binary: {first}"
            )));
        }
    }
    Ok(destination)
}

/// Map a host path inside the workspace to its container path under `/work`
/// (the mount point), falling back to `/work/out/<filename>`.
///
/// The container is Linux, so the result is `/`-separated regardless of the
/// host separator; `rel.display()` would embed `\` on Windows and hand the
/// sandbox a malformed path.
pub(super) fn container_input_path(workspace: &Path, host_path: &Path) -> String {
    host_path.strip_prefix(workspace).map_or_else(
        |_| {
            format!(
                "/work/out/{}",
                host_path.file_name().unwrap_or_default().to_string_lossy()
            )
        },
        |rel| format!("/work/{}", hf_core::runtime::posix_relative(rel)),
    )
}

/// Copy C/C++ source and header files from a project into the workspace
/// so the sandbox can compile the harness + target together.
///
/// For Rust projects it also stages the crate under test -- `Cargo.toml`,
/// `Cargo.lock`, and the `src/` tree -- so the cargo-fuzz project's path
/// dependency on the crate resolves inside the sandbox.
pub fn copy_project_sources(project: &Path, workspace: &Path) {
    let mut staged = 0_usize;
    stage_tree(
        project,
        project,
        workspace,
        &|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| STAGED_SOURCE_EXTENSIONS.contains(&extension))
        },
        &mut staged,
    );
    stage_rust_crate(project, workspace, &mut staged);
}

/// Source and header extensions staged for a C/C++ build.
const STAGED_SOURCE_EXTENSIONS: [&str; 6] = ["c", "h", "cc", "cpp", "cxx", "hpp"];

/// Directory names never staged: version control, build output, and fetched
/// dependencies. Compiling a stale copy out of `build/` is worse than not
/// finding the source at all, because the resulting crash points at code the
/// operator is not editing.
const STAGING_SKIP_DIRS: [&str; 4] = [".git", "target", "build", "node_modules"];

/// Cap on staged files. A project past this is not something we can stage into
/// a sandbox workspace and compile as one unit, and an untrusted project must
/// not be able to turn staging into an unbounded host traversal.
const MAX_STAGED_FILES: usize = 20_000;

/// Recursively copy files accepted by `accept` from `directory` into
/// `workspace`, preserving each file's path relative to `root`.
///
/// Symlinks are refused rather than followed, so a link inside the project
/// cannot pull a file from elsewhere on the host into the sandbox workspace.
/// Returns `false` when [`MAX_STAGED_FILES`] stopped the walk early.
fn stage_tree(
    root: &Path,
    directory: &Path,
    workspace: &Path,
    accept: &dyn Fn(&Path) -> bool,
    staged: &mut usize,
) -> bool {
    let Ok(entries) = std::fs::read_dir(directory) else {
        // An unreadable directory is not fatal on its own, but a missing source
        // surfaces later as a confusing compile error -- surface it here.
        tracing::warn!("failed to read project directory {}", directory.display());
        return true;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    // Sorted so staging a given project always visits files in the same order,
    // which keeps the file cap deterministic about what it drops.
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if *staged >= MAX_STAGED_FILES {
            tracing::warn!(
                "stopped staging {} at the {MAX_STAGED_FILES} file limit",
                root.display()
            );
            return false;
        }
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            tracing::warn!("failed to inspect {}", path.display());
            continue;
        };
        if kind.is_symlink() {
            tracing::warn!("refusing to stage symlink {}", path.display());
            continue;
        }
        if kind.is_dir() {
            let name = entry.file_name();
            if STAGING_SKIP_DIRS
                .iter()
                .any(|skipped| std::ffi::OsStr::new(skipped) == name)
            {
                continue;
            }
            if !stage_tree(root, &path, workspace, accept, staged) {
                return false;
            }
        } else if kind.is_file() && accept(&path) {
            stage_file(root, &path, workspace, staged);
        }
    }
    true
}

/// Copy one staged file, recreating its project-relative directories under
/// `workspace`.
fn stage_file(root: &Path, path: &Path, workspace: &Path, staged: &mut usize) {
    let Ok(relative) = path.strip_prefix(root) else {
        // `stage_tree` only ever descends from `root`, so this cannot happen;
        // skipping is still the safe response to a path outside the project.
        tracing::warn!("skipping {} from outside the project root", path.display());
        return;
    };
    let dest = workspace.join(relative);
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(
                "failed to create staging directory {}: {e}",
                parent.display()
            );
            return;
        }
    }
    if let Err(e) = std::fs::copy(path, &dest) {
        tracing::warn!(
            "failed to copy source {} into workspace: {e}",
            path.display()
        );
        return;
    }
    *staged += 1;
}

/// Stage a Rust crate (its manifest + `src/` tree) from `project` into
/// `workspace` so a cargo-fuzz project can depend on it by path. A no-op when the
/// project has no `Cargo.toml` (i.e. is not a Rust crate).
///
/// The `src/` walk goes through [`stage_tree`] like the C/C++ one: two staging
/// walks with different symlink and bound rules would leave the Rust path as
/// the weaker of the two for no reason.
fn stage_rust_crate(project: &Path, workspace: &Path, staged: &mut usize) {
    let manifest = project.join("Cargo.toml");
    if !manifest.is_file() {
        return;
    }
    for name in ["Cargo.toml", "Cargo.lock"] {
        let src = project.join(name);
        if src.is_file() {
            if let Err(e) = std::fs::copy(&src, workspace.join(name)) {
                tracing::warn!("failed to stage {} into workspace: {e}", src.display());
            }
        }
    }
    let src_dir = project.join("src");
    if src_dir.is_dir() {
        stage_tree(project, &src_dir, workspace, &|_| true, staged);
    }
}

#[cfg(test)]
mod container_input_path_tests {
    use std::path::PathBuf;

    #[test]
    fn workspace_paths_map_to_posix_container_paths() {
        // The sandbox is a Linux container, so its paths are `/`-separated no
        // matter which separator the host used to build the input path.
        let workspace = PathBuf::from("ws");
        let input = workspace.join("corpus").join("c");
        assert_eq!(
            super::container_input_path(&workspace, &input),
            "/work/corpus/c"
        );
    }

    #[test]
    fn foreign_paths_fall_back_to_out_by_filename() {
        let workspace = PathBuf::from("ws");
        let foreign = PathBuf::from("elsewhere").join("crash-abc");
        assert_eq!(
            super::container_input_path(&workspace, &foreign),
            "/work/out/crash-abc"
        );
    }
}

#[cfg(test)]
mod harness_binary_name_tests {
    use std::path::Path;

    #[test]
    fn harness_binary_name_is_one_safe_component() {
        for target in ["../../outside", "/etc/passwd", "ns::Parser/read", ""] {
            let name = super::harness_binary_name(target);
            assert!(name.starts_with("fuzz_"));
            assert_eq!(Path::new(&name).components().count(), 1, "{name}");
            assert!(!name.contains(".."), "{name}");
            assert!(!name.contains('/'), "{name}");
            assert!(!name.contains('\\'), "{name}");
        }
        assert_eq!(
            super::harness_binary_name("parse_entry"),
            "fuzz_parse_entry"
        );
    }

    /// The stem truncates at 64 characters, so every target longer than that
    /// must carry the disambiguating hash. Without it two targets sharing a
    /// 64-character prefix name one artifact -- and, since the stem also names
    /// the workspace directory, one workspace.
    #[test]
    fn stem_disambiguates_targets_sharing_a_truncated_prefix() {
        let prefix = "a".repeat(64);
        let first = format!("{prefix}_variant_one");
        let second = format!("{prefix}_variant_two");
        assert_ne!(
            super::harness_binary_name(&first),
            super::harness_binary_name(&second),
        );
    }
}

#[cfg(test)]
mod sanitize_target_tests {
    use std::path::Path;

    /// A target string is foreign data at the service boundary (`--target`,
    /// REST, GUI), and its sanitized form names a workspace directory. One
    /// portable component keeps two targets from sharing a workspace and keeps
    /// the path legal on a Windows host.
    #[test]
    fn sanitize_target_is_one_portable_component() {
        for target in [
            "../../outside",
            "/etc/passwd",
            "ns::Parser::read",
            "src/parser.c::parse_header",
            "std::vector<int>::push_back",
            "a/corpus",
            "",
        ] {
            let sanitized = super::sanitize_target(target);
            let rendered = sanitized.to_string_lossy().into_owned();
            assert_eq!(
                Path::new(&sanitized).components().count(),
                1,
                "{target} -> {rendered}"
            );
            assert!(
                rendered
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')),
                "{target} -> {rendered}"
            );
        }
    }

    /// Distinct targets never share a workspace directory, including the pairs
    /// that only differ in characters the sanitizer replaces.
    #[test]
    fn sanitize_target_separates_distinct_targets() {
        for (first, second) in [
            ("a/corpus", "a_corpus"),
            ("ns::read", "ns__read"),
            ("mod::parse", "mod/parse"),
        ] {
            assert_ne!(
                super::sanitize_target(first),
                super::sanitize_target(second),
                "{first} vs {second}"
            );
        }
    }

    /// Every symbol the scanners actually emit is a plain identifier, so the
    /// existing on-disk workspace name is preserved byte for byte.
    #[test]
    fn sanitize_target_preserves_plain_identifiers() {
        for target in ["parse_value", "parse_entry", "Parser.read", "fuzz-me"] {
            let expected = target.replace('.', "_");
            let sanitized = super::sanitize_target(target);
            if target == expected {
                assert_eq!(sanitized, Path::new(target), "{target}");
            }
        }
    }

    /// An empty target still yields a usable component, and it is not the one
    /// a target literally named `default` gets -- the two are different
    /// targets and must not share a workspace.
    #[test]
    fn sanitize_target_keeps_the_empty_target_distinct() {
        let empty = super::sanitize_target("");
        assert_eq!(Path::new(&empty).components().count(), 1);
        assert!(empty.to_string_lossy().starts_with("default"));
        assert_ne!(empty, super::sanitize_target("default"));
    }
}

#[cfg(test)]
mod harness_source_tests {
    use super::{read_current_harness_source, write_current_harness_source};

    #[test]
    fn canonical_harness_source_wins_over_language_specific_build_inputs() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(workspace.path().join("harness.c"), "stale C source").unwrap();
        write_current_harness_source(workspace.path(), "active Rust source").unwrap();

        assert_eq!(
            read_current_harness_source(workspace.path()).as_deref(),
            Some("active Rust source")
        );
    }
}

#[cfg(test)]
mod dictionary_tests {
    use super::build_workspace_dictionary;

    #[test]
    fn builds_dictionary_from_source_literals_excluding_harness() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("parse.c"),
            "int f(){ return strcmp(s, \"MAGIC\"); }",
        )
        .unwrap();
        // The generated harness literals must NOT pollute the dictionary.
        std::fs::write(
            dir.path().join("harness.c"),
            "int LLVMFuzzerTestOneInput(){ puts(\"HARNESS_ONLY\"); return 0; }",
        )
        .unwrap();

        let path = build_workspace_dictionary(dir.path(), "t.dict").expect("dict built");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"MAGIC\""), "missing target literal: {body}");
        assert!(
            !body.contains("HARNESS_ONLY"),
            "harness literal leaked: {body}"
        );
    }

    #[test]
    fn returns_none_when_no_literals() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("empty.c"), "int f(){ return 0; }").unwrap();
        assert!(build_workspace_dictionary(dir.path(), "t.dict").is_none());
    }
}

#[cfg(test)]
mod rust_staging_tests {
    use super::copy_project_sources;

    #[test]
    fn stages_rust_crate_manifest_and_src_tree() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname = \"lib\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("src").join("inner")).unwrap();
        std::fs::write(project.path().join("src").join("lib.rs"), "pub fn f() {}").unwrap();
        std::fs::write(
            project.path().join("src").join("inner").join("mod.rs"),
            "// nested",
        )
        .unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(workspace.path().join("Cargo.toml").is_file());
        assert!(workspace.path().join("src").join("lib.rs").is_file());
        // The src/ tree is copied recursively so multi-file crates build.
        assert!(workspace
            .path()
            .join("src")
            .join("inner")
            .join("mod.rs")
            .is_file());
    }

    #[test]
    fn non_rust_project_stages_no_crate() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("parse.c"), "int f(){ return 0; }").unwrap();

        copy_project_sources(project.path(), workspace.path());

        // C sources copy; no Cargo.toml means no Rust staging.
        assert!(workspace.path().join("parse.c").is_file());
        assert!(!workspace.path().join("Cargo.toml").exists());
        assert!(!workspace.path().join("src").exists());
    }
}

#[cfg(test)]
mod c_staging_tests {
    use super::copy_project_sources;

    #[test]
    fn nested_c_sources_stage_at_their_relative_paths() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("src/parser")).unwrap();
        std::fs::create_dir_all(project.path().join("include")).unwrap();
        std::fs::write(
            project.path().join("src/parser/dns.c"),
            "int p(void){return 0;}",
        )
        .unwrap();
        std::fs::write(project.path().join("include/dns.h"), "int p(void);").unwrap();
        std::fs::write(project.path().join("top.c"), "int t(void){return 0;}").unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(workspace.path().join("src/parser/dns.c").is_file());
        assert!(workspace.path().join("include/dns.h").is_file());
        assert!(workspace.path().join("top.c").is_file());
    }

    #[test]
    fn staging_refuses_a_symlinked_source_tree() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.c"), "int s(void){return 0;}").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), project.path().join("linked")).unwrap();
        let workspace = tempfile::tempdir().unwrap();

        copy_project_sources(project.path(), workspace.path());

        // A symlinked directory is never followed, so nothing outside the
        // project root can be staged into the sandbox workspace.
        assert!(!workspace.path().join("linked/secret.c").exists());
    }

    #[test]
    fn build_output_directories_are_not_staged() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        for skipped in [".git", "target", "build", "node_modules"] {
            std::fs::create_dir_all(project.path().join(skipped)).unwrap();
            std::fs::write(
                project.path().join(skipped).join("stale.c"),
                "int stale(void){return 0;}",
            )
            .unwrap();
        }
        std::fs::write(project.path().join("real.c"), "int r(void){return 0;}").unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(workspace.path().join("real.c").is_file());
        for skipped in [".git", "target", "build", "node_modules"] {
            assert!(
                !workspace.path().join(skipped).exists(),
                "staged {skipped}, which is build output or version control"
            );
        }
    }
}
