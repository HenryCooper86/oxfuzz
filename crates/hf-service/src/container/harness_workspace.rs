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
use super::workspace_file::replace_workspace_file;

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
    // A dictionary is optional; a failed confined write only disables its run flag.
    replace_workspace_file(
        workspace,
        Path::new(dict_name),
        std::io::Cursor::new(hf_engine::dict::render_dict(&tokens)),
        None,
    )
    .ok()
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
    replace_workspace_file(
        workspace,
        Path::new("harness.active"),
        std::io::Cursor::new(id.to_string()),
        None,
    )
    .map(|_| ())
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

/// Header suffixes accepted from the configured build directory. Generated
/// sources are staged only when the compile database references them (see
/// [`stage_generated_build_inputs`]).
const GENERATED_HEADER_EXTENSIONS: [&str; 6] = ["h", "hh", "hpp", "hxx", "inc", "inl"];

/// Stage the configured build's generated inputs into a harness workspace.
///
/// Out-of-tree build systems write generated headers (and sometimes generated
/// sources) into the build directory, which project staging skips by name; the
/// compile database's own `-I` flags already point there as staged `/work`
/// paths, so the flags resolve as soon as the files exist at the same
/// project-relative layout. Headers are staged by suffix from the database's
/// directory; sources are staged only when a database entry references them,
/// because a build directory also holds the build system's probe sources
/// (`CMake`'s `CompilerId`, each with its own `main`) that must never enter the
/// single-link harness compile. Returns the number of staged files.
///
/// # Errors
/// Returns `ClassifiedError` when the database lies outside the project, is
/// unreadable or malformed, or a referenced generated source is not a regular
/// file. Every failure fails closed rather than staging a partial tree.
pub fn stage_generated_build_inputs(
    project: &Path,
    database: &Path,
    workspace: &Path,
) -> Result<usize, ClassifiedError> {
    let build_dir = database.parent().ok_or_else(|| {
        ClassifiedError::Validation("compile database has no parent directory".to_owned())
    })?;
    let build_rel = build_dir.strip_prefix(project).map_err(|_| {
        ClassifiedError::Validation(
            "configured compile database lies outside the project".to_owned(),
        )
    })?;
    let json = super::build_context::read_compile_database_text(database)?;
    let entries = hf_discovery::build_context::parse_compile_database(&json)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;

    // Project staging skips the build directory by name, so its workspace
    // counterpart does not exist yet; the staged-file writer requires it.
    std::fs::create_dir_all(workspace.join(build_rel)).map_err(|error| {
        ClassifiedError::Internal(format!(
            "create staged build directory {}: {error}",
            workspace.join(build_rel).display()
        ))
    })?;
    let mut staged = 0_usize;
    stage_tree(
        build_dir,
        build_dir,
        &workspace.join(build_rel),
        &|path| {
            path.extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| GENERATED_HEADER_EXTENSIONS.contains(&extension))
        },
        &mut staged,
    );
    for entry in &entries {
        let Some(file) = database_file_in_project(&entry.file, project) else {
            continue;
        };
        if !file.starts_with(build_dir) {
            continue;
        }
        let Ok(relative) = file.strip_prefix(project) else {
            continue;
        };
        if relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            continue;
        }
        stage_one_generated_source(&file, &workspace.join(relative), &mut staged)?;
    }
    Ok(staged)
}

/// Resolve a database entry's translation unit onto the caller's project.
///
/// A database produced inside the sandbox records the container mount root
/// (`/work`); a normalized database records host paths. Both forms resolve
/// against the same project layout, so the entry is accepted when it already
/// lies under the project or maps from the container root onto it.
fn database_file_in_project(file: &Path, project: &Path) -> Option<PathBuf> {
    if let Ok(relative) = file.strip_prefix("/work") {
        return Some(project.join(relative));
    }
    file.starts_with(project).then(|| file.to_path_buf())
}

/// Copy one database-referenced generated source at its project-relative path.
fn stage_one_generated_source(
    source: &Path,
    destination: &Path,
    staged: &mut usize,
) -> Result<(), ClassifiedError> {
    let metadata = std::fs::symlink_metadata(source).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect generated source {}: {error}",
            source.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(format!(
            "generated source {} is not a regular file",
            source.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ClassifiedError::Internal(format!("mkdir generated source parent: {error}"))
        })?;
    }
    std::fs::copy(source, destination).map_err(|error| {
        ClassifiedError::Internal(format!(
            "stage generated source {}: {error}",
            source.display()
        ))
    })?;
    *staged += 1;
    Ok(())
}

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
    let source = match std::fs::File::open(path) {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!(
                "failed to open source {} for staging: {error}",
                path.display()
            );
            return;
        }
    };
    let permissions = match source.metadata() {
        Ok(metadata) => metadata.permissions(),
        Err(error) => {
            tracing::warn!(
                "failed to inspect source {} for staging: {error}",
                path.display()
            );
            return;
        }
    };
    if let Err(e) = replace_workspace_file(workspace, relative, source, Some(permissions)) {
        tracing::warn!(
            "failed to copy source {} into workspace: {e}",
            path.display()
        );
        return;
    }
    *staged += 1;
}

/// Stage Rust manifests and source files, including local workspace members,
/// so cargo-fuzz path dependencies resolve inside the sandbox. A no-op when
/// the project has no `Cargo.toml` (i.e. is not a Rust crate).
fn stage_rust_crate(project: &Path, workspace: &Path, staged: &mut usize) {
    if !project.join("Cargo.toml").is_file() {
        return;
    }
    stage_tree(
        project,
        project,
        workspace,
        &|path| {
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("Cargo.toml" | "Cargo.lock")
            ) || path.extension().and_then(|extension| extension.to_str()) == Some("rs")
        },
        staged,
    );
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
    fn stages_nested_local_workspace_member_without_build_output() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname = \"root\"\n[workspace]\nmembers = [\".\", \"crates/codec\"]\n[dependencies]\ncodec = { path = \"crates/codec\" }\n",
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/lib.rs"), "pub fn root() {}").unwrap();
        std::fs::create_dir_all(project.path().join("crates/codec/src")).unwrap();
        std::fs::write(
            project.path().join("crates/codec/Cargo.toml"),
            "[package]\nname = \"codec\"\n",
        )
        .unwrap();
        std::fs::write(
            project.path().join("crates/codec/src/lib.rs"),
            "pub fn codec() {}",
        )
        .unwrap();
        std::fs::create_dir_all(project.path().join("crates/codec/target")).unwrap();
        std::fs::write(project.path().join("crates/codec/target/stale.rs"), "stale").unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(workspace.path().join("Cargo.toml").is_file());
        assert!(workspace.path().join("src/lib.rs").is_file());
        assert!(workspace.path().join("crates/codec/Cargo.toml").is_file());
        assert!(workspace.path().join("crates/codec/src/lib.rs").is_file());
        assert!(!workspace.path().join("crates/codec/target").exists());
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

#[cfg(all(test, unix))]
mod sandbox_link_tests {
    use super::{
        build_workspace_dictionary, copy_project_sources, stage_generated_build_inputs,
        write_current_harness_id,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn active_marker_replaces_a_sandbox_link_without_writing_its_target() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "unchanged").unwrap();
        symlink(outside.path(), workspace.path().join("harness.active")).unwrap();

        let id = uuid::Uuid::new_v4();
        write_current_harness_id(workspace.path(), id).unwrap();

        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("harness.active")).unwrap(),
            id.to_string()
        );
    }

    #[test]
    fn restaging_replaces_a_sandbox_link_without_writing_its_target() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "unchanged").unwrap();
        std::fs::write(
            project.path().join("parse.c"),
            "int parse(void) { return 1; }",
        )
        .unwrap();
        symlink(outside.path(), workspace.path().join("parse.c")).unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("parse.c")).unwrap(),
            "int parse(void) { return 1; }"
        );
    }

    #[test]
    fn restaging_refuses_a_sandbox_link_in_a_parent_directory() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(
            project.path().join("src/parse.c"),
            "int parse(void) { return 1; }",
        )
        .unwrap();
        symlink(outside.path(), workspace.path().join("src")).unwrap();

        copy_project_sources(project.path(), workspace.path());

        assert!(!outside.path().join("parse.c").exists());
    }

    #[test]
    fn dictionary_replaces_a_sandbox_link_without_writing_its_target() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "unchanged").unwrap();
        std::fs::write(
            workspace.path().join("parse.c"),
            "int parse(void) { return strcmp(input, \"MAGIC\"); }",
        )
        .unwrap();
        symlink(outside.path(), workspace.path().join("fuzzer.dict")).unwrap();

        let dictionary = build_workspace_dictionary(workspace.path(), "fuzzer.dict").unwrap();

        assert_eq!(
            std::fs::read_to_string(outside.path()).unwrap(),
            "unchanged"
        );
        assert!(std::fs::read_to_string(dictionary)
            .unwrap()
            .contains("MAGIC"));
    }

    #[test]
    fn staged_inputs_remain_readable_by_the_sandbox_user() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let source = project.path().join("parse.c");
        std::fs::write(
            &source,
            "int parse(void) { return strcmp(input, \"MAGIC\"); }",
        )
        .unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        let private_source = project.path().join("private.c");
        std::fs::write(&private_source, "int private(void) { return 1; }").unwrap();
        std::fs::set_permissions(&private_source, std::fs::Permissions::from_mode(0o600)).unwrap();

        copy_project_sources(project.path(), workspace.path());
        let dictionary = build_workspace_dictionary(workspace.path(), "fuzzer.dict").unwrap();

        for path in [workspace.path().join("parse.c"), dictionary] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(mode & 0o444, 0o444);
        }
        let private_mode = std::fs::metadata(workspace.path().join("private.c"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(private_mode & 0o777, 0o600);
    }

    #[test]
    fn stages_generated_headers_and_referenced_sources_from_the_build_dir() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let build = project.path().join("build/parser");
        std::fs::create_dir_all(build.join("gen")).unwrap();
        std::fs::write(project.path().join("lib.c"), "int f(void);\n").unwrap();
        std::fs::write(build.join("gen/config.h"), "#define VERSION 1\n").unwrap();
        std::fs::write(build.join("gen/parser.c"), "int f(void) { return 0; }\n").unwrap();
        // Build-system probe sources have their own main() and are never
        // referenced by the project database; staging one would break the
        // single-link harness compile with a duplicate main.
        std::fs::write(build.join("probe.c"), "int main(void) { return 0; }\n").unwrap();
        std::fs::write(build.join("CMakeCache.txt"), "junk\n").unwrap();
        std::fs::write(build.join("libdemo.a"), "junk\n").unwrap();
        let database = build.join("compile_commands.json");
        std::fs::write(
            &database,
            serde_json::json!([
                {
                    "directory": build,
                    "file": project.path().join("lib.c"),
                    "arguments": ["cc", "-I", build, "-c", project.path().join("lib.c")]
                },
                {
                    "directory": build,
                    "file": build.join("gen/parser.c"),
                    "arguments": ["cc", "-I", build, "-c", build.join("gen/parser.c")]
                }
            ])
            .to_string(),
        )
        .unwrap();

        let staged = stage_generated_build_inputs(project.path(), &database, workspace.path())
            .expect("stage generated build inputs");

        // The header lands at its project-relative layout so the database's
        // own -I flags resolve without new plumbing.
        assert!(workspace.path().join("build/parser/gen/config.h").is_file());
        // The database-referenced generated source is staged; the unreferenced
        // probe source and artifacts are not.
        assert!(workspace.path().join("build/parser/gen/parser.c").is_file());
        assert!(!workspace.path().join("build/parser/probe.c").exists());
        assert!(!workspace
            .path()
            .join("build/parser/CMakeCache.txt")
            .exists());
        assert!(!workspace.path().join("build/parser/libdemo.a").exists());
        assert_eq!(staged, 2);
    }

    #[test]
    fn generated_input_staging_resolves_container_mount_paths() {
        // A database produced inside the sandbox records /work paths; its
        // generated-source entries must still stage against the project.
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let build = project.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::write(build.join("gen.c"), "int f(void) { return 0; }\n").unwrap();
        let database = build.join("compile_commands.json");
        std::fs::write(
            &database,
            serde_json::json!([
                {
                    "directory": "/work",
                    "file": "/work/build/gen.c",
                    "arguments": ["cc", "-I/work/build", "-c", "/work/build/gen.c"]
                }
            ])
            .to_string(),
        )
        .unwrap();

        let staged = stage_generated_build_inputs(project.path(), &database, workspace.path())
            .expect("stage generated build inputs");

        assert!(workspace.path().join("build/gen.c").is_file());
        assert_eq!(staged, 1);
    }

    #[test]
    fn generated_input_staging_rejects_databases_outside_the_project() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let foreign = tempfile::tempdir().unwrap();
        let database = foreign.path().join("compile_commands.json");
        std::fs::write(&database, "[]").unwrap();
        assert!(
            stage_generated_build_inputs(project.path(), &database, workspace.path()).is_err(),
            "a database outside the project must not drive staging"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_input_staging_refuses_symlinked_referenced_sources() {
        let project = tempfile::tempdir().unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let build = project.path().join("build");
        std::fs::create_dir_all(&build).unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("evil.c"),
            "int main(void) { return 0; }\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path().join("evil.c"), build.join("gen.c")).unwrap();
        let database = build.join("compile_commands.json");
        std::fs::write(
            &database,
            serde_json::json!([
                {
                    "directory": &build,
                    "file": build.join("gen.c"),
                    "arguments": ["cc", "-c", build.join("gen.c")]
                }
            ])
            .to_string(),
        )
        .unwrap();
        assert!(
            stage_generated_build_inputs(project.path(), &database, workspace.path()).is_err(),
            "a symlinked referenced source must fail closed"
        );
        assert!(!workspace.path().join("build/gen.c").exists());
    }
}
