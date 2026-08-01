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

/// Reduce an untrusted `target` to a path that cannot escape its parent
/// directory. Keeps only `Normal` components (so `..`, absolute roots, and
/// Windows prefixes are discarded) and falls back to `default` when nothing
/// safe remains.
pub(super) fn sanitize_target(target: &str) -> PathBuf {
    use std::path::Component;
    let safe: PathBuf = Path::new(target)
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect();
    if safe.as_os_str().is_empty() {
        PathBuf::from("default")
    } else {
        safe
    }
}

/// Stable single-component stem for target-derived artifact filenames.
fn target_artifact_stem(target: &str) -> String {
    use sha2::{Digest, Sha256};

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
    let changed = safe != target || safe.is_empty() || safe.len() > 80;
    if safe.is_empty() {
        safe.push_str("default");
    }
    safe.truncate(64);
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
pub(super) fn container_input_path(workspace: &Path, host_path: &Path) -> String {
    host_path.strip_prefix(workspace).map_or_else(
        |_| {
            format!(
                "/work/out/{}",
                host_path.file_name().unwrap_or_default().to_string_lossy()
            )
        },
        |rel| format!("/work/{}", rel.display()),
    )
}

/// Copy C/C++ source and header files from a project into the workspace
/// so the sandbox can compile the harness + target together.
///
/// For Rust projects it also stages the crate under test -- `Cargo.toml`,
/// `Cargo.lock`, and the `src/` tree -- so the cargo-fuzz project's path
/// dependency on the crate resolves inside the sandbox.
pub fn copy_project_sources(project: &Path, workspace: &Path) {
    let exts = ["c", "h", "cc", "cpp", "cxx", "hpp"];
    if let Ok(entries) = std::fs::read_dir(project) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if exts.contains(&ext) {
                    let dest = workspace.join(entry.file_name());
                    if let Err(e) = std::fs::copy(&path, &dest) {
                        // Not fatal on its own, but a missing source surfaces
                        // later as a confusing compile error -- surface it here.
                        tracing::warn!(
                            "failed to copy source {} into workspace: {e}",
                            path.display()
                        );
                    }
                }
            }
        }
    }
    stage_rust_crate(project, workspace);
}

/// Stage a Rust crate (its manifest + `src/` tree) from `project` into
/// `workspace` so a cargo-fuzz project can depend on it by path. A no-op when the
/// project has no `Cargo.toml` (i.e. is not a Rust crate).
fn stage_rust_crate(project: &Path, workspace: &Path) {
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
        if let Err(e) = copy_dir_recursive(&src_dir, &workspace.join("src")) {
            tracing::warn!("failed to stage crate src/ into workspace: {e}");
        }
    }
}

/// Recursively copy a directory tree, creating destination directories as needed.
fn copy_dir_recursive(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)?.flatten() {
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &dest)?;
        } else if path.is_file() {
            std::fs::copy(&path, &dest)?;
        }
    }
    Ok(())
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
