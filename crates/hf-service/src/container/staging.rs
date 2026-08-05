//! Approval-to-execution integrity.
//!
//! A human approves a specific harness revision. This module stages that exact
//! source and binary into a run-owned input directory, records their digests,
//! and re-verifies them immediately before launch. If anything changed between
//! approval and execution, the run fails closed rather than fuzzing something
//! the operator never saw.

use std::path::{Component, Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::RuntimeAdapter;
use hf_runtime::SANDBOX_IMAGE;
use hf_storage::RunRecord;
use uuid::Uuid;

use super::workspace::{
    ensure_workspace_directory, resolve_workspace_directory, run_output_relative, workspace_root,
};
use super::{harness_binary_name, is_regular_file, EXACT_DOCKER_IMAGE_REV_PREFIX};

/// Immutable inputs and writable evidence location prepared for one run.
pub(super) struct RunArtifacts {
    pub(super) binary_host: PathBuf,
    pub(super) source_host: PathBuf,
    pub(super) corpus_host: PathBuf,
    pub(super) corpus_relative: PathBuf,
    pub(super) binary_container: String,
    pub(super) corpus_container: String,
    pub(super) output_host: PathBuf,
    pub(super) output_container: String,
    pub(super) output_relative: PathBuf,
    pub(super) source_sha256: String,
    pub(super) binary_sha256: String,
}

/// Provenance of a replayed run: the original run it re-executes and the exact
/// RNG seed that run recorded. Threaded from `replay_run` into the normal run
/// path so the replayed run's persisted config pins the same seed and links
/// back to the original run.
#[derive(Clone, Copy)]
pub(super) struct ReplayProvenance {
    pub(super) original_run_id: Uuid,
    pub(super) seed: u64,
}

/// Compute a full SHA-256 digest without loading a potentially large binary in
/// memory.
pub(super) fn sha256_file(path: &Path) -> Result<String, ClassifiedError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).map_err(|e| {
        ClassifiedError::Validation(format!("read run artifact {}: {e}", path.display()))
    })?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).map_err(|e| {
            ClassifiedError::Validation(format!("hash run artifact {}: {e}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&chunk[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Move a persisted live-corpus file out of view before its database row is
/// deleted. The caller can atomically restore the returned path if the database
/// mutation fails.
pub(super) fn quarantine_corpus_entry(
    path: &Path,
    expected_sha256: &str,
) -> Result<Option<PathBuf>, ClassifiedError> {
    let root = workspace_root();
    let relative = path.strip_prefix(&root).map_err(|_| {
        ClassifiedError::Validation(format!(
            "persisted corpus path is outside the managed workspace: {}",
            path.display()
        ))
    })?;
    if relative.is_absolute()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "persisted corpus path is unsafe: {}",
            path.display()
        )));
    }
    let parent_relative = relative.parent().ok_or_else(|| {
        ClassifiedError::Validation(format!(
            "persisted corpus path has no parent: {}",
            path.display()
        ))
    })?;
    let parent = resolve_workspace_directory(&root, parent_relative)?;
    if parent.file_name().and_then(|name| name.to_str()) != Some("corpus") {
        return Err(ClassifiedError::Validation(format!(
            "persisted corpus path is not in a retained corpus directory: {}",
            path.display()
        )));
    }

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect persisted corpus entry {}: {error}",
                path.display()
            )));
        }
    };
    if !metadata.file_type().is_file()
        || metadata.len() > hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes
    {
        return Err(ClassifiedError::Validation(format!(
            "persisted corpus entry is not a bounded regular file: {}",
            path.display()
        )));
    }

    let quarantined = parent.join(format!(".oxfuzz-delete-{}", Uuid::new_v4()));
    std::fs::rename(path, &quarantined).map_err(|error| {
        ClassifiedError::Internal(format!(
            "quarantine corpus entry {}: {error}",
            path.display()
        ))
    })?;
    let quarantined_metadata = std::fs::symlink_metadata(&quarantined);
    let actual_sha256 = match quarantined_metadata {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() <= hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes =>
        {
            sha256_file(&quarantined)
        }
        Ok(_) => Err(ClassifiedError::Validation(
            "quarantined corpus entry is not a bounded regular file".to_owned(),
        )),
        Err(error) => Err(ClassifiedError::Validation(format!(
            "inspect quarantined corpus entry: {error}"
        ))),
    };
    let actual_sha256 = match actual_sha256 {
        Ok(actual_sha256) => actual_sha256,
        Err(error) => {
            let restore = std::fs::rename(&quarantined, path);
            let suffix = restore.err().map_or_else(String::new, |restore_error| {
                format!("; restore failed: {restore_error}")
            });
            return Err(ClassifiedError::Validation(format!("{error}{suffix}")));
        }
    };
    if actual_sha256 != expected_sha256 {
        let restore = std::fs::rename(&quarantined, path);
        let suffix = restore
            .err()
            .map_or_else(String::new, |error| format!("; restore failed: {error}"));
        return Err(ClassifiedError::Validation(format!(
            "persisted corpus content no longer matches {expected_sha256}{suffix}"
        )));
    }
    Ok(Some(quarantined))
}

/// Independently verifiable components of one immutable run context.
#[derive(Debug)]
pub(super) struct RunContextDigests {
    combined: String,
    source: String,
    corpus: String,
    sandbox: String,
}

pub(super) fn retain_run_context(run: &mut RunRecord, context: RunContextDigests) {
    run.context_rev = Some(context.combined);
    run.source_rev = Some(context.source);
    run.corpus_rev = Some(context.corpus);
    run.sandbox_rev = Some(format!(
        "{EXACT_DOCKER_IMAGE_REV_PREFIX}{}",
        context.sandbox
    ));
}

/// Digest the immutable comparison context for a coverage run: staged target
/// sources, the starting corpus, and the exact sandbox image identifier.
///
/// The walk is deliberately limited to build inputs staged by
/// `copy_project_sources` plus the corpus. Symlinks and unexpectedly large
/// trees fail closed so an untrusted workspace cannot turn regression
/// bookkeeping into an unbounded host traversal.
pub(super) fn run_context_digests(
    workspace: &Path,
    sandbox_image_sha256: &str,
) -> Result<RunContextDigests, ClassifiedError> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;

    const MAX_FILES: usize = 100_000;
    const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

    fn collect(
        root: &Path,
        directory: &Path,
        recursive: bool,
        paths: &mut Vec<PathBuf>,
    ) -> Result<(), ClassifiedError> {
        if !directory.exists() {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(directory).map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect comparison context {}: {error}",
                directory.display()
            ))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(ClassifiedError::Validation(format!(
                "comparison context contains a non-directory component: {}",
                directory.display()
            )));
        }
        let mut entries = std::fs::read_dir(directory)
            .map_err(|error| {
                ClassifiedError::Validation(format!(
                    "read comparison context {}: {error}",
                    directory.display()
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ClassifiedError::Validation(format!("read comparison context entry: {error}"))
            })?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| {
                ClassifiedError::Validation(format!(
                    "inspect comparison context {}: {error}",
                    path.display()
                ))
            })?;
            if kind.is_symlink() {
                return Err(ClassifiedError::Validation(format!(
                    "comparison context contains a symlink: {}",
                    path.display()
                )));
            }
            if kind.is_dir() {
                if recursive {
                    collect(root, &path, true, paths)?;
                }
            } else if kind.is_file() {
                paths.push(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            }
        }
        Ok(())
    }

    if sandbox_image_sha256.len() != 64
        || !sandbox_image_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ClassifiedError::Validation(
            "sandbox image digest must be 64 lowercase hexadecimal characters".to_owned(),
        ));
    }

    let mut relative_paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let extension = path.extension().and_then(|value| value.to_str());
            let is_source = matches!(extension, Some("c" | "h" | "cc" | "cpp" | "cxx" | "hpp"))
                && !name.starts_with("harness.");
            if is_source || matches!(name.as_ref(), "Cargo.toml" | "Cargo.lock") {
                relative_paths.push(PathBuf::from(name.as_ref()));
            }
        }
    }
    collect(workspace, &workspace.join("src"), true, &mut relative_paths)?;
    collect(
        workspace,
        &workspace.join("corpus"),
        false,
        &mut relative_paths,
    )?;
    relative_paths.sort();
    relative_paths.dedup();
    if relative_paths.len() > MAX_FILES {
        return Err(ClassifiedError::Validation(format!(
            "comparison context exceeds {MAX_FILES} files"
        )));
    }

    let mut combined_digest = Sha256::new();
    combined_digest.update(b"oxfuzz-run-context-v1\0");
    combined_digest.update(sandbox_image_sha256.as_bytes());
    combined_digest.update(b"\0");
    let mut source_digest = Sha256::new();
    source_digest.update(b"oxfuzz-run-source-v1\0");
    let mut corpus_digest = Sha256::new();
    corpus_digest.update(b"oxfuzz-run-corpus-v1\0");
    let mut total_bytes = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    for relative in relative_paths {
        let path = workspace.join(&relative);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect comparison input {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(ClassifiedError::Validation(format!(
                "comparison input is not a regular file: {}",
                path.display()
            )));
        }
        total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
            ClassifiedError::Validation("comparison context size overflow".to_owned())
        })?;
        if total_bytes > MAX_BYTES {
            return Err(ClassifiedError::Validation(format!(
                "comparison context exceeds {MAX_BYTES} bytes"
            )));
        }
        let component_digest = if relative.starts_with("corpus") {
            &mut corpus_digest
        } else {
            &mut source_digest
        };
        combined_digest.update(relative.to_string_lossy().as_bytes());
        combined_digest.update(b"\0");
        component_digest.update(relative.to_string_lossy().as_bytes());
        component_digest.update(b"\0");
        let mut file = std::fs::File::open(&path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "read comparison input {}: {error}",
                path.display()
            ))
        })?;
        loop {
            let read = file.read(&mut chunk).map_err(|error| {
                ClassifiedError::Validation(format!(
                    "hash comparison input {}: {error}",
                    path.display()
                ))
            })?;
            if read == 0 {
                break;
            }
            combined_digest.update(&chunk[..read]);
            component_digest.update(&chunk[..read]);
        }
        combined_digest.update(b"\0");
        component_digest.update(b"\0");
    }
    Ok(RunContextDigests {
        combined: format!("{:x}", combined_digest.finalize()),
        source: format!("{:x}", source_digest.finalize()),
        corpus: format!("{:x}", corpus_digest.finalize()),
        sandbox: sandbox_image_sha256.to_owned(),
    })
}

/// Resolve one runtime image reference before persisting or executing a run.
/// Docker returns a content-addressed `sha256:` ID. Proof-carrying runs reject
/// adapters without an immutable image identity.
pub(super) async fn resolve_run_sandbox_image(
    runtime: &dyn RuntimeAdapter,
) -> Result<hf_core::runtime::ImmutableImageReference, ClassifiedError> {
    runtime
        .resolve_image_reference(SANDBOX_IMAGE)
        .await?
        .ok_or_else(|| {
            ClassifiedError::Sandbox(
                "proof-carrying fuzz runs require an immutable sandbox image identity".to_owned(),
            )
        })
}

/// Copy the exact approved source/binary into a run-owned input directory and
/// create its isolated output directory. The primary workspace is mounted
/// read-only during execution, so these staged inputs cannot be rewritten by
/// the engine.
pub(super) fn stage_run_artifacts(
    workspace: &Path,
    run_id: Uuid,
    source: &str,
    binary: &Path,
) -> Result<RunArtifacts, ClassifiedError> {
    if !is_regular_file(binary) {
        return Err(ClassifiedError::Validation(format!(
            "approved harness binary is not a regular workspace file: {}",
            binary.display()
        )));
    }
    let workspace_root = std::fs::canonicalize(workspace).map_err(|e| {
        ClassifiedError::Validation(format!("resolve workspace {}: {e}", workspace.display()))
    })?;
    let approved_binary = std::fs::canonicalize(binary).map_err(|e| {
        ClassifiedError::Validation(format!(
            "resolve approved harness binary {}: {e}",
            binary.display()
        ))
    })?;
    if !approved_binary.starts_with(&workspace_root) {
        return Err(ClassifiedError::Validation(format!(
            "approved harness binary resolves outside workspace: {}",
            binary.display()
        )));
    }
    let runs_dir = ensure_workspace_directory(workspace, Path::new("runs"))?;
    let run_root = runs_dir.join(run_id.to_string());
    std::fs::create_dir(&run_root).map_err(|e| {
        ClassifiedError::Internal(format!(
            "create unique run directory {}: {e}",
            run_root.display()
        ))
    })?;
    let input_dir = run_root.join("input");
    let corpus_relative = PathBuf::from("runs")
        .join(run_id.to_string())
        .join("corpus");
    let corpus_host = workspace.join(&corpus_relative);
    let output_relative = run_output_relative(run_id);
    let output_host = workspace.join(&output_relative);
    std::fs::create_dir(&input_dir)
        .map_err(|e| ClassifiedError::Internal(format!("create run input directory: {e}")))?;
    std::fs::create_dir(&corpus_host)
        .map_err(|e| ClassifiedError::Internal(format!("create run corpus directory: {e}")))?;
    std::fs::create_dir(&output_host)
        .map_err(|e| ClassifiedError::Internal(format!("create run output directory: {e}")))?;

    let binary_host = input_dir.join("harness");
    std::fs::copy(&approved_binary, &binary_host).map_err(|e| {
        ClassifiedError::Validation(format!(
            "stage approved harness binary {}: {e}",
            binary.display()
        ))
    })?;
    let source_host = input_dir.join("harness.source");
    std::fs::write(&source_host, source)
        .map_err(|e| ClassifiedError::Internal(format!("stage approved harness source: {e}")))?;

    let live_corpus = ensure_workspace_directory(workspace, Path::new("corpus"))?;
    hf_corpus::snapshot(&live_corpus, &corpus_host)?;

    let source_sha256 = sha256_file(&source_host)?;
    let binary_sha256 = sha256_file(&binary_host)?;
    let run_container_root = format!("/work/runs/{run_id}");
    Ok(RunArtifacts {
        binary_host,
        source_host,
        corpus_host,
        corpus_relative,
        binary_container: format!("{run_container_root}/input/harness"),
        corpus_container: format!("{run_container_root}/corpus"),
        output_host,
        output_container: format!("{run_container_root}/out"),
        output_relative,
        source_sha256,
        binary_sha256,
    })
}

/// Fail closed if a staged source/binary changed between approval and launch.
pub(super) fn verify_run_artifacts(artifacts: &RunArtifacts) -> Result<(), ClassifiedError> {
    let source = sha256_file(&artifacts.source_host)?;
    if source != artifacts.source_sha256 {
        return Err(ClassifiedError::Validation(
            "approved harness source digest changed before launch".to_owned(),
        ));
    }
    let binary = sha256_file(&artifacts.binary_host)?;
    if binary != artifacts.binary_sha256 {
        return Err(ClassifiedError::Validation(
            "approved harness binary digest changed before launch".to_owned(),
        ));
    }
    Ok(())
}

/// Resolve the immutable source/binary pair proven by a persisted smoke run.
pub(super) fn qualification_evidence(
    harness: &Harness,
) -> Result<(Uuid, &str, &str), ClassifiedError> {
    let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
        ClassifiedError::Validation("harness has no persisted smoke qualification".to_owned())
    })?;
    let run_id = smoke.run_id.ok_or_else(|| {
        ClassifiedError::Validation(
            "harness qualification predates digest evidence; run smoke qualification again"
                .to_owned(),
        )
    })?;
    let source_sha256 = smoke.source_sha256.as_deref().ok_or_else(|| {
        ClassifiedError::Validation(
            "harness qualification has no source digest; run smoke qualification again".to_owned(),
        )
    })?;
    let binary_sha256 = smoke.binary_sha256.as_deref().ok_or_else(|| {
        ClassifiedError::Validation(
            "harness qualification has no binary digest; run smoke qualification again".to_owned(),
        )
    })?;
    Ok((run_id, source_sha256, binary_sha256))
}

/// Ensure the copy prepared for a run is the exact smoke-qualified pair.
pub(super) fn verify_staged_qualification(
    harness: &Harness,
    artifacts: &RunArtifacts,
) -> Result<(), ClassifiedError> {
    let (_, expected_source, expected_binary) = qualification_evidence(harness)?;
    if artifacts.source_sha256 != expected_source {
        return Err(ClassifiedError::Validation(
            "active harness source digest does not match smoke qualification".to_owned(),
        ));
    }
    if artifacts.binary_sha256 != expected_binary {
        return Err(ClassifiedError::Validation(
            "active harness binary digest does not match smoke qualification".to_owned(),
        ));
    }
    Ok(())
}

/// Hardened fuzzer profile: immutable primary workspace with only this run's
/// disposable corpus snapshot and output directory overlaid writable.
pub(super) fn run_sandbox_options(
    artifacts: &RunArtifacts,
    sandbox_image: Option<String>,
) -> hf_core::runtime::SandboxOptions {
    hf_core::runtime::SandboxOptions {
        extra_mounts: vec![
            hf_core::runtime::SandboxMount::writable(
                artifacts.corpus_host.clone(),
                artifacts.corpus_container.clone(),
            ),
            hf_core::runtime::SandboxMount::writable(
                artifacts.output_host.clone(),
                artifacts.output_container.clone(),
            ),
        ],
        workspace_read_only: true,
        max_file_size_bytes: Some(64 * 1024 * 1024),
        image: sandbox_image,
        ..hf_core::runtime::SandboxOptions::default()
    }
}

/// Hardened libFuzzer merge profile: the starting snapshot remains immutable
/// and only the bounded, disposable merge result can be written.
pub(super) fn minimization_sandbox_options(
    artifacts: &RunArtifacts,
) -> hf_core::runtime::SandboxOptions {
    hf_core::runtime::SandboxOptions {
        extra_mounts: vec![
            hf_core::runtime::SandboxMount::read_only(
                artifacts.corpus_host.clone(),
                artifacts.corpus_container.clone(),
            ),
            hf_core::runtime::SandboxMount::writable(
                artifacts.output_host.clone(),
                artifacts.output_container.clone(),
            ),
        ],
        workspace_read_only: true,
        max_file_size_bytes: Some(hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes),
        ..hf_core::runtime::SandboxOptions::default()
    }
}

pub(super) fn minimization_failure_with_rollback(
    corpus_dir: &Path,
    snapshot_dir: &Path,
    error: ClassifiedError,
) -> ClassifiedError {
    match hf_corpus::minimize(corpus_dir, snapshot_dir) {
        Ok(_) => error,
        Err(rollback_error) => ClassifiedError::Internal(format!(
            "{error}; restoring the retained corpus snapshot also failed: {rollback_error}"
        )),
    }
}

/// Resolve a persisted run's output directory, retaining the legacy flat path
/// as a read-only fallback for records created before run-scoped evidence.
pub(super) fn run_output_dir(
    workspace: &Path,
    run: &RunRecord,
) -> Result<PathBuf, ClassifiedError> {
    let Some(recorded) = run.evidence_dir.as_deref() else {
        return Ok(workspace.join("out"));
    };
    let expected = run_output_relative(run.id);
    if Path::new(recorded) != expected {
        return Err(ClassifiedError::Validation(format!(
            "run {} has invalid evidence directory '{}' (expected '{}')",
            run.id,
            recorded,
            expected.display()
        )));
    }
    resolve_workspace_directory(workspace, &expected)
}

/// Resolve the exact staged executable for a run, with the active binary only
/// as a compatibility fallback for legacy records.
pub(super) fn run_binary_path(
    workspace: &Path,
    run: &RunRecord,
    target: &str,
) -> Result<PathBuf, ClassifiedError> {
    let (relative, expected_digest) = run.binary_rev.as_deref().map_or_else(
        || (PathBuf::from(harness_binary_name(target)), None),
        |digest| {
            (
                PathBuf::from("runs")
                    .join(run.id.to_string())
                    .join("input")
                    .join("harness"),
                Some(digest),
            )
        },
    );
    if relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "run {} binary path is unsafe",
            run.id
        )));
    }
    let root = std::fs::canonicalize(workspace).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace {}: {error}",
            workspace.display()
        ))
    })?;
    let candidate = root.join(&relative);
    if !is_regular_file(&candidate) {
        return Err(ClassifiedError::Validation(format!(
            "run {} binary is missing or not a regular file: {}",
            run.id,
            candidate.display()
        )));
    }
    let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve run binary {}: {error}",
            candidate.display()
        ))
    })?;
    if !resolved.starts_with(&root) {
        return Err(ClassifiedError::Validation(format!(
            "run {} binary resolves outside its workspace",
            run.id
        )));
    }
    if let Some(expected) = expected_digest {
        let actual = sha256_file(&resolved)?;
        if actual != expected {
            return Err(ClassifiedError::Validation(format!(
                "run {} binary digest does not match persisted evidence",
                run.id
            )));
        }
    }
    Ok(resolved)
}

/// Resolve and verify the immutable harness source staged for a modern run.
pub(super) fn run_source_path(
    workspace: &Path,
    run: &RunRecord,
) -> Result<PathBuf, ClassifiedError> {
    let expected_digest = run.harness_rev.as_deref().ok_or_else(|| {
        ClassifiedError::Validation(format!("run {} predates immutable source evidence", run.id))
    })?;
    let root = std::fs::canonicalize(workspace).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace {}: {error}",
            workspace.display()
        ))
    })?;
    let source = root
        .join("runs")
        .join(run.id.to_string())
        .join("input")
        .join("harness.source");
    if !is_regular_file(&source) {
        return Err(ClassifiedError::Validation(format!(
            "run {} source is missing or not a regular file: {}",
            run.id,
            source.display()
        )));
    }
    let resolved = std::fs::canonicalize(&source).map_err(|error| {
        ClassifiedError::Validation(format!("resolve run source {}: {error}", source.display()))
    })?;
    if !resolved.starts_with(&root) || sha256_file(&resolved)? != expected_digest {
        return Err(ClassifiedError::Validation(format!(
            "run {} source digest does not match persisted evidence",
            run.id
        )));
    }
    Ok(resolved)
}

#[cfg(test)]
mod staging_tests {
    use super::{
        resolve_run_sandbox_image, run_binary_path, run_context_digests, run_output_dir,
        stage_run_artifacts, verify_run_artifacts,
    };
    use crate::container::workspace::workspace_relative_record;

    #[test]
    fn comparison_context_tracks_target_and_corpus_bytes() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("src")).unwrap();
        std::fs::create_dir(workspace.path().join("corpus")).unwrap();
        std::fs::write(workspace.path().join("src/lib.rs"), "pub fn parse() {}").unwrap();
        std::fs::write(workspace.path().join("corpus/seed"), b"one").unwrap();

        let first = run_context_digests(workspace.path(), &"a".repeat(64))
            .unwrap()
            .combined;
        assert_eq!(
            first,
            run_context_digests(workspace.path(), &"a".repeat(64))
                .unwrap()
                .combined
        );
        std::fs::write(workspace.path().join("corpus/seed"), b"two").unwrap();
        assert_ne!(
            first,
            run_context_digests(workspace.path(), &"a".repeat(64))
                .unwrap()
                .combined
        );
    }

    #[test]
    fn comparison_context_retains_independent_provenance_components() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("src")).unwrap();
        std::fs::create_dir(workspace.path().join("corpus")).unwrap();
        std::fs::write(workspace.path().join("src/lib.rs"), "pub fn parse() {}").unwrap();
        std::fs::write(workspace.path().join("corpus/seed"), b"one").unwrap();

        let first = run_context_digests(workspace.path(), &"a".repeat(64)).unwrap();
        std::fs::write(workspace.path().join("corpus/seed"), b"two").unwrap();
        let second = run_context_digests(workspace.path(), &"a".repeat(64)).unwrap();

        assert_eq!(first.source, second.source);
        assert_ne!(first.corpus, second.corpus);
        assert_ne!(first.combined, second.combined);
        assert_eq!(first.sandbox, second.sandbox);
        assert_eq!(first.sandbox.len(), 64);
        assert_eq!(first.sandbox, "a".repeat(64));

        let rebuilt_image = run_context_digests(workspace.path(), &"b".repeat(64)).unwrap();
        assert_ne!(second.combined, rebuilt_image.combined);
        assert_eq!(rebuilt_image.sandbox, "b".repeat(64));
    }

    #[cfg(unix)]
    #[test]
    fn comparison_context_rejects_symlinked_inputs() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), b"secret").unwrap();
        std::fs::create_dir(workspace.path().join("corpus")).unwrap();
        symlink(
            outside.path().join("secret"),
            workspace.path().join("corpus/seed"),
        )
        .unwrap();

        let error = run_context_digests(workspace.path(), &"a".repeat(64)).unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }

    #[test]
    fn comparison_context_rejects_non_digest_sandbox_identity() {
        let workspace = tempfile::tempdir().unwrap();

        let error = run_context_digests(workspace.path(), "oxfuzz/fuzz-sandbox:0.1.0").unwrap_err();

        assert!(error.to_string().contains("sandbox image digest"));
    }

    #[tokio::test]
    async fn proof_carrying_runs_reject_runtimes_without_immutable_image_identity() {
        let error = resolve_run_sandbox_image(&hf_runtime::StubRuntime)
            .await
            .unwrap_err();

        assert!(error
            .to_string()
            .contains("immutable sandbox image identity"));
    }

    #[test]
    fn staged_run_artifacts_are_digest_verified_before_launch() {
        let workspace = tempfile::tempdir().unwrap();
        let binary = workspace.path().join("fuzz_parse");
        std::fs::write(&binary, b"approved binary").unwrap();
        std::fs::create_dir(workspace.path().join("corpus")).unwrap();
        std::fs::write(workspace.path().join("corpus/seed"), b"retained").unwrap();
        let run_id = uuid::Uuid::new_v4();

        let artifacts =
            stage_run_artifacts(workspace.path(), run_id, "approved source", &binary).unwrap();
        assert_eq!(artifacts.source_sha256.len(), 64);
        assert_eq!(artifacts.binary_sha256.len(), 64);
        assert!(artifacts.output_host.is_dir());
        assert_eq!(
            std::fs::read(artifacts.corpus_host.join("seed")).unwrap(),
            b"retained"
        );
        std::fs::write(artifacts.corpus_host.join("seed"), b"run-local").unwrap();
        assert_eq!(
            std::fs::read(workspace.path().join("corpus/seed")).unwrap(),
            b"retained"
        );
        verify_run_artifacts(&artifacts).unwrap();

        std::fs::write(&artifacts.binary_host, b"tampered binary").unwrap();
        let error = verify_run_artifacts(&artifacts).unwrap_err();
        assert!(error.to_string().contains("binary digest changed"));
    }

    #[test]
    fn persisted_run_evidence_never_falls_back_after_tampering() {
        let workspace = tempfile::tempdir().unwrap();
        let active = workspace.path().join("fuzz_parse");
        std::fs::write(&active, b"mutable active binary").unwrap();
        let run_id = uuid::Uuid::new_v4();
        let artifacts = stage_run_artifacts(workspace.path(), run_id, "source", &active).unwrap();
        let mut run = hf_storage::RunRecord::new(
            "/project",
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            chrono::Utc::now(),
        );
        run.id = run_id;
        run.binary_rev = Some(artifacts.binary_sha256.clone());
        run.evidence_dir = Some(workspace_relative_record(&artifacts.output_relative));

        assert_eq!(
            run_output_dir(workspace.path(), &run).unwrap(),
            std::fs::canonicalize(&artifacts.output_host).unwrap()
        );
        assert_eq!(
            run_binary_path(workspace.path(), &run, "parse").unwrap(),
            std::fs::canonicalize(&artifacts.binary_host).unwrap()
        );

        std::fs::write(&artifacts.binary_host, b"tampered").unwrap();
        let error = run_binary_path(workspace.path(), &run, "parse").unwrap_err();
        assert!(error.to_string().contains("digest"));
        std::fs::remove_file(&artifacts.binary_host).unwrap();
        let error = run_binary_path(workspace.path(), &run, "parse").unwrap_err();
        assert!(error.to_string().contains("missing"));
    }

    #[test]
    fn persisted_run_rejects_mismatched_evidence_directory() {
        let workspace = tempfile::tempdir().unwrap();
        let mut run = hf_storage::RunRecord::new(
            "/project",
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            chrono::Utc::now(),
        );
        std::fs::create_dir_all(
            workspace
                .path()
                .join("runs")
                .join(run.id.to_string())
                .join("out"),
        )
        .unwrap();
        run.evidence_dir = Some("out".to_owned());

        let error = run_output_dir(workspace.path(), &run).unwrap_err();
        assert!(error.to_string().contains("invalid evidence directory"));
    }

    #[test]
    fn staged_run_artifacts_reject_a_lexical_parent_escape() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let outside = root.path().join("outside-binary");
        std::fs::write(&outside, b"outside").unwrap();
        let escaped = workspace.join("..").join("outside-binary");

        let result = stage_run_artifacts(
            &workspace,
            uuid::Uuid::new_v4(),
            "approved source",
            &escaped,
        );
        assert!(result.is_err(), "parent traversal staged an outside binary");
    }

    #[cfg(unix)]
    #[test]
    fn staged_run_artifacts_reject_a_symlinked_runs_directory() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let binary = workspace.path().join("fuzz_parse");
        std::fs::write(&binary, b"approved binary").unwrap();
        symlink(outside.path(), workspace.path().join("runs")).unwrap();

        let result = stage_run_artifacts(
            workspace.path(),
            uuid::Uuid::new_v4(),
            "approved source",
            &binary,
        );
        let Err(error) = result else {
            panic!("a build-created symlink redirected run evidence");
        };

        assert!(error.to_string().contains("runs"));
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }
}
