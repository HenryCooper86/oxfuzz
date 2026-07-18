//! Central dependency container -- shared by all presentation layers.
//!
//! Mirrors the `y-service::ServiceContainer` pattern: the GUI, CLI, and
//! web API all construct one container and call service methods through it.
//! This keeps business logic out of presentation crates (AGENTS.md 2.9) and
//! ensures every build / fuzz run goes through `hf-runtime` sandboxing
//! (AGENTS.md 2.12).

use std::fmt::Write;
use std::fs::{File, TryLockError};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus, SmokeRunSummary};
use hf_core::provider::ProviderPool;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetCandidate, TargetInventory, TargetLanguage};
use hf_guardrails::{Action, Decision, Guardrails};
use hf_runtime::{RuntimeConfig, SANDBOX_IMAGE};
use hf_storage::{
    AutoRevertEvent, GuardrailDecisionRecord, ProjectAutoRevert, RunKind, RunRecord, RunStatus,
    Store,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_RUN_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RUN_OUTPUT_ENTRIES: usize = 100_000;
const SMOKE_FUZZ_SECS: u64 = 60;
const COVERAGE_PRUNE_OPERATION_SECS: u64 = 600;
const COVERAGE_PRUNE_COMMAND_SECS: u64 = 10;
const CORPUS_MINIMIZE_SECS: u64 = 300;
/// Bound on the stored policy reason; denial reasons embed action labels that
/// can carry long parameters (e.g. a shell command).
const MAX_GUARDAIL_DETAIL_CHARS: usize = 256;
/// Newest decisions retained in the audit trail; recording prunes beyond this
/// window on write (mirrors schedule-execution history retention).
const GUARDRAIL_DECISION_RETENTION: usize = 1000;
const WORKSPACE_MANIFEST_FILE: &str = ".hobot-fuzz-workspace.json";
const WORKSPACE_MANIFEST_VERSION: u32 = 1;

type WorkspaceOperationGate = tokio::sync::RwLock<()>;

/// Workspace gates are keyed by resolved root rather than container instance:
/// independent service containers in one process can target the same root.
/// A weak registry avoids retaining a gate after its last lease is released.
static WORKSPACE_OPERATION_GATES: OnceLock<
    Mutex<std::collections::HashMap<PathBuf, Weak<WorkspaceOperationGate>>>,
> = OnceLock::new();

pub(crate) struct WorkspaceOperationLease {
    _process_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _system_guard: File,
}

struct WorkspaceCleanupLease {
    _process_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
    _system_guard: File,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct WorkspaceOwnershipManifest {
    application: String,
    version: u32,
    canonical_root: PathBuf,
}

fn fuzzing_policy_error(error: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("invalid fuzzing settings: {error}"))
}

fn require_fuzzing_harness_engine(
    engine: EngineKind,
    language: TargetLanguage,
) -> Result<(), ClassifiedError> {
    crate::config::resolve_harness_engine(Some(engine), language)
        .map(|_| ())
        .map_err(|error| fuzzing_policy_error(&error))
}

fn resolve_fuzzing_run(
    engine: EngineKind,
    duration_secs: u64,
) -> Result<crate::config::ResolvedFuzzingRun, ClassifiedError> {
    crate::config::resolve_fuzzing_run(Some(engine), Some(duration_secs))
        .map_err(|error| fuzzing_policy_error(&error))
}

/// Internal pipeline steps (smoke qualification, coverage pruning, corpus
/// minimization) run fixed implementation budgets, not operator-requested
/// campaigns, so they clamp to the configured ceiling instead of failing.
fn resolve_internal_run(
    engine: EngineKind,
    internal_budget_secs: u64,
) -> Result<crate::config::ResolvedFuzzingRun, ClassifiedError> {
    crate::config::resolve_internal_fuzzing_run(engine, internal_budget_secs)
        .map_err(|error| fuzzing_policy_error(&error))
}

/// Runs that reached a terminal state may own crash artifacts. Failed and
/// cancelled campaigns can produce valid partial evidence before stopping.
fn run_has_crash_evidence(status: RunStatus) -> bool {
    matches!(
        status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
    )
}

// ---------------------------------------------------------------------------
// Workspace resolution
// ---------------------------------------------------------------------------

/// The base directory that holds every per-project fuzz workspace.
///
/// Persistent by default so compiled harnesses, corpora, and crash reproducers
/// survive across sessions. It previously lived under `std::env::temp_dir()`,
/// which macOS (`/var/folders/.../T`) and Linux (`/tmp`) purge after a few days
/// -- silently deleting a campaign's artifacts and producing the confusing
/// "compiled harness not found" state after a successful compile. It now lives
/// under the same stable per-user directory as the database and run journal
/// ([`crate::init::user_app_dir`]).
///
/// Override with the `HF_WORKSPACE_DIR` environment variable to place
/// workspaces on a specific volume (e.g. a large scratch disk).
#[must_use]
pub fn workspace_root() -> PathBuf {
    configured_workspace_root().0
}

/// Create or validate the configured managed workspace root and its ownership
/// manifest before callers stage artifacts directly beneath it.
///
/// Normal service operations call this internally. It is also the canonical
/// setup boundary for integrations that must seed fixture artifacts before
/// invoking a workspace-backed operation.
///
/// # Errors
/// Returns `ClassifiedError` when the configured root is unsafe, unmanaged, or
/// cannot be initialized.
pub fn initialize_workspace_root() -> Result<PathBuf, ClassifiedError> {
    prepare_configured_workspace_root()
}

/// Pure resolver for [`workspace_root`], taking the `HF_WORKSPACE_DIR` value
/// explicitly so it can be tested without mutating global process env (which
/// races under the parallel test runner).
fn workspace_root_from(override_dir: Option<std::ffi::OsString>) -> PathBuf {
    if let Some(dir) = override_dir {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    crate::init::user_app_dir().join("workspaces")
}

fn workspace_root_selection(override_dir: Option<std::ffi::OsString>) -> (PathBuf, bool) {
    let uses_trusted_default = override_dir.as_ref().is_none_or(|dir| dir.is_empty());
    (workspace_root_from(override_dir), uses_trusted_default)
}

fn configured_workspace_root() -> (PathBuf, bool) {
    workspace_root_selection(std::env::var_os("HF_WORKSPACE_DIR"))
}

fn workspace_operation_gate(
    root: &Path,
) -> Result<(PathBuf, Arc<WorkspaceOperationGate>), ClassifiedError> {
    let key = comparable_path(root).ok_or_else(|| {
        ClassifiedError::Internal(format!("resolve workspace lease root {}", root.display()))
    })?;
    let registry =
        WORKSPACE_OPERATION_GATES.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut gates = registry.lock().map_err(|_| {
        ClassifiedError::Internal("workspace operation gate registry is poisoned".to_owned())
    })?;
    if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
        return Ok((key, gate));
    }
    let gate = Arc::new(WorkspaceOperationGate::new(()));
    gates.insert(key.clone(), Arc::downgrade(&gate));
    Ok((key, gate))
}

fn workspace_lock_file(root: &Path) -> Result<File, ClassifiedError> {
    use sha2::{Digest as _, Sha256};

    // Keep the lock outside the deletable workspace. The digest gives every
    // canonical/absolute root a stable cross-process rendezvous file without
    // exposing the path itself in the filename.
    let lock_dir = crate::init::user_app_dir().join("locks");
    std::fs::create_dir_all(&lock_dir).map_err(|error| {
        ClassifiedError::Internal(format!(
            "create workspace lease directory {}: {error}",
            lock_dir.display()
        ))
    })?;
    let digest = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let lock_path = lock_dir.join(format!("workspace-{digest:x}.lock"));
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "open workspace lease {}: {error}",
                lock_path.display()
            ))
        })
}

fn workspace_lock_error(error: TryLockError, cleanup: bool) -> ClassifiedError {
    match error {
        TryLockError::WouldBlock if cleanup => ClassifiedError::Validation(
            "workspace cannot be cleared while another workspace operation is active".to_owned(),
        ),
        TryLockError::WouldBlock => ClassifiedError::Validation(
            "workspace operation cannot start while workspace cleanup is active".to_owned(),
        ),
        TryLockError::Error(error) => {
            ClassifiedError::Internal(format!("acquire workspace lease: {error}"))
        }
    }
}

fn protected_workspace_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from(std::path::MAIN_SEPARATOR_STR)];
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(PathBuf::from(home));
    }
    if let Some(repo) = repo_root() {
        paths.push(repo);
    }
    if let Some(source_repo) = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
    {
        paths.push(source_repo.to_path_buf());
    }
    paths.push(crate::init::config_dir());
    paths.push(crate::config::data_dir());
    paths.push(crate::init::user_app_dir());
    paths
}

fn comparable_path(path: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(path).ok().or_else(|| {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(path)
        };
        Some(absolute)
    })
}

#[cfg(unix)]
fn same_filesystem_entry(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(left) = std::fs::metadata(left) else {
        return false;
    };
    let Ok(right) = std::fs::metadata(right) else {
        return false;
    };
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_filesystem_entry(left: &Path, right: &Path) -> bool {
    std::fs::canonicalize(left)
        .ok()
        .zip(std::fs::canonicalize(right).ok())
        .is_some_and(|(left, right)| left == right)
}

fn validate_workspace_cleanup_root(root: &Path) -> Result<(), ClassifiedError> {
    for protected in protected_workspace_paths() {
        let Some(protected) = comparable_path(&protected) else {
            continue;
        };
        let same_or_ancestor = protected == root
            || protected.starts_with(root)
            || protected
                .ancestors()
                .any(|ancestor| same_filesystem_entry(ancestor, root));
        if same_or_ancestor {
            return Err(ClassifiedError::Validation(format!(
                "workspace cleanup refused for protected path {}",
                root.display()
            )));
        }
    }
    Ok(())
}

fn workspace_manifest(root: &Path) -> PathBuf {
    root.join(WORKSPACE_MANIFEST_FILE)
}

fn validate_workspace_manifest(root: &Path) -> Result<(), ClassifiedError> {
    let manifest_path = workspace_manifest(root);
    let metadata = std::fs::symlink_metadata(&manifest_path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "workspace ownership manifest is missing or unreadable at {}: {error}",
            manifest_path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.len() > 16 * 1024 {
        return Err(ClassifiedError::Validation(format!(
            "workspace ownership manifest is not a small regular file: {}",
            manifest_path.display()
        )));
    }
    let bytes = std::fs::read(&manifest_path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "read workspace ownership manifest {}: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: WorkspaceOwnershipManifest = serde_json::from_slice(&bytes).map_err(|error| {
        ClassifiedError::Validation(format!(
            "parse workspace ownership manifest {}: {error}",
            manifest_path.display()
        ))
    })?;
    if manifest.application != "hobot_fuzz"
        || manifest.version != WORKSPACE_MANIFEST_VERSION
        || manifest.canonical_root != root
    {
        return Err(ClassifiedError::Validation(format!(
            "workspace ownership manifest does not identify {}",
            root.display()
        )));
    }
    Ok(())
}

fn write_workspace_manifest(root: &Path) -> Result<(), ClassifiedError> {
    use std::io::Write as _;

    let destination = workspace_manifest(root);
    let temporary = root.join(format!(".hobot-fuzz-workspace-{}.tmp", Uuid::new_v4()));
    let manifest = WorkspaceOwnershipManifest {
        application: "hobot_fuzz".to_owned(),
        version: WORKSPACE_MANIFEST_VERSION,
        canonical_root: root.to_path_buf(),
    };
    let encoded = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        ClassifiedError::Internal(format!("serialize workspace ownership manifest: {error}"))
    })?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "create workspace ownership manifest {}: {error}",
                temporary.display()
            ))
        })?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ClassifiedError::Internal(format!(
            "write workspace ownership manifest {}: {error}",
            temporary.display()
        )));
    }
    if let Err(error) = std::fs::rename(&temporary, &destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(ClassifiedError::Internal(format!(
            "commit workspace ownership manifest {}: {error}",
            destination.display()
        )));
    }
    Ok(())
}

/// Create a new managed workspace root, or verify the ownership manifest of an
/// existing one. Only the implicit per-user default may adopt legacy artifacts;
/// a non-empty `HF_WORKSPACE_DIR` override without a manifest is never adopted.
fn prepare_managed_workspace_root_with_adoption(
    root: &Path,
    adopt_legacy_default: bool,
) -> Result<PathBuf, ClassifiedError> {
    match std::fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ClassifiedError::Validation(format!(
                "workspace root must not be a symbolic link: {}",
                root.display()
            )));
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(ClassifiedError::Validation(format!(
                "workspace root is not a regular directory: {}",
                root.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "create workspace root {}: {error}",
                    root.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect workspace root {}: {error}",
                root.display()
            )));
        }
    }

    let canonical = std::fs::canonicalize(root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace root {}: {error}",
            root.display()
        ))
    })?;
    validate_workspace_cleanup_root(&canonical)?;

    match std::fs::symlink_metadata(workspace_manifest(&canonical)) {
        Ok(_) => validate_workspace_manifest(&canonical)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut entries = std::fs::read_dir(&canonical).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "read workspace root {}: {error}",
                    canonical.display()
                ))
            })?;
            if entries.next().is_some() && !adopt_legacy_default {
                return Err(ClassifiedError::Validation(format!(
                    "workspace root is non-empty and has no ownership manifest: {}",
                    canonical.display()
                )));
            }
            write_workspace_manifest(&canonical)?;
        }
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect workspace ownership manifest {}: {error}",
                workspace_manifest(&canonical).display()
            )));
        }
    }
    Ok(canonical)
}

/// Initialize an explicit workspace root for a service-owned subsystem after
/// that subsystem has completed all policy preflight checks.
#[cfg(feature = "automotive-scapy")]
pub(crate) fn initialize_workspace_root_at(root: &Path) -> Result<PathBuf, ClassifiedError> {
    prepare_managed_workspace_root_with_adoption(root, false)
}

#[cfg(test)]
fn prepare_managed_workspace_root(root: &Path) -> Result<PathBuf, ClassifiedError> {
    prepare_managed_workspace_root_with_adoption(root, false)
}

fn prepare_configured_workspace_root() -> Result<PathBuf, ClassifiedError> {
    let (root, uses_trusted_default) = configured_workspace_root();
    prepare_managed_workspace_root_with_adoption(&root, uses_trusted_default)
}

fn clear_managed_workspace_root(root: &Path) -> Result<(), ClassifiedError> {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect workspace root {}: {error}",
                root.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(ClassifiedError::Validation(format!(
            "workspace root must not be a symbolic link: {}",
            root.display()
        )));
    }
    if !metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "workspace root is not a regular directory: {}",
            root.display()
        )));
    }
    let canonical = std::fs::canonicalize(root).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace root {}: {error}",
            root.display()
        ))
    })?;
    validate_workspace_cleanup_root(&canonical)?;
    validate_workspace_manifest(&canonical)?;
    std::fs::remove_dir_all(&canonical).map_err(|error| {
        ClassifiedError::Internal(format!("clear workspace {}: {error}", canonical.display()))
    })
}

/// Resolve a per-project/per-target workspace directory so multiple projects
/// do not collide.
///
/// `<workspace_root>/<project_name>/<target>`
///
/// `target` is untrusted (it flows in from the CLI/REST/GUI), so it is
/// sanitised before use: only `Normal` path components are kept, dropping any
/// root, prefix, or `..` segment. This guarantees the result always stays
/// within the per-project base directory, satisfying the sandbox boundary in
/// AGENTS.md 2.12 (untrusted inputs never touch the host FS outside the
/// workspace).
#[must_use]
pub fn workspace_dir(project: &Path, target: &str) -> PathBuf {
    workspace_root()
        .join(project_slug(project))
        .join(sanitize_target(target))
}

/// The on-disk workspace directory holding every target's artifacts for a
/// single project (compiled harnesses, corpora, crash reproducers, coverage
/// builds). This is the parent of the per-target [`workspace_dir`] directories,
/// and the unit removed when a project is deleted.
pub fn project_workspace_dir(project: &Path) -> PathBuf {
    workspace_root().join(project_slug(project))
}

/// Unique service-owned staging directory for one sandboxed document import.
/// It must live below the runtime's approved workspace root, while remaining a
/// sibling of target workspaces so a running fuzzer cannot mutate the input.
fn document_staging_dir(project: &Path, import_id: Uuid) -> PathBuf {
    project_workspace_dir(project)
        .join(".service")
        .join("document-import")
        .join(import_id.to_string())
}

/// Workspace-relative output directory owned by one fuzz or smoke run.
fn run_output_relative(run_id: Uuid) -> PathBuf {
    PathBuf::from("runs").join(run_id.to_string()).join("out")
}

/// Create or resolve a service-owned directory below `workspace` without
/// following symlinks left by an earlier untrusted sandbox execution.
pub(crate) fn ensure_workspace_directory(
    workspace: &Path,
    relative: &Path,
) -> Result<PathBuf, ClassifiedError> {
    let workspace_metadata = std::fs::symlink_metadata(workspace).map_err(|e| {
        ClassifiedError::Validation(format!(
            "inspect workspace directory {}: {e}",
            workspace.display()
        ))
    })?;
    if !workspace_metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "workspace is not a regular directory: {}",
            workspace.display()
        )));
    }
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory path is unsafe: {}",
            relative.display()
        )));
    }

    let root = std::fs::canonicalize(workspace).map_err(|e| {
        ClassifiedError::Validation(format!("resolve workspace {}: {e}", workspace.display()))
    })?;
    let mut current = root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("relative path was validated above")
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ClassifiedError::Validation(format!(
                    "workspace directory is not a regular directory: {}",
                    current.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|e| {
                    ClassifiedError::Internal(format!(
                        "create workspace directory {}: {e}",
                        current.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect workspace directory {}: {error}",
                    current.display()
                )));
            }
        }
    }
    let resolved = std::fs::canonicalize(&current).map_err(|e| {
        ClassifiedError::Validation(format!(
            "resolve workspace directory {}: {e}",
            current.display()
        ))
    })?;
    if !resolved.starts_with(&root) {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory escaped {}: {}",
            root.display(),
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Resolve an existing regular directory below a workspace without accepting
/// symlinks in any component.
fn resolve_workspace_directory(
    workspace: &Path,
    relative: &Path,
) -> Result<PathBuf, ClassifiedError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory path is unsafe: {}",
            relative.display()
        )));
    }
    let root = std::fs::canonicalize(workspace).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace {}: {error}",
            workspace.display()
        ))
    })?;
    let mut current = root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("relative path was validated above")
        };
        current.push(name);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect workspace directory {}: {error}",
                current.display()
            ))
        })?;
        if !metadata.file_type().is_dir() {
            return Err(ClassifiedError::Validation(format!(
                "workspace directory is not a regular directory: {}",
                current.display()
            )));
        }
    }
    let resolved = std::fs::canonicalize(&current).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve workspace directory {}: {error}",
            current.display()
        ))
    })?;
    if !resolved.starts_with(&root) {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory escaped {}: {}",
            root.display(),
            resolved.display()
        )));
    }
    Ok(resolved)
}

/// Immutable inputs and writable evidence location prepared for one run.
struct RunArtifacts {
    binary_host: PathBuf,
    source_host: PathBuf,
    corpus_host: PathBuf,
    corpus_relative: PathBuf,
    binary_container: String,
    corpus_container: String,
    output_host: PathBuf,
    output_container: String,
    output_relative: PathBuf,
    source_sha256: String,
    binary_sha256: String,
}

/// Compute a full SHA-256 digest without loading a potentially large binary in
/// memory.
fn sha256_file(path: &Path) -> Result<String, ClassifiedError> {
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
fn quarantine_corpus_entry(
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

    let quarantined = parent.join(format!(".hobot-fuzz-delete-{}", Uuid::new_v4()));
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

/// Digest the immutable comparison context for a coverage run: staged target
/// sources, the starting corpus, and the exact sandbox image identifier.
///
/// The walk is deliberately limited to build inputs staged by
/// `copy_project_sources` plus the corpus. Symlinks and unexpectedly large
/// trees fail closed so an untrusted workspace cannot turn regression
/// bookkeeping into an unbounded host traversal.
fn run_context_digest(workspace: &Path) -> Result<String, ClassifiedError> {
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

    let mut digest = Sha256::new();
    digest.update(b"hobot-fuzz-run-context-v1\0");
    digest.update(SANDBOX_IMAGE.as_bytes());
    digest.update(b"\0");
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
        digest.update(relative.to_string_lossy().as_bytes());
        digest.update(b"\0");
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
            digest.update(&chunk[..read]);
        }
        digest.update(b"\0");
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Copy the exact approved source/binary into a run-owned input directory and
/// create its isolated output directory. The primary workspace is mounted
/// read-only during execution, so these staged inputs cannot be rewritten by
/// the engine.
fn stage_run_artifacts(
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
fn verify_run_artifacts(artifacts: &RunArtifacts) -> Result<(), ClassifiedError> {
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

/// Outcome of scanning a run-owned output tree against its retained-evidence
/// budget.
///
/// The third state matters: a running fuzzer creates, renames, and deletes
/// files continuously, so an entry enumerated by `read_dir` can vanish before
/// its `symlink_metadata` call. That transient race must not be conflated with
/// a genuine budget overflow -- doing so let the live monitor kill a perfectly
/// valid campaign and discard its results.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutputBudget {
    /// Definitely within budget.
    Within,
    /// A definite violation: total/file bytes or entry count over the limit, or
    /// a symlink/special file that actually exists in the tree.
    Exceeded,
    /// The scan could not be completed because the tree changed underneath it
    /// (a transient `NotFound`/read error). Neither within nor over budget.
    Indeterminate,
}

/// Scan a run-owned output tree, distinguishing a real budget overflow from a
/// transient filesystem race. A definite overflow or structural violation
/// (symlink/special file) is [`OutputBudget::Exceeded`]; a metadata/read error
/// on an individual entry is [`OutputBudget::Indeterminate`] rather than a
/// false overflow.
fn output_budget_status(
    root: &Path,
    max_bytes: u64,
    max_entries: usize,
    max_file_bytes: u64,
) -> OutputBudget {
    let mut pending = vec![root.to_path_buf()];
    let mut total_bytes = 0_u64;
    let mut entries = 0usize;
    while let Some(directory) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
            return OutputBudget::Indeterminate;
        };
        if !metadata.file_type().is_dir() {
            return OutputBudget::Exceeded;
        }
        let Ok(children) = std::fs::read_dir(&directory) else {
            return OutputBudget::Indeterminate;
        };
        for child in children {
            let Ok(child) = child else {
                return OutputBudget::Indeterminate;
            };
            entries += 1;
            if entries > max_entries {
                return OutputBudget::Exceeded;
            }
            let path = child.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                // The entry vanished between enumeration and stat -- normal
                // fuzzer churn, not an overflow. Skip it.
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return OutputBudget::Indeterminate,
            };
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_file() {
                if metadata.len() > max_file_bytes {
                    return OutputBudget::Exceeded;
                }
                let Some(next) = total_bytes.checked_add(metadata.len()) else {
                    return OutputBudget::Exceeded;
                };
                total_bytes = next;
                if total_bytes > max_bytes {
                    return OutputBudget::Exceeded;
                }
            } else {
                return OutputBudget::Exceeded;
            }
        }
    }
    OutputBudget::Within
}

async fn monitor_run_output(
    output: PathBuf,
    corpus: PathBuf,
    max_output_file_bytes: u64,
    run_cancel: CancellationToken,
    stop: CancellationToken,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = interval.tick() => {
                let path = output.clone();
                let corpus_path = corpus.clone();
                // Only a *definite* overflow cancels the run. A transient scan
                // error (a file the fuzzer just deleted) is Indeterminate and is
                // retried on the next tick rather than latching a false kill.
                let exceeded_now = tokio::task::spawn_blocking(move || {
                    output_budget_status(
                        &path,
                        MAX_RUN_OUTPUT_BYTES,
                        MAX_RUN_OUTPUT_ENTRIES,
                        max_output_file_bytes,
                    ) == OutputBudget::Exceeded
                        || output_budget_status(
                            &corpus_path,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
                        ) == OutputBudget::Exceeded
                })
                .await
                .unwrap_or(false);
                if exceeded_now {
                    exceeded.store(true, std::sync::atomic::Ordering::Release);
                    run_cancel.cancel();
                    return;
                }
            }
        }
    }
}

/// Whether a finished run's artifacts may be retained. Returns false only on a
/// *definite* overflow; a transient scan race (Indeterminate) does not fail a
/// completed run, mirroring the live monitor so results are not discarded over
/// a filesystem hiccup.
async fn run_artifacts_within_budget(artifacts: &RunArtifacts, max_output_file_bytes: u64) -> bool {
    let output = artifacts.output_host.clone();
    let corpus = artifacts.corpus_host.clone();
    tokio::task::spawn_blocking(move || {
        output_budget_status(
            &output,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            max_output_file_bytes,
        ) != OutputBudget::Exceeded
            && output_budget_status(
                &corpus,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            ) != OutputBudget::Exceeded
    })
    .await
    .unwrap_or(false)
}

async fn merge_run_discoveries(
    engine: EngineKind,
    artifacts: &RunArtifacts,
    retained_corpus: &Path,
) -> Result<hf_core::corpus::Corpus, ClassifiedError> {
    let run_corpus = artifacts.corpus_host.clone();
    let run_output = artifacts.output_host.clone();
    let retained_corpus = retained_corpus.to_path_buf();
    let (corpus, _) = tokio::task::spawn_blocking(move || {
        if matches!(engine, EngineKind::AflPlusPlus | EngineKind::Honggfuzz) {
            hf_corpus::grow(&run_corpus, &run_output)?;
        }
        hf_corpus::merge_snapshot(&retained_corpus, &run_corpus)
    })
    .await
    .map_err(|error| ClassifiedError::Internal(format!("join corpus merge task: {error}")))??;
    Ok(corpus)
}

struct TerminalRunMetrics {
    edges: u64,
    execs: f64,
    crashes: u64,
}

fn retained_coverage_samples(
    series: &std::sync::Mutex<Vec<(f64, u64, f64)>>,
) -> Vec<CoverageSample> {
    let raw = series
        .lock()
        .map(|samples| samples.clone())
        .unwrap_or_default();
    downsample(&raw, 150)
        .into_iter()
        .map(|(t, edges, execs)| CoverageSample { t, edges, execs })
        .collect()
}

async fn persist_terminal_run_evidence(
    store: &Store,
    run_id: Uuid,
    metrics: &TerminalRunMetrics,
    series: &std::sync::Mutex<Vec<(f64, u64, f64)>>,
) -> Result<(), ClassifiedError> {
    store
        .set_run_stats(run_id, metrics.edges, metrics.execs, metrics.crashes)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    let samples = retained_coverage_samples(series);
    if !samples.is_empty() {
        let json = serde_json::to_string(&samples).map_err(|error| {
            ClassifiedError::Internal(format!("serialize run samples: {error}"))
        })?;
        store
            .set_run_samples(run_id, &json)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    }
    Ok(())
}

async fn terminal_run_metrics(
    engine: EngineKind,
    artifacts: &RunArtifacts,
    result: &hf_engine::runner::RunResult,
) -> Result<TerminalRunMetrics, ClassifiedError> {
    let mut edges = 0_u64;
    let mut execs = 0.0_f64;
    let mut finding_reported = false;
    for progress in &result.progress {
        match progress {
            FuzzProgress::EdgesCovered(value) => edges = edges.max(*value),
            FuzzProgress::ExecsPerSec(value) => execs = execs.max(*value),
            FuzzProgress::CrashesFound(count) => finding_reported |= *count > 0,
            FuzzProgress::LogLine(_) | FuzzProgress::Done => {}
        }
    }

    let mut terminal_afl_crashes = 0_u64;
    if engine == EngineKind::AflPlusPlus {
        let output = artifacts.output_host.clone();
        if let Some(stats) = tokio::task::spawn_blocking(move || {
            hf_engine::afl::read_fuzzer_stats(&output)
                .map_err(|error| ClassifiedError::Validation(error.to_string()))
        })
        .await
        .map_err(|error| {
            ClassifiedError::Internal(format!("join AFL++ statistics task: {error}"))
        })?? {
            if let Some(value) = stats.edges_found {
                edges = edges.max(value);
            }
            if let Some(value) = stats.execs_per_sec {
                execs = execs.max(value);
            }
            terminal_afl_crashes = stats.saved_crashes.unwrap_or(0);
        }
    }
    // Recursive crash-artifact walk over a possibly large output tree: run it on
    // the blocking pool, like the AFL stats read above, rather than stalling a
    // tokio worker (and progress streaming) on synchronous filesystem I/O.
    let crash_out = artifacts.output_host.clone();
    let artifact_crashes =
        tokio::task::spawn_blocking(move || collect_crash_inputs(engine, &crash_out).len() as u64)
            .await
            .map_err(|error| {
                ClassifiedError::Internal(format!("join crash-artifact scan task: {error}"))
            })?;
    Ok(TerminalRunMetrics {
        edges,
        execs,
        crashes: artifact_crashes
            .max(u64::from(finding_reported))
            .max(terminal_afl_crashes),
    })
}

/// Resolve the immutable source/binary pair proven by a persisted smoke run.
fn qualification_evidence(harness: &Harness) -> Result<(Uuid, &str, &str), ClassifiedError> {
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
fn verify_staged_qualification(
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
fn run_sandbox_options(artifacts: &RunArtifacts) -> hf_core::runtime::SandboxOptions {
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
        ..hf_core::runtime::SandboxOptions::default()
    }
}

/// Hardened libFuzzer merge profile: the starting snapshot remains immutable
/// and only the bounded, disposable merge result can be written.
fn minimization_sandbox_options(artifacts: &RunArtifacts) -> hf_core::runtime::SandboxOptions {
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

fn minimization_failure_with_rollback(
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
fn run_output_dir(workspace: &Path, run: &RunRecord) -> Result<PathBuf, ClassifiedError> {
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
fn run_binary_path(
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
fn run_source_path(workspace: &Path, run: &RunRecord) -> Result<PathBuf, ClassifiedError> {
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

/// Remove a sensitive staging directory even if the async import is aborted.
struct StagingDirectoryGuard(PathBuf);

impl Drop for StagingDirectoryGuard {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A human-readable `DefectDojo` product name for a project: its directory
/// basename, falling back to the full path when there is no basename.
fn defectdojo_project_name(project: &Path) -> String {
    project
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| project.to_string_lossy().into_owned())
}

fn canonical_project_root(project: &Path) -> Result<PathBuf, ClassifiedError> {
    let canonical = std::fs::canonicalize(project).map_err(|error| {
        ClassifiedError::Validation(format!(
            "resolve project root {}: {error}",
            project.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect project root {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "project root {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn stored_project_matches(stored: &Path, canonical: &Path) -> bool {
    stored == canonical || std::fs::canonicalize(stored).is_ok_and(|resolved| resolved == canonical)
}

fn project_lookup_identity(project: &Path) -> PathBuf {
    std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf())
}

/// A per-project workspace directory name: the human-readable basename plus a
/// short deterministic hash of the full path. The hash disambiguates projects
/// that share a basename (e.g. `/a/libfoo` and `/b/libfoo`) so their persistent
/// workspaces -- and thus compiled binaries, corpora, and crash reproducers --
/// never collide, while the basename keeps the directory recognizable. Stable
/// across processes (SHA-256, unlike `DefaultHasher`), so the same project maps
/// to the same workspace on every invocation.
fn project_slug(project: &Path) -> String {
    use sha2::{Digest, Sha256};
    let identity = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
    let name = identity
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");
    let mut hasher = Sha256::new();
    hasher.update(identity.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    format!("{name}-{}", &digest[..8])
}

/// Resolve a per-project directory beneath an explicit managed workspace root.
#[must_use]
#[cfg(feature = "automotive-scapy")]
pub(crate) fn project_workspace_dir_at(root: &Path, project: &Path) -> PathBuf {
    root.join(project_slug(project))
}

/// Whether the in-container qemu for a syzkaller run can use KVM hardware
/// acceleration. Requires a Linux host with `/dev/kvm`, and that the sandbox
/// arch matches the host arch (KVM cannot accelerate a foreign architecture).
/// On macOS/Windows the Docker VM does not expose nested KVM, so this is always
/// false and qemu falls back to slow TCG emulation.
fn syz_kvm_usable(platform: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        hf_runtime::norm_platform(platform) == hf_runtime::host_platform()
            && Path::new("/dev/kvm").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = platform;
        false
    }
}

/// Reduce an untrusted `target` to a path that cannot escape its parent
/// directory. Keeps only `Normal` components (so `..`, absolute roots, and
/// Windows prefixes are discarded) and falls back to `default` when nothing
/// safe remains.
fn sanitize_target(target: &str) -> PathBuf {
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

fn harness_binary_name(target: &str) -> String {
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
fn build_workspace_dictionary(workspace: &Path, dict_name: &str) -> Option<PathBuf> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let entries = std::fs::read_dir(workspace).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "c" | "cc" | "cpp" | "cxx" | "h" | "hpp" | "hh") {
            continue;
        }
        // Skip the generated harness itself -- its literals are hobot's, not
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

/// Read the current harness source from a target workspace, trying the known
/// per-language harness filenames. Returns `None` when none exists yet.
/// The source filename used inside a reproduction bundle for a language.
fn harness_bundle_filename(lang: TargetLanguage) -> &'static str {
    match lang {
        TargetLanguage::C => "harness.c",
        TargetLanguage::Cpp => "harness.cc",
        TargetLanguage::Rust => "harness.rs",
        TargetLanguage::Go => "harness.go",
        TargetLanguage::Python => "harness.py",
    }
}

fn read_current_harness_source(workspace: &Path) -> Option<String> {
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
fn read_current_harness_id(workspace: &Path) -> Option<Uuid> {
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
fn write_current_harness_source(workspace: &Path, source: &str) -> Result<(), ClassifiedError> {
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
fn write_current_harness_id(workspace: &Path, id: Uuid) -> Result<(), ClassifiedError> {
    std::fs::write(workspace.join("harness.active"), id.to_string())
        .map_err(|e| ClassifiedError::Internal(format!("write active harness id: {e}")))
}

/// Atomically reactivate an already-verified historical executable.
fn write_current_harness_binary(
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
fn container_input_path(workspace: &Path, host_path: &Path) -> String {
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

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn is_regular_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn stage_crash_inputs(engine: EngineKind, out_dir: &Path, staging: &Path) -> usize {
    if !is_regular_directory(out_dir)
        || std::fs::create_dir_all(staging).is_err()
        || !is_regular_directory(staging)
    {
        return 0;
    }
    let mut staged = 0usize;
    for path in collect_crash_inputs(engine, out_dir) {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if std::fs::copy(&path, staging.join(name)).is_ok() {
            staged += 1;
        }
    }
    staged
}

/// Collect crash input file paths from a run output directory, skipping engine
/// bookkeeping. Looks both at the top level (flat-output engines) and one level
/// down under `<instance>/crashes/` (AFL++ output layout).
fn collect_crash_inputs(engine: EngineKind, out_dir: &Path) -> Vec<PathBuf> {
    hf_crash::ingest_for_engine(out_dir, engine, Uuid::nil(), Uuid::nil()).map_or_else(
        |error| {
            tracing::warn!(path = %out_dir.display(), %error, "crash artifact scan failed");
            Vec::new()
        },
        |result| {
            if result.is_truncated() {
                tracing::warn!(
                    path = %out_dir.display(),
                    artifact_limit_reached = result.artifact_limit_reached,
                    report_limit_reached = result.report_limit_reached,
                    "crash artifact scan reached a safety limit"
                );
            }
            result
                .crashes
                .into_iter()
                .map(|crash| crash.input_path)
                .collect()
        },
    )
}

fn collect_legacy_crash_inputs(out_dir: &Path) -> Vec<PathBuf> {
    hf_crash::ingest(out_dir, Uuid::nil(), Uuid::nil()).map_or_else(
        |_| Vec::new(),
        |crashes| crashes.into_iter().map(|crash| crash.input_path).collect(),
    )
}

/// Collect legacy flat evidence plus every isolated run output for a target.
fn collect_workspace_crash_inputs(workspace: &Path) -> Vec<PathBuf> {
    let mut inputs = collect_legacy_crash_inputs(&workspace.join("out"));
    let runs = workspace.join("runs");
    if !is_regular_directory(&runs) {
        return inputs;
    }
    if let Ok(entries) = std::fs::read_dir(runs) {
        for entry in entries.flatten() {
            let run = entry.path();
            if is_regular_directory(&run) {
                inputs.extend(collect_legacy_crash_inputs(&run.join("out")));
            }
        }
    }
    inputs
}

#[cfg(test)]
mod crash_input_boundary_tests {
    use super::{collect_crash_inputs, stage_crash_inputs};
    use hf_core::engine::EngineKind;

    #[cfg(unix)]
    #[test]
    fn crash_staging_and_collection_ignore_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let out = root.path().join("out");
        let staging = root.path().join("staging");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("crash-real"), b"real crash").unwrap();

        let outside = root.path().join("outside-secret");
        std::fs::write(&outside, b"must not be staged").unwrap();
        symlink(&outside, out.join("crash-link")).unwrap();

        let collected = collect_crash_inputs(EngineKind::LibFuzzer, &out);
        assert_eq!(collected, vec![out.join("crash-real")]);
        assert_eq!(stage_crash_inputs(EngineKind::LibFuzzer, &out, &staging), 1);
        assert_eq!(
            std::fs::read(staging.join("crash-real")).unwrap(),
            b"real crash"
        );
        assert!(!staging.join("crash-link").exists());

        let external_out = root.path().join("external-out");
        std::fs::create_dir_all(&external_out).unwrap();
        std::fs::write(external_out.join("crash-secret"), b"outside").unwrap();
        let linked_out = root.path().join("linked-out");
        symlink(&external_out, &linked_out).unwrap();
        assert!(collect_crash_inputs(EngineKind::LibFuzzer, &linked_out).is_empty());
        assert_eq!(
            stage_crash_inputs(
                EngineKind::LibFuzzer,
                &linked_out,
                &root.path().join("linked-staging")
            ),
            0
        );
    }
}

/// Cache value: the signature the export was computed for + the raw
/// `llvm-cov export` JSON.
type ExportCache = std::sync::Mutex<std::collections::HashMap<String, (u64, String)>>;

/// Process-global cache of raw `llvm-cov export` JSON, keyed by `project::target`
/// and tagged with the corpus+harness signature it was computed for. The
/// covered-set, summary, and frontier accessors all parse from this single
/// cached export, so the expensive (~180s) coverage pipeline runs at most once
/// per signature instead of once per accessor.
fn export_cache() -> &'static ExportCache {
    static CACHE: std::sync::OnceLock<ExportCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Build the uncovered-frontier lines for the refine prompt: the target's
/// reachable functions that `llvm-cov` shows as unreached, each annotated with
/// its `file:line:col` location, deduplicated to the first location per
/// function. Falls back to the full frontier when none of the reachable names
/// match the frontier (e.g. llvm-cov name mangling on C++/Rust), so refinement
/// is never left blind while still carrying locations.
fn frontier_refine_lines(
    reachable: &[String],
    frontier: &[hf_coverage::UncoveredRegion],
) -> Vec<String> {
    let format_region = |region: &hf_coverage::UncoveredRegion| {
        if region.file.is_empty() {
            region.function.clone()
        } else {
            format!(
                "{} ({}:{}:{})",
                region.function, region.file, region.line, region.col
            )
        }
    };
    let reachable_set: std::collections::HashSet<&str> =
        reachable.iter().map(String::as_str).collect();
    let mut seen = std::collections::HashSet::new();
    let targeted: Vec<String> = frontier
        .iter()
        .filter(|region| reachable_set.contains(region.function.as_str()))
        .filter(|region| seen.insert(region.function.clone()))
        .map(&format_region)
        .collect();
    if !targeted.is_empty() {
        return targeted;
    }
    let mut seen = std::collections::HashSet::new();
    frontier
        .iter()
        .filter(|region| seen.insert(region.function.clone()))
        .map(format_region)
        .collect()
}

/// A cheap fingerprint of the inputs that affect coverage: stable corpus file
/// metadata plus the canonical active harness source. Changes when a run grows
/// the corpus or a successful build commits a new harness, invalidating caches.
fn coverage_signature(workspace: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::time::UNIX_EPOCH;

    let modified_nanos = |meta: &std::fs::Metadata| -> u128 {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos())
    };

    let mut corpus_metadata = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace.join("corpus")) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                corpus_metadata.push((entry.file_name(), meta.len(), modified_nanos(&meta)));
            }
        }
    }
    corpus_metadata.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    corpus_metadata.hash(&mut hasher);
    read_current_harness_source(workspace).hash(&mut hasher);
    hasher.finish()
}

/// Parse `llvm-cov export` JSON, returning the names of functions with a
/// non-zero execution count (the covered set).
fn parse_covered_functions(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut covered: Vec<String> = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("functions"))
        .and_then(serde_json::Value::as_array)
        .map(|funcs| {
            funcs
                .iter()
                .filter(|f| {
                    f.get("count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
                })
                .filter_map(|f| {
                    f.get("name")
                        .and_then(|n| n.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    covered.sort();
    covered.dedup();
    covered
}

/// Recursively collect and parse every `.casrep` report under `dir`.
/// Collapse crashes that CASR placed in the same cluster to one representative
/// (the first seen). Crashes without a cluster id pass through unchanged, so
/// this only ever tightens dedup, never loses an un-clustered crash.
fn bucket_by_cluster(crashes: Vec<hf_core::crash::Crash>) -> Vec<hf_core::crash::Crash> {
    let mut seen_clusters = std::collections::HashSet::new();
    let mut kept = Vec::with_capacity(crashes.len());
    for crash in crashes {
        match crash.casr.as_ref().and_then(|c| c.cluster) {
            Some(cluster) if !seen_clusters.insert(cluster) => {} // duplicate cluster -> drop
            _ => kept.push(crash),
        }
    }
    kept
}

fn collect_casreps(dir: &Path) -> Vec<(PathBuf, hf_core::crash::CasrReport)> {
    let mut out = Vec::new();
    collect_casreps_into(dir, &mut out);
    out
}

fn collect_casreps_into(dir: &Path, out: &mut Vec<(PathBuf, hf_core::crash::CasrReport)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_casreps_into(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("casrep") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(mut report) = hf_crash::parse_casrep(&content) {
                    // CASR groups equivalent crashes into `cl<N>` dirs; carry the
                    // cluster id so triage can bucket by it.
                    report.cluster = hf_crash::cluster_from_path(&path);
                    out.push((path, report));
                }
            }
        }
    }
}

/// Map a `.casrep` path back to the crash input it analyzed. CASR names each
/// report after its input file (`id:000….casrep` -> `id:000…`); match that
/// filename against the actual crash inputs so an AFL++ input nested under
/// `out/<instance>/crashes/` resolves to its real location rather than a
/// nonexistent `out/<name>` (which broke `verify_regressions`/reproduce). Falls
/// back to the flat `out_dir/<name>` layout (libFuzzer) when not found.
fn casrep_input_path(out_dir: &Path, casrep: &Path, crash_inputs: &[PathBuf]) -> PathBuf {
    let Some(stem) = casrep.file_stem().and_then(|s| s.to_str()) else {
        return casrep.to_path_buf();
    };
    crash_inputs
        .iter()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some(stem))
        .cloned()
        .unwrap_or_else(|| out_dir.join(stem))
}

/// A stable crash id derived from its run, stack signature, and input file, so
/// re-triaging the same run replaces each crash row rather than inserting a new
/// one (the `crashes` table is keyed on `id`; a fresh random UUID per triage
/// pass would accumulate identical duplicate rows). The input filename keeps
/// distinct crashes apart even when they share (or lack) a signature.
fn deterministic_crash_id(run_id: Uuid, signature: &str, input: &Path) -> Uuid {
    let file = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let name = format!("{run_id}|{signature}|{file}");
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes())
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

/// Build the sandbox image from the repo's Dockerfile for a given platform.
///
/// # Errors
/// Returns `ClassifiedError::Internal` if the `docker build` command fails.
pub fn build_sandbox_image(root: &Path, platform: &str) -> Result<(), ClassifiedError> {
    let status = std::process::Command::new(hf_runtime::docker_bin())
        .current_dir(root)
        .args([
            "build",
            "--platform",
            platform,
            "-t",
            SANDBOX_IMAGE,
            "-f",
            "docker/sandbox/Dockerfile",
            ".",
        ])
        .status()
        .map_err(|e| ClassifiedError::Internal(format!("docker build: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ClassifiedError::Internal("docker build failed".to_owned()))
    }
}

/// Walk up from the current dir and the executable path looking for the repo
/// root (the directory that contains `docker/sandbox/Dockerfile`).
pub fn repo_root() -> Option<PathBuf> {
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        starts.push(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        starts.push(exe);
    }
    for start in starts {
        let mut cur: Option<&Path> = Some(start.as_path());
        while let Some(p) = cur {
            if p.join("Cargo.toml").is_file() && p.join("config").is_dir() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
    }
    None
}

/// RAII guard that keeps an agent turn registered in the container's
/// `active_agents` list for its lifetime, removing it on drop (even if the turn
/// panics or is cancelled). Returned by [`ServiceContainer::track_agent`].
#[must_use = "the agent turn is only tracked while this guard is alive"]
pub struct AgentTurnGuard {
    active_agents: Arc<std::sync::Mutex<Vec<String>>>,
    label: String,
}

impl Drop for AgentTurnGuard {
    fn drop(&mut self) {
        if let Ok(mut agents) = self.active_agents.lock() {
            if let Some(pos) = agents.iter().position(|a| a == &self.label) {
                agents.remove(pos);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ServiceContainer
// ---------------------------------------------------------------------------

/// All wired application services, constructed from a runtime + optional
/// provider pool.
///
/// The container is `Clone` (it wraps `Arc`) so Tauri commands can capture
/// it by value.
#[derive(Clone)]
pub struct ServiceContainer {
    runtime: Arc<dyn RuntimeAdapter>,
    /// The LLM provider pool, held in a shared swappable cell so it can be
    /// reloaded from config at runtime ([`Self::reload_providers`]) and the new
    /// pool is seen by every clone of this container (and thus every consumer)
    /// without a restart.
    provider_pool: Arc<std::sync::RwLock<Option<Arc<dyn ProviderPool>>>>,
    store: Option<Arc<Store>>,
    session_manager: Option<Arc<hf_session::SessionManager>>,
    checkpoint_manager: Option<Arc<hf_session::ChatCheckpointManager>>,
    guardrails: Guardrails,
    diagnostics: Arc<crate::diagnostics::DiagnosticsRecorder>,
    run_journal: Arc<crate::recovery::RunJournal>,
    /// Cancellation tokens for in-flight fuzz runs, keyed by run id. A run
    /// registers its token on start and removes it on completion;
    /// [`Self::cancel_run`] fires the token to stop the run cooperatively.
    active_runs: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    /// Labels of agent turns currently executing, so the Observability panel can
    /// show live agent activity instead of always "No active agent instances".
    /// A turn registers via [`Self::track_agent`] and is removed when the
    /// returned guard drops. Shared across clones of this container.
    active_agents: Arc<std::sync::Mutex<Vec<String>>>,
    /// Per-session locks serializing every chat read-modify-write operation.
    /// Turns, rollback, branching, and deletion share this lock so transcript,
    /// metadata, and checkpoint mutations cannot interleave. Different
    /// sessions still run concurrently. Shared across clones.
    session_turn_locks: Arc<
        std::sync::Mutex<
            std::collections::HashMap<hf_core::types::SessionId, Arc<tokio::sync::Mutex<()>>>,
        >,
    >,
    /// Late-bound link to the campaign scheduler, shared across clones of this
    /// container so any operation in this process (scheduled or interactive)
    /// can emit scheduler events (crash found, run terminated). Set by
    /// `CampaignScheduler::try_start` via [`Self::bind_scheduler_events`].
    scheduler_events:
        Arc<std::sync::Mutex<Option<std::sync::Weak<hf_scheduler::SchedulerManager>>>>,
    /// Keeps the periodic provider health-check task alive; when the last
    /// clone of the container drops, the guard cancels and aborts the loop.
    /// `None` for containers built via [`Self::new`] (tests, stubs).
    _health_task: Option<Arc<ProviderHealthTask>>,
}

/// RAII guard that removes a run's cancellation token from the active-runs map
/// on drop, so the entry cannot leak if the `run_fuzzer` future is
/// dropped/aborted rather than returning normally (which would otherwise leave
/// a phantom run that `active_run_ids` reports and `cancel_run` can never clear).
struct ActiveRunGuard {
    active_runs: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    run_id: Uuid,
}

/// Cadence used by the provider health-check loop while no provider pool is
/// configured; matches the `ProviderPool` trait's default interval.
const PROVIDER_HEALTH_CHECK_FALLBACK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

/// RAII guard for the periodic provider health-check task: dropping it cancels
/// the loop and aborts the task, so the background worker never outlives the
/// container that spawned it.
struct ProviderHealthTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ProviderHealthTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// Spawn the periodic provider health-check loop: every pool-configured
/// interval, health-check each frozen provider and thaw the ones that respond
/// ([`ProviderPool::thaw_frozen_providers`]). This is what recovers providers
/// whose freeze has no auto-thaw (permanent freezes from invalid keys or
/// exhausted quota) without a process restart.
///
/// The loop reads the pool from the shared cell on every tick, so a pool
/// swapped in by [`ServiceContainer::reload_providers`] is picked up without
/// respawning the task, and runs an initial check immediately so providers
/// frozen before a restart recover without waiting a full interval.
fn spawn_provider_health_checks(
    pool_cell: Arc<std::sync::RwLock<Option<Arc<dyn ProviderPool>>>>,
) -> ProviderHealthTask {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let handle = tokio::spawn(async move {
        loop {
            let pool = pool_cell.read().ok().and_then(|guard| guard.clone());
            let interval = if let Some(pool) = pool {
                let thawed = pool.thaw_frozen_providers().await;
                if thawed > 0 {
                    tracing::info!(
                        thawed,
                        "frozen providers recovered by periodic health check"
                    );
                }
                pool.health_check_interval()
            } else {
                // No provider configured (yet); keep a modest cadence so a
                // pool installed by a later reload starts getting checks.
                PROVIDER_HEALTH_CHECK_FALLBACK_INTERVAL
            };
            tokio::select! {
                () = token.cancelled() => break,
                () = tokio::time::sleep(interval) => {}
            }
        }
    });
    ProviderHealthTask { cancel, handle }
}

/// Truncate a policy reason to the audit column's bound, on a char boundary.
fn bounded_guardrail_detail(reason: &str) -> String {
    reason.chars().take(MAX_GUARDAIL_DETAIL_CHARS).collect()
}

fn ensure_run_journal_durable(
    journal: &crate::recovery::RunJournal,
) -> Result<(), ClassifiedError> {
    journal.durability_error().map_or(Ok(()), |error| {
        Err(ClassifiedError::Storage(format!(
            "run recovery journal is degraded: {error}"
        )))
    })
}

fn close_run_journal(
    journal: &crate::recovery::RunJournal,
    run_id: Uuid,
) -> Result<(), ClassifiedError> {
    journal.close_run(run_id);
    ensure_run_journal_durable(journal)
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.remove(&self.run_id);
        }
    }
}

/// Last-resort lifecycle repair for an inserted run. If its async operation is
/// aborted or returns through an unhandled error path, mark the row failed and
/// close its recovery journal instead of leaving a permanent `Running` record.
struct PersistedRunGuard {
    store: Arc<Store>,
    journal: Option<Arc<crate::recovery::RunJournal>>,
    run_id: Uuid,
    armed: bool,
}

impl PersistedRunGuard {
    fn new(
        store: Arc<Store>,
        journal: Option<Arc<crate::recovery::RunJournal>>,
        run_id: Uuid,
    ) -> Self {
        Self {
            store,
            journal,
            run_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PersistedRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(journal) = &self.journal {
            if let Err(error) = close_run_journal(journal, self.run_id) {
                tracing::error!(run_id = %self.run_id, %error, "failed to close aborted run journal");
            }
        }
        let store = Arc::clone(&self.store);
        let run_id = self.run_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = store
                    .set_run_status(run_id, RunStatus::Failed, Some(Utc::now()))
                    .await
                {
                    tracing::error!(%run_id, %error, "failed to repair aborted run status");
                }
            });
        } else {
            tracing::error!(%run_id, "aborted run status could not be repaired without an async runtime");
        }
    }
}

/// Build the per-model cost table (`model -> (per-1k-in, per-1k-out)`) from the
/// configured providers, for LLM cost diagnostics.
fn build_cost_map() -> std::collections::HashMap<String, (f64, f64)> {
    crate::config::get_providers()
        .into_iter()
        .map(|p| (p.model, (p.cost_per_1k_input, p.cost_per_1k_output)))
        .collect()
}

/// Build the `hf-session` managers over a database store: the [`SessionManager`]
/// (`SQLite` session tree + `JSONL` display/context transcripts) and a
/// [`ChatCheckpointManager`] sharing the same stores for turn-level rollback
/// (checkpoints are persisted in `SQLite` so undo survives restarts).
///
/// [`SessionManager`]: hf_session::SessionManager
/// [`ChatCheckpointManager`]: hf_session::ChatCheckpointManager
fn build_session_managers(
    store: &Arc<Store>,
) -> (
    Arc<hf_session::SessionManager>,
    Arc<hf_session::ChatCheckpointManager>,
) {
    use hf_core::session::{
        ChatCheckpointStore, DisplayTranscriptStore, SessionStore, TranscriptStore,
    };

    let base = crate::init::user_app_dir().join("transcripts");
    let session_store: Arc<dyn SessionStore> =
        Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()));
    let transcript: Arc<dyn TranscriptStore> =
        Arc::new(hf_storage::JsonlTranscriptStore::new(base.join("context")));
    let display: Arc<dyn DisplayTranscriptStore> = Arc::new(
        hf_storage::JsonlDisplayTranscriptStore::new(base.join("display")),
    );
    // Persist checkpoints in the DB so turn-level rollback survives a restart
    // (the in-memory store lost them on exit, silently no-op'ing rollback).
    let checkpoint_store: Arc<dyn ChatCheckpointStore> = Arc::new(
        hf_storage::SqliteChatCheckpointStore::new(store.pool().clone()),
    );

    let manager = Arc::new(hf_session::SessionManager::new(
        Arc::clone(&session_store),
        Arc::clone(&transcript),
        Arc::clone(&display),
        crate::config::effective_session_config(),
    ));
    let checkpoints = Arc::new(hf_session::ChatCheckpointManager::new(
        transcript,
        display,
        checkpoint_store,
        session_store,
    ));
    (manager, checkpoints)
}

fn chat_storage_error(context: &str, error: impl std::fmt::Display) -> ClassifiedError {
    ClassifiedError::Storage(format!("{context}: {error}"))
}

impl ServiceContainer {
    /// Create a new `ServiceContainer` without persistence.
    #[must_use]
    pub fn new(
        runtime: Arc<dyn RuntimeAdapter>,
        provider_pool: Option<Arc<dyn ProviderPool>>,
    ) -> Self {
        Self {
            runtime,
            provider_pool: Arc::new(std::sync::RwLock::new(provider_pool)),
            store: None,
            session_manager: None,
            checkpoint_manager: None,
            guardrails: Guardrails::permissive(),
            diagnostics: Arc::new(crate::diagnostics::DiagnosticsRecorder::new(
                build_cost_map(),
            )),
            run_journal: Arc::new(crate::recovery::RunJournal::in_memory()),
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            scheduler_events: Arc::new(std::sync::Mutex::new(None)),
            _health_task: None,
        }
    }

    /// Create a non-persistent container backed by the stub runtime.
    ///
    /// Intended for presentation-layer tests and health checks that need the
    /// service API surface without Docker, an LLM provider, or a database.
    #[must_use]
    pub fn stubbed() -> Self {
        Self::new(Arc::new(hf_runtime::StubRuntime), None)
    }

    /// The LLM cost/trace diagnostics recorder for this session.
    #[must_use]
    pub fn diagnostics(&self) -> &Arc<crate::diagnostics::DiagnosticsRecorder> {
        &self.diagnostics
    }

    /// Runs interrupted by an app crash/quit, awaiting recovery.
    #[must_use]
    pub fn interrupted_runs(&self) -> Vec<crate::recovery::InterruptedRun> {
        self.run_journal.interrupted()
    }

    /// Dismiss an interrupted run from the recovery list.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when the recovery journal cannot durably
    /// record the dismissal.
    pub fn dismiss_interrupted_run(&self, run_id: &str) -> Result<(), ClassifiedError> {
        ensure_run_journal_durable(&self.run_journal)?;
        self.run_journal.dismiss(run_id);
        ensure_run_journal_durable(&self.run_journal)
    }

    /// Aggregated LLM cost/usage recorded this session.
    pub async fn cost_summary(
        &self,
    ) -> Result<crate::diagnostics::CostSummary, crate::diagnostics::DiagnosticsError> {
        self.diagnostics.summary().await
    }

    /// Attach a persistence store (and the session manager derived from it),
    /// returning the updated container.
    #[must_use]
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        let (sessions, checkpoints) = build_session_managers(&store);
        self.session_manager = Some(sessions);
        self.checkpoint_manager = Some(checkpoints);
        self.store = Some(store);
        self
    }

    /// Connect persistence at an explicit path and attach it to this container.
    ///
    /// This keeps embedding and presentation tests on the service boundary
    /// without exposing the infrastructure store type in their manifests.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError::Storage`] when the database cannot be
    /// opened or migrated.
    pub async fn with_store_path(self, path: PathBuf) -> Result<Self, ClassifiedError> {
        let store = Store::connect(path)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(self.with_store(Arc::new(store)))
    }

    /// The chat checkpoint manager (turn-level rollback), if a database is
    /// configured.
    #[must_use]
    pub fn checkpoint_manager(&self) -> Option<&Arc<hf_session::ChatCheckpointManager>> {
        self.checkpoint_manager.as_ref()
    }

    /// Create a turn checkpoint recording the transcript length before this
    /// turn (so a later rollback restores the pre-turn state).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the session is unknown, persistence is not
    /// configured, or the checkpoint cannot be saved.
    pub async fn chat_create_checkpoint(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) -> Result<(), ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.create_chat_checkpoint_unlocked(session, message_count_before)
            .await
    }

    async fn create_chat_checkpoint_unlocked(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) -> Result<(), ClassifiedError> {
        let manager = self.chat_checkpoint_manager()?;
        let turn = manager
            .current_turn(session)
            .await
            .map_err(|error| chat_storage_error("read current chat turn", error))?
            .saturating_add(1);
        manager
            .create_checkpoint(
                session,
                turn,
                message_count_before,
                Uuid::new_v4().to_string(),
            )
            .await
            .map_err(|error| chat_storage_error("create chat checkpoint", error))?;
        Ok(())
    }

    pub(crate) async fn persist_chat_turn_unlocked(
        &self,
        session: &hf_core::types::SessionId,
        messages: &[hf_core::types::Message],
    ) -> Result<(), ClassifiedError> {
        let sessions = self.chat_session_manager()?;
        let checkpoints = self.chat_checkpoint_manager()?;
        let snapshot = sessions
            .snapshot_transcripts(session)
            .await
            .map_err(|error| chat_storage_error("snapshot chat transcript", error))?;
        let message_count_before = snapshot.context_count();
        let turn = checkpoints
            .current_turn(session)
            .await
            .map_err(|error| chat_storage_error("read current chat turn", error))?
            .saturating_add(1);

        sessions
            .append_messages(session, messages)
            .await
            .map_err(|error| chat_storage_error("append chat turn", error))?;
        if let Err(error) = checkpoints
            .create_checkpoint(
                session,
                turn,
                u32::try_from(message_count_before).unwrap_or(u32::MAX),
                Uuid::new_v4().to_string(),
            )
            .await
        {
            let compensation = sessions
                .restore_transcript_snapshot(session, &snapshot)
                .await;
            let detail = match compensation {
                Ok(()) => format!(
                    "create chat checkpoint failed and transcript was rolled back: {error}"
                ),
                Err(rollback) => format!(
                    "create chat checkpoint failed: {error}; transcript compensation failed: {rollback}"
                ),
            };
            return Err(ClassifiedError::Storage(detail));
        }
        Ok(())
    }

    /// Roll back the most recent chat turn, truncating the transcript.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when the session/checkpoint is unavailable or
    /// any transcript, metadata, or checkpoint mutation fails.
    pub async fn chat_rollback_last(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<usize, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_checkpoint_manager()?
            .rollback_last(session)
            .await
            .map(|result| result.messages_removed)
            .map_err(|error| chat_storage_error("rollback last chat turn", error))
    }

    /// List the (still-valid) per-turn checkpoints for a session, each with a
    /// preview of the user message that started the turn.
    pub async fn chat_checkpoints(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<crate::checkpoints::CheckpointView>, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        let checkpoints = self.chat_checkpoint_manager()?;
        let sessions = self.chat_session_manager()?;
        let list = checkpoints
            .list_checkpoints(session)
            .await
            .map_err(|error| chat_storage_error("list chat checkpoints", error))?;
        let transcript = sessions
            .read_transcript(session)
            .await
            .map_err(|error| chat_storage_error("read chat checkpoint previews", error))?;
        let mut valid: Vec<_> = list.into_iter().filter(|c| !c.invalidated).collect();
        // Present turns oldest-first for the picker, regardless of the store's
        // list ordering (the trait returns them newest-first).
        valid.sort_by_key(|c| c.turn_number);
        Ok(valid
            .into_iter()
            .map(|c| {
                let preview = transcript
                    .get(usize::try_from(c.message_count_before).unwrap_or(usize::MAX))
                    .map(|m| m.content.chars().take(80).collect())
                    .unwrap_or_default();
                crate::checkpoints::CheckpointView {
                    checkpoint_id: c.checkpoint_id,
                    turn_number: c.turn_number,
                    message_count_before: c.message_count_before,
                    preview,
                }
            })
            .collect())
    }

    /// Roll back to a specific checkpoint (removing that turn and everything
    /// after). Returns the number of messages removed.
    pub async fn chat_rollback_to(
        &self,
        session: &hf_core::types::SessionId,
        checkpoint_id: &str,
    ) -> Result<usize, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_checkpoint_manager()?
            .rollback_to(session, checkpoint_id)
            .await
            .map(|result| result.messages_removed)
            .map_err(|error| chat_storage_error("rollback chat to checkpoint", error))
    }

    /// Fork a conversation: create a branch session off `parent`, copying the
    /// parent's transcript up to `fork_message_count` so the branch can diverge
    /// independently. Returns the new session id.
    pub async fn chat_branch(
        &self,
        parent: &hf_core::types::SessionId,
        fork_message_count: u32,
        title: Option<String>,
    ) -> Result<String, ClassifiedError> {
        if fork_message_count == 0 {
            return Err(ClassifiedError::Validation(
                "cannot branch an empty conversation".to_owned(),
            ));
        }
        let _guard = self.chat_session_guard(parent).await?;
        let message_index =
            usize::try_from(fork_message_count.saturating_sub(1)).unwrap_or(usize::MAX);
        self.chat_session_manager()?
            .fork_session(parent, message_index, title)
            .await
            .map(|branch| branch.id.0)
            .map_err(|error| chat_storage_error("branch chat session", error))
    }

    /// The canonical display transcript of a session, for loading a branch into
    /// the chat view.
    pub async fn chat_history(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<hf_core::types::Message>, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_session_manager()?
            .read_display_transcript(session)
            .await
            .map_err(|error| chat_storage_error("read chat history", error))
    }

    /// Create a new top-level chat session, returning its id, or `None` when no
    /// database is configured. Shared by every presentation layer so session
    /// creation behaves identically (AGENTS.md 2.9).
    pub async fn create_chat_session(
        &self,
        title: Option<String>,
    ) -> Result<Option<String>, ClassifiedError> {
        let Some(manager) = self.session_manager.as_ref() else {
            return Ok(None);
        };
        let id = manager
            .create_session(hf_core::session::CreateSessionOptions {
                parent_id: None,
                session_type: hf_core::session::SessionType::Main,
                agent_id: None,
                title: title.or_else(|| Some("Chat".to_owned())),
            })
            .await
            .map(|node| node.id.0)
            .map_err(|error| chat_storage_error("create chat session", error))?;
        Ok(Some(id))
    }

    /// Delete a chat session and its transcript (used by the "clear history"
    /// action). No-op when no session store is configured. Returns whether a
    /// deletion was performed.
    pub async fn delete_chat_session(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<bool, ClassifiedError> {
        let Some(manager) = self.session_manager.as_ref() else {
            return Ok(false);
        };
        let _guard = self.chat_session_guard(session).await?;
        manager
            .delete_session(session)
            .await
            .map_err(|error| chat_storage_error("delete chat session", error))?;
        // Drop the per-session turn lock now that the session is gone, so a
        // long-lived server does not accumulate one dead mutex per deleted
        // session for its entire lifetime. `_guard` still holds a clone of the
        // Arc, so the mutex is released only when this call returns; a later
        // caller for a (recreated) id simply gets a fresh lock.
        {
            let mut locks = self
                .session_turn_locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            locks.remove(session);
        }
        Ok(true)
    }

    /// All sessions in the same conversation tree as `session` (the main session
    /// plus every branch), for the branch switcher.
    pub async fn chat_branches(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<crate::checkpoints::BranchView>, ClassifiedError> {
        use hf_core::session::{SessionFilter, SessionType};
        let _guard = self.chat_session_guard(session).await?;
        let sessions = self.chat_session_manager()?;
        let node = sessions
            .get_session(session)
            .await
            .map_err(|error| chat_storage_error("read chat session tree", error))?;
        let filter = SessionFilter {
            root_id: Some(node.root_id.clone()),
            ..SessionFilter::default()
        };
        let mut nodes = sessions
            .list_sessions(&filter)
            .await
            .map_err(|error| chat_storage_error("list chat session tree", error))?;
        nodes.sort_by_key(|n| (n.depth, n.created_at));
        Ok(nodes
            .into_iter()
            .map(|n| {
                let is_main = n.session_type == SessionType::Main;
                let active = n.id == *session;
                crate::checkpoints::BranchView {
                    title: n.title.unwrap_or_else(|| {
                        if is_main {
                            "Main".to_owned()
                        } else {
                            format!("Branch (depth {})", n.depth)
                        }
                    }),
                    id: n.id.0,
                    depth: n.depth,
                    is_main,
                    active,
                }
            })
            .collect())
    }

    async fn validate_chat_session(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<(), ClassifiedError> {
        let node = self
            .chat_session_manager()?
            .get_session(session)
            .await
            .map_err(|_| {
                ClassifiedError::Validation("unknown or invalid chat session".to_owned())
            })?;
        if node.state != hf_core::session::SessionState::Active {
            return Err(ClassifiedError::Validation(
                "chat session is not active".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn chat_session_guard(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, ClassifiedError> {
        // Validate before adding an entry to the lock map so arbitrary ids do
        // not retain mutexes. Validate again after acquisition to close the
        // race with a deletion that was already waiting on the same lock.
        self.validate_chat_session(session).await?;
        let guard = self.session_turn_lock(session).lock_owned().await;
        self.validate_chat_session(session).await?;
        Ok(guard)
    }

    fn chat_session_manager(&self) -> Result<&Arc<hf_session::SessionManager>, ClassifiedError> {
        self.session_manager.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("chat persistence is not configured".to_owned())
        })
    }

    fn chat_checkpoint_manager(
        &self,
    ) -> Result<&Arc<hf_session::ChatCheckpointManager>, ClassifiedError> {
        self.checkpoint_manager.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("chat checkpoints are not configured".to_owned())
        })
    }

    /// The conversation session manager (if a database is configured): the
    /// `hf-session` tree model with display + context transcripts.
    #[must_use]
    pub fn session_manager(&self) -> Option<&Arc<hf_session::SessionManager>> {
        self.session_manager.as_ref()
    }

    /// The lock serializing persistent chat operations on `session`, creating
    /// it on first use. Distinct sessions take distinct locks and are
    /// unaffected.
    #[must_use]
    pub fn session_turn_lock(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .session_turn_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(locks.entry(session.clone()).or_default())
    }

    /// Replace the guardrail engine (e.g. install an interactive HITL gate),
    /// returning the updated container.
    #[must_use]
    pub fn with_guardrails(mut self, guardrails: Guardrails) -> Self {
        self.guardrails = guardrails;
        self
    }

    /// Attach (or replace) the LLM provider pool, returning the updated
    /// container. Lets a command pick up a freshly-configured provider without
    /// an app restart.
    #[must_use]
    pub fn with_provider_pool(self, pool: Arc<dyn ProviderPool>) -> Self {
        // Recover a poisoned lock so the pool is installed rather than silently
        // dropped (see `reload_providers`).
        {
            let mut guard = self
                .provider_pool
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = Some(pool);
        }
        self
    }

    /// Per-provider health/usage for the Observability panel: freeze state,
    /// in-flight and total requests, and error counts. Empty when no provider
    /// pool is configured.
    pub async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        match self.provider_pool() {
            Some(pool) => pool.provider_statuses().await,
            None => Vec::new(),
        }
    }

    /// Thaw a provider in the live pool after a verifying health check.
    ///
    /// This is the manual recovery path for providers whose freeze has no
    /// auto-thaw (permanent freezes from invalid keys or exhausted quota):
    /// the pool health-checks the provider and only re-enables it when it
    /// responds, so a still-broken provider stays frozen.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Provider` when no pool is configured or the
    /// health check fails, and `ClassifiedError::Validation` when no provider
    /// with `provider_id` exists in the pool.
    pub async fn thaw_provider(&self, provider_id: &str) -> Result<(), ClassifiedError> {
        let pool = self
            .provider_pool()
            .ok_or_else(|| ClassifiedError::Provider("no LLM provider configured".to_owned()))?;
        let pid = hf_core::types::ProviderId::from_string(provider_id);
        // Distinguish "no such provider" (a client error) from a failed health
        // check (a provider error) instead of string-matching the pool's error.
        let known = pool.provider_statuses().await.iter().any(|s| s.id == pid);
        if !known {
            return Err(ClassifiedError::Validation(format!(
                "unknown provider id: {provider_id}"
            )));
        }
        pool.thaw(&pid)
            .await
            .map_err(|e| ClassifiedError::Provider(format!("thaw {provider_id}: {e}")))
    }

    /// A live system snapshot for the Observability panel: per-provider health
    /// and usage, the agent pool, and runtime memory counters. Merges live
    /// provider stats (concurrency/requests/errors) with the provider config
    /// (model/tags/limits), the canonical agent registry, and session
    /// diagnostics (tokens/cost by model).
    pub async fn system_snapshot(
        &self,
    ) -> Result<SystemSnapshot, crate::diagnostics::DiagnosticsError> {
        let statuses = self.provider_statuses().await;
        let configs = crate::config::get_providers();
        let cost = self.diagnostics.summary().await?;

        let providers = statuses
            .into_iter()
            .map(|s| {
                let cfg = configs.iter().find(|c| c.id == s.id.0);
                let model = cfg.map(|c| c.model.clone()).unwrap_or_default();
                let by_model = cost.by_model.iter().find(|m| m.model == model);
                let error_rate = if s.total_requests > 0 {
                    s.total_errors as f64 / s.total_requests as f64
                } else {
                    0.0
                };
                ProviderSnapshot {
                    id: s.id.0,
                    model,
                    tags: cfg.map(|c| c.tags.clone()).unwrap_or_default(),
                    is_frozen: s.is_frozen,
                    active_requests: s.active_requests,
                    max_concurrency: cfg.map_or(0, |c| c.max_concurrency),
                    total_requests: s.total_requests,
                    total_errors: s.total_errors,
                    error_rate,
                    total_input_tokens: by_model.map_or(0, |m| m.input_tokens),
                    total_output_tokens: by_model.map_or(0, |m| m.output_tokens),
                    estimated_cost_usd: by_model.map_or(0.0, |m| m.cost_usd),
                }
            })
            .collect();

        let (targets, crashes) = if let Some(store) = &self.store {
            (
                store.list_all_targets().await?.len(),
                store.list_all_crashes().await?.len(),
            )
        } else {
            (0, 0)
        };
        let memory = MemorySnapshot {
            pending_runs: self.active_run_ids().len(),
            interrupted_runs: self.interrupted_runs().len(),
            llm_calls: cost.calls,
            targets,
            crashes,
        };

        let mut agents = self.active_agent_pool();
        agents.available_slots = self.list_agent_definitions().len();

        Ok(SystemSnapshot {
            providers,
            agents,
            memory,
        })
    }

    /// A cheap snapshot of a target's on-disk artifacts (compiled harness,
    /// corpus size, crash inputs) for the Info panel. Pure filesystem reads --
    /// no sandbox, no LLM.
    #[must_use]
    pub fn artifact_summary(&self, project: &Path, target: &str) -> ArtifactSummary {
        let Ok(_workspace_operation) = Self::try_acquire_workspace_operation_now() else {
            return ArtifactSummary {
                harness_built: false,
                corpus_count: 0,
                crash_count: 0,
            };
        };
        let workspace = workspace_dir(project, target);
        let harness_built = workspace.join(harness_binary_name(target)).exists();
        let corpus_count =
            hf_corpus::list(&workspace.join("corpus")).map_or(0, |c| c.entries.len());
        let crash_count = collect_workspace_crash_inputs(&workspace).len();
        ArtifactSummary {
            harness_built,
            corpus_count,
            crash_count,
        }
    }

    /// Every crash persisted to the store, across all targets and runs.
    ///
    /// This is the correct source for a browse-all artifacts view: it returns
    /// crashes already ingested by triage regardless of which target's workspace
    /// they came from, rather than re-scanning a single (possibly wrong) target
    /// workspace. Returns an empty list when no database is configured.
    pub async fn all_crashes(&self) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        match self.store.as_ref() {
            Some(store) => Ok(store.list_all_crashes().await?),
            None => Ok(Vec::new()),
        }
    }

    /// Delete a single crash reproducer by id.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_crash(&self, crash_id: &str) -> Result<(), ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            store
                .delete_crash(crash_id)
                .await
                .map_err(|e| ClassifiedError::Internal(format!("delete crash: {e}")))?;
        }
        Ok(())
    }

    /// Delete one exact persisted corpus entry and its managed file.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_corpus_entry(
        &self,
        sha256: &str,
        expected_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let mut matches = store
            .list_all_corpus_entries_with_targets()
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .filter(|(_, entry)| entry.sha256 == sha256 && entry.path == expected_path);
        let (target_id, entry) = matches.next().ok_or_else(|| {
            ClassifiedError::Validation(format!("corpus entry not found: {sha256}"))
        })?;
        if matches.next().is_some() {
            return Err(ClassifiedError::Validation(format!(
                "corpus entry identity is ambiguous: {sha256} at {}",
                expected_path.display()
            )));
        }

        let quarantined = quarantine_corpus_entry(&entry.path, sha256)?;
        if let Err(error) = store.delete_corpus_entry(target_id, sha256).await {
            if let Some(quarantined) = quarantined {
                std::fs::rename(&quarantined, &entry.path).map_err(|restore_error| {
                    ClassifiedError::Internal(format!(
                        "delete corpus entry failed: {error}; restore failed: {restore_error}"
                    ))
                })?;
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        if let Some(quarantined) = quarantined {
            if let Err(error) = std::fs::remove_file(&quarantined) {
                tracing::warn!(
                    path = %quarantined.display(),
                    "deleted corpus row but could not remove quarantined file: {error}"
                );
            }
        }
        Ok(())
    }

    /// Clear every persisted crash and corpus entry (the Artifacts browser).
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn clear_all_artifacts(&self) -> Result<(), ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            store
                .clear_all_artifacts()
                .await
                .map_err(|e| ClassifiedError::Internal(format!("clear artifacts: {e}")))?;
        }
        Ok(())
    }

    /// Delete a single run and the crashes it produced.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_run(&self, run_id: &str) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        let run = store
            .get_run(id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {id}")))?;
        if !run_has_crash_evidence(run.status) || self.active_run_ids().contains(&id) {
            return Err(ClassifiedError::Validation(format!(
                "run {id} is still active and cannot be deleted"
            )));
        }
        self.ensure_run_is_not_qualification(store, id).await?;
        let evidence_root = self.run_evidence_root(store, &run).await?;
        store
            .delete_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Internal(format!("delete run: {e}")))?;
        if let Some(root) = evidence_root {
            std::fs::remove_dir_all(&root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "remove run evidence {}: {error}",
                    root.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Clear every persisted run and the crashes it produced (Run History).
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn clear_all_runs(&self) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let runs = store
            .list_runs(None)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        if runs.iter().any(|run| {
            !run_has_crash_evidence(run.status) || self.active_run_ids().contains(&run.id)
        }) {
            return Err(ClassifiedError::Validation(
                "run history contains an active run and cannot be cleared".to_owned(),
            ));
        }
        for run in &runs {
            self.ensure_run_is_not_qualification(store, run.id).await?;
        }
        let mut evidence_roots = Vec::new();
        for run in &runs {
            if let Some(root) = self.run_evidence_root(store, run).await? {
                evidence_roots.push(root);
            }
        }
        store
            .clear_all_runs()
            .await
            .map_err(|e| ClassifiedError::Internal(format!("clear runs: {e}")))?;
        for root in evidence_roots {
            std::fs::remove_dir_all(&root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "remove run evidence {}: {error}",
                    root.display()
                ))
            })?;
        }
        Ok(())
    }

    async fn ensure_run_is_not_qualification(
        &self,
        store: &Store,
        run_id: Uuid,
    ) -> Result<(), ClassifiedError> {
        let referenced = store
            .list_all_harnesses()
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .any(|harness| {
                harness.smoke_run.as_ref().and_then(|smoke| smoke.run_id) == Some(run_id)
            });
        if referenced {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} is retained harness qualification evidence"
            )));
        }
        Ok(())
    }

    async fn run_evidence_root(
        &self,
        store: &Store,
        run: &RunRecord,
    ) -> Result<Option<PathBuf>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(recorded) = run.evidence_dir.as_deref() else {
            return Ok(None);
        };
        let expected = run_output_relative(run.id);
        if Path::new(recorded) != expected {
            return Err(ClassifiedError::Validation(format!(
                "run {} has invalid evidence directory '{}'",
                run.id, recorded
            )));
        }
        let harness_id = run
            .config
            .as_ref()
            .map(|config| config.harness_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run {} has evidence but no harness attribution",
                    run.id
                ))
            })?;
        let harness = store.get_harness(harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation(format!("run {} evidence has no harness record", run.id))
        })?;
        let target = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|target| target.id == harness.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run {} evidence has no target record", run.id))
            })?;
        let workspace = workspace_dir(Path::new(&run.project_root), &target.symbol);
        let relative_root = PathBuf::from("runs").join(run.id.to_string());
        let candidate = workspace.join(&relative_root);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                resolve_workspace_directory(&workspace, &relative_root).map(Some)
            }
            Ok(_) => Err(ClassifiedError::Validation(format!(
                "run {} evidence root is not a regular directory: {}",
                run.id,
                candidate.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ClassifiedError::Validation(format!(
                "inspect run {} evidence root: {error}",
                run.id
            ))),
        }
    }

    /// Run history for a project (or all projects when `None`), newest first,
    /// enriched with the crash count per run. Powers the Runs history view.
    pub async fn run_history(
        &self,
        project: Option<&Path>,
    ) -> Result<Vec<RunHistoryItem>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let canonical_project = project.map(project_lookup_identity);
        let runs = store
            .list_runs(None)
            .await?
            .into_iter()
            .filter(|run| {
                canonical_project.as_ref().is_none_or(|canonical| {
                    stored_project_matches(Path::new(&run.project_root), canonical)
                })
            })
            .collect::<Vec<_>>();
        let crashes = store.list_all_crashes().await?;
        let harnesses: std::collections::HashMap<Uuid, Harness> = store
            .list_all_harnesses()
            .await?
            .into_iter()
            .map(|h| (h.id, h))
            .collect();
        let targets: std::collections::HashMap<Uuid, String> = store
            .list_all_targets()
            .await?
            .into_iter()
            .map(|t| (t.id, t.symbol))
            .collect();
        let mut crashes_by_run: std::collections::HashMap<Uuid, usize> =
            std::collections::HashMap::new();
        for c in &crashes {
            *crashes_by_run.entry(c.run_id).or_insert(0) += 1;
        }
        let mut items: Vec<RunHistoryItem> = runs
            .into_iter()
            .map(|r| {
                let target_id = r
                    .config
                    .as_ref()
                    .and_then(|cfg| harnesses.get(&cfg.harness_id))
                    .map(|h| h.target_id);
                let target = target_id.and_then(|id| targets.get(&id).cloned());
                // Presentation layers use this opaque key to compare a run only
                // with an experiment that has the same target, engine, budget,
                // sanitizer, corpus, environment, and engine arguments.
                let comparison_key = match (
                    r.status,
                    r.kind,
                    target_id,
                    r.config.as_ref(),
                    r.context_rev.as_deref(),
                ) {
                    (RunStatus::Done, RunKind::Campaign, Some(id), Some(cfg), Some(context)) => {
                        Some(auto_revert_comparison_key(id, cfg, context))
                    }
                    _ => None,
                };
                let duration_secs = r
                    .ended_at
                    .map(|end| (end - r.started_at).num_seconds().max(0));
                RunHistoryItem {
                    id: r.id.to_string(),
                    project_root: r.project_root,
                    target,
                    comparison_key,
                    engine: format!("{:?}", r.engine),
                    status: format!("{:?}", r.status),
                    started_at: r.started_at.to_rfc3339(),
                    ended_at: r.ended_at.map(|t| t.to_rfc3339()),
                    duration_secs,
                    // Prefer the fuzzer's recorded crash count (available even
                    // without triage); fall back to the deduped crashes table
                    // for runs recorded before stats were persisted.
                    crashes: r.crash_count.map_or_else(
                        || crashes_by_run.get(&r.id).copied().unwrap_or(0),
                        |c| usize::try_from(c).unwrap_or(0),
                    ),
                    edges: r.edges,
                    execs: r.execs,
                    harness_rev: r.harness_rev,
                    binary_rev: r.binary_rev,
                    evidence_dir: r.evidence_dir,
                }
            })
            .collect();
        items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        Ok(items)
    }

    /// The intra-run coverage/throughput curve for a run (empty if none was
    /// recorded, e.g. runs from before this was captured).
    pub async fn run_coverage_series(
        &self,
        run_id: &str,
    ) -> Result<Vec<CoverageSample>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        let Some(json) = store.run_samples(id).await? else {
            return Ok(Vec::new());
        };
        serde_json::from_str(&json)
            .map_err(|error| ClassifiedError::Storage(format!("decode run samples: {error}")))
    }

    /// The harness source a run used, for diffing revisions (empty if none was
    /// recorded).
    pub async fn run_harness_source(&self, run_id: &str) -> Result<String, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(String::new());
        };
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        Ok(store.run_harness_source(id).await?.unwrap_or_default())
    }

    /// Restore the exact source and executable a run used, so that promoted
    /// qualification becomes current again without recompiling different bytes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run/harness/evidence cannot be resolved,
    /// digest verification fails, or activation cannot be committed.
    pub async fn revert_harness_from_run(
        &self,
        run_id: &str,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let id = Uuid::parse_str(run_id)
            .map_err(|e| ClassifiedError::Validation(format!("bad run id: {e}")))?;
        let run = store
            .get_run(id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation("run not found".to_owned()))?;
        let harness_id = run.config.as_ref().map(|c| c.harness_id).ok_or_else(|| {
            ClassifiedError::Validation("run has no harness reference".to_owned())
        })?;
        let harness = store.get_harness(harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation("the harness for this run no longer exists".to_owned())
        })?;
        let symbol = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|t| t.id == harness.target_id)
            .map(|t| t.symbol)
            .ok_or_else(|| {
                ClassifiedError::Validation("the target for this run no longer exists".to_owned())
            })?;
        let project = std::path::PathBuf::from(&run.project_root);
        if harness.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "only a promoted historical harness can be restored".to_owned(),
            ));
        }
        let (qualification_run, expected_source, expected_binary) =
            qualification_evidence(&harness)?;
        if run.harness_rev.as_deref() != Some(expected_source)
            || run.binary_rev.as_deref() != Some(expected_binary)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {id} does not contain the exact promoted qualification artifacts"
            )));
        }
        if store.get_run(qualification_run).await?.is_none() {
            return Err(ClassifiedError::Validation(
                "the historical harness qualification run is missing".to_owned(),
            ));
        }

        let workspace = workspace_dir(&project, &symbol);
        let source_path = run_source_path(&workspace, &run)?;
        let binary_path = run_binary_path(&workspace, &run, &symbol)?;
        let source = std::fs::read_to_string(&source_path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "read historical harness source {}: {error}",
                source_path.display()
            ))
        })?;
        if source != harness.source {
            return Err(ClassifiedError::Validation(format!(
                "run {id} source does not match its promoted harness record"
            )));
        }

        self.authorize_recorded(
            Action::CompileHarness,
            "revert_harness_from_run",
            Some(&project),
        )
        .await?;
        let active_binary = workspace.join(harness_binary_name(&symbol));
        let backup = workspace.join(format!("harness.restore.{}.backup", Uuid::new_v4()));
        let had_active_binary = is_regular_file(&active_binary);
        if had_active_binary {
            std::fs::copy(&active_binary, &backup).map_err(|error| {
                ClassifiedError::Internal(format!("back up active harness binary: {error}"))
            })?;
        }
        let old_source = std::fs::read(workspace.join("harness.source")).ok();
        let old_id = std::fs::read(workspace.join("harness.active")).ok();

        let activate = (|| -> Result<(), ClassifiedError> {
            let restored = write_current_harness_binary(&workspace, &symbol, &binary_path)?;
            if sha256_file(&restored)? != expected_binary {
                return Err(ClassifiedError::Validation(
                    "restored harness binary failed post-copy digest verification".to_owned(),
                ));
            }
            write_current_harness_source(&workspace, &source)?;
            write_current_harness_id(&workspace, harness.id)?;
            Ok(())
        })();
        if let Err(error) = activate {
            if had_active_binary {
                let _ = std::fs::copy(&backup, &active_binary);
            } else {
                let _ = std::fs::remove_file(&active_binary);
            }
            if let Some(bytes) = old_source {
                let _ = std::fs::write(workspace.join("harness.source"), bytes);
            }
            if let Some(bytes) = old_id {
                let _ = std::fs::write(workspace.join("harness.active"), bytes);
            }
            let _ = std::fs::remove_file(&backup);
            return Err(error);
        }
        let _ = std::fs::remove_file(&backup);
        self.verify_harness_qualification(&project, &symbol, &harness)
            .await?;
        Ok(CompileOutcome {
            status: HarnessStatus::Promoted,
            binary_name: harness_binary_name(&symbol),
            workspace,
        })
    }

    /// The target a persisted run exercised, resolved through its harness
    /// (`run.config.harness_id -> harness.target_id`). `None` if unrecorded.
    async fn run_target_id(
        &self,
        store: &Store,
        run: &RunRecord,
    ) -> Result<Option<Uuid>, ClassifiedError> {
        let Some(harness_id) = run.config.as_ref().map(|c| c.harness_id) else {
            return Ok(None);
        };
        Ok(store
            .get_harness(harness_id)
            .await?
            .map(|harness| harness.target_id))
    }

    /// The effective auto-revert policy for a project: its stored per-project
    /// override when one is set, otherwise the global policy from config.
    async fn effective_auto_revert_policy(
        &self,
        project: &Path,
    ) -> Result<crate::config::AutoRevertPolicy, ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            let key = project.to_string_lossy().to_string();
            if let Some(o) = store.project_auto_revert(&key).await? {
                return Ok(crate::config::AutoRevertPolicy {
                    enabled: o.enabled,
                    threshold_pct: o.threshold_pct,
                    notify_only: o.notify_only,
                });
            }
        }
        Ok(crate::config::auto_revert_policy())
    }

    /// A project's auto-revert override, or `None` when it inherits the global
    /// policy. For the settings UI to show whether an override is in effect.
    pub async fn project_auto_revert_override(
        &self,
        project: &Path,
    ) -> Result<Option<ProjectAutoRevert>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let key = project.to_string_lossy().to_string();
        Ok(store.project_auto_revert(&key).await?)
    }

    /// The effective auto-revert policy for a project (its override merged over
    /// the global default) plus whether an override is in effect -- for a badge
    /// that shows the active project's resolved policy.
    pub async fn effective_auto_revert_view(
        &self,
        project: &Path,
    ) -> Result<EffectiveAutoRevert, ClassifiedError> {
        let overridden = self.project_auto_revert_override(project).await?.is_some();
        let p = self.effective_auto_revert_policy(project).await?;
        Ok(EffectiveAutoRevert {
            enabled: p.enabled,
            threshold_pct: p.threshold_pct,
            notify_only: p.notify_only,
            overridden,
        })
    }

    /// Every project's auto-revert override, keyed by project root -- so a
    /// projects overview can badge which ones diverge from the global policy.
    /// Empty when no store is configured or no project overrides.
    pub async fn project_auto_revert_overrides(
        &self,
    ) -> Result<std::collections::HashMap<String, ProjectAutoRevert>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(std::collections::HashMap::new());
        };
        Ok(store
            .all_project_auto_reverts()
            .await?
            .into_iter()
            .collect())
    }

    /// Set (or replace) a project's auto-revert override.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the write fails.
    pub async fn set_project_auto_revert_override(
        &self,
        project: &Path,
        enabled: bool,
        threshold_pct: f64,
        notify_only: bool,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        if !crate::config::valid_auto_revert_threshold(threshold_pct) {
            return Err(ClassifiedError::Validation(format!(
                "auto-revert threshold must be a finite percentage in (0, 100], got {threshold_pct}"
            )));
        }
        store
            .set_project_auto_revert(
                &key,
                ProjectAutoRevert {
                    enabled,
                    threshold_pct,
                    notify_only,
                },
            )
            .await?;
        Ok(())
    }

    /// Clear a project's auto-revert override, so it inherits the global policy.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the delete fails.
    pub async fn clear_project_auto_revert_override(
        &self,
        project: &Path,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        store.clear_project_auto_revert(&key).await?;
        Ok(())
    }

    /// Evaluate the auto-revert policy for a just-finished run and, if it
    /// triggered, restore the most recent comparable (last-good) harness revision.
    ///
    /// The policy fires only when it is enabled and this run's harness revision
    /// differs from a comparable finished run for the same target *and* this
    /// run's peak edge coverage dropped by at least the configured percentage
    /// versus a prior run with the same target, engine, budget, resources,
    /// sanitizer, corpus location, environment, and engine arguments. The
    /// restore reuses [`Self::revert_harness_from_run`], so exact-artifact
    /// activation is HITL-gated exactly like a manual revert -- a denied approval
    /// simply leaves the harness unchanged. Returns the outcome only when the
    /// revert applied.
    async fn maybe_auto_revert(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        this_edges: u64,
        this_rev: Option<&str>,
    ) -> Option<AutoRevertOutcome> {
        let policy = match self.effective_auto_revert_policy(project).await {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read its effective policy");
                return None;
            }
        };
        if !policy.enabled {
            return None;
        }
        let store = self.store.as_ref()?;
        // Without a recorded revision we cannot attribute a change to a harness.
        let this_rev = this_rev.filter(|r| !r.is_empty())?;
        // The most recent comparable finished run for this same target, before
        // this one, that recorded edge coverage and a harness revision.
        let key = project.to_string_lossy().to_string();
        let mut runs = match store.list_runs(Some(&key)).await {
            Ok(runs) => runs,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read comparable runs");
                return None;
            }
        };
        runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        let this_run = runs.iter().find(|r| r.id == this_run_id).cloned()?;
        let this_config = this_run.config.as_ref()?;
        if this_run.status != RunStatus::Done || this_run.kind != RunKind::Campaign {
            return None;
        }
        let this_context = this_run
            .context_rev
            .as_deref()
            .filter(|value| !value.is_empty())?;
        // Resolve the target through the run's persisted harness rather than
        // re-discovering it as C. This keeps C++, Rust, and future language runs
        // eligible for the same rollback policy.
        let target_id = match self.run_target_id(store, &this_run).await {
            Ok(Some(target_id)) => target_id,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not resolve the current run target");
                return None;
            }
        };
        let mut prev = None;
        for r in runs {
            if r.id == this_run_id
                || r.status != RunStatus::Done
                || r.kind != RunKind::Campaign
                || r.edges.is_none()
                || r.harness_rev.is_none()
                || r.harness_rev.as_deref() == Some(this_rev)
                || r.context_rev.as_deref() != Some(this_context)
            {
                continue;
            }
            if r.started_at >= this_run.started_at {
                continue;
            }
            let Some(previous_config) = r.config.as_ref() else {
                continue;
            };
            if !auto_revert_baseline_compatible(previous_config, this_config) {
                continue;
            }
            let candidate_target = match self.run_target_id(store, &r).await {
                Ok(candidate_target) => candidate_target,
                Err(error) => {
                    tracing::warn!(%error, "auto-revert could not resolve a baseline run target");
                    return None;
                }
            };
            if candidate_target == Some(target_id) {
                prev = Some(r);
                break;
            }
        }
        let prev = prev?;
        let prev_rev = prev.harness_rev.clone().unwrap_or_default();
        let prev_edges = prev.edges.unwrap_or(0);
        let drop_pct = auto_revert_decision(
            &prev_rev,
            this_rev,
            prev_edges,
            this_edges,
            policy.threshold_pct,
        )?;

        let prev_id = prev.id.to_string();
        let outcome = |reverted: bool| AutoRevertOutcome {
            reverted_to_run: prev_id.clone(),
            from_rev: this_rev.to_owned(),
            to_rev: prev_rev.clone(),
            previous_edges: prev_edges,
            regressed_edges: this_edges,
            drop_pct,
            reverted,
        };

        // Notify-only: report the regression (journal + surfaced outcome) but do
        // not touch the harness. This is the safe default for headless/scheduled
        // campaigns, which run permissively and would otherwise mutate unattended.
        if policy.notify_only {
            let detail = format!(
                "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev}; comparable last-good {prev_rev} is run {prev_id} (notify-only, not restored)"
            );
            tracing::warn!("auto-revert (notify-only): {detail}");
            self.run_journal
                .note(this_run_id, "auto-revert-notify", &detail);
            let out = outcome(false);
            self.persist_auto_revert_event(project, target, this_run_id, &out)
                .await;
            return Some(out);
        }

        // Regression confirmed: restore the comparable baseline's harness. The
        // recompile is HITL-gated inside `harness_compile`; if approval is denied
        // the active canonical revision and binary remain unchanged.
        match self.revert_harness_from_run(&prev_id).await {
            Ok(_) => {
                let detail = format!(
                    "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev} -> restored comparable baseline {prev_rev} from run {prev_id}"
                );
                tracing::warn!("auto-revert: {detail}");
                self.run_journal.note(this_run_id, "auto-revert", &detail);
                let out = outcome(true);
                self.persist_auto_revert_event(project, target, this_run_id, &out)
                    .await;
                Some(out)
            }
            Err(e) => {
                tracing::warn!("auto-revert declined or failed: {e}");
                None
            }
        }
    }

    /// Persist an auto-revert firing to the durable audit trail (best-effort).
    async fn persist_auto_revert_event(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        out: &AutoRevertOutcome,
    ) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let ev = AutoRevertEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            project_root: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            run_id: this_run_id.to_string(),
            from_rev: out.from_rev.clone(),
            to_rev: out.to_rev.clone(),
            previous_edges: out.previous_edges,
            regressed_edges: out.regressed_edges,
            drop_pct: out.drop_pct,
            reverted: out.reverted,
        };
        if let Err(e) = store.record_auto_revert_event(&ev).await {
            tracing::warn!("failed to record auto-revert event: {e}");
        }
    }

    /// The auto-revert audit trail (newest first), scoped to `project` when given
    /// or across all projects otherwise. Empty without a store.
    pub async fn auto_revert_events(
        &self,
        project: Option<&Path>,
        limit: usize,
    ) -> Result<Vec<AutoRevertEvent>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let key = project.map(|p| p.to_string_lossy().to_string());
        Ok(store
            .list_auto_revert_events(key.as_deref(), i64::try_from(limit).unwrap_or(200))
            .await?)
    }

    // -- Guardrail decision audit --------------------------------------------

    /// Authorize `action`, appending the decision to the durable policy audit
    /// trail. Every authorizing service entry point goes through here so the
    /// record is uniform: the policy outcome, and the approval-gate outcome
    /// when the gate was consulted.
    ///
    /// Recording is best-effort (AGENTS.md 2.5): a storage failure is logged
    /// and never changes the authorization outcome, which stays exactly what
    /// [`Guardrails::authorize`] returns.
    pub(crate) async fn authorize_recorded(
        &self,
        action: Action,
        origin: &'static str,
        project: Option<&Path>,
    ) -> Result<(), hf_guardrails::GuardrailError> {
        let action_kind = action.kind();
        let risk_tier = action.risk();
        let policy_decision = self.guardrails.policy().evaluate(&action);
        let outcome = self.guardrails.authorize(action).await;
        let (decision, detail) = match (&policy_decision, &outcome) {
            (Decision::RequireApproval { reason, .. }, Ok(())) => {
                ("approved", Some(reason.clone()))
            }
            (Decision::RequireApproval { .. }, Err(error)) => {
                ("denied_by_operator", Some(error.to_string()))
            }
            (Decision::Deny { reason }, _) => ("denied", Some(reason.clone())),
            (Decision::Allow, Ok(())) => ("allowed", None),
            (Decision::Allow, Err(error)) => ("denied", Some(error.to_string())),
        };
        self.record_guardrail_decision(GuardrailDecisionRecord {
            id: Uuid::new_v4().to_string(),
            decided_at: Utc::now(),
            action: action_kind.to_owned(),
            risk_tier: risk_tier.as_str().to_owned(),
            decision: decision.to_owned(),
            origin: origin.to_owned(),
            project: project.map(|path| path.to_string_lossy().into_owned()),
            detail: detail.map(|detail| bounded_guardrail_detail(&detail)),
        })
        .await;
        outcome
    }

    /// Persist one guardrail decision, then prune the trail to its retention
    /// window. Failures are logged, never propagated: the audit write must not
    /// change the operation's outcome.
    async fn record_guardrail_decision(&self, record: GuardrailDecisionRecord) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if let Err(error) = store.record_guardrail_decision(&record).await {
            tracing::warn!(%error, "failed to record guardrail decision");
            return;
        }
        if let Err(error) = store
            .prune_guardrail_decisions(GUARDRAIL_DECISION_RETENTION)
            .await
        {
            tracing::warn!(%error, "failed to prune guardrail decisions");
        }
    }

    /// The guardrail decision audit trail (newest first), capped at `limit`
    /// rows. Empty without a store.
    pub async fn policy_decisions(
        &self,
        limit: usize,
    ) -> Result<Vec<GuardrailDecisionRecord>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(store
            .list_guardrail_decisions(i64::try_from(limit).unwrap_or(200))
            .await?)
    }

    /// A JSON bundle of a project's persisted fuzzing data (targets, runs,
    /// harnesses, crashes, corpus) for hand-off to other tools. Scoped by
    /// project; pass `None` to export everything.
    pub async fn export_project_data(
        &self,
        project: Option<&Path>,
    ) -> Result<serde_json::Value, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(store) = self.store.as_ref() else {
            return Ok(serde_json::json!({ "error": "no database configured" }));
        };
        let canonical_project = project.map(canonical_project_root).transpose()?;
        let key = canonical_project
            .as_ref()
            .map(|path| path.to_string_lossy().to_string());
        let targets = store.list_all_targets().await?;
        let scoped_targets: Vec<_> = match canonical_project.as_ref() {
            Some(canonical) => targets
                .into_iter()
                .filter(|target| stored_project_matches(&target.project_root, canonical))
                .collect(),
            None => targets,
        };
        let target_ids: std::collections::HashSet<Uuid> =
            scoped_targets.iter().map(|t| t.id).collect();
        let harnesses: Vec<_> = store
            .list_all_harnesses()
            .await?
            .into_iter()
            .filter(|h| key.is_none() || target_ids.contains(&h.target_id))
            .collect();
        let crashes: Vec<_> = store
            .list_all_crashes()
            .await?
            .into_iter()
            .filter(|c| key.is_none() || target_ids.contains(&c.target_id))
            .collect();
        let corpus: Vec<_> = store
            .list_all_corpus_entries_with_targets()
            .await?
            .into_iter()
            .filter(|(target_id, _)| key.is_none() || target_ids.contains(target_id))
            .map(|(_, entry)| entry)
            .collect();
        let runs = self.run_history(canonical_project.as_deref()).await?;
        let evidence: Vec<_> = scoped_targets
            .iter()
            .map(|target| {
                let workspace = workspace_dir(&target.project_root, &target.symbol);
                serde_json::json!({
                    "target_id": target.id,
                    "target": target.symbol,
                    "workspace": workspace,
                    "active_harness_id": read_current_harness_id(&workspace),
                    "active_harness_source": read_current_harness_source(&workspace),
                    "binary": workspace.join(harness_binary_name(&target.symbol)),
                    "binary_present": workspace.join(harness_binary_name(&target.symbol)).is_file(),
                    "corpus_dir": workspace.join("corpus"),
                    "run_evidence_root": workspace.join("runs"),
                    "legacy_crash_dir": workspace.join("out"),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "schema": "hobot_fuzz.export.v2",
            "generated_at": Utc::now().to_rfc3339(),
            "tool_version": env!("CARGO_PKG_VERSION"),
            "project": key,
            "targets": scoped_targets,
            "harnesses": harnesses,
            "crashes": crashes,
            "corpus": corpus,
            "runs": runs,
            "evidence": evidence,
        }))
    }

    /// Every corpus entry persisted to the store, across all targets.
    ///
    /// The browse-all counterpart to [`Self::corpus_list`] (which is scoped to a
    /// single target's on-disk corpus). Returns an empty list when no database
    /// is configured.
    pub async fn all_corpus_entries(
        &self,
    ) -> Result<Vec<hf_core::corpus::CorpusEntry>, ClassifiedError> {
        match self.store.as_ref() {
            Some(store) => Ok(store.list_all_corpus_entries().await?),
            None => Ok(Vec::new()),
        }
    }

    /// Internal-team dashboard summary for the active project/target.
    pub async fn workbench_dashboard(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Result<crate::workbench::WorkbenchDashboard, ClassifiedError> {
        crate::workbench::dashboard(self.store.as_deref(), project, target).await
    }

    /// Generated harnesses that need human review or promotion.
    pub async fn harness_review_queue(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Result<Vec<crate::workbench::HarnessReviewItem>, ClassifiedError> {
        crate::workbench::harness_review_queue(self.store.as_deref(), project, target).await
    }

    /// Build a human-reviewable issue draft for a crash, targeting the fuzzed
    /// project's configured GitHub/GitLab repository.
    ///
    /// Non-publishing: it returns a title, Markdown body, labels, the provider,
    /// and a prefilled new-issue URL. Use [`Self::file_issue`] to actually file it.
    pub async fn issue_export(
        &self,
        project: &Path,
        crash_id: &str,
    ) -> Result<crate::workbench::IssueExport, ClassifiedError> {
        crate::workbench::issue_export(self.store.as_deref(), project, crash_id).await
    }

    /// Whether a usable issue-tracker integration is configured (provider + repo).
    #[must_use]
    pub fn issue_tracker_configured(&self) -> bool {
        crate::issue_tracker::is_configured()
    }

    /// File a crash as an issue via the configured provider's API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the tracker is unconfigured, lacks a token,
    /// the crash is unknown, or the API rejects the request.
    pub async fn file_issue(
        &self,
        crash_id: &str,
    ) -> Result<crate::issue_tracker::CreatedIssue, ClassifiedError> {
        crate::workbench::file_issue(self.store.as_deref(), crash_id).await
    }

    /// Verify the issue-tracker URL + token without filing anything.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, tokenless, or the API rejects it.
    pub async fn issue_tracker_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::issue_tracker::load_config()?;
        let token = crate::issue_tracker::resolve_token(&cfg)?;
        let client = crate::issue_tracker::IssueTrackerClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// Saved editable report drafts for the internal workbench.
    pub fn list_report_drafts(
        &self,
    ) -> Result<Vec<crate::report_store::ReportDraft>, ClassifiedError> {
        crate::report_store::list_report_drafts()
    }

    /// Save or update one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid input and storage errors for failed
    /// filesystem writes.
    pub fn save_report_draft(
        &self,
        id: Option<String>,
        title: &str,
        project: &str,
        target: Option<&str>,
        status: &str,
        content: &str,
    ) -> Result<crate::report_store::ReportDraft, ClassifiedError> {
        crate::report_store::save_report_draft(id, title, project, target, status, content)
    }

    /// Delete one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid ids and storage errors for failed
    /// filesystem deletion.
    pub fn delete_report_draft(&self, id: &str) -> Result<(), ClassifiedError> {
        crate::report_store::delete_report_draft(id)
    }

    /// Ingest a document into a project's knowledge base.
    ///
    /// Converts the file (PDF, Office, HTML, CSV, ...) to Markdown with
    /// `markitdown` inside the sandbox (offline; network-isolated), stores the
    /// Markdown under the per-project knowledge docs dir, and re-indexes the
    /// project so the harness-author and triage agents can search it (specs,
    /// RFCs, threat models). Returns the post-index stats.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the file is missing, the sandbox conversion
    /// fails, or the Markdown cannot be written.
    pub async fn ingest_document(
        &self,
        project: &Path,
        file: &Path,
    ) -> Result<crate::knowledge::KnowledgeStats, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if !is_regular_file(file) {
            return Err(ClassifiedError::Validation(format!(
                "document is not a regular file: {}",
                file.display()
            )));
        }
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ClassifiedError::Validation("invalid document name".to_owned()))?;

        // Stage below the Docker runtime's approved workspace root, not in the
        // durable knowledge directory (which lives elsewhere in app data).
        prepare_configured_workspace_root()?;
        let docs = crate::knowledge::docs_dir(project);
        let staging = document_staging_dir(project, Uuid::new_v4());
        std::fs::create_dir_all(&staging)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir staging: {e}")))?;
        let staging_guard = StagingDirectoryGuard(staging.clone());
        std::fs::copy(file, staging.join(name))
            .map_err(|e| ClassifiedError::Internal(format!("stage document: {e}")))?;

        let cmd = vec!["markitdown".to_owned(), format!("/work/{name}")];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let result = self.runtime.run_command(&cmd, &staging, &limits).await;
        drop(staging_guard);
        let result = result?.require_completed("document conversion")?;
        if result.exit_code != 0 || result.stdout.trim().is_empty() {
            return Err(ClassifiedError::Internal(format!(
                "markitdown failed (exit {}): {}",
                result.exit_code,
                result.stderr.lines().last().unwrap_or_default()
            )));
        }

        // Persist the Markdown under the docs dir, then re-index.
        std::fs::create_dir_all(&docs)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir docs: {e}")))?;
        let stem = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        std::fs::write(docs.join(format!("{stem}.md")), &result.stdout)
            .map_err(|e| ClassifiedError::Internal(format!("write doc markdown: {e}")))?;

        crate::knowledge::index_project(project)
    }

    /// Reload the provider pool from the current on-disk config, swapping it in
    /// for every consumer of this container (and its clones) so Settings edits
    /// apply live without a restart. Returns `true` if a pool was loaded (i.e.
    /// the config has at least one enabled provider).
    pub fn reload_providers(&self) -> bool {
        // Mirror `bootstrap`'s config-or-env resolution: a provider configured
        // only via `HF_PROVIDER_API_KEY` must survive a Settings reload. Using
        // config alone here would swap in `None` and silently disable the LLM
        // (e.g. after saving an unrelated setting) until a restart.
        let pool = provider_pool_from_config().or_else(provider_pool_from_env);
        let loaded = pool.is_some();
        // Recover a poisoned lock rather than skipping the swap: dropping the
        // write on poison would keep the stale pool while still returning
        // `loaded = true`, so the caller (UI) believes a reload that never
        // happened succeeded.
        let mut guard = self
            .provider_pool
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = pool;
        loaded
    }

    /// The active guardrail engine.
    #[must_use]
    pub fn guardrails(&self) -> &Guardrails {
        &self.guardrails
    }

    /// Ask the operator to approve an agent's tool call, for an agent running
    /// with manual autonomy that gates every action. Returns whether it was
    /// approved. Tighten-only: it only ever adds a prompt via the guardrail
    /// gate; it never bypasses the policy or auto-allows.
    pub async fn approve_agent_tool(&self, tool: &str, agent: &str) -> bool {
        self.guardrails
            .require_approval(
                &Action::AgentTool {
                    name: tool.to_owned(),
                },
                &format!("agent '{agent}' runs with manual autonomy and requests tool '{tool}'"),
            )
            .await
    }

    /// Construct the canonical container used by every presentation layer
    /// (CLI, web, GUI): a Docker (or stub) runtime, an LLM provider pool from
    /// the environment, and the persistence store from `HF_DB_PATH`.
    ///
    /// Storage and the provider pool are optional: when unavailable the
    /// container still serves every non-persistent, non-LLM operation, so a
    /// missing database or API key degrades gracefully instead of failing.
    pub async fn bootstrap() -> Self {
        let runtime = runtime_from_env();
        let config_dir = crate::init::config_dir();
        let private_config_ready = crate::config::secure_config_directory(&config_dir).map_or_else(
            |error| {
                tracing::warn!(
                    "ignoring file-based providers because private config validation failed in {}: {error}",
                    config_dir.display()
                );
                false
            },
            |()| true,
        );
        // Prefer the GUI-managed config/providers.toml; fall back to env vars.
        let provider_pool = private_config_ready
            .then(provider_pool_from_config)
            .flatten()
            .or_else(provider_pool_from_env);
        let store = match Store::connect_from_env().await {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                tracing::warn!("persistence disabled: {e}");
                None
            }
        };
        let (session_manager, checkpoint_manager) = match store.as_ref().map(build_session_managers)
        {
            Some((sessions, checkpoints)) => (Some(sessions), Some(checkpoints)),
            None => (None, None),
        };
        // Open the persistent run journal and detect runs interrupted by a prior
        // crash/quit (scopes opened but never closed). Reconcile the DB so those
        // runs are not left stuck as `Running` forever.
        let run_journal = Arc::new(crate::recovery::RunJournal::open(
            crate::init::user_app_dir().join("run_journal.jsonl"),
        ));
        if let Some(store) = &store {
            for run in run_journal.interrupted() {
                let id = match run.run_id.parse::<Uuid>() {
                    Ok(id) => id,
                    Err(error) => {
                        tracing::error!(
                            run_id = %run.run_id,
                            %error,
                            "cannot repair interrupted run with an invalid id"
                        );
                        continue;
                    }
                };
                if let Err(error) = store
                    .set_run_status(id, RunStatus::Failed, Some(Utc::now()))
                    .await
                {
                    tracing::error!(run_id = %id, %error, "failed to repair interrupted run status");
                }
            }
        }
        // Persist diagnostics to the database when one is configured, so LLM
        // cost/usage accumulates across restarts; otherwise keep it in-memory.
        let diagnostics = Arc::new(match &store {
            Some(store) => crate::diagnostics::DiagnosticsRecorder::with_store(
                build_cost_map(),
                Arc::new(hf_diagnostics::SqliteTraceStore::new(store.pool().clone())),
            ),
            None => crate::diagnostics::DiagnosticsRecorder::new(build_cost_map()),
        });
        let provider_pool = Arc::new(std::sync::RwLock::new(provider_pool));
        // Recover frozen providers (including permanent freezes, which have no
        // auto-thaw) on the pool's configured health-check cadence. The guard
        // is stored on the container so the task dies with it.
        let health_task = Arc::new(spawn_provider_health_checks(Arc::clone(&provider_pool)));
        Self {
            runtime,
            provider_pool,
            store,
            session_manager,
            guardrails: Guardrails::from_env(),
            checkpoint_manager,
            diagnostics,
            run_journal,
            active_runs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            active_agents: Arc::new(std::sync::Mutex::new(Vec::new())),
            session_turn_locks: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            scheduler_events: Arc::new(std::sync::Mutex::new(None)),
            _health_task: Some(health_task),
        }
    }

    /// The current provider pool (if an LLM is configured). Returns an owned
    /// handle snapshotted from the swappable cell, so a concurrent
    /// [`Self::reload_providers`] never invalidates it mid-use.
    #[must_use]
    pub fn provider_pool(&self) -> Option<Arc<dyn ProviderPool>> {
        self.provider_pool.read().ok().and_then(|g| g.clone())
    }

    /// The persistence store (if a database is configured).
    #[must_use]
    pub fn store(&self) -> Option<&Arc<Store>> {
        self.store.as_ref()
    }

    /// Late-bind the campaign scheduler so service operations emit scheduler
    /// events (crash found, run terminated) into its event bridge. Called by
    /// `CampaignScheduler::try_start`; the slot is shared across clones of
    /// this container, so one bind covers every surface built from it.
    pub(crate) fn bind_scheduler_events(&self, manager: &Arc<hf_scheduler::SchedulerManager>) {
        if let Ok(mut slot) = self.scheduler_events.lock() {
            *slot = Some(Arc::downgrade(manager));
        }
    }

    /// Emit a scheduler event through the bound campaign scheduler, if any.
    ///
    /// Best-effort by design: a container without a scheduler (one-shot CLI
    /// invocations) or a stopped scheduler simply drops the event, and neither
    /// case may fail the operation that produced it.
    async fn emit_scheduler_event(&self, event_type: &str, payload: serde_json::Value) {
        let manager = self
            .scheduler_events
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade));
        if let Some(manager) = manager {
            manager
                .emit_event(hf_scheduler::IncomingEvent {
                    event_type: event_type.to_owned(),
                    payload: Some(payload),
                    timestamp: Utc::now(),
                })
                .await;
        }
    }

    /// Runtime adapter used by service-owned optional subsystems.
    #[must_use]
    #[cfg(feature = "automotive-scapy")]
    pub(crate) fn runtime_adapter(&self) -> &Arc<dyn RuntimeAdapter> {
        &self.runtime
    }

    /// Clear all learned knowledge across every project: discovered targets and
    /// their harnesses, corpus entries, and crashes, plus all runs.
    /// Configuration and on-disk workspaces are left untouched. A no-op when no
    /// store is configured.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the delete fails.
    pub async fn clear_knowledge(&self) -> Result<(), ClassifiedError> {
        if let Some(store) = &self.store {
            store
                .clear_knowledge()
                .await
                .map_err(|e| ClassifiedError::Internal(format!("clear knowledge: {e}")))?;
        }
        Ok(())
    }

    /// Delete every trace of a single project: its persisted records (targets,
    /// runs, harnesses, corpus entries, crashes) and its on-disk workspace
    /// (compiled harnesses, corpora, crash reproducers, coverage builds). Other
    /// projects are untouched. The DB delete and the disk delete are done
    /// together so a project never lingers in one place after being cleared from
    /// the other. A no-op when no store is configured.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if either the DB delete or the workspace
    /// removal fails.
    pub async fn delete_project(&self, project: &Path) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // The DB stores canonical project roots (discovery/run inserts go through
        // `canonical_project_root`), and the on-disk workspace slug canonicalizes
        // too. Delete both halves under one canonical identity so a raw, symlinked,
        // or trailing-slash caller path can never wipe the disk while orphaning the
        // DB rows (e.g. `/tmp/p` vs the stored `/private/tmp/p` on macOS).
        let identity = project_lookup_identity(project);
        if let Some(store) = &self.store {
            let key = identity.to_string_lossy();
            store
                .delete_project(&key)
                .await
                .map_err(|e| ClassifiedError::Internal(format!("delete project: {e}")))?;
        }
        let dir = project_workspace_dir(&identity);
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            // Already absent is success -- nothing on disk to reclaim.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ClassifiedError::Internal(format!(
                    "delete project workspace {}: {e}",
                    dir.display()
                )));
            }
        }
        Ok(())
    }

    /// Register an executing agent turn labelled `label` (e.g. the agent id) so
    /// the Observability panel reflects live activity. The turn stays tracked
    /// until the returned [`AgentTurnGuard`] is dropped.
    pub fn track_agent(&self, label: &str) -> AgentTurnGuard {
        if let Ok(mut agents) = self.active_agents.lock() {
            agents.push(label.to_owned());
        }
        AgentTurnGuard {
            active_agents: Arc::clone(&self.active_agents),
            label: label.to_owned(),
        }
    }

    /// A snapshot of the agent turns currently executing.
    fn active_agent_pool(&self) -> AgentPoolSnapshot {
        let labels = self
            .active_agents
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default();
        let instances: Vec<AgentInstanceSnapshot> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| AgentInstanceSnapshot {
                instance_id: format!("turn-{i}"),
                agent_name: label.clone(),
                state: "running".to_owned(),
                elapsed_ms: 0,
                iterations: 0,
                tokens_used: 0,
            })
            .collect();
        AgentPoolSnapshot {
            active_instances: instances.len(),
            available_slots: 0,
            total_instances: instances.len(),
            instances,
        }
    }

    /// Enter a workspace-backed service operation. Both guards are `Send`, so
    /// callers may retain the lease across sandbox, storage, and provider awaits.
    async fn acquire_workspace_operation(
        &self,
    ) -> Result<WorkspaceOperationLease, ClassifiedError> {
        let root = workspace_root();
        self.acquire_workspace_operation_at(&root).await
    }

    pub(crate) async fn acquire_workspace_operation_at(
        &self,
        root: &Path,
    ) -> Result<WorkspaceOperationLease, ClassifiedError> {
        let (root, gate) = workspace_operation_gate(root)?;
        let process_guard = gate.read_owned().await;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock_shared()
            .map_err(|error| workspace_lock_error(error, false))?;
        Ok(WorkspaceOperationLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    /// Enter a synchronous workspace read without racing whole-root cleanup.
    fn try_acquire_workspace_operation_now() -> Result<WorkspaceOperationLease, ClassifiedError> {
        let root = workspace_root();
        let (root, gate) = workspace_operation_gate(&root)?;
        let process_guard = gate.try_read_owned().map_err(|_| {
            ClassifiedError::Validation(
                "workspace operation cannot start while workspace cleanup is active".to_owned(),
            )
        })?;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock_shared()
            .map_err(|error| workspace_lock_error(error, false))?;
        Ok(WorkspaceOperationLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    /// Take the whole-workspace cleanup lease without blocking a runtime thread.
    /// Cleanup is an explicit user action, so an overlapping operation is
    /// rejected and can be retried after that operation finishes.
    fn try_acquire_workspace_cleanup(
        root: &Path,
    ) -> Result<WorkspaceCleanupLease, ClassifiedError> {
        let (root, gate) = workspace_operation_gate(root)?;
        let process_guard = gate.try_write_owned().map_err(|_| {
            ClassifiedError::Validation(
                "workspace cannot be cleared while another workspace operation is active"
                    .to_owned(),
            )
        })?;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock()
            .map_err(|error| workspace_lock_error(error, true))?;
        Ok(WorkspaceCleanupLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    /// Delete every on-disk fuzz workspace (compiled harnesses, corpora, crash
    /// reproducers, coverage builds), reclaiming disk space. Since the
    /// workspace is now persistent, it grows over time; this is the affordance
    /// to reset it. Persistent DB records (targets, runs, crashes) are left
    /// intact -- re-running a campaign rebuilds the workspace on disk.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the workspace directory cannot be removed.
    pub fn clear_workspace(&self) -> Result<(), ClassifiedError> {
        let (root, uses_trusted_default) = configured_workspace_root();
        self.clear_workspace_at_with_adoption(&root, uses_trusted_default)
    }

    #[cfg(test)]
    fn clear_workspace_at(&self, root: &Path) -> Result<(), ClassifiedError> {
        self.clear_workspace_at_with_adoption(root, false)
    }

    fn clear_workspace_at_with_adoption(
        &self,
        root: &Path,
        adopt_legacy_default: bool,
    ) -> Result<(), ClassifiedError> {
        let _workspace_cleanup = Self::try_acquire_workspace_cleanup(root)?;
        let active_runs = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?;
        if !active_runs.is_empty() {
            return Err(ClassifiedError::Validation(
                "workspace cannot be cleared while an active fuzz run exists".to_owned(),
            ));
        }
        match std::fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect workspace root {}: {error}",
                    root.display()
                )));
            }
        }
        prepare_managed_workspace_root_with_adoption(root, adopt_legacy_default)?;
        clear_managed_workspace_root(root)
    }

    // -- Discovery --------------------------------------------------------

    /// Discover fuzzing targets in a project.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the project root cannot be read.
    pub async fn discover(
        &self,
        project: &Path,
        lang: TargetLanguage,
    ) -> Result<TargetInventory, ClassifiedError> {
        self.authorize_recorded(Action::Discover, "discover", Some(project))
            .await?;
        let inv = hf_discovery::discover(project, lang).await?;
        if let Some(store) = &self.store {
            store.save_inventory(&inv, Utc::now()).await?;
        }
        Ok(inv)
    }

    /// Re-rank a target inventory using the configured LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Provider` if no provider is configured, or the
    /// underlying ranking error if the LLM call fails.
    pub async fn rank(
        &self,
        inventory: TargetInventory,
    ) -> Result<TargetInventory, ClassifiedError> {
        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for ranking".to_owned())
        })?;
        let bridge =
            LlmProviderBridge::new(pool).with_diagnostics(Arc::clone(&self.diagnostics), "rank");
        let ranked = hf_discovery::rank(inventory, Box::new(bridge)).await?;
        if let Some(store) = &self.store {
            store.save_inventory(&ranked, Utc::now()).await?;
        }
        Ok(ranked)
    }

    // -- Harness ----------------------------------------------------------

    /// Draft a harness for a target using the LLM provider pool.
    ///
    /// Falls back to a heuristic template when no provider is configured so
    /// the GUI still produces a draft without an API key.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the LLM call fails or the target is not
    /// found.
    pub async fn harness_draft(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<HarnessDraft, ClassifiedError> {
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::DraftHarness, "harness_draft", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            // Augment the prompt with related project context when this
            // project has been indexed; empty on any failure, which renders
            // the un-augmented prompt.
            let related = crate::knowledge::harness_related_context(project, &candidate);
            match hf_harness::draft_with_context(&candidate, engine, &related, Box::new(provider))
                .await
            {
                Ok(draft) => Ok(draft),
                // The LLM is configured but the call failed (provider down, auth,
                // bad model, network). Degrade to the heuristic draft so the
                // pipeline still produces a usable harness instead of dead-ending
                // on a red error; the warning makes the LLM failure visible.
                Err(e) => {
                    tracing::warn!(
                        "LLM harness draft for '{target}' failed ({e}); \
                         falling back to heuristic draft"
                    );
                    Ok(heuristic_draft(&candidate, engine))
                }
            }
        } else {
            // No LLM configured: generate a heuristic draft so the GUI still
            // produces something useful.
            Ok(heuristic_draft(&candidate, engine))
        }
    }

    /// Resolve a target symbol to its discovered candidate id.
    ///
    /// Unknown symbols are rejected rather than being attached to the nil UUID.
    /// Shared by harness compilation and triage so persisted records key off the
    /// same canonical project and target identity.
    async fn resolve_target_id(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            if let Some(candidate) = targets.iter().find(|candidate| {
                stored_project_matches(&candidate.project_root, &project)
                    && candidate.symbol == target
                    && candidate.language == lang
            }) {
                return Ok(candidate.id);
            }
        }
        self.discover(&project, lang)
            .await?
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .map(|c| c.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    /// Targets in `project` that a scheduled campaign can legally run: those a
    /// human has smoke-qualified and promoted a harness for. `run_campaign`
    /// refuses everything else, so this is exactly the set the Automation view
    /// should offer -- and it carries the engine and language off the harness,
    /// so a schedule cannot be created for a combination that will fail at 3am.
    ///
    /// One entry per (target, engine) pair: a target promoted for two engines is
    /// schedulable under either.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when persistence is not configured.
    pub async fn schedulable_targets(
        &self,
        project: &Path,
    ) -> Result<Vec<SchedulableTarget>, ClassifiedError> {
        // Resolve targets the same way `resolve_target_id` does -- with the
        // path-tolerant `stored_project_matches` over every stored target --
        // rather than an exact `list_targets(project_root)` string match. A
        // trailing-slash/symlinked/relative project path otherwise reports "no
        // schedulable targets" for a project that `run_campaign` would happily
        // run, because the two disagreed on path normalization. Uses the same
        // graceful identity (canonicalize-or-raw), so a project that does not
        // exist yields an empty list rather than an error.
        let identity = project_lookup_identity(project);
        let fuzzing = crate::config::effective_fuzzing_settings()
            .map_err(|error| fuzzing_policy_error(&error))?;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "scheduling campaigns requires the persistent service store".to_owned(),
            )
        })?;
        let targets = store
            .list_all_targets()
            .await
            .map_err(ClassifiedError::from)?;

        let mut schedulable = Vec::new();
        for candidate in targets
            .into_iter()
            .filter(|candidate| stored_project_matches(&candidate.project_root, &identity))
        {
            let harnesses = store
                .list_harnesses(candidate.id)
                .await
                .map_err(ClassifiedError::from)?;
            for harness in harnesses.iter().filter(|h| {
                h.status == HarnessStatus::Promoted && fuzzing.require_engine(h.engine).is_ok()
            }) {
                schedulable.push(SchedulableTarget {
                    target: candidate.symbol.clone(),
                    engine: harness.engine.as_str().to_owned(),
                    language: harness.language.as_str().to_owned(),
                    fit_score: candidate.fit_score,
                });
            }
        }
        schedulable.sort_by(|a, b| (&a.target, &a.engine).cmp(&(&b.target, &b.engine)));
        schedulable.dedup_by(|a, b| a.target == b.target && a.engine == b.engine);
        Ok(schedulable)
    }

    /// Resolve a target without assuming that it is C. Persisted discovery is
    /// authoritative; only missing projects are scanned across supported
    /// languages. This prevents run, triage, and corpus records for Rust/C++
    /// targets from being silently attached to the nil UUID.
    async fn resolve_target_id_any_language(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Uuid, ClassifiedError> {
        self.resolve_target_candidate_any_language(project, target)
            .await?
            .map(|candidate| candidate.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    async fn resolve_target_candidate_any_language(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Option<TargetCandidate>, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            if let Some(candidate) = targets.iter().find(|candidate| {
                stored_project_matches(&candidate.project_root, &project)
                    && candidate.symbol == target
            }) {
                return Ok(Some(candidate.clone()));
            }
        }
        for language in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            match self.discover(&project, language).await {
                Ok(inventory) => {
                    if let Some(candidate) = inventory
                        .candidates
                        .into_iter()
                        .find(|candidate| candidate.symbol == target)
                    {
                        return Ok(Some(candidate));
                    }
                }
                Err(ClassifiedError::Validation(message))
                    if message.contains("not yet supported by the scanner") => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Resolve the persisted record for the binary/source revision currently
    /// active in a target workspace. The explicit id marker is authoritative;
    /// source matching keeps pre-marker workspaces upgrade-compatible.
    async fn active_harness(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let workspace = workspace_dir(project, target);
        let source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no active harness source for '{target}'; compile the harness first"
            ))
        })?;

        if let Some(id) = read_current_harness_id(&workspace) {
            let harness = store
                .get_harness(id)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?
                .ok_or_else(|| {
                    ClassifiedError::Validation(format!(
                        "active harness record {id} is missing; compile '{target}' again"
                    ))
                })?;
            if harness.engine != engine || harness.source != source {
                return Err(ClassifiedError::Validation(format!(
                    "active harness metadata for '{target}' does not match its binary/source; compile it again"
                )));
            }
            return Ok(harness);
        }

        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let harnesses = store
            .list_harnesses(target_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        harnesses
            .into_iter()
            .filter(|harness| harness.engine == engine && harness.source == source)
            .max_by_key(|harness| match harness.status {
                HarnessStatus::Promoted => 4,
                HarnessStatus::SmokePassed => 3,
                HarnessStatus::Compiled => 2,
                HarnessStatus::Draft => 1,
                HarnessStatus::Failed => 0,
            })
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "no persisted qualification record matches the active {engine:?} harness for '{target}'; compile it again"
                ))
            })
    }

    /// Verify that the active source/executable and the persisted smoke run all
    /// describe the same immutable qualification evidence.
    async fn verify_harness_qualification(
        &self,
        project: &Path,
        target: &str,
        harness: &Harness,
    ) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let (qualification_run_id, expected_source, expected_binary) =
            qualification_evidence(harness)?;
        let workspace = workspace_dir(project, target);
        let source_path = workspace.join("harness.source");
        let binary_path = workspace.join(harness_binary_name(target));
        if !is_regular_file(&source_path) || !is_regular_file(&binary_path) {
            return Err(ClassifiedError::Validation(
                "qualified harness artifacts are missing or are not regular files; compile and smoke again"
                    .to_owned(),
            ));
        }
        if sha256_file(&source_path)? != expected_source {
            return Err(ClassifiedError::Validation(
                "active harness source digest does not match smoke qualification".to_owned(),
            ));
        }
        if sha256_file(&binary_path)? != expected_binary {
            return Err(ClassifiedError::Validation(
                "active harness binary digest does not match smoke qualification".to_owned(),
            ));
        }

        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let run = store
            .get_run(qualification_run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(
                    "smoke qualification run is missing; run smoke qualification again".to_owned(),
                )
            })?;
        let same_harness = run
            .config
            .as_ref()
            .is_some_and(|config| config.harness_id == harness.id);
        if run.status != RunStatus::Done
            || !same_harness
            || run.harness_rev.as_deref() != Some(expected_source)
            || run.binary_rev.as_deref() != Some(expected_binary)
        {
            return Err(ClassifiedError::Validation(
                "smoke qualification evidence does not match the active harness digests".to_owned(),
            ));
        }
        let recorded_source = store
            .run_harness_source(qualification_run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        if recorded_source.as_deref() != Some(harness.source.as_str()) {
            return Err(ClassifiedError::Validation(
                "smoke qualification source evidence does not match the active harness".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reconcile one target's persisted corpus with its exact on-disk state.
    async fn persist_corpus(
        &self,
        target_id: Uuid,
        corpus: &hf_core::corpus::Corpus,
    ) -> Result<(), ClassifiedError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .replace_corpus_entries(target_id, &corpus.entries)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))
    }

    /// Compile a harness in the sandbox via `hf-runtime`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the build command fails.
    pub async fn harness_compile(
        &self,
        source: String,
        project: &Path,
        engine: EngineKind,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_compile", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let build_cmd = hf_harness::build_command(engine, lang, &harness_binary_name(target));
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: self.resolve_target_id(project, target, lang).await?,
            engine,
            source,
            language: lang,
            build_cmd,
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Draft,
            smoke_run: None,
        };
        let compiled = hf_harness::compile(harness, self.runtime.as_ref(), &workspace).await?;
        // Persist the compiled harness so it survives restarts and the
        // Harness/list views can show it before pointing the active marker at
        // the record. Qualification is safety-critical, so a configured store
        // must durably accept the record.
        if let Some(store) = &self.store {
            store
                .upsert_harness(&compiled)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        }
        write_current_harness_source(&workspace, &compiled.source)?;
        write_current_harness_id(&workspace, compiled.id)?;
        Ok(CompileOutcome {
            status: compiled.status,
            binary_name: compiled
                .build_cmd
                .output
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(target)
                .to_string(),
            workspace,
        })
    }

    /// Draft the harness source for a candidate: LLM-authored when a provider is
    /// configured, otherwise the heuristic template. Never fails -- an LLM error
    /// degrades to the heuristic draft so generation can proceed.
    async fn draft_harness_source(
        &self,
        project: &Path,
        candidate: &TargetCandidate,
        engine: EngineKind,
    ) -> String {
        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            let related = crate::knowledge::harness_related_context(project, candidate);
            match hf_harness::draft_with_context(candidate, engine, &related, Box::new(provider))
                .await
            {
                Ok(draft) => return draft.source,
                Err(e) => tracing::warn!(
                    "LLM harness draft for '{}' failed ({e}); using heuristic draft",
                    candidate.symbol
                ),
            }
        }
        heuristic_draft(candidate, engine).source
    }

    /// Generate a harness end to end with automatic repair: draft -> compile,
    /// and on a compile failure feed the diagnostics back to the LLM for up to
    /// `max_repairs` corrective passes before giving up.
    ///
    /// This is the recommended entry point over calling `harness_draft` +
    /// `harness_compile` separately: a large fraction of first-draft harnesses
    /// fail to compile, and abandoning the target on the first failure wastes a
    /// discovered, potentially high-value target. Repair recovers many of them.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown,
    /// `ClassifiedError::Harness` if the harness still fails to build after
    /// `max_repairs` attempts, or an infrastructure error from the sandbox.
    pub async fn harness_generate(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_generate", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let source = self.draft_harness_source(project, &candidate, engine).await;
        self.compile_source_with_repair(&candidate, engine, lang, &workspace, source, max_repairs)
            .await
    }

    /// Compile `initial_source` in the sandbox, and on a compile failure feed the
    /// diagnostics back to the LLM for up to `max_repairs` corrective passes.
    /// Shared by harness generation and coverage-guided refinement.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Harness` if the harness still fails to build
    /// after `max_repairs` attempts, or an infrastructure error from the sandbox.
    async fn compile_source_with_repair(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let target = &candidate.symbol;
        let mut source = initial_source;
        let mut repairs_used = 0usize;
        let mut last_diagnostics = String::new();

        loop {
            let mut build_cmd =
                hf_harness::build_command(engine, lang, &harness_binary_name(target));
            build_cmd.output = PathBuf::from(harness_binary_name(target));
            let harness = Harness {
                id: Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: source.clone(),
                language: lang,
                build_cmd,
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            match hf_harness::try_compile(harness, self.runtime.as_ref(), workspace).await? {
                hf_harness::CompileResult::Ok(compiled) => {
                    if let Some(store) = &self.store {
                        store
                            .upsert_harness(&compiled)
                            .await
                            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
                    }
                    write_current_harness_source(workspace, &compiled.source)?;
                    // Point `harness.active` at the freshly-compiled harness, as
                    // `harness_compile` does. Without this, a repair/refine that
                    // rewrites the source leaves the marker on the previous id, so
                    // `active_harness` later reads a stale id whose source no
                    // longer matches and hard-errors ("compile it again") even
                    // though the refined harness built cleanly.
                    write_current_harness_id(workspace, compiled.id)?;
                    let binary_name = compiled
                        .build_cmd
                        .output
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(target)
                        .to_string();
                    return Ok(HarnessGenOutcome {
                        status: compiled.status,
                        binary_name,
                        workspace: workspace.to_path_buf(),
                        repairs_used,
                    });
                }
                hf_harness::CompileResult::Failed(failure) => {
                    last_diagnostics = failure.diagnostics();
                    if repairs_used >= max_repairs {
                        break;
                    }
                    let Some(pool) = self.provider_pool() else {
                        // No LLM to repair with; the first failure is terminal.
                        break;
                    };
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
                    match hf_harness::repair(
                        candidate,
                        engine,
                        &source,
                        &last_diagnostics,
                        Box::new(provider),
                    )
                    .await
                    {
                        Ok(draft) => {
                            source = draft.source;
                            repairs_used += 1;
                        }
                        Err(e) => {
                            tracing::warn!("harness repair for '{target}' failed: {e}");
                            break;
                        }
                    }
                }
            }
        }

        let diag: String = last_diagnostics.chars().take(600).collect();
        Err(ClassifiedError::Harness(format!(
            "harness for '{target}' failed to build after {repairs_used} repair attempt(s): {diag}"
        )))
    }

    /// Coverage-guided harness refinement: when coverage has stagnated, ask the
    /// LLM to reshape the current harness so the fuzzer reaches the target's
    /// still-uncovered reachable functions, then compile the result (with the
    /// same auto-repair loop as generation).
    ///
    /// Recomputes coverage to determine which reachable functions are still
    /// uncovered, so the model gets a concrete goal rather than "improve this".
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown or has no
    /// current harness, `ClassifiedError::Provider` if no LLM is configured, or
    /// an error from the refine/compile steps.
    pub async fn harness_refine(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_refine", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = inv
            .candidates
            .iter()
            .find(|c| c.symbol == target)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        let workspace = workspace_dir(project, target);
        let current_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no current harness for '{target}' to refine; generate one first"
            ))
        })?;

        // Prefer the dynamic llvm-cov frontier (uncovered code with file:line
        // locations) so the refine prompt points the LLM at concrete gaps. Fall
        // back to the static reachable-minus-covered names when no source
        // coverage frontier is available (non-C targets, tooling missing) --
        // both accessors early-return without running the pipeline for a
        // non-C target, so the fallback costs nothing extra.
        let frontier = self.coverage_uncovered(project, target).await;
        let uncovered: Vec<String> = if frontier.is_empty() {
            let covered: std::collections::HashSet<String> = self
                .coverage_functions(project, target)
                .await
                .into_iter()
                .collect();
            candidate
                .reachable_functions
                .iter()
                .filter(|f| !covered.contains(*f))
                .cloned()
                .collect()
        } else {
            frontier_refine_lines(&candidate.reachable_functions, &frontier)
        };

        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for refinement".to_owned())
        })?;
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_refine");
        let refined = hf_harness::refine(
            &candidate,
            engine,
            &current_source,
            &uncovered,
            Box::new(provider),
        )
        .await?;

        self.compile_source_with_repair(
            &candidate,
            engine,
            lang,
            &workspace,
            refined.source,
            max_repairs,
        )
        .await
    }

    /// Run an approved fuzzing campaign end to end: discover (and pick the best
    /// target when none is given) -> require the active harness to have passed
    /// smoke qualification and explicit promotion -> seed the corpus -> loop
    /// [run -> triage -> feed crashes back] until a crash is found or
    /// `max_iterations` is reached.
    ///
    /// This is the coded orchestration the scheduler and "just fuzz this" flows
    /// use, so a scheduled campaign runs the whole pipeline rather than a single
    /// fixed run. Each iteration is bounded by `duration_secs`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if discovery finds no target or any mandatory
    /// qualification, persistence, run, or triage step fails.
    pub async fn run_campaign(
        &self,
        project: &Path,
        target: Option<&str>,
        engine: EngineKind,
        lang: TargetLanguage,
        duration_secs: u64,
        max_iterations: usize,
    ) -> Result<CampaignOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        let engine = resolved.engine;
        // 1. Choose a target: the caller's, else the top-ranked candidate.
        let inv = self.discover(project, lang).await?;
        let target = match target.filter(|t| !t.is_empty()) {
            Some(t) => t.to_owned(),
            None => inv
                .ranked()
                .first()
                .map(|c| c.symbol.clone())
                .ok_or_else(|| {
                    ClassifiedError::Validation("no fuzzable targets discovered".to_owned())
                })?,
        };

        // 2. Scheduled/agent campaigns may use only a revision a human already
        // approved. Generation, smoke, and promotion are deliberately separate
        // workbench operations.
        let harness = self.active_harness(project, &target, engine).await?;
        if harness.language != lang || harness.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(format!(
                "campaign target '{target}' needs a smoke-qualified, explicitly promoted {lang:?} harness"
            )));
        }
        let _ = self.generate_seeds_llm(project, &target, lang, 12).await;

        // 3. Run -> triage loop, stopping on the first crash or the iteration cap.
        let noop = |_: FuzzProgress| {};
        let mut edges = 0u64;
        let mut crashes = 0usize;
        let mut iterations = 0usize;
        let mut auto_reverts = 0usize;
        let mut termination = hf_core::runtime::CommandTermination::Completed;
        let mut last_stagnation: Option<hf_coverage::StagnationProposal> = None;
        let cap = max_iterations.max(1);
        while iterations < cap {
            iterations += 1;
            let summary = self
                .run_fuzzer_with_started(project, &target, resolved, &noop, &|_| {})
                .await?;
            termination = summary.termination;
            edges = edges.max(summary.edges);
            last_stagnation = summary.stagnation.clone();
            // A refine step between iterations can regress coverage; the policy
            // (armed via config) then restores the last-good harness, or, in
            // notify-only mode, flags it. Count either so history shows it.
            if summary.auto_revert.is_some() {
                auto_reverts += 1;
            }

            if termination == hf_core::runtime::CommandTermination::Cancelled {
                break;
            }

            let triaged = self.triage_run(project, &target, summary.run_id).await?;
            crashes = triaged.len();
            // Feed any crash reproducers back into the corpus (close the loop).
            let _ = self
                .corpus_absorb_crashes_for_run(project, &target, summary.run_id)
                .await;

            if crashes > 0 || iterations >= cap {
                break;
            }
        }

        // Coverage-driven loop: if the campaign plateaued on coverage without
        // finding a crash, PROPOSE a targeted refined harness aimed at the
        // uncovered frontier. HITL (AGENTS.md 2.12): the proposal is left
        // `Compiled`, never promoted or auto-run, and it is only attempted when
        // the compile action is already policy-allowed -- otherwise the plateau
        // is surfaced for a human to trigger refinement through the normal
        // approval path, so the campaign never blocks here.
        let refine = if crashes == 0
            && termination != hf_core::runtime::CommandTermination::Cancelled
            && last_stagnation == Some(hf_coverage::StagnationProposal::NewHarness)
        {
            self.propose_refine_on_plateau(project, &target, engine, lang)
                .await
        } else {
            None
        };

        Ok(CampaignOutcome {
            target,
            harness_status: harness.status,
            crashes,
            edges,
            iterations,
            auto_reverts,
            termination,
            refine,
        })
    }

    /// Draft a targeted refined harness in response to a coverage plateau, as a
    /// proposal only. Returns `None` (no proposal) when refinement is not
    /// applicable: no LLM provider, no uncovered frontier (non-C target or full
    /// coverage), or the compile action is not already policy-allowed (so we
    /// never block a headless campaign on an approval prompt, nor compile
    /// without an Allow decision). The refined harness stays `Compiled`; the
    /// existing promotion gate keeps it from being auto-run.
    async fn propose_refine_on_plateau(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Option<RefineProposal> {
        self.provider_pool()?;
        if !matches!(
            self.guardrails.policy().evaluate(&Action::CompileHarness),
            Decision::Allow
        ) {
            return None;
        }
        // Populate the frontier cache once; `harness_refine` reuses it (same
        // signature) rather than re-running the expensive coverage pipeline.
        let frontier_locations = self.coverage_uncovered(project, target).await.len();
        if frontier_locations == 0 {
            return None;
        }
        // Two corrective passes is enough for a targeted re-draft; keep it small
        // so a plateau does not turn into a long repair loop.
        match self.harness_refine(project, target, engine, lang, 2).await {
            Ok(outcome) => Some(RefineProposal {
                frontier_locations,
                compiled: outcome.status == HarnessStatus::Compiled,
                note: format!(
                    "coverage plateaued; proposed a refined harness for {frontier_locations} \
                     uncovered location(s), left Compiled for human review"
                ),
            }),
            Err(error) => {
                tracing::warn!(%error, "coverage-plateau refine proposal failed");
                Some(RefineProposal {
                    frontier_locations,
                    compiled: false,
                    note: format!("coverage plateaued; refine proposal failed: {error}"),
                })
            }
        }
    }

    /// Run a short smoke fuzz (60 seconds, clamped to the configured campaign
    /// ceiling) on the active, persisted harness revision and durably record
    /// its qualification evidence.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the binary is missing or the smoke run
    /// finds zero execs/sec.
    pub async fn harness_smoke(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<SmokeRunSummary, ClassifiedError> {
        let resolved = resolve_internal_run(engine, SMOKE_FUZZ_SECS)?;
        if !engine.supports_language(lang) {
            return Err(ClassifiedError::Validation(format!(
                "fuzzing engine '{}' does not support {lang:?} harnesses",
                engine.as_str()
            )));
        }
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        self.authorize_recorded(Action::RunHarness, "harness_smoke", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let harness = self.active_harness(project, target, engine).await?;
        if harness.language != lang {
            return Err(ClassifiedError::Validation(format!(
                "active harness language is {:?}, not {lang:?}",
                harness.language
            )));
        }
        if !matches!(
            harness.status,
            HarnessStatus::Compiled | HarnessStatus::SmokePassed | HarnessStatus::Promoted
        ) {
            return Err(ClassifiedError::Validation(format!(
                "only a compiled harness can be smoke-qualified; active status is {:?}",
                harness.status
            )));
        }
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let binary_name = harness_binary_name(target);
        let binary = workspace.join(&binary_name);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }

        // Allocate the run identity before execution so its immutable inputs and
        // every finding are owned by one durable evidence directory.
        let smoke_config = FuzzRunConfig {
            harness_id: harness.id,
            engine: resolved.engine,
            duration: Some(std::time::Duration::from_secs(resolved.duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(workspace.join("corpus")),
            sanitizer: harness.sanitizer,
            env: Vec::new(),
            extra_args: Vec::new(),
        };
        let mut smoke_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            Some(smoke_config.clone()),
            Utc::now(),
        );
        smoke_record.kind = RunKind::Smoke;
        smoke_record.context_rev = Some(run_context_digest(&workspace)?);
        let artifacts = stage_run_artifacts(&workspace, smoke_record.id, &harness.source, &binary)?;
        smoke_record.status = RunStatus::Running;
        smoke_record.harness_rev = Some(artifacts.source_sha256.clone());
        smoke_record.binary_rev = Some(artifacts.binary_sha256.clone());
        smoke_record.evidence_dir = Some(artifacts.output_relative.to_string_lossy().into_owned());
        if let Err(error) = store.insert_run(&smoke_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        // Journal the smoke run like a campaign run. Without this, a process
        // kill/crash during the ~60s smoke window leaves a permanent `Running`
        // row: clear_all_runs and delete_run both reject a run with no crash
        // evidence, so that orphan makes clear_all_runs fail forever and cannot
        // be removed via the service API. Journaling lets bootstrap reconcile it
        // to Failed on the next launch, exactly like a full run.
        self.run_journal
            .open_run(smoke_record.id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            smoke_record.id,
        );
        if let Err(error) = store
            .set_run_harness_source(smoke_record.id, &harness.source)
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        if let Err(error) = verify_run_artifacts(&artifacts) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let mut staged_harness = harness;
        staged_harness.build_cmd.output = artifacts.binary_host.clone();
        let mut smoked = match hf_harness::smoke_fuzz_in_paths_with_config(
            staged_harness,
            self.runtime.as_ref(),
            &workspace,
            &artifacts.corpus_relative,
            &artifacts.output_relative,
            &smoke_config,
        )
        .await
        {
            Ok(smoked) => smoked,
            Err(error) => {
                let _ = store
                    .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                return Err(error);
            }
        };
        // Fail smoke only on a definite overflow; a transient scan race must not
        // fail a valid smoke run (mirrors the campaign monitor).
        if output_budget_status(
            &artifacts.output_host,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            64 * 1024 * 1024,
        ) == OutputBudget::Exceeded
            || output_budget_status(
                &artifacts.corpus_host,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            ) == OutputBudget::Exceeded
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Sandbox(
                "smoke corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let Some(summary) = smoked.smoke_run.as_mut() else {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Harness(
                "smoke run produced no summary".to_owned(),
            ));
        };
        summary.source_sha256 = Some(artifacts.source_sha256.clone());
        summary.binary_sha256 = Some(artifacts.binary_sha256.clone());
        summary.run_id = Some(smoke_record.id);
        let summary = summary.clone();
        if let Err(error) = store
            .set_run_stats(
                smoke_record.id,
                0,
                summary.execs_per_sec,
                u64::from(summary.crashes),
            )
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        store
            .set_run_status(smoke_record.id, RunStatus::Done, Some(Utc::now()))
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        store
            .upsert_harness(&smoked)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        // Close the journal entry on success before disarming the guard, so a
        // cleanly-completed smoke run is not reconciled to Failed on restart.
        self.run_journal.close_run(smoke_record.id);
        persisted_run.disarm();
        Ok(summary)
    }

    /// Promote the active harness after a clean persisted smoke run. Calling
    /// this method is the explicit human approval boundary used by every
    /// presentation layer; agents and schedulers never call it implicitly.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the active revision has not completed a
    /// crash-free smoke run or its qualification record cannot be persisted.
    pub async fn harness_promote(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let mut harness = self.active_harness(project, target, engine).await?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness '{target}' has no persisted smoke evidence; run smoke qualification first"
            ))
        })?;
        if harness.status != HarnessStatus::SmokePassed || !smoke.passed {
            return Err(ClassifiedError::Validation(format!(
                "harness '{target}' cannot be promoted until a crash-free smoke run passes"
            )));
        }
        self.verify_harness_qualification(project, target, &harness)
            .await?;
        harness.status = HarnessStatus::Promoted;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".to_owned(),
            )
        })?;
        store
            .upsert_harness(&harness)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(harness)
    }

    /// Promote a harness with documented smoke findings. This is intentionally
    /// separate from clean promotion so callers cannot accidentally treat a
    /// crash-bearing revision as crash-free.
    pub async fn harness_promote_with_findings(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let mut harness = self.active_harness(project, target, engine).await?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run smoke qualification before approving findings".into())
        })?;
        if smoke.crashes == 0 {
            return Err(ClassifiedError::Validation(
                "known-findings approval requires at least one smoke crash".into(),
            ));
        }
        self.verify_harness_qualification(project, target, &harness)
            .await?;
        harness.status = HarnessStatus::Promoted;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".into(),
            )
        })?;
        store
            .upsert_harness(&harness)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(harness)
    }

    // -- Seeds ------------------------------------------------------------

    /// Generate seed corpus inputs for a target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn generate_seeds(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let seeds = generate_target_seeds(target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &hf_corpus::list(&corpus_dir)?)
            .await?;
        corpus
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ClassifiedError::Internal(
                            "generated seed path has no UTF-8 filename".to_owned(),
                        )
                    })?
                    .to_owned();
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect()
    }

    /// Generate a seed corpus for a target using the LLM (structural, format-
    /// aware seeds), falling back to the heuristic seeds when no provider is
    /// configured or the model returns nothing usable. Seeds are written into
    /// the target's corpus directory and deduplicated by content hash.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory or a seed file cannot
    /// be written.
    pub async fn generate_seeds_llm(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
        count: usize,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // Clamp the requested count to a sane range so no presentation layer can
        // ask the LLM for zero or an absurd number of seeds. Owning the bound
        // here keeps CLI, REST, and Tauri consistent (the clamp previously lived
        // only in the web handler).
        let count = count.clamp(1, 64);
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // LLM seeds when a provider and the target candidate are available.
        let mut datas: Vec<Vec<u8>> = Vec::new();
        if let Some(pool) = self.provider_pool() {
            if let Ok(inv) = self.discover(project, lang).await {
                if let Some(candidate) = inv.candidates.iter().find(|c| c.symbol == target) {
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "seed_gen");
                    match hf_harness::generate_seeds(candidate, count, Box::new(provider)).await {
                        Ok(seeds) => datas = seeds,
                        Err(e) => tracing::warn!("LLM seed generation for '{target}' failed: {e}"),
                    }
                }
            }
        }
        // Fall back to the heuristic seeds so a corpus is always produced.
        if datas.is_empty() {
            datas = generate_target_seeds(target)
                .into_iter()
                .map(|(data, _)| data)
                .collect();
        }

        let mut named_seeds = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, data) in datas.into_iter().enumerate() {
            use sha2::{Digest as _, Sha256};
            let sha = format!("{:x}", Sha256::digest(&data));
            if !seen.insert(sha.clone()) {
                continue;
            }
            let name = format!("llmseed_{i}");
            named_seeds.push((data, name));
        }

        // Make the AI seeds first-class, tracked corpus entries (parity with
        // corpus_seed/corpus_grow), so they show in the browse-all corpus view
        // and survive as persisted rows -- previously LLM seeds only landed on
        // disk. Listing the dir also folds in any pre-existing entries; the
        // exact target reconciliation stays idempotent.
        let target_id = self.resolve_target_id(project, target, lang).await?;
        let generated = hf_corpus::seed(target_id, &corpus_dir, named_seeds).await?;
        let entries = generated
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let corpus = hf_corpus::list(&corpus_dir)?;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(entries)
    }

    // -- Run --------------------------------------------------------------

    /// Reserve and launch a fuzz campaign in a service-owned background task.
    ///
    /// The returned UUID is already persisted, recovery-journaled, and
    /// registered for cooperative cancellation. Progress and lifecycle sinks
    /// always receive that same service-owned id. A request future may be
    /// dropped after this method returns without aborting the campaign.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when preflight or durable reservation
    /// fails. Errors after reservation are reflected in the persisted run and
    /// delivered as a [`RunLifecycleStatus::Failed`] lifecycle callback.
    pub async fn start_fuzzer(
        &self,
        project: PathBuf,
        target: String,
        engine: EngineKind,
        duration_secs: u64,
        on_progress: Arc<dyn Fn(Uuid, FuzzProgress) + Send + Sync + 'static>,
        on_status: Arc<dyn Fn(Uuid, RunLifecycleStatus) + Send + Sync + 'static>,
    ) -> Result<Uuid, ClassifiedError> {
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let active_id = Arc::new(std::sync::Mutex::new(None));
        let container = self.clone();

        tokio::spawn({
            let started_tx = Arc::clone(&started_tx);
            let active_id = Arc::clone(&active_id);
            async move {
                let progress_sink = {
                    let active_id = Arc::clone(&active_id);
                    let on_progress = Arc::clone(&on_progress);
                    move |progress| {
                        if let Ok(id) = active_id.lock() {
                            if let Some(id) = *id {
                                on_progress(id, progress);
                            }
                        }
                    }
                };
                let started_sink = {
                    let active_id = Arc::clone(&active_id);
                    let started_tx = Arc::clone(&started_tx);
                    let on_status = Arc::clone(&on_status);
                    move |run_id| {
                        if let Ok(mut id) = active_id.lock() {
                            *id = Some(run_id);
                        }
                        on_status(run_id, RunLifecycleStatus::Running);
                        if let Ok(mut sender) = started_tx.lock() {
                            if let Some(sender) = sender.take() {
                                let _ = sender.send(Ok(run_id));
                            }
                        }
                    }
                };

                let result = container
                    .run_fuzzer_with_started(
                        &project,
                        &target,
                        resolved,
                        &progress_sink,
                        &started_sink,
                    )
                    .await;
                match result {
                    Ok(summary) => {
                        let status = if summary.termination
                            == hf_core::runtime::CommandTermination::Cancelled
                        {
                            RunLifecycleStatus::Cancelled
                        } else {
                            RunLifecycleStatus::Done
                        };
                        on_status(summary.run_id, status);
                    }
                    Err(error) => {
                        let run_id = active_id.lock().ok().and_then(|id| *id);
                        if let Some(run_id) = run_id {
                            tracing::error!(%run_id, %error, "background fuzz run failed");
                            on_status(run_id, RunLifecycleStatus::Failed);
                        } else if let Ok(mut sender) = started_tx.lock() {
                            if let Some(sender) = sender.take() {
                                let _ = sender.send(Err(error));
                            }
                        }
                    }
                }
            }
        });

        started_rx.await.map_err(|_| {
            ClassifiedError::Internal(
                "background fuzz task ended before durable reservation".to_owned(),
            )
        })?
    }

    /// Read the durable lifecycle state for one run.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when persistence is unavailable or the
    /// stored row cannot be decoded.
    pub async fn run_control_status(
        &self,
        run_id: Uuid,
    ) -> Result<Option<RunControlStatus>, ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run control requires the persistent service store".into())
        })?;
        let Some(run) = store
            .get_run(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        else {
            return Ok(None);
        };
        let active = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?
            .contains_key(&run_id);
        Ok(Some(RunControlStatus {
            run_id,
            status: run.status.into(),
            active,
            started_at: run.started_at.to_rfc3339(),
            ended_at: run.ended_at.map(|ended_at| ended_at.to_rfc3339()),
        }))
    }

    /// Request cooperative cancellation for one durable run.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when run state cannot be read or the
    /// active-run registry is unavailable.
    pub async fn request_run_cancel(
        &self,
        run_id: Uuid,
    ) -> Result<RunCancelOutcome, ClassifiedError> {
        let Some(status) = self.run_control_status(run_id).await? else {
            return Ok(RunCancelOutcome::NotFound);
        };
        if status.status != RunLifecycleStatus::Running || !status.active {
            return Ok(RunCancelOutcome::Inactive);
        }
        let runs = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?;
        let Some(token) = runs.get(&run_id) else {
            return Ok(RunCancelOutcome::Inactive);
        };
        if token.is_cancelled() {
            return Ok(RunCancelOutcome::Inactive);
        }
        token.cancel();
        Ok(RunCancelOutcome::Accepted)
    }

    /// Cancel an in-flight fuzz run by id.
    ///
    /// Fires the run's cancellation token, which cooperatively tears down the
    /// sandboxed fuzzer (the container is killed) and lets [`Self::run_fuzzer`]
    /// return with the partial results it collected, marking the run
    /// `Cancelled`. Returns `true` if a matching active run was found.
    #[must_use]
    pub fn cancel_run(&self, run_id: Uuid) -> bool {
        let Ok(runs) = self.active_runs.lock() else {
            return false;
        };
        if let Some(token) = runs.get(&run_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Cancel every in-flight fuzz run, returning how many were signalled.
    ///
    /// Used for a blanket stop (e.g. a CLI Ctrl-C) where the caller does not
    /// track individual run ids.
    pub fn cancel_all_runs(&self) -> usize {
        let Ok(runs) = self.active_runs.lock() else {
            return 0;
        };
        for token in runs.values() {
            token.cancel();
        }
        runs.len()
    }

    /// The ids of fuzz runs currently in flight.
    #[must_use]
    pub fn active_run_ids(&self) -> Vec<Uuid> {
        self.active_runs
            .lock()
            .map(|runs| runs.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Run a fuzz campaign via `hf-engine::runner::EngineRunner`.
    ///
    /// `on_progress` is called for each parsed `FuzzProgress` event so the
    /// caller can stream it to the UI.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is not supported or the
    /// sandboxed command returns a non-zero exit code.
    pub async fn run_fuzzer(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        duration_secs: u64,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        self.run_fuzzer_with_started(project, target, resolved, on_progress, &|_| {})
            .await
    }

    /// Run a fuzzer to termination and notify event-driven schedules about the
    /// outcome: `run.completed` on success (cancellation included), `run.failed`
    /// when a started run terminates with a failure. Errors before the run
    /// becomes durable are rejections, not run failures, and emit nothing.
    async fn run_fuzzer_with_started(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        let engine = resolved.engine;
        // Capture the run id once the run is durable so a failure event can
        // name it.
        let started_run = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = std::sync::Arc::clone(&started_run);
        let tracked_started = move |run_id: Uuid| {
            if let Ok(mut slot) = captured.lock() {
                *slot = Some(run_id);
            }
            on_started(run_id);
        };
        let result = self
            .run_fuzzer_with_started_inner(project, target, resolved, on_progress, &tracked_started)
            .await;
        match &result {
            Ok(summary) => {
                self.emit_scheduler_event(
                    crate::scheduler::EVENT_RUN_COMPLETED,
                    serde_json::json!({
                        "project": project.display().to_string(),
                        "target": target,
                        "run_id": summary.run_id.to_string(),
                        "engine": engine.as_str(),
                        "edges": summary.edges,
                        "execs": summary.execs,
                        "crashes": summary.crashes,
                        "termination": summary.termination,
                    }),
                )
                .await;
            }
            Err(error) => {
                let run_id = started_run.lock().ok().and_then(|slot| *slot);
                if let Some(run_id) = run_id {
                    self.emit_scheduler_event(
                        crate::scheduler::EVENT_RUN_FAILED,
                        serde_json::json!({
                            "project": project.display().to_string(),
                            "target": target,
                            "run_id": run_id.to_string(),
                            "engine": engine.as_str(),
                            "error": error.to_string(),
                        }),
                    )
                    .await;
                }
            }
        }
        result
    }

    async fn run_fuzzer_with_started_inner(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        const MAX_RAW_COVERAGE_SAMPLES: usize = 10_000;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        let engine = resolved.engine;
        let duration_secs = resolved.duration_secs;

        let qualified = self.active_harness(project, target, engine).await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(format!(
                "active harness '{target}' is {:?}; run smoke qualification and explicitly promote it before starting a full campaign",
                qualified.status
            )));
        }
        self.verify_harness_qualification(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: format!("{engine:?}"),
                duration_secs,
            },
            "run_fuzzer",
            Some(project),
        )
        .await?;
        ensure_run_journal_durable(&self.run_journal)?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = ensure_workspace_directory(&workspace, Path::new("corpus"))?;

        let bin = harness_binary_name(target);
        let binary = workspace.join(&bin);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{bin}' not found -- compile the harness first."
            )));
        }

        // Build a dictionary from the target sources and point the engine at it.
        // A dictionary of the literals the target compares against is one of the
        // cheapest coverage multipliers; absent literals just yield no flag.
        let dict_name = "fuzzer.dict".to_owned();
        let extra_args = if build_workspace_dictionary(&workspace, &dict_name).is_some() {
            hf_engine::dict::dict_run_args(engine, &format!("/work/{dict_name}"))
        } else {
            Vec::new()
        };

        let run_cfg = FuzzRunConfig {
            // Link the run to the target's compiled harness so the target-scoped
            // workbench dashboard can attribute it. A throwaway id here would
            // leave every run unattributable (dashboard shows zero runs).
            harness_id: qualified.id,
            engine,
            duration: Some(std::time::Duration::from_secs(duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(corpus_dir.clone()),
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args,
        };
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("fuzz runs require the persistent service store".to_owned())
        })?;
        let mut run_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            Some(run_cfg.clone()),
            Utc::now(),
        );
        run_record.context_rev = Some(run_context_digest(&workspace)?);
        let artifacts = stage_run_artifacts(&workspace, run_record.id, &qualified.source, &binary)?;
        if let Err(error) = verify_staged_qualification(&qualified, &artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        if let Err(error) = verify_run_artifacts(&artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        let sandbox = run_sandbox_options(&artifacts);
        run_record.status = RunStatus::Running;
        run_record.harness_rev = Some(artifacts.source_sha256.clone());
        run_record.binary_rev = Some(artifacts.binary_sha256.clone());
        run_record.evidence_dir = Some(artifacts.output_relative.to_string_lossy().into_owned());
        let run_id = run_record.id;
        if let Err(error) = store.insert_run(&run_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        self.run_journal.open_run(run_id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            run_id,
        );
        if let Err(error) = store
            .set_run_harness_source(run_record.id, &qualified.source)
            .await
        {
            let failure_recorded = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            if failure_recorded.is_ok() {
                self.run_journal.close_run(run_id);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        // Register a cancellation token so `cancel_run(run_id)` can stop this
        // run cooperatively. `ActiveRunGuard` removes it again when this scope
        // ends -- crucially, even if the `run_fuzzer` future is dropped/aborted
        // (e.g. wrapped in a `timeout`) rather than returning normally. A plain
        // post-await removal would leak the entry on abort, leaving a phantom
        // run that `active_run_ids` reports and `cancel_run` can never clear.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
        // The run is durable and cancellable at this point. Non-blocking
        // presentation transports may now return the exact UUID; no engine
        // process has been launched yet.
        on_started(run_id);

        let runner = hf_engine::runner::EngineRunner::new();
        // Watch edge readings for stagnation while forwarding every event.
        let feedback = CoverageFeedback::new(
            run_id,
            crate::config::coverage_stagnation_policy(),
            on_progress,
        );
        // Accumulate an intra-run coverage/throughput time series live, so the
        // run's coverage curve can be charted later. Each fuzzer stats line emits
        // an EdgesCovered then an ExecsPerSec event; pair them and stamp the
        // elapsed time.
        let series: std::sync::Arc<std::sync::Mutex<Vec<(f64, u64, f64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_edges = std::sync::atomic::AtomicU64::new(0);
        let run_started = std::time::Instant::now();
        let series_w = std::sync::Arc::clone(&series);
        let watched = |p: FuzzProgress| {
            use std::sync::atomic::Ordering::Relaxed;
            match &p {
                FuzzProgress::EdgesCovered(v) => {
                    feedback.on_edges(*v);
                    last_edges.store(*v, Relaxed);
                }
                FuzzProgress::ExecsPerSec(v) => {
                    let t = run_started.elapsed().as_secs_f64();
                    let e = last_edges.load(Relaxed);
                    if let Ok(mut s) = series_w.lock() {
                        if s.len() < MAX_RAW_COVERAGE_SAMPLES {
                            s.push((t, e, *v));
                        } else if let Some(last) = s.last_mut() {
                            *last = (t, e, *v);
                        }
                    }
                }
                _ => {}
            }
            on_progress(p);
        };
        let output_monitor_stop = CancellationToken::new();
        let output_budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_monitor = tokio::spawn(monitor_run_output(
            artifacts.output_host.clone(),
            artifacts.corpus_host.clone(),
            64 * 1024 * 1024,
            cancel.clone(),
            output_monitor_stop.clone(),
            Arc::clone(&output_budget_exceeded),
        ));
        // Stream progress live: `on_progress` fires for each output line and
        // stat as the fuzzer runs, not post-hoc.
        let run_result = runner
            .run_streaming_opts(
                engine,
                &run_cfg,
                &artifacts.binary_container,
                &artifacts.corpus_container,
                &artifacts.output_container,
                self.runtime.as_ref(),
                &workspace,
                &sandbox,
                &cancel,
                &watched,
            )
            .await;
        output_monitor_stop.cancel();
        let _ = output_monitor.await;
        if !run_artifacts_within_budget(&artifacts, 64 * 1024 * 1024).await {
            output_budget_exceeded.store(true, std::sync::atomic::Ordering::Release);
        }
        if output_budget_exceeded.load(std::sync::atomic::Ordering::Acquire) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(ClassifiedError::Sandbox(
                "fuzz run corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let result = match run_result {
            Ok(result) => result,
            Err(error) => {
                let status_update = store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        let was_cancelled = result.termination == hf_core::runtime::CommandTermination::Cancelled;

        // Keep the retained corpus immutable throughout execution. Engines
        // write only to this run's disposable snapshot/output; after the
        // sandbox exits, bounded corpus APIs preflight those discoveries and
        // atomically merge unique inputs into the live corpus.
        let retained = match merge_run_discoveries(engine, &artifacts, &corpus_dir).await {
            Ok(corpus) => corpus,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        // persist_corpus derives the target from the explicit `qualified.target_id`
        // argument and `retained.entries`, never `retained.target_id`, so no
        // identity copy is needed here.
        if let Err(error) = self.persist_corpus(qualified.target_id, &retained).await {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(error);
        }

        // Summarize from the parsed events. Live streaming already forwarded
        // them to `on_progress`, so do not re-emit here.
        let metrics = match terminal_run_metrics(engine, &artifacts, &result).await {
            Ok(metrics) => metrics,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        if let Err(error) =
            persist_terminal_run_evidence(store, run_record.id, &metrics, &series).await
        {
            let _ = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            self.run_journal.close_run(run_id);
            return Err(error);
        }
        let TerminalRunMetrics {
            edges,
            execs,
            crashes,
        } = metrics;
        // A run becomes terminal only after its summary evidence is durable.
        // This prevents a `Done` record whose stats or coverage curve were lost.
        let status = if was_cancelled {
            RunStatus::Cancelled
        } else {
            RunStatus::Done
        };
        let status_update = store
            .set_run_status(run_record.id, status, Some(Utc::now()))
            .await;
        status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        if let Err(error) = close_run_journal(&self.run_journal, run_id) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            persisted_run.disarm();
            return Err(error);
        }
        persisted_run.disarm();
        // Auto-revert policy: if this run's harness revision regressed coverage
        // past the threshold versus the latest comparable run for this target,
        // restore that last-good revision (HITL-gated recompile). Skipped for
        // cancelled runs, whose truncated coverage is not a fair comparison.
        let auto_revert = if was_cancelled {
            None
        } else {
            self.maybe_auto_revert(
                project,
                target,
                run_id,
                edges,
                run_record.harness_rev.as_deref(),
            )
            .await
        };
        Ok(RunSummary {
            run_id,
            edges,
            execs,
            crashes,
            termination: result.termination,
            stagnation: feedback.proposal(),
            auto_revert,
        })
    }

    /// Run a syzkaller kernel-fuzzing campaign through the sandbox.
    ///
    /// syzkaller fuzzes an OS kernel by mutating syscall sequences inside a
    /// managed VM whose kernel is built with KCOV coverage. User-selected
    /// artifacts are copied into a unique service-owned directory, manager
    /// paths are rewritten to those staged copies, and `syz-manager` progress
    /// is streamed to `on_progress`.
    ///
    /// qemu runs with the standard capability and privilege hardening, no
    /// container network, and at most the `/dev/kvm` device. The selected
    /// rootfs is never mounted writable; qemu receives a disposable copy.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if Docker is unavailable, an artifact path is
    /// invalid, or the sandbox run fails.
    pub async fn run_syzkaller(
        &self,
        opts: &SyzkallerRunOpts,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<SyzkallerSummary, ClassifiedError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let resolved = resolve_fuzzing_run(EngineKind::Syzkaller, opts.duration_secs)?;
        let duration_secs = resolved.duration_secs;

        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "Syzkaller".to_owned(),
                duration_secs,
            },
            "run_syzkaller",
            None,
        )
        .await?;

        let platform = opts
            .arch
            .as_deref()
            .map_or_else(hf_runtime::host_platform, hf_runtime::norm_platform);
        let target_triple = format!("linux/{}", hf_runtime::platform_short(&platform));

        let log = |s: &str| on_progress(FuzzProgress::LogLine(s.to_owned()));
        let nonempty = |o: &Option<String>| {
            o.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let manager_cfg = nonempty(&opts.manager_cfg);
        let kernel_image = nonempty(&opts.kernel_image);
        let disk_image = nonempty(&opts.disk_image);
        let ssh_key = nonempty(&opts.ssh_key);

        let have_artifacts = kernel_image.is_some() && disk_image.is_some();

        // No artifacts at all: surface what a campaign needs and stop (no error).
        if manager_cfg.is_none() && !have_artifacts {
            for line in [
                format!("syzkaller (kernel fuzzing) -- project: {}", opts.project),
                "No campaign artifacts provided. syzkaller drives a VM against a".to_owned(),
                "KCOV-instrumented kernel; it needs one of:".to_owned(),
                "  (a) a kernel image (bzImage) + a rootfs disk image, or".to_owned(),
                "  (b) an existing syz-manager config (manager.cfg).".to_owned(),
                "Build a KCOV kernel + rootfs per the setup guide, then select them above:"
                    .to_owned(),
                "https://github.com/google/syzkaller/blob/master/docs/linux/setup.md".to_owned(),
            ] {
                log(&line);
            }
            on_progress(FuzzProgress::Done);
            return Ok(SyzkallerSummary::default());
        }

        if !hf_runtime::docker_daemon_ready() {
            return Err(ClassifiedError::Sandbox(
                "Docker daemon not running -- cannot launch syz-manager.".to_owned(),
            ));
        }

        // Use KVM when the host can (native-arch Linux with /dev/kvm); this is
        // orders of magnitude faster than TCG emulation. It drives both the
        // synthesized qemu args and the sole device passthrough below.
        let use_kvm = syz_kvm_usable(&platform);
        let run_id = Uuid::new_v4();
        let provided_config = manager_cfg.is_some();
        let workspace_root = prepare_configured_workspace_root()?;
        let stage_request = crate::syzkaller::SyzkallerStageRequest {
            workspace_root,
            run_id,
            target_triple: target_triple.clone(),
            manager_cfg: manager_cfg.map(PathBuf::from),
            kernel_image: kernel_image.map(PathBuf::from),
            disk_image: disk_image.map(PathBuf::from),
            ssh_key: ssh_key.map(PathBuf::from),
            vm_count: opts.vm_count,
            use_kvm,
            // Size the VM fan-out to the same budget the container is given so
            // the swap-less cgroup cannot OOM-kill qemu.
            container_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
        };
        // Rootfs images can be several GiB. Keep the copy off the async runtime
        // while retaining a guard that removes staging on completion or abort.
        let stage =
            tokio::task::spawn_blocking(move || crate::syzkaller::prepare_stage(&stage_request))
                .await
                .map_err(|error| {
                    ClassifiedError::Internal(format!("join syzkaller staging task: {error}"))
                })??;
        let workspace = stage.root.clone();
        let sandbox_opts = crate::syzkaller::sandbox_options(&stage, &platform, use_kvm);
        if provided_config {
            log("Validated and rewrote the provided manager.cfg into isolated staging.");
        } else {
            log(&format!(
                "Synthesized an isolated qemu manager.cfg ({target_triple})."
            ));
        }

        log(&format!(
            "Launching syz-manager in the sandbox for {duration_secs}s..."
        ));
        if use_kvm {
            log("Note: qemu uses KVM acceleration (/dev/kvm passed through) -- expect good exec rates.");
        } else {
            log("Note: qemu runs under TCG emulation inside Docker (no KVM on this host) -- expect low exec rates.");
        }

        // A graceful multi-VM syz-manager teardown scales with the VM count, so
        // the outer Docker deadline reuses the engine sandbox headroom per VM
        // rather than a flat 30s -- a slow shutdown that tripped the old margin
        // was classified as TimedOut and discarded the whole campaign summary.
        // The inner `timeout --kill-after` force-kills syz-manager well before
        // this backstop, so reaching it is genuinely exceptional.
        let vm_estimate = opts
            .vm_count
            .unwrap_or(2)
            .clamp(1, crate::syzkaller::MAX_VM_COUNT);
        let teardown_grace_secs =
            hf_engine::runner::SANDBOX_TIMEOUT_HEADROOM_SECS.saturating_mul(u64::from(vm_estimate));
        let inner_kill_after_secs = (teardown_grace_secs / 2).max(1);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            // The inner `timeout` governs the campaign; give the sandbox deadline
            // a VM-scaled grace margin so it is only a teardown backstop.
            max_duration_secs: duration_secs.saturating_add(teardown_grace_secs),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        // Cross-line state for the streaming callback.
        let peak_edges = AtomicU64::new(0);
        let last_execs = AtomicU64::new(0);
        let peak_crashes = AtomicU64::new(0);
        // Previous (sample time, cumulative execs) for deriving an exec *rate*
        // from syzkaller's cumulative counter.
        let exec_rate_state = std::sync::Mutex::new(Option::<(std::time::Instant, u64)>::None);
        let on_line = |line: &str| {
            if let Some((cover, executed, crash_ct)) =
                hf_engine::progress::parse_syzkaller_status(line)
            {
                peak_edges.fetch_max(cover, Ordering::Relaxed);
                last_execs.store(executed, Ordering::Relaxed);
                let prev = peak_crashes.load(Ordering::Relaxed);
                if crash_ct > prev {
                    on_progress(FuzzProgress::CrashesFound(
                        u32::try_from(crash_ct - prev).unwrap_or(u32::MAX),
                    ));
                    peak_crashes.store(crash_ct, Ordering::Relaxed);
                }
                on_progress(FuzzProgress::EdgesCovered(cover));
                // syzkaller reports a cumulative execution count; convert it to a
                // per-second rate before emitting on the rate channel so the
                // throughput chart does not render a monotonically climbing total.
                if let Ok(mut guard) = exec_rate_state.lock() {
                    let now = std::time::Instant::now();
                    if let Some((prev_time, prev_execs)) = *guard {
                        let elapsed = now.duration_since(prev_time).as_secs_f64();
                        if elapsed > 0.0 && executed >= prev_execs {
                            let rate = (executed - prev_execs) as f64 / elapsed;
                            on_progress(FuzzProgress::ExecsPerSec(rate));
                        }
                    }
                    *guard = Some((now, executed));
                }
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            } else if !line.trim().is_empty() {
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            }
        };

        // Register the cancellation token so the UI Stop button (which fires
        // `cancel_all_runs`) and `cancel_run` can tear down a long KVM campaign.
        // `ActiveRunGuard` removes it again even if this future is aborted.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
        let cmd = syzkaller_manager_command(
            crate::syzkaller::CONTAINER_MANAGER_CONFIG,
            duration_secs,
            inner_kill_after_secs,
        );
        let writable_monitor =
            crate::syzkaller::WritableBudgetMonitor::start(&stage, cancel.clone());
        let run_result = self
            .runtime
            .run_command_streaming_opts(&cmd, &workspace, &limits, &sandbox_opts, &cancel, &on_line)
            .await;
        // Always stop the monitor, but surface a genuine run failure (Docker
        // died, container setup error) ahead of the budget verdict: otherwise a
        // real failure that also happened to trip the scratch budget would be
        // reported as a generic budget error, hiding the root cause.
        let within_budget = writable_monitor.finish().await;
        let result = run_result?;
        if !within_budget {
            return Err(ClassifiedError::Sandbox(
                "syzkaller scratch/workdir exceeded its 4 GiB growth or 100000-entry budget"
                    .to_owned(),
            ));
        }

        // GNU `timeout` uses 124 when the requested campaign budget expires;
        // that is the normal bounded completion path. Any other non-zero exit
        // for a genuinely Completed process means the manager or its container
        // setup failed and must not be presented as a successful campaign.
        match result.termination {
            hf_core::runtime::CommandTermination::Completed
                if result.exit_code != 0 && result.exit_code != 124 =>
            {
                let detail = result.stderr.lines().last().unwrap_or("no error output");
                return Err(ClassifiedError::Sandbox(format!(
                    "syz-manager exited with {}: {detail}",
                    result.exit_code
                )));
            }
            hf_core::runtime::CommandTermination::TimedOut => {
                // The inner `timeout --kill-after` already bounds the campaign;
                // reaching the outer deadline means a slow multi-VM teardown, not
                // a failure. Streaming already captured the coverage/crash
                // metrics, so treat it as a bounded completion instead of
                // discarding the summary.
                log("syz-manager reached the sandbox teardown backstop; treating the streamed campaign as complete.");
            }
            _ => {}
        }

        // Lift crash reproducers and the corpus database out of the disposable
        // staging workdir before the stage guard drops (and deletes) it, so
        // found crashes reach retained evidence and the corpus can be reused.
        // Best-effort: a copy hiccup is logged, never a reason to discard a
        // valid campaign summary.
        if let Some(evidence_dir) = workspace
            .parent()
            .map(|parent| parent.join("evidence").join(run_id.to_string()))
        {
            let stage_root = workspace.clone();
            let evidence = tokio::task::spawn_blocking(move || {
                crate::syzkaller::retain_campaign_evidence(&stage_root, &evidence_dir)
            })
            .await
            .map_err(|error| {
                ClassifiedError::Internal(format!("join syzkaller evidence task: {error}"))
            })?;
            match evidence {
                Ok(Some(path)) => log(&format!(
                    "Retained syzkaller crash reproducers and corpus under {}.",
                    path.display()
                )),
                Ok(None) => {}
                Err(error) => log(&format!(
                    "Warning: could not retain syzkaller campaign evidence: {error}"
                )),
            }
        }

        if matches!(
            result.termination,
            hf_core::runtime::CommandTermination::Completed
                | hf_core::runtime::CommandTermination::TimedOut
        ) {
            on_progress(FuzzProgress::Done);
        }
        Ok(SyzkallerSummary {
            edges: peak_edges.load(Ordering::Relaxed),
            execs: last_execs.load(Ordering::Relaxed) as f64,
            crashes: peak_crashes.load(Ordering::Relaxed),
            exit_code: Some(result.exit_code),
            termination: Some(result.termination),
        })
    }

    // -- Triage -----------------------------------------------------------

    /// Ingest and deduplicate crash artifacts from the output directory.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the output directory cannot be read.
    pub async fn triage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let run = match self.latest_run_record(project, Some(target)).await? {
            Some(run) => run,
            None if self.store.is_some() => {
                return Err(ClassifiedError::Validation(format!(
                    "no terminal run for target '{target}' has attributable crash evidence; run smoke qualification or a campaign before triage"
                )));
            }
            None => RunRecord::new(
                project.to_string_lossy(),
                EngineKind::LibFuzzer,
                None,
                Utc::now(),
            ),
        };
        self.triage_run_record(project, target, run).await
    }

    /// Triage the evidence owned by one exact persisted run.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run is missing, belongs to another
    /// project/target, is nonterminal, or its evidence is invalid.
    pub async fn triage_run(
        &self,
        project: &Path,
        target: &str,
        run_id: Uuid,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {run_id}")))?;
        if !stored_project_matches(Path::new(&run.project_root), project)
            || !run_has_crash_evidence(run.status)
            || self.run_target_id(store, &run).await?
                != Some(self.resolve_target_id_any_language(project, target).await?)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} does not own terminal evidence for target '{target}'"
            )));
        }
        self.triage_run_record(project, target, run).await
    }

    async fn triage_run_record(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        const TRIAGE_BUDGET: std::time::Duration = std::time::Duration::from_mins(5);

        tokio::time::timeout(
            TRIAGE_BUDGET,
            self.triage_run_record_inner(project, target, run),
        )
        .await
        .map_err(|_| {
            ClassifiedError::Sandbox(format!(
                "triage exceeded its {} second end-to-end budget",
                TRIAGE_BUDGET.as_secs()
            ))
        })?
    }

    async fn triage_run_record_inner(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        /// Cap on LLM bug-report drafts per triage pass: a run may surface many
        /// distinct bugs, and one report each would fan out into hundreds of LLM
        /// calls. Crashes beyond the cap are still ingested and persisted, just
        /// without a drafted report.
        const MAX_BUG_REPORT_DRAFTS: usize = 20;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        self.authorize_recorded(Action::Triage, "triage_run", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let run_id = run.id;
        let engine = run.engine;
        let out_dir = run_output_dir(&workspace, &run)?;
        let run_binary = run_binary_path(&workspace, &run, target)?;
        let source_context = if run.harness_rev.is_some() {
            let source = run_source_path(&workspace, &run)?;
            std::fs::read_to_string(&source).ok()
        } else {
            None
        };

        // Prefer CASR: it reproduces each crash, classifies exploitability and
        // severity, and clusters/deduplicates -- all in the sandbox. Fall back to
        // the built-in reproduce/classify/dedup path when CASR is unavailable (no
        // harness binary, native runtime without casr, or the tool errored). The
        // captured sanitizer traces (`logs`) feed bug-report drafting; CASR-path
        // crashes carry their summary instead.
        let (mut deduped, mut logs): (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ) = match self
            .run_casr_triage(&workspace, &out_dir, &run_binary, engine, run_id, target_id)
            .await?
        {
            Some(crashes) if !crashes.is_empty() => (crashes, std::collections::HashMap::new()),
            _ => {
                self.legacy_triage(&out_dir, &workspace, &run_binary, engine, run_id, target_id)
                    .await?
            }
        };

        // Give each crash a deterministic id so persisting is idempotent: a
        // second triage of the same run replaces these rows instead of adding
        // duplicates (the report lists every persisted crash for the run).
        for crash in &mut deduped {
            crash.id = deterministic_crash_id(run_id, &crash.stack_signature, &crash.input_path);
        }

        // Persist the completed classification NOW, before the optional (and
        // slower) minimization and LLM bug-report phases. Those phases run under
        // the same end-to-end triage budget; without this early write, a run
        // with many crashes or a slow provider would time out mid-enrichment and
        // discard all classification, and because ids are deterministic the
        // re-run would time out identically -- triage could never persist. The
        // final upsert below re-writes the same rows with the enriched fields.
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }

        // Native minimizers execute against the immutable run-owned harness and
        // original crash input. Legacy records without binary digest evidence
        // remain triageable but cannot claim a verified minimized artifact.
        if run.binary_rev.is_some() {
            self.minimize_triaged_crashes(
                &workspace,
                run_id,
                engine,
                &run_binary,
                &mut deduped,
                &mut logs,
            )
            .await;
        }

        // Draft an LLM bug report for each unique crash when a provider is
        // configured, using the captured sanitizer trace (capped, see above).
        if let Some(pool) = self.provider_pool() {
            let unique = deduped.len();
            for crash in deduped.iter_mut().take(MAX_BUG_REPORT_DRAFTS) {
                let bridge = LlmProviderBridge::new(Arc::clone(&pool))
                    .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
                let log = logs
                    .get(&crash.input_path)
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| crash.summary.clone());
                // Augment the report prompt with related project context when
                // this project has been indexed; empty on any failure, which
                // renders the un-augmented prompt.
                let related =
                    crate::knowledge::triage_related_context(project, target, &crash.summary);
                let related_section = hf_prompt::render_related_context_section(&related);
                match hf_crash::draft_report_with_context(
                    crash,
                    &log,
                    source_context.as_deref(),
                    if related_section.is_empty() {
                        None
                    } else {
                        Some(related_section.as_str())
                    },
                    Box::new(bridge),
                )
                .await
                {
                    Ok(report) => crash.bug_report = Some(report),
                    Err(e) => tracing::warn!("bug report drafting failed for {}: {e}", crash.id),
                }
            }
            if unique > MAX_BUG_REPORT_DRAFTS {
                tracing::info!(
                    "capped bug-report drafting at {MAX_BUG_REPORT_DRAFTS} of {unique} unique crashes"
                );
            }
        }

        // Re-check immutable evidence after untrusted triage execution before
        // persisting any derived classification.
        let _ = run_binary_path(&workspace, &run, target)?;
        if run.harness_rev.is_some() {
            let _ = run_source_path(&workspace, &run)?;
        }
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }
        // Triage completed with classified crashes: fire event-driven
        // schedules listening for `crash.found`.
        if !deduped.is_empty() {
            self.emit_scheduler_event(
                crate::scheduler::EVENT_CRASH_FOUND,
                serde_json::json!({
                    "project": project.display().to_string(),
                    "target": target,
                    "run_id": run_id.to_string(),
                    "crashes": deduped.len(),
                }),
            )
            .await;
        }
        Ok(deduped)
    }

    async fn minimize_triaged_crashes(
        &self,
        workspace: &Path,
        run_id: Uuid,
        engine: EngineKind,
        binary: &Path,
        crashes: &mut [hf_core::crash::Crash],
        logs: &mut std::collections::HashMap<PathBuf, String>,
    ) {
        use crate::crash_minimization::{prepare, PreparedMinimization, MAX_CRASH_MINIMIZATIONS};
        let Ok(_workspace_operation) = self.acquire_workspace_operation().await else {
            tracing::warn!("crash minimization skipped because the workspace is unavailable");
            return;
        };

        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        for crash in crashes.iter_mut().take(MAX_CRASH_MINIMIZATIONS) {
            let original = crash.input_path.clone();
            let prepared = match prepare(workspace, run_id, engine, binary, &original, crash.id) {
                Ok(prepared) => prepared,
                Err(error) => {
                    tracing::warn!(
                        crash_id = %crash.id,
                        "crash minimization staging failed: {error}"
                    );
                    continue;
                }
            };
            let minimized = match prepared {
                PreparedMinimization::Unsupported => break,
                PreparedMinimization::Complete(path) => Some(path),
                PreparedMinimization::Run(run) => {
                    let result = self
                        .runtime
                        .run_command_opts(&run.command, workspace, &limits, &run.sandbox)
                        .await;
                    match result {
                        Ok(result)
                            if result.termination
                                == hf_core::runtime::CommandTermination::Completed
                                && result.exit_code == 0 =>
                        {
                            match run.publish() {
                                Ok(path) => Some(path),
                                Err(error) => {
                                    tracing::warn!(
                                        crash_id = %crash.id,
                                        "crash minimizer output was rejected: {error}"
                                    );
                                    None
                                }
                            }
                        }
                        Ok(result) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                termination = ?result.termination,
                                exit_code = result.exit_code,
                                "crash minimizer did not complete successfully"
                            );
                            None
                        }
                        Err(error) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                "crash minimizer failed: {error}"
                            );
                            None
                        }
                    }
                }
            };
            if let Some(path) = minimized {
                if let Some(log) = logs.get(&original).cloned() {
                    logs.insert(path.clone(), log);
                }
                crash.input_path = path;
                crash.minimized = true;
            }
        }
    }

    /// Regression check: replay stored crash inputs against the current harness
    /// and report which ones still crash.
    ///
    /// The workflow is: fix the bug, recompile the harness, then run this to
    /// confirm the fix (and catch re-introductions). Prefers the persisted
    /// crashes for the project's latest run; falls back to crash inputs staged
    /// under the run output directory. Requires a compiled harness binary.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the harness is missing or the action is
    /// denied by guardrails.
    pub async fn verify_regressions(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<RegressionResult>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // Replaying crash inputs runs the (untrusted) harness in the sandbox --
        // gate it like triage.
        self.authorize_recorded(Action::Triage, "verify_regressions", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let binary_name = harness_binary_name(target);
        if !workspace.join(&binary_name).exists() {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }

        // (crash_id, input_path) pairs: persisted crashes first, else staged.
        let mut inputs: Vec<(String, PathBuf)> = Vec::new();
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        if let Some(store) = &self.store {
            if let Some(run) = &latest_run {
                let crashes = store.list_crashes_by_run(run.id).await?;
                inputs.extend(
                    crashes
                        .into_iter()
                        .map(|c| (c.id.to_string(), c.input_path)),
                );
            }
        }
        if inputs.is_empty() {
            let out_dir = match latest_run.as_ref() {
                Some(run) => run_output_dir(&workspace, run)?,
                None => workspace.join("out"),
            };
            inputs = latest_run
                .as_ref()
                .map_or_else(
                    || collect_legacy_crash_inputs(&out_dir),
                    |run| collect_crash_inputs(run.engine, &out_dir),
                )
                .into_iter()
                .map(|p| (String::new(), p))
                .collect();
        }

        let mut results = Vec::with_capacity(inputs.len());
        for (crash_id, input) in inputs {
            if !is_regular_file(&input) {
                continue;
            }
            let binary = workspace.join(harness_binary_name(target));
            let trace = self.reproduce_crash(&workspace, &binary, &input).await;
            let verified = trace.is_some();
            let still_crashes = trace.as_deref().is_some_and(hf_crash::looks_like_crash);
            let summary = if still_crashes {
                trace
                    .as_deref()
                    .unwrap_or_default()
                    .lines()
                    .find(|l| {
                        let s = l.to_ascii_lowercase();
                        s.contains("error") || s.contains("summary")
                    })
                    .unwrap_or("still crashes")
                    .trim()
                    .chars()
                    .take(200)
                    .collect()
            } else if verified {
                "no crash on replay (fixed)".to_owned()
            } else {
                "replay did not complete; result is inconclusive".to_owned()
            };
            results.push(RegressionResult {
                crash_id,
                input: input.display().to_string(),
                still_crashes,
                verified,
                summary,
            });
        }
        Ok(results)
    }

    /// Fetch the raw `llvm-cov export` JSON for a target, cached per target by
    /// the corpus+harness signature. The covered-set, summary, and frontier
    /// accessors all parse from this one cached export, so the expensive (~180s)
    /// coverage pipeline runs at most once per signature rather than once per
    /// accessor. `None` when no C harness was built or the pipeline did not
    /// complete cleanly (a transient failure is not cached, so it retries).
    async fn coverage_export_json_cached(&self, project: &Path, target: &str) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        let workspace = workspace_dir(project, target);
        if !workspace.join("harness.c").exists() {
            return None;
        }
        let cache_key = format!("{}::{target}", project.display());
        let signature = coverage_signature(&workspace);
        if let Some((cached_sig, cached)) = export_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&cache_key).cloned())
        {
            if cached_sig == signature {
                return Some(cached);
            }
        }
        let json = self.run_coverage_export(&workspace).await?;
        if let Ok(mut map) = export_cache().lock() {
            map.insert(cache_key, (signature, json.clone()));
        }
        Some(json)
    }

    /// Functions covered by a fuzz run, for the call-tree coverage overlay.
    ///
    /// Parses the shared cached `llvm-cov export` for per-function execution
    /// counts -- engine-agnostic, since the export comes from a purpose-built
    /// coverage binary rather than the run's. Empty when no harness was built or
    /// coverage tooling is unavailable.
    pub async fn coverage_functions(&self, project: &Path, target: &str) -> Vec<String> {
        self.coverage_export_json_cached(project, target)
            .await
            .map(|json| parse_covered_functions(&json))
            .unwrap_or_default()
    }

    /// Run the C source-coverage pipeline (build with instrumentation -> replay
    /// the corpus -> `llvm-cov export`) in the sandbox for an already-resolved
    /// `workspace`, returning the raw export JSON. `None` when the pipeline does
    /// not complete cleanly (so the caller does not cache a transient failure).
    /// The caller holds the workspace-operation guard and has verified a harness
    /// exists. Prefer [`Self::coverage_export_json_cached`], which adds the
    /// guard, harness check, and per-signature cache.
    async fn run_coverage_export(&self, workspace: &Path) -> Option<String> {
        let pipeline = "clang -g -O1 -fsanitize=fuzzer -fprofile-instr-generate \
             -fcoverage-mapping *.c -o fuzz_cov 2>/dev/null \
             && LLVM_PROFILE_FILE=cov.profraw ./fuzz_cov -runs=0 corpus 2>/dev/null; \
             llvm-profdata merge -sparse cov.profraw -o cov.profdata 2>/dev/null \
             && llvm-cov export ./fuzz_cov -instr-profile=cov.profdata 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 180,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, workspace, &limits).await {
            Ok(result)
                if result.termination == hf_core::runtime::CommandTermination::Completed
                    && result.exit_code == 0 =>
            {
                Some(result.stdout)
            }
            Ok(result) => {
                tracing::warn!(
                    termination = ?result.termination,
                    exit_code = result.exit_code,
                    "coverage collection did not complete cleanly; not caching so it retries"
                );
                None
            }
            Err(e) => {
                tracing::warn!("coverage collection failed: {e}");
                None
            }
        }
    }

    /// The uncovered frontier for a target: the `file:line` locations the
    /// current corpus has not reached, extracted from the same `llvm-cov export`
    /// the covered-set overlay uses. Drives targeted harness refinement
    /// ([`Self::harness_refine`]). Empty when no C harness was built or the
    /// coverage tooling is unavailable. Cached per target by the corpus+harness
    /// signature, like [`Self::coverage_functions`].
    pub async fn coverage_uncovered(
        &self,
        project: &Path,
        target: &str,
    ) -> Vec<hf_coverage::UncoveredRegion> {
        self.coverage_export_json_cached(project, target)
            .await
            .map(|json| hf_coverage::parse_llvm_cov_uncovered(&json))
            .unwrap_or_default()
    }

    /// Line/region/function coverage totals for a fuzz run.
    ///
    /// Complements [`Self::coverage_functions`] (which names covered functions
    /// for the call-tree overlay) with the structural percentages reviewers
    /// actually report: lines, functions, and regions covered out of the total.
    /// Builds the same source-based-coverage binary in the sandbox, replays the
    /// corpus, and parses the `llvm-cov export` totals. Returns `None` when no
    /// harness was built or the coverage tooling is unavailable. Cached per
    /// target by the corpus+harness signature, like the covered-function set.
    pub async fn coverage_summary(
        &self,
        project: &Path,
        target: &str,
    ) -> Option<hf_coverage::CoverageSummary> {
        let json = self.coverage_export_json_cached(project, target).await?;
        hf_coverage::parse_llvm_cov_summary(&json)
    }

    /// Assemble a self-contained reproduction bundle for `crash` into `dest`:
    /// the current harness source, the crash input bytes, and a `REPRODUCE.md`
    /// manifest carrying the exact build and run steps. A maintainer can then
    /// reproduce the finding with only the target toolchain -- no `hobot_fuzz`
    /// install (VISION reproducibility). Returns the bundle directory.
    ///
    /// # Errors
    /// Returns a validation error if the harness or crash input is missing (or
    /// the input is not a regular file -- symlinks are refused, never followed),
    /// or an internal error if the bundle cannot be written.
    pub async fn export_repro_bundle(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        crash: &hf_core::crash::Crash,
        dest: &Path,
    ) -> Result<PathBuf, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let workspace = workspace_dir(&project_root, target);
        let harness_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!("no harness source for '{target}' to bundle"))
        })?;
        // Copy the crash input by value; refuse a symlinked input rather than
        // following it out of the workspace into an unrelated file.
        if !is_regular_file(&crash.input_path) {
            return Err(ClassifiedError::Validation(format!(
                "crash input {} is missing or not a regular file",
                crash.input_path.display()
            )));
        }
        let input = std::fs::read(&crash.input_path).map_err(|e| {
            ClassifiedError::Validation(format!(
                "read crash input {}: {e}",
                crash.input_path.display()
            ))
        })?;
        let harness_filename = harness_bundle_filename(lang).to_owned();
        let build = hf_harness::build_command(engine, lang, "fuzz_bin");
        let build_command = format!(
            "{} {} {} -o {}",
            build.compiler,
            build.args.join(" "),
            harness_filename,
            build.output.display()
        );
        let manifest = crate::repro::ReproManifest {
            project: project_root.to_string_lossy().into_owned(),
            target: target.to_owned(),
            language: format!("{lang:?}"),
            engine: engine.as_str().to_owned(),
            // Harnesses build with ASan by default (see `build_command`).
            sanitizer: "address".to_owned(),
            build_command,
            harness_filename,
            input_filename: "crash_input".to_owned(),
            binary_name: "fuzz_bin".to_owned(),
            crash_kind: format!("{:?}", crash.kind),
            crash_summary: crash.summary.clone(),
            stack_signature: crash.stack_signature.clone(),
            minimized: crash.minimized,
        };
        crate::repro::write_repro_bundle(dest, &manifest, &harness_source, &input)
            .map_err(|e| ClassifiedError::Internal(format!("write repro bundle: {e}")))
    }

    /// Persisted crashes for the most recent matching run (empty without a
    /// store or matching runs). `target = None` selects project-wide history.
    async fn crashes_for_latest_run(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let run = self.latest_run_record(project, target).await?;
        Ok(match run {
            // Guard against any pre-existing duplicate rows (e.g. crashes
            // persisted before the deterministic-id fix): collapse by signature.
            Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
            None => Vec::new(),
        })
    }

    /// Export the latest run's crashes as a SARIF 2.1.0 document (string),
    /// for `GitHub` code scanning / security dashboards. Empty `results` when
    /// there are no crashes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected serialization failure.
    pub async fn export_sarif(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let crashes = self.crashes_for_latest_run(project, Some(target)).await?;
        let sarif =
            crate::sarif::crashes_to_sarif(&crashes, env!("CARGO_PKG_VERSION"), &project_root);
        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ClassifiedError::Internal(format!("serialize sarif: {e}")))
    }

    /// Whether a usable `DefectDojo` config is present (for the settings UI to show
    /// a configured / not-configured state without attempting a push).
    #[must_use]
    pub fn defectdojo_configured(&self) -> bool {
        crate::defectdojo::is_configured()
    }

    /// The configured `DefectDojo` base URL (no trailing slash), or `None` when it
    /// is unconfigured / still the placeholder. Lets presentation layers open the
    /// web UI without hard-coding or re-reading the config themselves.
    #[must_use]
    pub fn defectdojo_url(&self) -> Option<String> {
        crate::defectdojo::load_config()
            .ok()
            .map(|c| c.url.trim_end_matches('/').to_owned())
    }

    /// Verify the configured `DefectDojo` URL + token by calling its API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, the token is missing, or the
    /// server is unreachable / rejects auth.
    pub async fn defectdojo_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// Push the latest run's triaged crashes to `DefectDojo` as findings.
    ///
    /// Reuses `crashes_for_latest_run` and the shared CWE/severity
    /// mapping so the `DefectDojo` push and the SARIF export never disagree. The
    /// product defaults to the project's directory name and the test to the
    /// target, so repeat pushes land in the same `DefectDojo` test and dedup.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, there are no crashes to push,
    /// or the `DefectDojo` request fails.
    pub async fn push_to_defectdojo(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<crate::defectdojo::PushOutcome, ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let crashes = self.crashes_for_latest_run(project, target).await?;
        if crashes.is_empty() {
            return Err(ClassifiedError::Validation(
                "no triaged crashes to push to DefectDojo".to_owned(),
            ));
        }
        let findings = crate::defectdojo::crashes_to_generic(&crashes);
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        let product_name = cfg
            .product_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| defectdojo_project_name(project));
        let engagement_name = cfg
            .engagement_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Fuzzing".to_owned());
        let test_title =
            Some(target.map_or_else(|| "hobot_fuzz".to_owned(), |t| format!("hobot_fuzz: {t}")));
        let import = crate::defectdojo::ImportTarget {
            product_name,
            product_type_name: cfg.resolved_product_type(),
            engagement_name,
            test_title,
            reimport: cfg.reimport,
            auto_create: cfg.auto_create,
            // This push carries only the latest run's crashes, not the target's
            // complete crash history, so it must not close still-open findings a
            // shorter/non-deterministic run happened not to rediscover.
            close_old_findings: false,
        };
        client.import(&import, &findings).await
    }

    /// Compose a detailed Markdown campaign report for a target.
    ///
    /// Aggregates the discovered target, the most recent run, its triaged
    /// crashes (with CASR severity + LLM bug reports), line/region coverage, and
    /// corpus composition into one self-contained document. Missing persistence
    /// or tooling is represented honestly as unavailable data.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected internal failure.
    pub async fn generate_report(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        use crate::report::{render_markdown, ReportData};

        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        // Resolve the target candidate (best-effort) and its id.
        let candidate = self
            .resolve_target_candidate_any_language(project, target)
            .await?;
        let target_id = candidate.as_ref().map_or_else(Uuid::nil, |c| c.id);

        // Latest run + its crashes from the store, when persistence is wired.
        let (run, crashes) = if let Some(store) = &self.store {
            let run = self.latest_run_record(project, Some(target)).await?;
            let crashes = match &run {
                // Collapse any pre-existing duplicate rows by signature so the
                // report never lists the same crash twice.
                Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
                None => Vec::new(),
            };
            (run, crashes)
        } else {
            (None, Vec::new())
        };

        // Live coverage (best-effort) and corpus composition.
        let coverage = self.coverage_summary(project, target).await;
        let covered_functions = self.coverage_functions(project, target).await.len();
        let corpus = self
            .collect_corpus_stats(project, target, target_id)
            .await?;

        let data = ReportData {
            generated_at: Utc::now().to_rfc3339(),
            project: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            candidate,
            run,
            crashes,
            coverage,
            covered_functions,
            corpus,
        };

        // The deterministic fact-sheet is always correct and carries the graphs;
        // it is the no-provider fallback AND the grounded input for the LLM.
        let facts = render_markdown(&data);

        // When a provider is configured, have the LLM compose a professional
        // narrative grounded in those facts. On any failure, fall back to the
        // deterministic fact-sheet so a report is always produced.
        if let Some(pool) = self.provider_pool() {
            match self.compose_ai_report(&pool, &facts, &data).await {
                Ok(report) => return Ok(report),
                Err(e) => tracing::warn!("AI report composition failed, using fact-sheet: {e}"),
            }
        }
        Ok(facts)
    }

    /// Document formats this host can export a report to (see
    /// [`crate::report_export::available_formats`]).
    #[must_use]
    pub fn report_formats(&self) -> Vec<String> {
        crate::report_export::available_formats()
    }

    /// Compose the report for `target` and write it to `out_path` in `format`.
    /// Markdown and HTML always work; PDF/DOCX require pandoc (and, for PDF, a
    /// PDF engine).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if composition, format parsing, or the export
    /// (IO / external tool) fails.
    pub async fn export_report(
        &self,
        project: &Path,
        target: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        let markdown = self.generate_report(project, target).await?;
        let title = format!("hobot_fuzz report — {target}");
        crate::report_export::write_report(&markdown, &title, fmt, out_path)
    }

    /// Write already-composed report `markdown` (e.g. a saved draft) to
    /// `out_path` in `format`, without recomposing it.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on unknown format or export failure.
    pub fn export_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        crate::report_export::write_report(markdown, title, fmt, out_path)
    }

    /// Compose the narrative report with the LLM, grounded in the fact-sheet.
    async fn compose_ai_report(
        &self,
        pool: &Arc<dyn ProviderPool>,
        facts: &str,
        data: &crate::report::ReportData,
    ) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;

        let messages = vec![
            Message::system(crate::report::report_system_prompt()),
            Message::user(crate::report::report_user_prompt(facts, data)),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["reasoning", "code", "general"]),
            )
            .await?;
        self.diagnostics
            .record("report", &resp.model, &resp.usage)
            .await;
        let text = resp.text().trim();
        if text.is_empty() {
            return Err(ClassifiedError::Provider(
                "empty report from provider".to_owned(),
            ));
        }
        // Guarantee the campaign graphs survive even if the model dropped them.
        Ok(crate::report::ensure_graphs(text, data))
    }

    /// Summarize corpus composition for the report, preferring the persisted
    /// entries (richer source tags) and falling back to the workspace listing.
    async fn collect_corpus_stats(
        &self,
        project: &Path,
        target: &str,
        target_id: Uuid,
    ) -> Result<crate::report::CorpusStats, ClassifiedError> {
        use hf_core::corpus::CorpusSource;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let entries = match &self.store {
            Some(store) if target_id != Uuid::nil() => store.list_corpus_entries(target_id).await?,
            _ => Vec::new(),
        };
        let entries = if entries.is_empty() {
            // No persisted entries: read the live corpus directory.
            let workspace = workspace_dir(project, target);
            hf_corpus::list(&workspace.join("corpus"))?.entries
        } else {
            entries
        };

        let mut stats = crate::report::CorpusStats::default();
        for e in &entries {
            stats.count += 1;
            stats.total_bytes += e.size;
            match e.source {
                CorpusSource::Seed => stats.seeds += 1,
                CorpusSource::Fuzzer => stats.from_fuzzer += 1,
                CorpusSource::Minimized => stats.minimized += 1,
                CorpusSource::Manual => {}
            }
        }
        Ok(stats)
    }

    /// Replay a single crash input through the compiled harness in the sandbox
    /// and return the combined stdout+stderr (the sanitizer trace). A forced
    /// stop or runtime failure is inconclusive and returns `None`.
    async fn reproduce_crash(
        &self,
        workspace: &Path,
        binary_host: &Path,
        input_host_path: &Path,
    ) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        if !binary_host.is_file() {
            return None;
        }
        let binary = container_input_path(workspace, binary_host);
        let container_input = container_input_path(workspace, input_host_path);
        let cmd = vec![binary, container_input];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 30,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            // A crashing input exits non-zero; the trace is the useful output.
            Ok(result) if result.termination == hf_core::runtime::CommandTermination::Completed => {
                Some(format!("{}\n{}", result.stdout, result.stderr))
            }
            Ok(result) => {
                tracing::warn!(termination = ?result.termination, "crash reproduction did not complete");
                None
            }
            Err(e) => {
                tracing::warn!("crash reproduction failed: {e}");
                None
            }
        }
    }

    /// Most recent terminal persisted run in a project, optionally restricted to one
    /// target through `run.config.harness_id -> harness.target_id`.
    async fn latest_run_record(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<Option<RunRecord>, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let runs = store
            .list_runs(None)
            .await?
            .into_iter()
            .filter(|run| stored_project_matches(Path::new(&run.project_root), project))
            .collect::<Vec<_>>();
        let Some(target) = target else {
            return Ok(runs
                .into_iter()
                .find(|run| run_has_crash_evidence(run.status)));
        };
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        if target_id.is_nil() {
            return Ok(None);
        }
        for run in runs {
            if !run_has_crash_evidence(run.status) {
                continue;
            }
            if self.run_target_id(store, &run).await? == Some(target_id) {
                return Ok(Some(run));
            }
        }
        Ok(None)
    }

    /// Run CASR over the crash dir in the sandbox, returning one `Crash` per
    /// unique (clustered) report with its severity/analysis. Returns `None` when
    /// CASR is unavailable or produced nothing, so the caller can fall back.
    async fn run_casr_triage(
        &self,
        workspace: &Path,
        out_dir: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<Option<Vec<hf_core::crash::Crash>>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if !binary_host.is_file() {
            return Ok(None);
        }
        let binary = container_input_path(workspace, binary_host);
        if !out_dir.exists() {
            return Ok(None);
        }
        // CASR's input expectation differs by driver: `casr-afl` walks the AFL
        // output tree (out/<instance>/crashes/...), while `casr-libfuzzer` wants
        // a flat directory of crash inputs. For non-AFL engines we stage only
        // real crash inputs into a clean dir, since engines like honggfuzz mix
        // coverage maps and logs into `out` that CASR would otherwise replay.
        let crash_dir = if engine == EngineKind::AflPlusPlus {
            container_input_path(workspace, out_dir)
        } else {
            let staging = workspace
                .join("runs")
                .join(run_id.to_string())
                .join("triage")
                .join("casr_in");
            let _ = std::fs::remove_dir_all(&staging);
            if stage_crash_inputs(engine, out_dir, &staging) == 0 {
                return Ok(None);
            }
            container_input_path(workspace, &staging)
        };
        // Fresh CASR output directory each pass.
        let casr_host = workspace
            .join("runs")
            .join(run_id.to_string())
            .join("triage")
            .join("casr_out");
        let _ = std::fs::remove_dir_all(&casr_host);
        std::fs::create_dir_all(&casr_host).map_err(|error| {
            ClassifiedError::Internal(format!(
                "create CASR output directory {}: {error}",
                casr_host.display()
            ))
        })?;
        let casr_container = container_input_path(workspace, &casr_host);
        let cmd = hf_crash::casr_command(engine, &binary, &crash_dir, &casr_container, 30);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 240,
            env: std::collections::HashMap::new(),
            ptrace: true,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            extra_mounts: vec![hf_core::runtime::SandboxMount::writable(
                casr_host.clone(),
                casr_container.clone(),
            )],
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            Ok(r) if r.termination != hf_core::runtime::CommandTermination::Completed => {
                return Err(ClassifiedError::Sandbox(format!(
                    "CASR triage was force-stopped: {:?}",
                    r.termination
                )));
            }
            Ok(r) if r.exit_code != 0 => {
                tracing::warn!(
                    "casr exited {}: {}",
                    r.exit_code,
                    r.stderr.lines().last().unwrap_or_default()
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("casr run failed, falling back to built-in triage: {e}");
                return Ok(None);
            }
        }
        let reports = collect_casreps(&casr_host);
        if reports.is_empty() {
            tracing::info!("casr produced no reports; falling back to built-in triage");
            return Ok(None);
        }
        // The actual crash inputs, including AFL++'s nested
        // out/<instance>/crashes/ layout, so each casrep resolves to a real file.
        let crash_inputs = collect_crash_inputs(engine, out_dir);
        let mut crashes = reports
            .into_iter()
            .map(|(path, casr)| {
                let input_path = casrep_input_path(out_dir, &path, &crash_inputs);
                let signature = if casr.crashline.is_empty() {
                    casr.stack.first().cloned().unwrap_or_default()
                } else {
                    casr.crashline.clone()
                };
                let summary = if casr.severity_short.is_empty() {
                    casr.crashline.clone()
                } else {
                    format!("{} at {}", casr.severity_short, casr.crashline)
                };
                hf_core::crash::Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path,
                    stack_signature: signature,
                    kind: hf_crash::kind_from_short(&casr.severity_short),
                    summary,
                    minimized: false,
                    bug_report: None,
                    casr: Some(casr),
                }
            })
            .collect::<Vec<_>>();
        // Bucket by CASR cluster: keep one representative per cluster (clusters
        // are CASR's own "same bug" grouping, stronger than our stack signature).
        // Crashes CASR did not cluster (cluster=None) all pass through.
        crashes = bucket_by_cluster(crashes);
        tracing::info!("casr triaged {} unique crash(es)", crashes.len());
        Ok(Some(crashes))
    }

    /// Built-in triage fallback: replay crashes in the sandbox until the set of
    /// distinct stack signatures saturates, classify, and dedup. Returns the
    /// deduped crashes plus captured sanitizer traces for bug-report drafting.
    async fn legacy_triage(
        &self,
        out_dir: &Path,
        workspace: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<
        (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ),
        ClassifiedError,
    > {
        /// Hard cap on sandbox crash replays per triage pass.
        const MAX_REPRODUCE: usize = 300;
        /// Stop reproducing after this many consecutive crashes with no new
        /// stack signature (the distinct-bug set has saturated).
        const SIGNATURE_STAGNATION: usize = 40;

        let ingested = hf_crash::ingest_for_engine(out_dir, engine, run_id, target_id)?;
        if ingested.is_truncated() {
            tracing::warn!(
                run_id = %run_id,
                artifact_limit_reached = ingested.artifact_limit_reached,
                report_limit_reached = ingested.report_limit_reached,
                "triage crash ingestion reached a safety limit"
            );
        }
        let crashes = ingested.crashes;
        let total_ingested = crashes.len();
        let mut logs: std::collections::HashMap<PathBuf, String> = std::collections::HashMap::new();
        let mut reproduced: Vec<hf_core::crash::Crash> = Vec::new();
        let mut seen_signatures: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut since_new_signature = 0usize;
        for mut crash in crashes {
            if reproduced.len() >= MAX_REPRODUCE || since_new_signature >= SIGNATURE_STAGNATION {
                break;
            }
            let log = self
                .reproduce_crash(workspace, binary_host, &crash.input_path)
                .await;
            if log.as_deref().is_none_or(|value| value.trim().is_empty()) {
                since_new_signature += 1;
            } else if let Some(log) = log.as_deref() {
                let (kind, sig, summary) = hf_crash::classify(log);
                crash.kind = kind;
                crash.summary = summary;
                if seen_signatures.insert(sig.clone()) {
                    since_new_signature = 0;
                } else {
                    since_new_signature += 1;
                }
                crash.stack_signature = sig;
            }
            if let Some(log) = log {
                logs.insert(crash.input_path.clone(), log);
            }
            reproduced.push(crash);
        }
        if reproduced.len() < total_ingested {
            tracing::info!(
                "reproduced {} of {total_ingested} crash inputs ({} distinct signatures) before saturating",
                reproduced.len(),
                seen_signatures.len()
            );
        }
        Ok((hf_crash::dedup(reproduced), logs))
    }

    // -- Corpus -----------------------------------------------------------

    /// List corpus entries for a project/target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read.
    pub fn corpus_list(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<hf_core::corpus::Corpus, ClassifiedError> {
        let _workspace_operation = Self::try_acquire_workspace_operation_now()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        hf_corpus::list(&corpus_dir)
    }

    /// Seed the corpus with default inputs.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn corpus_seed(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_seed", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let seeds = vec![
            (b"{}".to_vec(), "seed_empty".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
        ];
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(corpus.entries.len())
    }

    /// Grow the corpus from engine output.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the directories cannot be read.
    pub async fn corpus_grow(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_grow", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        let out_dir = match latest_run.as_ref() {
            Some(run) => run_output_dir(&workspace, run)?,
            None => workspace.join("out"),
        };
        let mut corpus = hf_corpus::grow(&corpus_dir, &out_dir)?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        corpus.target_id = target_id;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(corpus.entries.len())
    }

    /// Prune duplicate-coverage entries from the corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be removed.
    pub async fn corpus_prune(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_prune", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let corpus = hf_corpus::list(&corpus_dir)?;
        let pruned = hf_corpus::prune(corpus)?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        self.persist_corpus(target_id, &pruned).await?;
        Ok(pruned.entries.len())
    }

    /// Coverage-based corpus minimization: run each input through `afl-showmap`
    /// in the sandbox to fingerprint the edges it covers, then drop inputs whose
    /// coverage is already represented by another. This is a true distillation
    /// (keep one input per distinct coverage set), unlike `corpus_prune` which,
    /// absent coverage data, can only collapse byte-identical files.
    ///
    /// Inputs for which a successful `afl-showmap` command yields no coverage
    /// keep a `None` coverage hash and fall back to content-dedup, so this never
    /// collapses two genuinely distinct inputs under an empty key. Qualification
    /// and sandbox failures abort without pruning.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read.
    pub async fn corpus_prune_coverage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let resolved =
            resolve_internal_run(EngineKind::AflPlusPlus, COVERAGE_PRUNE_OPERATION_SECS)?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_prune_coverage", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let mut corpus = hf_corpus::list(&corpus_dir)?;
        let before = corpus.entries.len();
        if before == 0 {
            return Ok(MinimizeOutcome {
                before: 0,
                after: 0,
            });
        }
        if before > 10_000 {
            return Err(ClassifiedError::Validation(
                "coverage pruning is limited to 10000 corpus inputs per operation".to_owned(),
            ));
        }

        let qualified = self
            .active_harness(project, target, EngineKind::AflPlusPlus)
            .await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "coverage pruning requires an explicitly promoted AFL++ harness".to_owned(),
            ));
        }
        self.verify_harness_qualification(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "AFL++ showmap".to_owned(),
                duration_secs: resolved.duration_secs,
            },
            "corpus_prune_coverage",
            Some(project),
        )
        .await?;

        let bin = harness_binary_name(target);
        let binary = workspace.join(&bin);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "promoted AFL++ harness binary is missing: {}",
                binary.display()
            )));
        }
        let binary_container = format!("/work/{bin}");
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            max_duration_secs: COVERAGE_PRUNE_COMMAND_SECS.min(resolved.duration_secs),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(resolved.duration_secs);
        for entry in &mut corpus.entries {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return Err(ClassifiedError::Sandbox(
                    "coverage pruning exceeded its 10-minute operation budget".to_owned(),
                ));
            };
            let input_container = container_input_path(&workspace, &entry.path);
            let args = hf_engine::showmap::build_showmap_args(&binary_container, &input_container);
            let result = tokio::time::timeout(
                remaining,
                self.runtime
                    .run_command_opts(&args, &workspace, &limits, &sandbox),
            )
            .await
            .map_err(|_| {
                ClassifiedError::Sandbox(
                    "coverage pruning exceeded its 10-minute operation budget".to_owned(),
                )
            })?;
            let result = result?.require_completed("AFL++ coverage pruning")?;
            if result.exit_code != 0 {
                return Err(ClassifiedError::Sandbox(format!(
                    "AFL++ coverage pruning exited with status {}: {}",
                    result.exit_code,
                    result.stderr.trim()
                )));
            }
            if let Some(hash) = hf_engine::showmap::coverage_hash(&result.stdout) {
                entry.coverage_hash = Some(hash);
            }
        }

        let pruned = hf_corpus::prune(corpus)?;
        let after = pruned.entries.len();
        self.persist_corpus(qualified.target_id, &pruned).await?;
        Ok(MinimizeOutcome { before, after })
    }

    /// Feed triaged crash reproducers back into the corpus.
    ///
    /// Closes the run -> triage -> corpus loop: every crash-triggering input
    /// surfaced by the most recent triage (persisted crashes for the target's
    /// latest run, falling back to scanning the run output directory) is copied
    /// into the corpus, deduplicated by content, so the harness keeps exercising
    /// the paths that already broke it. Returns the number of inputs newly
    /// added.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read or written.
    pub async fn corpus_absorb_crashes(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        self.corpus_absorb_run_record(project, target, latest_run)
            .await
    }

    /// Feed crash reproducers from one exact run back into the target corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run does not own terminal evidence for
    /// this target or the corpus cannot be read or written.
    pub async fn corpus_absorb_crashes_for_run(
        &self,
        project: &Path,
        target: &str,
        run_id: Uuid,
    ) -> Result<usize, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {run_id}")))?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        if target_id.is_nil()
            || !stored_project_matches(Path::new(&run.project_root), project)
            || !run_has_crash_evidence(run.status)
            || self.run_target_id(store, &run).await? != Some(target_id)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} does not own terminal evidence for target '{target}'"
            )));
        }
        self.corpus_absorb_run_record(project, target, Some(run))
            .await
    }

    async fn corpus_absorb_run_record(
        &self,
        project: &Path,
        target: &str,
        run: Option<RunRecord>,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_absorb_crashes", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // Prefer the deduplicated crash set triage persisted for the latest run;
        // fall back to whatever crash inputs are staged under the run output.
        let mut inputs: Vec<PathBuf> = Vec::new();
        if let Some(store) = &self.store {
            if let Some(run) = &run {
                let crashes = store.list_crashes_by_run(run.id).await?;
                inputs.extend(crashes.into_iter().map(|c| c.input_path));
            }
        }
        if inputs.is_empty() {
            let out_dir = match run.as_ref() {
                Some(run) => run_output_dir(&workspace, run)?,
                None => workspace.join("out"),
            };
            inputs = run.as_ref().map_or_else(
                || collect_legacy_crash_inputs(&out_dir),
                |run| collect_crash_inputs(run.engine, &out_dir),
            );
        }

        let (mut corpus, added) = hf_corpus::absorb(&corpus_dir, &inputs)?;
        if self.store.is_some() {
            let target_id = self.resolve_target_id_any_language(project, target).await?;
            corpus.target_id = target_id;
            self.persist_corpus(target_id, &corpus).await?;
        }
        Ok(added)
    }

    /// Coverage-guided corpus minimization.
    ///
    /// Runs libFuzzer's canonical `-merge=1` pass with the exact promoted and
    /// smoke-qualified harness. The service exposes only an immutable run-owned
    /// corpus snapshot and a bounded writable output directory to the sandbox;
    /// a successful merge is then reconciled into the retained corpus and its
    /// database inventory. Returns the entry counts before and after.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read or
    /// rewritten.
    pub async fn corpus_minimize(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let resolved = resolve_internal_run(EngineKind::LibFuzzer, CORPUS_MINIMIZE_SECS)?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_minimize", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = ensure_workspace_directory(&workspace, Path::new("corpus"))?;
        let before = hf_corpus::list(&corpus_dir)?.entries.len();
        if before == 0 {
            return Ok(MinimizeOutcome {
                before: 0,
                after: 0,
            });
        }

        let qualified = self
            .active_harness(project, target, EngineKind::LibFuzzer)
            .await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "corpus minimization requires an explicitly promoted libFuzzer harness".to_owned(),
            ));
        }
        self.verify_harness_qualification(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "libFuzzer corpus minimization".to_owned(),
                duration_secs: resolved.duration_secs,
            },
            "corpus_minimize",
            Some(project),
        )
        .await?;

        let binary = workspace.join(harness_binary_name(target));
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "promoted libFuzzer harness binary is missing: {}",
                binary.display()
            )));
        }
        let artifacts =
            stage_run_artifacts(&workspace, Uuid::new_v4(), &qualified.source, &binary)?;
        let run_root = artifacts.output_host.parent().ok_or_else(|| {
            ClassifiedError::Internal("minimization output has no run directory".to_owned())
        })?;
        let _staging_guard = StagingDirectoryGuard(run_root.to_path_buf());
        verify_staged_qualification(&qualified, &artifacts)?;
        verify_run_artifacts(&artifacts)?;

        let cmd = vec![
            artifacts.binary_container.clone(),
            "-merge=1".to_owned(),
            artifacts.output_container.clone(),
            artifacts.corpus_container.clone(),
        ];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            max_duration_secs: resolved.duration_secs,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = minimization_sandbox_options(&artifacts);
        let cancel = CancellationToken::new();
        let monitor_stop = CancellationToken::new();
        let budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let monitor = tokio::spawn(monitor_run_output(
            artifacts.output_host.clone(),
            artifacts.corpus_host.clone(),
            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            cancel.clone(),
            monitor_stop.clone(),
            Arc::clone(&budget_exceeded),
        ));
        let result = self
            .runtime
            .run_command_streaming_opts(&cmd, &workspace, &limits, &sandbox, &cancel, &|_| {})
            .await;
        monitor_stop.cancel();
        let _ = monitor.await;
        if !run_artifacts_within_budget(
            &artifacts,
            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
        )
        .await
        {
            budget_exceeded.store(true, std::sync::atomic::Ordering::Release);
        }
        if budget_exceeded.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ClassifiedError::Sandbox(
                "corpus minimization exceeded its corpus/output budget".to_owned(),
            ));
        }
        let result = result?.require_completed("corpus minimization")?;
        if result.exit_code != 0 {
            return Err(ClassifiedError::Sandbox(format!(
                "corpus minimization exited with status {}: {}",
                result.exit_code,
                result.stderr.trim()
            )));
        }

        let merged = hf_corpus::list(&artifacts.output_host)?;
        if merged.entries.is_empty() {
            return Err(ClassifiedError::Sandbox(
                "corpus minimization produced an empty survivor set".to_owned(),
            ));
        }
        let mut minimized = match hf_corpus::minimize(&corpus_dir, &artifacts.output_host) {
            Ok(corpus) => corpus,
            Err(error) => {
                return Err(minimization_failure_with_rollback(
                    &corpus_dir,
                    &artifacts.corpus_host,
                    error,
                ));
            }
        };
        minimized.target_id = qualified.target_id;
        if let Err(error) = self.persist_corpus(qualified.target_id, &minimized).await {
            return Err(minimization_failure_with_rollback(
                &corpus_dir,
                &artifacts.corpus_host,
                error,
            ));
        }
        Ok(MinimizeOutcome {
            before,
            after: minimized.entries.len(),
        })
    }

    // -- Chat -------------------------------------------------------------

    /// Send a chat message to the LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if no provider is configured or the LLM
    /// call fails.
    pub async fn chat_send(&self, message: &str) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;
        self.authorize_recorded(Action::Chat, "chat_send", None)
            .await?;
        let pool = self
            .provider_pool()
            .ok_or_else(|| ClassifiedError::Provider("no LLM provider configured".to_owned()))?;
        let messages = vec![
            Message::system(
                "You are hobot_fuzz, an AI fuzzing assistant. You help users discover \
                 fuzzing targets, generate harnesses, run fuzzing engines, triage crashes, \
                 and manage corpora. Be concise and actionable.",
            ),
            Message::user(message),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["general", "reasoning", "code"]),
            )
            .await?;
        self.diagnostics
            .record("chat", &resp.model, &resp.usage)
            .await;
        Ok(resp.text().to_owned())
    }
}

// ---------------------------------------------------------------------------
// Environment-driven construction
// ---------------------------------------------------------------------------

/// Build the sandbox runtime from the environment: a Docker runtime when the
/// daemon is reachable (and `HF_USE_DOCKER` is not disabled), else the stub.
#[must_use]
pub fn runtime_from_env() -> Arc<dyn RuntimeAdapter> {
    let use_docker = std::env::var("HF_USE_DOCKER").map_or(true, |v| v != "0" && v != "false");
    if use_docker && hf_runtime::docker_daemon_ready() {
        let cfg = RuntimeConfig::default();
        Arc::new(hf_runtime::docker::DockerRuntime::new(
            cfg,
            &workspace_root(),
        ))
    } else {
        Arc::new(hf_runtime::StubRuntime)
    }
}

/// Build an LLM provider pool from `HF_PROVIDER_*` env vars, or `None` when no
/// API key is configured.
#[must_use]
pub fn provider_pool_from_env() -> Option<Arc<dyn ProviderPool>> {
    let api_key = std::env::var("HF_PROVIDER_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())?;
    let model = std::env::var("HF_PROVIDER_MODEL").unwrap_or_else(|_| "gpt-4o".to_owned());
    let base_url = std::env::var("HF_PROVIDER_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_owned());
    // Build a single-provider pool through the TOML schema so every
    // ProviderConfig field receives its serde default without an unwieldy
    // struct literal. Values are escaped as TOML basic strings via the `toml`
    // serializer so a `"`, `\`, or newline in the API key/model/base URL cannot
    // produce malformed TOML that silently parses to `None` and disables the LLM.
    let quote = |value: &str| toml::Value::String(value.to_owned()).to_string();
    let toml_str = format!(
        "[[providers]]
\
         id = \"env\"
\
         provider_type = \"openai-compat\"
\
         model = {model_q}
\
         api_key = {api_key_q}
\
         base_url = {base_url_q}
\
         tags = [\"general\", \"reasoning\", \"code\"]
",
        model_q = quote(&model),
        api_key_q = quote(&api_key),
        base_url_q = quote(&base_url),
    );
    let cfg: hf_provider::ProviderPoolConfig = toml::from_str(&toml_str).ok()?;
    hf_provider::ProviderPoolImpl::from_config(&cfg)
        .ok()
        .map(|p| Arc::new(p) as Arc<dyn ProviderPool>)
}

/// Build an LLM provider pool from `config/providers.toml` (the file the GUI
/// Settings -> Providers tab writes). Returns `None` if the file is missing,
/// unparsable, or has no enabled provider.
#[must_use]
pub fn provider_pool_from_config() -> Option<Arc<dyn ProviderPool>> {
    let path = crate::init::config_dir().join("providers.toml");
    let text = std::fs::read_to_string(&path).ok()?;
    let cfg: hf_provider::ProviderPoolConfig = match toml::from_str(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            // A typo'd providers.toml previously disabled the LLM silently,
            // indistinguishable from "no config". Surface the parse error.
            tracing::warn!("failed to parse {}: {e}", path.display());
            return None;
        }
    };
    if !cfg.providers.iter().any(|p| p.enabled) {
        return None;
    }
    match hf_provider::ProviderPoolImpl::from_config(&cfg) {
        Ok(pool) => Some(Arc::new(pool) as Arc<dyn ProviderPool>),
        Err(e) => {
            tracing::warn!("failed to build provider pool from config: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

/// The result of a harness compile.
#[derive(Debug, Clone)]
pub struct CompileOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
}

/// Outcome of an end-to-end harness generation with automatic repair: the
/// compiled harness plus how many repair attempts it took to get there.
#[derive(Debug, Clone)]
pub struct HarnessGenOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
    /// Number of LLM repair passes applied before the harness compiled (0 when
    /// the first draft built cleanly).
    pub repairs_used: usize,
}

/// A generated seed entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SeedEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

/// The result of a corpus minimization pass: entry counts before and after.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct MinimizeOutcome {
    pub before: usize,
    pub after: usize,
}

/// Outcome of an autonomous end-to-end campaign
/// ([`ServiceContainer::run_campaign`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignOutcome {
    /// The target the campaign fuzzed (chosen automatically when not supplied).
    pub target: String,
    /// Status of the promoted harness revision used by the campaign.
    pub harness_status: HarnessStatus,
    /// Unique crashes surfaced by the final triage.
    pub crashes: usize,
    /// Peak edge coverage observed across the campaign's runs.
    pub edges: u64,
    /// How many run -> triage iterations the campaign performed.
    pub iterations: usize,
    /// How many iterations triggered the auto-revert policy (a harness revision
    /// regressed coverage past the threshold). Counts both applied reverts and
    /// notify-only detections, so headless history surfaces self-healing.
    pub auto_reverts: usize,
    /// Why the final campaign iteration stopped.
    pub termination: hf_core::runtime::CommandTermination,
    /// When the campaign plateaued on coverage without finding a crash, the
    /// result of the automatic targeted-refinement *proposal*. The refined
    /// harness is left `Compiled` (never promoted or auto-run), preserving the
    /// human promotion gate. `None` when no plateau was detected or refinement
    /// was not attempted (no provider, non-C target, or the compile action
    /// requires approval).
    #[serde(default)]
    pub refine: Option<RefineProposal>,
}

/// Outcome of an automatic coverage-plateau refinement proposal (HITL-safe:
/// the refined harness is only compiled, never promoted or executed).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RefineProposal {
    /// Uncovered frontier locations that drove the refinement.
    pub frontier_locations: usize,
    /// Whether a refined harness compiled successfully (still only `Compiled`,
    /// awaiting human review and promotion).
    pub compiled: bool,
    /// A short human-readable note for the run log.
    pub note: String,
}

/// Outcome of replaying one stored crash input against the current harness.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegressionResult {
    /// Persisted crash id (empty if the input came from the output dir).
    pub crash_id: String,
    /// The crash input that was replayed.
    pub input: String,
    /// True if the input still triggers a crash (a regression / unfixed bug).
    pub still_crashes: bool,
    /// Whether the sandbox replay completed and the result is conclusive.
    pub verified: bool,
    /// A short trace/summary line from the replay.
    pub summary: String,
}

/// Per-provider health + usage for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderSnapshot {
    pub id: String,
    pub model: String,
    pub tags: Vec<String>,
    pub is_frozen: bool,
    pub active_requests: usize,
    pub max_concurrency: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// A single agent turn currently executing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInstanceSnapshot {
    pub instance_id: String,
    pub agent_name: String,
    pub state: String,
    pub elapsed_ms: u64,
    pub iterations: u32,
    pub tokens_used: u64,
}

/// Agent pool state. `available_slots` is the number of registered definitions;
/// `active_instances` and `instances` describe live per-turn executions.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentPoolSnapshot {
    pub active_instances: usize,
    pub available_slots: usize,
    pub total_instances: usize,
    pub instances: Vec<AgentInstanceSnapshot>,
}

/// Runtime/state counters for the Observability panel's Memory section.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct MemorySnapshot {
    pub pending_runs: usize,
    pub interrupted_runs: usize,
    pub llm_calls: u64,
    pub targets: usize,
    pub crashes: usize,
}

/// A live snapshot of system state for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemSnapshot {
    pub providers: Vec<ProviderSnapshot>,
    pub agents: AgentPoolSnapshot,
    pub memory: MemorySnapshot,
}

/// A cheap snapshot of a target's on-disk artifacts, for the Info panel.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ArtifactSummary {
    /// Whether the compiled harness binary (`fuzz_<target>`) exists.
    pub harness_built: bool,
    /// Number of corpus inputs on disk.
    pub corpus_count: usize,
    /// Number of crash inputs staged in the run output directory.
    pub crash_count: usize,
}

/// One point on a run's intra-run coverage/throughput curve.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageSample {
    /// Seconds elapsed since the run started.
    pub t: f64,
    /// Edge coverage at that moment.
    pub edges: u64,
    /// Executions/second at that moment.
    pub execs: f64,
}

/// Reduce a time series to at most `cap` points by uniform stride, always
/// keeping the last sample so the curve reaches its true end.
fn downsample(series: &[(f64, u64, f64)], cap: usize) -> Vec<(f64, u64, f64)> {
    if series.len() <= cap || cap == 0 {
        return series.to_vec();
    }
    let stride = series.len().div_ceil(cap);
    let mut out: Vec<(f64, u64, f64)> = series.iter().step_by(stride).copied().collect();
    if let Some(last) = series.last() {
        if out.last() != Some(last) {
            out.push(*last);
        }
    }
    out
}

/// The auto-revert decision, isolated from the async plumbing so its rules are
/// unit-testable. Returns `Some(drop_pct)` when the policy should restore the
/// previous harness: the revision changed (`prev_rev != this_rev`), there is a
/// non-zero baseline, coverage dropped, and the drop meets the threshold.
/// Returns `None` otherwise.
fn auto_revert_decision(
    prev_rev: &str,
    this_rev: &str,
    prev_edges: u64,
    this_edges: u64,
    threshold_pct: f64,
) -> Option<f64> {
    // Only a genuine revision change can be a revision regression; an unchanged
    // harness covering fewer edges is run-to-run noise.
    if prev_rev == this_rev {
        return None;
    }
    // No baseline, or coverage held/improved -> nothing to revert.
    if prev_edges == 0 || this_edges >= prev_edges {
        return None;
    }
    let drop_pct = (prev_edges - this_edges) as f64 / prev_edges as f64 * 100.0;
    (drop_pct >= threshold_pct).then_some(drop_pct)
}

/// Whether two run configurations produce coverage measurements that are safe
/// to compare for an automatic harness rollback.
///
/// The harness id is intentionally ignored because a revision change is the
/// subject of the comparison. Engine, budget, sanitizer, corpus location,
/// environment, engine arguments, and the separately persisted comparison
/// context must match; otherwise a lower edge count can be caused by the
/// experimental setup rather than the new harness.
fn auto_revert_baseline_compatible(previous: &FuzzRunConfig, current: &FuzzRunConfig) -> bool {
    previous.engine == current.engine
        && previous.duration == current.duration
        && previous.max_mem_mb == current.max_mem_mb
        && previous.max_cpus == current.max_cpus
        && previous.seed_corpus == current.seed_corpus
        && previous.sanitizer == current.sanitizer
        && previous.env == current.env
        && previous.extra_args == current.extra_args
}

/// Stable opaque key for grouping comparable coverage experiments in
/// presentation layers. The harness id is excluded so revision A/B results for
/// the same target and execution context share a key.
fn auto_revert_comparison_key(
    target_id: Uuid,
    config: &FuzzRunConfig,
    context_rev: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let context = serde_json::json!({
        "target_id": target_id,
        "engine": config.engine,
        "duration": config.duration,
        "max_mem_mb": config.max_mem_mb,
        "max_cpus": config.max_cpus,
        "seed_corpus": config.seed_corpus,
        "sanitizer": config.sanitizer,
        "env": config.env,
        "extra_args": config.extra_args,
        "context_rev": context_rev,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&context).unwrap_or_default());
    format!("{:x}", hasher.finalize())[..16].to_owned()
}

/// A target a scheduled campaign can legally run (see
/// [`ServiceContainer::schedulable_targets`]): it has a promoted harness, and
/// the engine and language are the harness's own, not a guess.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SchedulableTarget {
    pub target: String,
    /// Canonical engine id, e.g. `libfuzzer`.
    pub engine: String,
    /// Canonical language id, e.g. `c`.
    pub language: String,
    /// Discovery fit score (0..1). Portfolio campaigns rotate highest-first, so
    /// the most promising targets get fuzzed sooner and more often.
    pub fit_score: f64,
}

/// One run in the persisted run history (see [`ServiceContainer::run_history`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunHistoryItem {
    pub id: String,
    pub project_root: String,
    /// Target symbol resolved through the run's persisted harness.
    pub target: Option<String>,
    /// Opaque grouping key shared only by directly comparable successful runs.
    pub comparison_key: Option<String>,
    pub engine: String,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_secs: Option<i64>,
    pub crashes: usize,
    /// Peak edge coverage, once the run finished (None for older/pending runs).
    pub edges: Option<u64>,
    /// Peak executions/second, once the run finished.
    pub execs: Option<f64>,
    /// Full SHA-256 of the approved harness source the run used.
    pub harness_rev: Option<String>,
    /// Full SHA-256 of the staged executable the run used.
    pub binary_rev: Option<String>,
    /// Workspace-relative run output directory.
    pub evidence_dir: Option<String>,
}

/// Public lifecycle states used by non-blocking run-control transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLifecycleStatus {
    /// The durable row exists but execution has not started.
    Pending,
    /// The sandboxed engine is active and may be cancelled cooperatively.
    Running,
    /// Execution completed and terminal evidence is durable.
    Done,
    /// Execution failed and the durable row has been repaired.
    Failed,
    /// The user requested cooperative cancellation.
    Cancelled,
}

impl RunLifecycleStatus {
    /// Stable lowercase transport representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl From<RunStatus> for RunLifecycleStatus {
    fn from(status: RunStatus) -> Self {
        match status {
            RunStatus::Pending => Self::Pending,
            RunStatus::Running => Self::Running,
            RunStatus::Done => Self::Done,
            RunStatus::Failed => Self::Failed,
            RunStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Durable status snapshot for one service-owned run UUID.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunControlStatus {
    /// Service-owned run UUID.
    pub run_id: Uuid,
    /// Durable lifecycle state.
    pub status: RunLifecycleStatus,
    /// Whether a cooperative cancellation token is currently registered.
    pub active: bool,
    /// RFC3339 reservation time.
    pub started_at: String,
    /// RFC3339 terminal time, when complete.
    pub ended_at: Option<String>,
}

/// Domain outcome of a cooperative cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCancelOutcome {
    /// The active run's token was signalled.
    Accepted,
    /// No durable run exists for the requested UUID.
    NotFound,
    /// The run exists but is terminal or no longer active.
    Inactive,
}

/// A fuzz run summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    /// Persisted run that owns this summary and its evidence.
    pub run_id: Uuid,
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    /// Authoritative reason the sandboxed engine stopped.
    pub termination: hf_core::runtime::CommandTermination,
    /// The highest coverage-stagnation proposal tier surfaced during the run
    /// (improve mutation inputs / regenerate the harness / stop the target),
    /// or `None` if coverage kept progressing. Lets a presentation layer offer
    /// an iterate-next affordance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stagnation: Option<hf_coverage::StagnationProposal>,
    /// Set when the auto-revert policy fired: this run's harness regressed
    /// coverage past the configured threshold, so an earlier (last-good)
    /// revision was restored and recompiled. Lets a presentation layer surface
    /// the automatic action. `None` when the policy is off or did not trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_revert: Option<AutoRevertOutcome>,
}

/// The outcome of the auto-revert policy firing for a finished run: its harness
/// revision changed and coverage dropped past the threshold, so the previous
/// run's (last-good) harness was restored and recompiled.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AutoRevertOutcome {
    /// The id of the earlier run whose harness was (or would be) restored.
    pub reverted_to_run: String,
    /// The regressed run's harness revision (the one that was replaced).
    pub from_rev: String,
    /// The restored run's harness revision.
    pub to_rev: String,
    /// Peak edge coverage of the restored (previous) run.
    pub previous_edges: u64,
    /// Peak edge coverage of the regressed run.
    pub regressed_edges: u64,
    /// The percent coverage drop that triggered the revert.
    pub drop_pct: f64,
    /// `true` when the harness was actually restored and recompiled; `false`
    /// when the policy is in notify-only mode and only reported the regression.
    pub reverted: bool,
}

/// The resolved auto-revert policy for a project, plus whether a per-project
/// override is in effect (vs inheriting the global default).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct EffectiveAutoRevert {
    /// Whether the policy is armed for this project.
    pub enabled: bool,
    /// The coverage-drop threshold (percent) that triggers a revert.
    pub threshold_pct: f64,
    /// Report the regression without restoring the harness.
    pub notify_only: bool,
    /// `true` when a per-project override applies; `false` when inheriting global.
    pub overridden: bool,
}

/// Inputs for a syzkaller kernel-fuzzing campaign.
#[derive(Debug, Clone, Default)]
pub struct SyzkallerRunOpts {
    /// Project label (for logging only).
    pub project: String,
    /// Target architecture (e.g. `"amd64"`); defaults to the host platform.
    pub arch: Option<String>,
    /// Campaign duration in seconds.
    pub duration_secs: u64,
    /// Path to a KCOV kernel image (bzImage). Required without `manager_cfg`;
    /// otherwise overrides the config's `vm.kernel` path.
    pub kernel_image: Option<String>,
    /// Path to a rootfs disk image. Required without `manager_cfg`; otherwise
    /// overrides the config's `image` path. The selected file is copied before
    /// qemu receives a writable view.
    pub disk_image: Option<String>,
    /// Optional SSH private key for the VM; overrides the config's `sshkey`.
    pub ssh_key: Option<String>,
    /// Path to an existing `syz-manager` config. The service parses and
    /// rewrites managed paths rather than mounting this file or its parent.
    pub manager_cfg: Option<String>,
    /// Number of fuzzing VMs (default 2); overrides a supplied config when set
    /// and is clamped to the service maximum of four.
    pub vm_count: Option<u32>,
}

/// Result of a syzkaller campaign.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyzkallerSummary {
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    pub exit_code: Option<i32>,
    /// Authoritative reason the sandbox stopped.
    pub termination: Option<hf_core::runtime::CommandTermination>,
}

/// Build the syzkaller manager argv without a shell interpolation boundary.
///
/// Keeping the staged config path as one argv element makes its bytes data
/// rather than executable syntax. The inner timeout ends the campaign at its
/// requested budget with a graceful `TERM`, then `--kill-after` force-kills a
/// syz-manager that ignores it -- both before the sandbox teardown backstop, so
/// a hung manager cannot trip the outer Docker deadline and discard the summary.
fn syzkaller_manager_command(
    manager_cfg: &str,
    duration_secs: u64,
    kill_after_secs: u64,
) -> Vec<String> {
    vec![
        "timeout".to_owned(),
        "--signal=TERM".to_owned(),
        format!("--kill-after={kill_after_secs}"),
        duration_secs.to_string(),
        "syz-manager".to_owned(),
        format!("-config={manager_cfg}"),
    ]
}

// ---------------------------------------------------------------------------
// LLM provider bridge: wraps a ProviderPool as a single LlmProvider
// ---------------------------------------------------------------------------

struct LlmProviderBridge {
    pool: Arc<dyn ProviderPool>,
    meta: hf_core::provider::ProviderMetadata,
    /// When set, each completion is recorded as a cost/trace diagnostic under
    /// the given operation label.
    diag: Option<(Arc<crate::diagnostics::DiagnosticsRecorder>, String)>,
}

impl LlmProviderBridge {
    fn new(pool: Arc<dyn ProviderPool>) -> Self {
        use hf_core::provider::{
            ProviderCapability, ProviderMetadata, ProviderType, ToolCallingMode,
        };
        let meta = ProviderMetadata {
            id: hf_core::types::ProviderId::from_string("pool-bridge"),
            provider_type: ProviderType::Custom,
            model: String::new(),
            tags: Vec::new(),
            capabilities: vec![ProviderCapability::Text],
            max_concurrency: 1,
            context_window: 128_000,
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,
            tool_calling_mode: ToolCallingMode::PromptBased,
        };
        Self {
            pool,
            meta,
            diag: None,
        }
    }

    /// Record completions through this bridge as diagnostics under `op`.
    fn with_diagnostics(
        mut self,
        recorder: Arc<crate::diagnostics::DiagnosticsRecorder>,
        op: &str,
    ) -> Self {
        self.diag = Some((recorder, op.to_owned()));
        self
    }
}

#[async_trait::async_trait]
impl hf_core::provider::LlmProvider for LlmProviderBridge {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let response = self
            .pool
            .chat_completion(request, &hf_core::provider::RouteRequest::default())
            .await?;
        if let Some((recorder, op)) = &self.diag {
            recorder.record(op, &response.model, &response.usage).await;
        }
        Ok(response)
    }

    async fn chat_completion_stream(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        self.pool
            .chat_completion_stream(request, &hf_core::provider::RouteRequest::default())
            .await
    }

    fn metadata(&self) -> &hf_core::provider::ProviderMetadata {
        &self.meta
    }
}

// ---------------------------------------------------------------------------
// Heuristic harness draft (no-LLM fallback)
// ---------------------------------------------------------------------------

/// Generate a heuristic harness draft when no LLM provider is configured.
fn heuristic_draft(candidate: &TargetCandidate, engine: EngineKind) -> HarnessDraft {
    let includes = generate_includes(candidate);
    let forward_decl = generate_forward_decl(&candidate.symbol, candidate.signature.as_deref());
    let body = generate_harness_body(&candidate.symbol, candidate.signature.as_deref());
    let source = format!(
        r"// Auto-generated harness for {symbol}
// Engine: {engine}
// Target: {file}:{line}
#include <stdint.h>
#include <stddef.h>
{includes}
{forward_decl}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Target signature: {sig}
{body}
    return 0;
}}
",
        symbol = candidate.symbol,
        engine = engine_label(engine),
        file = candidate.location.file.display(),
        line = candidate.location.line,
        includes = includes,
        forward_decl = forward_decl,
        sig = candidate.signature.as_deref().unwrap_or("(unknown)"),
        body = body,
    );
    HarnessDraft {
        target_id: candidate.id,
        engine,
        source,
        rationale: String::new(),
        build_cmd: hf_harness::build_command(
            engine,
            candidate.language,
            &harness_binary_name(&candidate.symbol),
        ),
    }
}

fn engine_label(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::ClusterFuzzLite => "ClusterFuzzLite",
        EngineKind::Syzkaller => "syzkaller",
    }
}

/// Build the `#include` line for a target's header.
fn generate_includes(candidate: &TargetCandidate) -> String {
    let file = &candidate.location.file;
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    format!("#include \"{stem}.h\"")
}

/// Build a forward declaration for the target function so the harness
/// compiles even when the header does not export the symbol.
///
/// Uses the signature captured by the scanner (the declarator portion of the
/// function definition).  We prepend the return type that the scanner strips
/// out (best-effort: assume `int` when unknown) and terminate with `;`.
fn generate_forward_decl(symbol: &str, signature: Option<&str>) -> String {
    let Some(sig) = signature else {
        return format!("int {symbol}();");
    };
    // The scanner stores the declarator, e.g. "parse_value_inner(const char
    // *buf, size_t len, value_t *out, int *err)".  Use it verbatim and append
    // `;` to form a prototype.  When the return type is not visible we
    // declare it as `int` (C default) so the compiler has a prototype.
    let trimmed = sig.trim();
    if trimmed.is_empty() {
        return format!("int {symbol}();");
    }
    // If the declarator already has a return type prefix, keep it; otherwise
    // assume int.
    let has_return_type = trimmed.split_whitespace().next().is_some_and(|first_word| {
        // If the first token contains the function name (starts with the
        // symbol or has no space before the opening paren) there is no
        // explicit return type in the declarator.
        !first_word.starts_with(symbol) && first_word != symbol
    });
    if has_return_type {
        format!("{trimmed};")
    } else {
        format!("int {trimmed};")
    }
}

/// Build the body of `LLVMFuzzerTestOneInput` for a target.
fn generate_harness_body(symbol: &str, signature: Option<&str>) -> String {
    let fallback = format!("    {symbol}((const char *)data, size);");
    let Some(sig) = signature else {
        return fallback;
    };
    let (Some(open), Some(close)) = (sig.find('('), sig.rfind(')')) else {
        return fallback;
    };
    // Guard against a malformed declarator where the first `(` is at or after the
    // last `)` (e.g. an oddly-parsed `foo)(...` signature): `open + 1 > close`
    // would make the slice below panic on a start-past-end range.
    if open >= close {
        return fallback;
    }
    let params_str = &sig[open + 1..close];
    let params: Vec<&str> = params_str
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "void")
        .collect();
    if params.is_empty() {
        return fallback;
    }

    let mut decls: Vec<String> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let mut buffer_used = false;

    for (i, param) in params.iter().enumerate() {
        let star_count = param.matches('*').count();
        let is_char_like =
            param.contains("char") || param.contains("uint8") || param.contains("void");
        if star_count == 1 && is_char_like && !buffer_used {
            args.push("(const char *)data".to_string());
            buffer_used = true;
        } else if star_count >= 1 {
            let base = param[..param.find('*').unwrap_or(param.len())]
                .trim()
                .trim_start_matches("const ")
                .trim();
            let base = if base.is_empty() { "char" } else { base };
            decls.push(format!("    {base} _arg{i} = {{0}};"));
            args.push(format!("&_arg{i}"));
        } else {
            args.push("size".to_string());
        }
    }

    let mut body = String::new();
    for d in &decls {
        body.push_str(d);
        body.push('\n');
    }
    let _ = write!(body, "    {symbol}({});", args.join(", "));
    body
}

/// Coverage-guided feedback for a live fuzz run.
///
/// Feeds each streamed edge reading into a [`hf_coverage::CoverageTracker`]
/// and, while coverage stays flat, surfaces an escalating
/// [`StagnationProposal`](hf_coverage::StagnationProposal) to the user: a live
/// log line each time the proposal escalates a tier (improve the mutation
/// inputs -> regenerate the harness -> stop the target), and the highest
/// tier reached on the final [`RunSummary`]. This realizes the coverage
/// feedback loop from `docs/design/corpus-coverage-design.md` §4: we detect
/// stagnation and *propose* iterating rather than regenerating a harness
/// autonomously, which would bypass the human-in-the-loop review that harness
/// execution requires (AGENTS.md §2.12).
struct CoverageFeedback<'a> {
    /// The run the streamed edge readings are measured for.
    run_id: Uuid,
    tracker: std::sync::Mutex<hf_coverage::CoverageTracker>,
    /// Latched proposal: the highest tier surfaced so far, so each tier is
    /// proposed at most once.
    proposal: std::sync::Mutex<Option<hf_coverage::StagnationProposal>>,
    policy: hf_coverage::StagnationPolicy,
    emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
}

impl<'a> CoverageFeedback<'a> {
    fn new(
        run_id: Uuid,
        policy: hf_coverage::StagnationPolicy,
        emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Self {
        Self {
            run_id,
            tracker: std::sync::Mutex::new(hf_coverage::CoverageTracker::new()),
            proposal: std::sync::Mutex::new(None),
            policy,
            emit,
        }
    }

    /// Record a cumulative edge count from a stat pulse and, whenever the
    /// stagnation proposal escalates to a tier not yet surfaced, emit and
    /// latch it.
    fn on_edges(&self, edges: u64) {
        let Ok(mut tracker) = self.tracker.lock() else {
            return;
        };
        tracker.update(&hf_core::coverage::CoverageReport {
            run_id: self.run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        });
        let Some(proposal) = hf_coverage::propose_action(&tracker, &self.policy) else {
            return;
        };
        let Ok(mut slot) = self.proposal.lock() else {
            return;
        };
        // Only a tier not yet surfaced is announced.
        if slot.as_ref() == Some(&proposal) {
            return;
        }
        (self.emit)(FuzzProgress::LogLine(format!(
            "[coverage] no new edges for {}s -- {}",
            tracker.stagnation_secs(),
            describe_proposal(&proposal),
        )));
        *slot = Some(proposal);
    }

    /// The highest proposal tier surfaced during the run, if any.
    fn proposal(&self) -> Option<hf_coverage::StagnationProposal> {
        self.proposal.lock().ok().and_then(|p| p.clone())
    }
}

/// A short, user-facing description of a stagnation proposal for the run log.
fn describe_proposal(proposal: &hf_coverage::StagnationProposal) -> &'static str {
    match proposal {
        hf_coverage::StagnationProposal::NewHarness => {
            "consider regenerating the harness to reach new code paths"
        }
        hf_coverage::StagnationProposal::CustomMutator => {
            "consider adding seeds, a dictionary, or a custom mutator"
        }
        hf_coverage::StagnationProposal::Stop => "consider stopping this target",
    }
}

#[cfg(test)]
mod casrep_path_tests {
    use super::casrep_input_path;
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_afl_nested_crash_input() {
        // AFL++ nests the input under out/<instance>/crashes/; the casrep sits in
        // casr_out. The resolved path must point at the real nested file.
        let out = Path::new("/work/out");
        let nested = PathBuf::from("/work/out/default/crashes/id:000001,sig:06");
        let inputs = vec![nested.clone()];
        let casrep = Path::new("/work/casr_out/id:000001,sig:06.casrep");
        assert_eq!(casrep_input_path(out, casrep, &inputs), nested);
    }

    #[test]
    fn falls_back_to_flat_layout_for_libfuzzer() {
        // libFuzzer crashes sit directly in out/; when the input list does not
        // contain a match, fall back to out/<name>.
        let out = Path::new("/work/out");
        let casrep = Path::new("/work/casr_out/crash-abc.casrep");
        assert_eq!(
            casrep_input_path(out, casrep, &[]),
            PathBuf::from("/work/out/crash-abc")
        );
    }
}

#[cfg(test)]
mod coverage_feedback_tests {
    use super::{CoverageFeedback, FuzzProgress};
    use hf_coverage::{StagnationPolicy, StagnationProposal};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    fn policy(threshold_secs: u64) -> StagnationPolicy {
        StagnationPolicy {
            threshold_secs,
            new_harness_windows: 2,
            stop_windows: 3,
        }
    }

    fn log_line_count(emitted: &Mutex<Vec<FuzzProgress>>) -> usize {
        emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|p| matches!(p, FuzzProgress::LogLine(_)))
            .count()
    }

    /// An instant `secs` in the past, for deterministic stagnation aging.
    fn backdated(secs: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn proposes_once_when_edges_plateau() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        // threshold 0: the first flat pulse after the initial reading is stagnant.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100); // first reading -- never stagnant (needs >1 update)
        assert_eq!(fb.proposal(), None);
        fb.on_edges(100); // flat -> stagnant -> propose the first tier
        fb.on_edges(100); // still flat, same tier -> must NOT propose again (latched)

        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));
        assert_eq!(
            log_line_count(&emitted),
            1,
            "the proposal must be surfaced exactly once"
        );
    }

    #[test]
    fn escalates_the_proposal_as_stagnation_drags_on() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(100), &emit);
        let report = |edges| hf_core::coverage::CoverageReport {
            run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        };

        // Coverage last progressed 150s ago: one full 100s stagnation window.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(100), backdated(150));
        fb.on_edges(100);
        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));

        // 250s flat: the second window escalates to a new-harness proposal.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(101), backdated(250));
        fb.on_edges(101);
        assert_eq!(fb.proposal(), Some(StagnationProposal::NewHarness));

        // 350s flat: the third window recommends stopping the target.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(102), backdated(350));
        fb.on_edges(102);
        fb.on_edges(102); // same tier again -> not re-surfaced
        assert_eq!(fb.proposal(), Some(StagnationProposal::Stop));

        assert_eq!(
            log_line_count(&emitted),
            3,
            "each escalation tier must be surfaced exactly once"
        );
    }

    #[test]
    fn no_proposal_on_a_single_reading() {
        let emit = |_p: FuzzProgress| {};
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn threshold_gates_the_proposal() {
        let emit = |_p: FuzzProgress| {};
        // A high threshold is not reached in the test's wall-clock window, so a
        // flat plateau does not (yet) propose.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(3600), &emit);
        fb.on_edges(100);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn coverage_report_carries_the_run_id() {
        // The report fed to the tracker must name the run the coverage was
        // measured for, not the nil UUID.
        let emit = |_p: FuzzProgress| {};
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.tracker.lock().unwrap().run_id(), run_id);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::parse_covered_functions;

    #[test]
    fn parses_covered_functions_from_llvm_cov_json() {
        let json = r#"{"data":[{"functions":[
            {"name":"parse_entry","count":5},
            {"name":"validate","count":2},
            {"name":"never_called","count":0},
            {"name":"decode","count":3}
        ]}]}"#;
        let covered = parse_covered_functions(json);
        assert_eq!(covered, vec!["decode", "parse_entry", "validate"]);
        assert!(!covered.contains(&"never_called".to_owned()));
    }

    #[test]
    fn parse_handles_garbage() {
        assert!(parse_covered_functions("not json").is_empty());
        assert!(parse_covered_functions("{}").is_empty());
    }

    #[test]
    fn coverage_signature_changes_when_corpus_grows() {
        use super::coverage_signature;
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        std::fs::write(ws.join("harness.c"), "x").unwrap();
        std::fs::create_dir_all(ws.join("corpus")).unwrap();
        std::fs::write(ws.join("corpus/a"), "1").unwrap();

        let sig1 = coverage_signature(ws);
        // Same inputs -> same signature (cache hit).
        assert_eq!(sig1, coverage_signature(ws));
        // A new corpus file -> different signature (cache invalidated).
        std::fs::write(ws.join("corpus/b"), "2").unwrap();
        assert_ne!(sig1, coverage_signature(ws));
    }

    fn region(function: &str, file: &str, line: u32) -> hf_coverage::UncoveredRegion {
        hf_coverage::UncoveredRegion {
            function: function.to_owned(),
            file: file.to_owned(),
            line,
            col: 1,
        }
    }

    #[test]
    fn frontier_refine_lines_targets_reachable_functions_with_locations() {
        use super::frontier_refine_lines;
        let reachable = vec!["parse_header".to_owned(), "decode_body".to_owned()];
        let frontier = vec![
            region("parse_header", "parser.c", 42),
            // A second region of the same function collapses to the first line.
            region("parse_header", "parser.c", 51),
            // Not reachable -> excluded when a reachable match exists.
            region("internal_helper", "util.c", 9),
        ];
        let lines = frontier_refine_lines(&reachable, &frontier);
        assert_eq!(lines, vec!["parse_header (parser.c:42:1)".to_owned()]);
    }

    #[test]
    fn frontier_refine_lines_falls_back_to_full_frontier_when_no_reachable_match() {
        use super::frontier_refine_lines;
        // llvm-cov names (mangled) do not intersect the scanner's plain names.
        let reachable = vec!["parse_header".to_owned()];
        let frontier = vec![
            region("_Z6mangledv", "parser.cc", 7),
            region("", "", 0), // empty file -> bare function name
        ];
        let lines = frontier_refine_lines(&reachable, &frontier);
        assert_eq!(
            lines,
            vec!["_Z6mangledv (parser.cc:7:1)".to_owned(), String::new()]
        );
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::{
        document_staging_dir, output_budget_status, prepare_managed_workspace_root,
        prepare_managed_workspace_root_with_adoption, project_workspace_dir,
        read_current_harness_source, run_binary_path, run_context_digest, run_output_dir,
        run_output_relative, stage_run_artifacts, verify_run_artifacts, workspace_dir,
        workspace_lock_file, workspace_root_selection, write_current_harness_source, OutputBudget,
        ServiceContainer, WORKSPACE_MANIFEST_FILE,
    };
    use std::path::{Component, Path};

    /// The per-project workspace base every resolved path must stay within.
    fn base(project: &Path) -> std::path::PathBuf {
        super::workspace_root().join(super::project_slug(project))
    }

    #[test]
    fn workspace_root_uses_dedicated_app_workspace_root() {
        // With no override the workspace root normally lives under the
        // platform app-data dir. In restricted environments that path can be
        // unwritable, so `user_app_dir` may fall back to temp; either way,
        // artifacts stay under a dedicated hobot_fuzz/workspaces root rather
        // than directly in the OS temp directory.
        let root = super::workspace_root_from(None);
        assert!(root.ends_with(std::path::Path::new("hobot_fuzz").join("workspaces")));
        assert_ne!(root, std::env::temp_dir());
    }

    #[test]
    fn workspace_root_honors_env_override() {
        let root = super::workspace_root_from(Some("/mnt/scratch/hf".into()));
        assert_eq!(root, std::path::PathBuf::from("/mnt/scratch/hf"));
        // An empty override falls back to the persistent default.
        let empty = super::workspace_root_from(Some(String::new().into()));
        assert!(empty.ends_with("workspaces"));
    }

    #[test]
    fn only_the_implicit_default_root_is_trusted_for_legacy_adoption() {
        let (_, default_is_trusted) = workspace_root_selection(None);
        let (_, empty_override_is_trusted) =
            workspace_root_selection(Some(std::ffi::OsString::new()));
        let (override_root, override_is_trusted) =
            workspace_root_selection(Some("/mnt/scratch/hf".into()));

        assert!(default_is_trusted);
        assert!(empty_override_is_trusted);
        assert!(!override_is_trusted);
        assert_eq!(override_root, std::path::PathBuf::from("/mnt/scratch/hf"));
    }

    #[test]
    fn managed_workspace_preparation_creates_an_ownership_manifest() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");

        let canonical = prepare_managed_workspace_root(&root).unwrap();

        assert_eq!(canonical, std::fs::canonicalize(&root).unwrap());
        let manifest = root.join(WORKSPACE_MANIFEST_FILE);
        assert!(std::fs::symlink_metadata(manifest)
            .unwrap()
            .file_type()
            .is_file());
    }

    #[test]
    fn managed_workspace_preparation_does_not_claim_unrelated_data() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("unowned-workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("operator-data"), b"keep").unwrap();

        let error = prepare_managed_workspace_root(&root).unwrap_err();

        assert!(error.to_string().contains("non-empty"));
        assert!(!root.join(WORKSPACE_MANIFEST_FILE).exists());
        assert_eq!(std::fs::read(root.join("operator-data")).unwrap(), b"keep");
    }

    #[test]
    fn trusted_default_preparation_migrates_legacy_artifacts() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("legacy-default-workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("existing-artifact"), b"artifact").unwrap();

        prepare_managed_workspace_root_with_adoption(&root, true).unwrap();

        assert!(root.join(WORKSPACE_MANIFEST_FILE).is_file());
        assert_eq!(
            std::fs::read(root.join("existing-artifact")).unwrap(),
            b"artifact"
        );
    }

    #[test]
    fn trusted_default_cleanup_migrates_then_removes_a_legacy_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("legacy-default-workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("existing-artifact"), b"artifact").unwrap();

        ServiceContainer::stubbed()
            .clear_workspace_at_with_adoption(&root, true)
            .unwrap();

        assert!(!root.exists());
        assert!(parent.path().is_dir());
    }

    #[test]
    fn workspace_cleanup_removes_only_a_managed_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&root).unwrap();
        std::fs::create_dir(root.join("project")).unwrap();
        std::fs::write(root.join("project/artifact"), b"artifact").unwrap();

        ServiceContainer::stubbed()
            .clear_workspace_at(&root)
            .unwrap();

        assert!(!root.exists());
        assert!(parent.path().is_dir());
    }

    #[test]
    fn workspace_cleanup_treats_an_absent_root_as_success() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("missing-workspace");

        ServiceContainer::stubbed()
            .clear_workspace_at(&root)
            .unwrap();

        assert!(!root.exists());
    }

    #[test]
    fn workspace_cleanup_rejects_an_unowned_nonempty_root() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("unowned-workspace");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("keep-me"), b"unrelated").unwrap();

        let error = ServiceContainer::stubbed()
            .clear_workspace_at(&root)
            .unwrap_err();

        assert!(error.to_string().contains("ownership manifest"));
        assert_eq!(std::fs::read(root.join("keep-me")).unwrap(), b"unrelated");
    }

    #[test]
    fn workspace_cleanup_rejects_a_manifest_for_another_root() {
        let parent = tempfile::tempdir().unwrap();
        let first = parent.path().join("first-workspace");
        let second = parent.path().join("second-workspace");
        prepare_managed_workspace_root(&first).unwrap();
        prepare_managed_workspace_root(&second).unwrap();
        std::fs::copy(
            first.join(WORKSPACE_MANIFEST_FILE),
            second.join(WORKSPACE_MANIFEST_FILE),
        )
        .unwrap();
        std::fs::write(second.join("keep-me"), b"artifact").unwrap();

        let error = ServiceContainer::stubbed()
            .clear_workspace_at(&second)
            .unwrap_err();

        assert!(error.to_string().contains("does not identify"));
        assert!(second.join("keep-me").is_file());
    }

    #[test]
    fn workspace_cleanup_rejects_protected_roots() {
        let container = ServiceContainer::stubbed();
        let mut protected = vec![std::path::PathBuf::from(std::path::MAIN_SEPARATOR_STR)];
        if let Some(home) = std::env::var_os("HOME") {
            let home = std::path::PathBuf::from(home);
            #[cfg(target_os = "macos")]
            {
                let case_alias =
                    std::path::PathBuf::from(home.to_string_lossy().to_ascii_uppercase());
                if case_alias.exists() {
                    protected.push(case_alias);
                }
            }
            protected.push(home);
        }
        if let Some(repo) = super::repo_root() {
            protected.push(repo);
        }
        protected.push(crate::init::config_dir());
        protected.push(crate::config::data_dir());

        for root in protected {
            if !root.exists() {
                continue;
            }
            let error = container.clear_workspace_at(&root).unwrap_err();
            assert!(
                error.to_string().contains("protected path"),
                "unexpected error for {}: {error}",
                root.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn workspace_cleanup_rejects_a_symlink_root() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&target).unwrap();
        std::fs::write(target.join("keep-me"), b"artifact").unwrap();
        let link = parent.path().join("workspace-link");
        symlink(&target, &link).unwrap();

        let error = ServiceContainer::stubbed()
            .clear_workspace_at(&link)
            .unwrap_err();

        assert!(error.to_string().contains("symbolic link"));
        assert!(target.join("keep-me").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_cleanup_rejects_a_symlink_manifest() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&root).unwrap();
        let manifest = root.join(WORKSPACE_MANIFEST_FILE);
        let contents = std::fs::read(&manifest).unwrap();
        std::fs::remove_file(&manifest).unwrap();
        let outside = parent.path().join("outside-manifest");
        std::fs::write(&outside, contents).unwrap();
        symlink(&outside, &manifest).unwrap();

        let error = ServiceContainer::stubbed()
            .clear_workspace_at(&root)
            .unwrap_err();

        assert!(error.to_string().contains("ownership manifest"));
        assert!(root.is_dir());
        assert!(outside.is_file());
    }

    #[test]
    fn workspace_cleanup_refuses_while_a_run_is_active() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&root).unwrap();
        std::fs::write(root.join("keep-me"), b"artifact").unwrap();
        let container = ServiceContainer::stubbed();
        container.active_runs.lock().unwrap().insert(
            uuid::Uuid::new_v4(),
            tokio_util::sync::CancellationToken::new(),
        );

        let error = container.clear_workspace_at(&root).unwrap_err();

        assert!(error.to_string().contains("active fuzz run"));
        assert!(root.join("keep-me").is_file());
    }

    #[tokio::test]
    async fn workspace_cleanup_refuses_while_any_workspace_operation_is_active() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&root).unwrap();
        std::fs::write(root.join("keep-me"), b"artifact").unwrap();
        let operation_container = ServiceContainer::stubbed();
        let cleanup_container = ServiceContainer::stubbed();
        let operation = operation_container
            .acquire_workspace_operation_at(&root)
            .await
            .unwrap();
        assert!(
            operation_container.active_runs.lock().unwrap().is_empty(),
            "the lease must protect pre-registration staging"
        );

        let error = cleanup_container.clear_workspace_at(&root).unwrap_err();

        assert!(error.to_string().contains("workspace operation"));
        assert!(root.join("keep-me").is_file());
        drop(operation);
        cleanup_container.clear_workspace_at(&root).unwrap();
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn workspace_operations_wait_until_cleanup_releases_the_exclusive_lease() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        prepare_managed_workspace_root(&root).unwrap();
        let cleanup = ServiceContainer::try_acquire_workspace_cleanup(&root)
            .expect("exclusive cleanup lease");
        let waiting_container = ServiceContainer::stubbed();
        let (attempting_tx, attempting_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            let _ = attempting_tx.send(());
            let _operation = waiting_container
                .acquire_workspace_operation_at(&root)
                .await
                .expect("workspace operation lease");
            tokio::task::yield_now().await;
        });
        attempting_rx.await.unwrap();
        tokio::task::yield_now().await;

        assert!(!waiter.is_finished(), "operation entered during cleanup");
        drop(cleanup);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("operation should enter after cleanup")
            .unwrap();
    }

    #[test]
    fn workspace_file_lease_blocks_cleanup_without_the_process_gate() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("managed-workspace");
        let root = prepare_managed_workspace_root(&root).unwrap();
        let operation_file = workspace_lock_file(&root).unwrap();
        operation_file.try_lock_shared().unwrap();

        let cleanup_file = workspace_lock_file(&root).unwrap();
        assert!(matches!(
            cleanup_file.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));

        drop(cleanup_file);
        drop(operation_file);
        workspace_lock_file(&root).unwrap().try_lock().unwrap();
    }

    #[test]
    fn document_conversion_staging_stays_inside_the_sandbox_workspace() {
        let project = Path::new("/home/user/project");
        let import_id = uuid::Uuid::new_v4();
        let staging = document_staging_dir(project, import_id);

        assert!(staging.starts_with(project_workspace_dir(project)));
        assert!(staging.ends_with(import_id.to_string()));
    }

    #[test]
    fn each_run_gets_a_unique_evidence_directory() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();

        assert_eq!(
            run_output_relative(first),
            std::path::PathBuf::from("runs")
                .join(first.to_string())
                .join("out")
        );
        assert_ne!(run_output_relative(first), run_output_relative(second));
    }

    #[test]
    fn comparison_context_tracks_target_and_corpus_bytes() {
        let workspace = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join("src")).unwrap();
        std::fs::create_dir(workspace.path().join("corpus")).unwrap();
        std::fs::write(workspace.path().join("src/lib.rs"), "pub fn parse() {}").unwrap();
        std::fs::write(workspace.path().join("corpus/seed"), b"one").unwrap();

        let first = run_context_digest(workspace.path()).unwrap();
        assert_eq!(first, run_context_digest(workspace.path()).unwrap());
        std::fs::write(workspace.path().join("corpus/seed"), b"two").unwrap();
        assert_ne!(first, run_context_digest(workspace.path()).unwrap());
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

        let error = run_context_digest(workspace.path()).unwrap_err();
        assert!(error.to_string().contains("symlink"));
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
    fn run_output_budget_rejects_oversized_or_excessive_evidence() {
        let output = tempfile::tempdir().unwrap();
        std::fs::write(output.path().join("one"), b"1234").unwrap();
        let within = |max_bytes, max_entries, max_file_bytes| {
            output_budget_status(output.path(), max_bytes, max_entries, max_file_bytes)
                == OutputBudget::Within
        };
        assert!(within(4, 1, 4));
        assert!(!within(3, 1, 4));
        assert!(!within(4, 1, 3));
        std::fs::write(output.path().join("two"), b"x").unwrap();
        assert!(!within(10, 1, 10));
    }

    #[test]
    fn output_budget_status_distinguishes_overflow_from_transient_scan_error() {
        let output = tempfile::tempdir().unwrap();
        std::fs::write(output.path().join("one"), b"1234").unwrap();
        // Clean, within limits.
        assert_eq!(
            output_budget_status(output.path(), 4, 1, 4),
            OutputBudget::Within
        );
        // Definite overflow (byte budget exceeded).
        assert_eq!(
            output_budget_status(output.path(), 3, 1, 4),
            OutputBudget::Exceeded
        );
        // A root that does not exist is a transient/indeterminate scan result,
        // NOT an overflow -- the live monitor must not treat this as a reason to
        // kill the run.
        let missing = output.path().join("gone");
        assert_eq!(
            output_budget_status(&missing, 10, 10, 10),
            OutputBudget::Indeterminate
        );
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
        run.evidence_dir = Some(artifacts.output_relative.to_string_lossy().into_owned());

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

    #[test]
    fn normal_target_is_preserved() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "parse_json");
        assert_eq!(ws, base(project).join("parse_json"));
    }

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

    #[test]
    fn projects_sharing_a_basename_get_distinct_workspaces() {
        // Two different projects with the same directory name must not share a
        // workspace, or one's compiled binary/corpus/crashes would be used for
        // the other's runs/triage.
        let a = workspace_dir(Path::new("/a/libfoo"), "parse");
        let b = workspace_dir(Path::new("/b/libfoo"), "parse");
        assert_ne!(a, b, "same-basename projects collided");
    }

    #[test]
    fn same_project_maps_to_a_stable_workspace() {
        // The slug must be deterministic so compile -> run -> triage across
        // separate invocations all resolve to the same on-disk workspace.
        let project = Path::new("/home/user/myproj");
        assert_eq!(
            workspace_dir(project, "parse_json"),
            workspace_dir(project, "parse_json")
        );
    }

    #[test]
    fn cpp_style_target_is_preserved() {
        // C++ symbols contain `::`; that is filesystem-safe and must survive.
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "ns::Class::method");
        assert_eq!(ws, base(project).join("ns::Class::method"));
    }

    #[test]
    fn dotdot_target_cannot_escape_workspace() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "../../../../etc/evil");
        // Stays inside the project workspace base...
        assert!(
            ws.starts_with(base(project)),
            "escaped workspace: {}",
            ws.display()
        );
        // ...and contains no parent-dir traversal components.
        assert!(
            !ws.components().any(|c| c == Component::ParentDir),
            "path retained `..`: {}",
            ws.display()
        );
    }

    #[test]
    fn absolute_target_cannot_escape_workspace() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "/etc/passwd");
        assert!(
            ws.starts_with(base(project)),
            "escaped workspace: {}",
            ws.display()
        );
        assert_ne!(ws, Path::new("/etc/passwd"));
    }

    #[test]
    fn empty_or_all_traversal_target_falls_back() {
        let project = Path::new("/home/user/myproj");
        assert_eq!(workspace_dir(project, ""), base(project).join("default"));
        assert_eq!(
            workspace_dir(project, "../.."),
            base(project).join("default")
        );
    }

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
mod syzkaller_command_tests {
    use super::syzkaller_manager_command;

    #[test]
    fn manager_config_path_is_a_literal_argument_not_shell_source() {
        let path = "/tmp/manager;touch /work/pwn.cfg";
        let command = syzkaller_manager_command(path, 90, 30);

        assert_eq!(
            command,
            vec![
                "timeout",
                "--signal=TERM",
                "--kill-after=30",
                "90",
                "syz-manager",
                "-config=/tmp/manager;touch /work/pwn.cfg",
            ]
        );
        assert!(!command.iter().any(|arg| arg == "bash" || arg == "-c"));
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
mod downsample_tests {
    use super::downsample;

    #[test]
    fn keeps_short_series_intact() {
        let s = vec![(0.0, 1, 10.0), (1.0, 2, 20.0)];
        assert_eq!(downsample(&s, 10).len(), 2);
    }

    #[test]
    fn caps_and_keeps_last() {
        let s: Vec<(f64, u64, f64)> = (0..100).map(|i| (f64::from(i), i as u64, 0.0)).collect();
        let out = downsample(&s, 10);
        assert!(out.len() <= 11, "capped near the target, got {}", out.len());
        assert_eq!(out.last().unwrap().1, 99, "always keeps the final sample");
    }
}

#[cfg(test)]
mod auto_revert_tests {
    use super::{
        auto_revert_baseline_compatible, auto_revert_comparison_key, auto_revert_decision,
    };
    use hf_core::engine::{EngineKind, FuzzRunConfig};
    use hf_core::target::Sanitizer;
    use std::path::PathBuf;
    use std::time::Duration;
    use uuid::Uuid;

    fn config(engine: EngineKind, duration_secs: u64) -> FuzzRunConfig {
        FuzzRunConfig {
            harness_id: Uuid::new_v4(),
            engine,
            duration: Some(Duration::from_secs(duration_secs)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: Some(PathBuf::from("/work/corpus")),
            sanitizer: Sanitizer::Address,
            env: vec![("MODE".to_owned(), "strict".to_owned())],
            extra_args: vec!["-dict=/work/parser.dict".to_owned()],
        }
    }

    #[test]
    fn baseline_requires_matching_engine_budget_and_execution_context() {
        let current = config(EngineKind::LibFuzzer, 60);
        let mut baseline = current.clone();
        baseline.harness_id = Uuid::new_v4();
        assert!(auto_revert_baseline_compatible(&baseline, &current));

        baseline.engine = EngineKind::AflPlusPlus;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.duration = Some(Duration::from_hours(1));
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.max_cpus = 4;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.sanitizer = Sanitizer::Undefined;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.env.clear();
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.extra_args.clear();
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
    }

    #[test]
    fn comparison_key_groups_only_the_same_target_and_run_context() {
        let target = Uuid::new_v4();
        let current = config(EngineKind::LibFuzzer, 60);
        let mut other_revision = current.clone();
        other_revision.harness_id = Uuid::new_v4();
        assert_eq!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &other_revision, "context-a")
        );

        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(Uuid::new_v4(), &current, "context-a")
        );
        other_revision.duration = Some(Duration::from_mins(10));
        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &other_revision, "context-a")
        );
        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &current, "context-b")
        );
    }

    #[test]
    fn fires_when_changed_harness_drops_coverage_past_threshold() {
        // 1000 -> 700 edges is a 30% drop with a changed revision.
        let drop = auto_revert_decision("old", "new", 1000, 700, 20.0);
        assert!(matches!(drop, Some(p) if (p - 30.0).abs() < f64::EPSILON));
    }

    #[test]
    fn does_not_fire_when_harness_unchanged() {
        // Same revision: a coverage dip is noise, not a revision regression.
        assert!(auto_revert_decision("same", "same", 1000, 100, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_below_threshold() {
        // 1000 -> 900 is only a 10% drop; threshold is 20%.
        assert!(auto_revert_decision("old", "new", 1000, 900, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_when_coverage_held_or_improved() {
        assert!(auto_revert_decision("old", "new", 1000, 1000, 20.0).is_none());
        assert!(auto_revert_decision("old", "new", 1000, 1200, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_without_a_baseline() {
        assert!(auto_revert_decision("old", "new", 0, 0, 20.0).is_none());
    }

    #[test]
    fn fires_exactly_at_threshold() {
        let drop = auto_revert_decision("old", "new", 100, 80, 20.0);
        assert!(matches!(drop, Some(p) if (p - 20.0).abs() < f64::EPSILON));
    }
}

#[cfg(test)]
mod crash_id_tests {
    use super::deterministic_crash_id;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn same_run_signature_and_input_yield_the_same_id() {
        // Re-triaging the same crash must produce the same id (idempotent
        // persistence -> INSERT OR REPLACE collapses the duplicate).
        let run = Uuid::new_v4();
        let a = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        let b = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_runs_or_signatures_yield_distinct_ids() {
        let run = Uuid::new_v4();
        let base = deterministic_crash_id(run, "sig", Path::new("/work/out/crash-abc"));
        // Different input file -> different id (keeps distinct crashes apart).
        assert_ne!(
            base,
            deterministic_crash_id(run, "sig", Path::new("/work/out/crash-def"))
        );
        // Different signature -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(run, "other", Path::new("/work/out/crash-abc"))
        );
        // Different run -> different id.
        assert_ne!(
            base,
            deterministic_crash_id(Uuid::new_v4(), "sig", Path::new("/work/out/crash-abc"))
        );
    }
}

#[cfg(test)]
mod journal_boundary_tests {
    use super::ensure_run_journal_durable;

    #[test]
    fn degraded_recovery_journal_blocks_new_execution() {
        let directory = tempfile::tempdir().unwrap();
        let wal = directory.path().join("run_journal.jsonl");
        std::fs::write(&wal, b"{truncated").unwrap();
        let journal = crate::recovery::RunJournal::open(wal);

        let error = ensure_run_journal_durable(&journal)
            .expect_err("degraded recovery evidence must fail closed");

        assert!(error
            .to_string()
            .contains("run recovery journal is degraded"));
    }
}

#[cfg(test)]
mod provider_health_task_tests {
    use super::spawn_provider_health_checks;
    use hf_core::provider::ProviderPool;
    use std::sync::Arc;
    use std::time::Duration;

    fn mock_pool_with_interval(interval_secs: u64) -> Arc<dyn ProviderPool> {
        let provider: Arc<dyn hf_core::provider::LlmProvider> =
            Arc::new(hf_test_utils::mock_provider::MockProvider::fixed("ok"));
        let config = hf_provider::ProviderPoolConfig {
            health_check_interval_secs: interval_secs,
            ..Default::default()
        };
        let pool: Arc<dyn ProviderPool> = Arc::new(hf_provider::ProviderPoolImpl::from_providers(
            vec![provider],
            &config,
        ));
        pool
    }

    async fn wait_until_thawed(pool: &Arc<dyn ProviderPool>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !pool.provider_statuses().await[0].is_frozen {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the health task should thaw the provider promptly");
    }

    #[tokio::test]
    async fn health_task_recovers_a_frozen_provider_without_waiting_a_full_interval() {
        let pool = mock_pool_with_interval(60);
        let pid = hf_core::types::ProviderId::from_string("mock-provider");
        pool.freeze(&pid, "test freeze".to_owned()).await;
        assert!(pool.provider_statuses().await[0].is_frozen);

        let cell = Arc::new(std::sync::RwLock::new(Some(Arc::clone(&pool))));
        let task = spawn_provider_health_checks(cell);

        // The loop runs an initial check immediately, so recovery must land
        // well before the pool's 60s interval elapses.
        wait_until_thawed(&pool).await;

        // Dropping the guard cancels and aborts the loop: no leaked task.
        drop(task);
    }

    #[tokio::test]
    async fn health_task_follows_provider_pool_swaps() {
        // Mirrors `reload_providers`: the loop reads the shared cell on every
        // tick, so a pool swapped in later is health-checked without
        // respawning the task.
        let pool_a = mock_pool_with_interval(1);
        let cell = Arc::new(std::sync::RwLock::new(Some(pool_a)));
        let task = spawn_provider_health_checks(Arc::clone(&cell));

        let pool_b = mock_pool_with_interval(1);
        let pid = hf_core::types::ProviderId::from_string("mock-provider");
        pool_b.freeze(&pid, "test freeze".to_owned()).await;
        *cell.write().expect("pool cell poisoned") = Some(Arc::clone(&pool_b));

        wait_until_thawed(&pool_b).await;

        drop(task);
    }
}

#[cfg(test)]
mod guardrail_decision_tests {
    use std::sync::Arc;

    use hf_guardrails::{Action, AutoApprove, DenyAll, GuardrailPolicy, Guardrails, RiskTier};
    use hf_storage::Store;

    use super::ServiceContainer;

    async fn container_with_store(guardrails: Guardrails) -> (ServiceContainer, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(dir.path().join("decisions.db"))
            .await
            .unwrap();
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_guardrails(guardrails)
            .with_store(Arc::new(store));
        (container, dir)
    }

    fn strict_deny_guardrails() -> Guardrails {
        Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::Low),
            },
            Arc::new(DenyAll),
        )
    }

    #[tokio::test]
    async fn allowed_decisions_are_recorded_with_action_tier_origin_and_project() {
        let (container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;

        container
            .authorize_recorded(
                Action::Discover,
                "unit_origin",
                Some(std::path::Path::new("/proj")),
            )
            .await
            .unwrap();

        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.action, "discover");
        assert_eq!(row.risk_tier, "low");
        assert_eq!(row.decision, "allowed");
        assert_eq!(row.origin, "unit_origin");
        assert_eq!(row.project.as_deref(), Some("/proj"));
        assert_eq!(row.detail, None);
    }

    #[tokio::test]
    async fn policy_denials_are_recorded_and_the_error_path_is_unchanged() {
        let (container, _dir) = container_with_store(strict_deny_guardrails()).await;

        let error = container
            .authorize_recorded(Action::Discover, "unit_origin", None)
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("guardrail denied"),
            "the denial surfaces through the existing error path: {error}"
        );
        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "denied");
        assert!(
            rows[0]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("denied by policy")),
            "the denial detail names the policy rule: {:?}",
            rows[0].detail
        );
    }

    #[tokio::test]
    async fn approval_gate_outcomes_are_recorded() {
        let (approved_container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(AutoApprove),
        ))
        .await;
        approved_container
            .authorize_recorded(Action::RunHarness, "harness_smoke", None)
            .await
            .unwrap();
        let rows = approved_container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "approved");
        assert_eq!(rows[0].risk_tier, "high");

        let (declined_container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        let error = declined_container
            .authorize_recorded(Action::RunHarness, "harness_smoke", None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("approval declined"));
        let rows = declined_container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "denied_by_operator");
    }

    #[tokio::test]
    async fn recording_failure_never_changes_the_authorization_outcome() {
        let (allowed, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        allowed.store().unwrap().pool().close().await;
        assert!(
            allowed
                .authorize_recorded(Action::Discover, "unit_origin", None)
                .await
                .is_ok(),
            "a broken decision store must not block an allowed action"
        );

        let (denied, _dir) = container_with_store(strict_deny_guardrails()).await;
        denied.store().unwrap().pool().close().await;
        assert!(
            denied
                .authorize_recorded(Action::Discover, "unit_origin", None)
                .await
                .is_err(),
            "a broken decision store must not unblock a denied action"
        );
    }

    #[tokio::test]
    async fn decision_details_are_bounded() {
        let (container, _dir) = container_with_store(strict_deny_guardrails()).await;
        let long_command = "x".repeat(10_000);

        let _ = container
            .authorize_recorded(
                Action::ShellExec {
                    command: long_command,
                },
                "unit_origin",
                None,
            )
            .await;

        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        let detail = rows[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail.chars().count() <= 256,
            "detail is bounded, got {} chars",
            detail.chars().count()
        );
    }

    #[tokio::test]
    async fn policy_decisions_are_newest_first_and_bounded() {
        let (container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        for origin in ["first", "second", "third"] {
            container
                .authorize_recorded(Action::Discover, origin, None)
                .await
                .unwrap();
        }

        let rows = container.policy_decisions(2).await.unwrap();
        assert_eq!(rows.len(), 2);
        let origins: Vec<&str> = rows.iter().map(|row| row.origin.as_str()).collect();
        assert_eq!(origins, ["third", "second"], "newest first");
    }

    #[tokio::test]
    async fn containers_without_a_store_record_nothing_and_read_empty() {
        let container =
            ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_guardrails(
                Guardrails::new(GuardrailPolicy::default(), Arc::new(DenyAll)),
            );

        container
            .authorize_recorded(Action::Discover, "unit_origin", None)
            .await
            .unwrap();

        assert!(container.policy_decisions(10).await.unwrap().is_empty());
    }
}
