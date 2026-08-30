//! The managed workspace boundary.
//!
//! Every path that a project name, target name, or run id contributes to is
//! resolved here. The module exists so that boundary has one name and one test
//! surface: `AGENTS.md` 2.12 requires untrusted inputs never to touch the host
//! filesystem outside the workspace, and that guarantee is only as good as the
//! resolution functions below.

use std::fs::{File, TryLockError};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use hf_core::error::ClassifiedError;
use uuid::Uuid;

use super::{project_slug, repo_root, sanitize_target, WORKSPACE_CLEANUP_BUSY_MESSAGE};

const WORKSPACE_MANIFEST_FILE: &str = ".oxfuzz-workspace.json";
const WORKSPACE_MANIFEST_VERSION: u32 = 1;

type WorkspaceOperationGate = tokio::sync::RwLock<()>;
type TargetRevisionGate = tokio::sync::Mutex<()>;

/// Workspace gates are keyed by resolved root rather than container instance:
/// independent service containers in one process can target the same root.
/// A weak registry avoids retaining a gate after its last lease is released.
static WORKSPACE_OPERATION_GATES: OnceLock<
    Mutex<std::collections::HashMap<PathBuf, Weak<WorkspaceOperationGate>>>,
> = OnceLock::new();

static TARGET_REVISION_GATES: OnceLock<
    Mutex<std::collections::HashMap<PathBuf, Weak<TargetRevisionGate>>>,
> = OnceLock::new();

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct WorkspaceOwnershipManifest {
    application: String,
    version: u32,
    canonical_root: PathBuf,
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

pub(super) fn configured_workspace_root() -> (PathBuf, bool) {
    workspace_root_selection(std::env::var_os("HF_WORKSPACE_DIR"))
}

pub(super) fn workspace_operation_gate(
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

pub(super) fn workspace_lock_file(root: &Path) -> Result<File, ClassifiedError> {
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

/// Return the process-local gate and canonical key for one managed target
/// workspace. Callers hold the workspace-operation lease before this gate.
pub(super) fn target_revision_gate(
    workspace: &Path,
) -> Result<(PathBuf, Arc<TargetRevisionGate>), ClassifiedError> {
    let key = comparable_path(workspace).ok_or_else(|| {
        ClassifiedError::Internal(format!(
            "resolve harness revision workspace {}",
            workspace.display()
        ))
    })?;
    let registry =
        TARGET_REVISION_GATES.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut gates = registry.lock().map_err(|_| {
        ClassifiedError::Internal("harness revision gate registry is poisoned".to_owned())
    })?;
    if let Some(gate) = gates.get(&key).and_then(Weak::upgrade) {
        return Ok((key, gate));
    }
    let gate = Arc::new(TargetRevisionGate::new(()));
    gates.insert(key.clone(), Arc::downgrade(&gate));
    Ok((key, gate))
}

/// Open the cross-process exclusive lock for one canonical target workspace.
pub(super) fn target_revision_lock_file(workspace: &Path) -> Result<File, ClassifiedError> {
    use sha2::{Digest as _, Sha256};

    let lock_dir = crate::init::user_app_dir().join("locks");
    std::fs::create_dir_all(&lock_dir).map_err(|error| {
        ClassifiedError::Internal(format!(
            "create harness revision lease directory {}: {error}",
            lock_dir.display()
        ))
    })?;
    let digest = Sha256::digest(workspace.as_os_str().as_encoded_bytes());
    let lock_path = lock_dir.join(format!("harness-revision-{digest:x}.lock"));
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "open harness revision lease {}: {error}",
                lock_path.display()
            ))
        })
}

pub(super) fn workspace_lock_error(error: TryLockError, cleanup: bool) -> ClassifiedError {
    match error {
        TryLockError::WouldBlock if cleanup => {
            ClassifiedError::Validation(WORKSPACE_CLEANUP_BUSY_MESSAGE.to_owned())
        }
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
    if manifest.application != "oxfuzz"
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
    let temporary = root.join(format!(".oxfuzz-workspace-{}.tmp", Uuid::new_v4()));
    let manifest = WorkspaceOwnershipManifest {
        application: "oxfuzz".to_owned(),
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
pub(super) fn prepare_managed_workspace_root_with_adoption(
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

#[cfg(test)]
fn prepare_managed_workspace_root(root: &Path) -> Result<PathBuf, ClassifiedError> {
    prepare_managed_workspace_root_with_adoption(root, false)
}

pub(super) fn prepare_configured_workspace_root() -> Result<PathBuf, ClassifiedError> {
    let (root, uses_trusted_default) = configured_workspace_root();
    prepare_managed_workspace_root_with_adoption(&root, uses_trusted_default)
}

pub(super) fn clear_managed_workspace_root(root: &Path) -> Result<(), ClassifiedError> {
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
pub(super) fn document_staging_dir(project: &Path, import_id: Uuid) -> PathBuf {
    project_workspace_dir(project)
        .join(".service")
        .join("document-import")
        .join(import_id.to_string())
}

/// Create a unique Build Doctor snapshot directory below the managed runtime
/// root without following any pre-existing workspace symlink.
#[cfg(feature = "build-doctor")]
pub(crate) fn build_doctor_staging_dir(
    project: &Path,
    operation_id: Uuid,
) -> Result<PathBuf, ClassifiedError> {
    let root = prepare_configured_workspace_root()?;
    let relative = PathBuf::from(project_slug(project))
        .join(".service")
        .join("build-doctor")
        .join(operation_id.to_string());
    ensure_workspace_directory(&root, &relative)
}

/// Workspace-relative output directory owned by one fuzz or smoke run.
pub(super) fn run_output_relative(run_id: Uuid) -> PathBuf {
    PathBuf::from("runs").join(run_id.to_string()).join("out")
}

/// A workspace-relative path in the form persisted to the database: always
/// `/`-separated, so one record means the same directory on every host. A
/// plain `to_string_lossy` would store `runs\<id>\out` on Windows and make
/// the row unreadable elsewhere.
pub(super) fn workspace_relative_record(path: &Path) -> String {
    hf_core::runtime::posix_relative(path)
}

/// Resolve an existing regular directory below a workspace without accepting
/// symlinks in any component.
pub(super) fn resolve_workspace_directory(
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

#[cfg(test)]
use super::ServiceContainer;

#[cfg(test)]
impl ServiceContainer {
    #[cfg(test)]
    fn clear_workspace_at(&self, root: &Path) -> Result<(), ClassifiedError> {
        self.clear_workspace_at_with_adoption(root, false)
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::{
        document_staging_dir, prepare_managed_workspace_root,
        prepare_managed_workspace_root_with_adoption, project_workspace_dir, run_output_relative,
        workspace_dir, workspace_lock_file, workspace_manifest, workspace_root_selection,
        ServiceContainer, WORKSPACE_MANIFEST_FILE,
    };
    use std::path::{Component, Path};

    fn base(project: &Path) -> std::path::PathBuf {
        super::workspace_root().join(super::project_slug(project))
    }

    #[test]
    fn workspace_root_uses_dedicated_app_workspace_root() {
        // With no override the workspace root normally lives under the
        // platform app-data dir. In restricted environments that path can be
        // unwritable, so `user_app_dir` may fall back to temp; either way,
        // artifacts stay under a dedicated oxfuzz/workspaces root rather
        // than directly in the OS temp directory.
        let root = super::workspace_root_from(None);
        assert!(root.ends_with(std::path::Path::new("oxfuzz").join("workspaces")));
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
    fn normal_target_is_preserved() {
        let project = Path::new("/home/user/myproj");
        let ws = workspace_dir(project, "parse_json");
        assert_eq!(ws, base(project).join("parse_json"));
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
    fn qualified_target_becomes_one_portable_component() {
        // A C++ symbol carries `::`, and the documented `file.c::symbol` target
        // syntax carries `::` and `/`. Neither may reach the filesystem raw:
        // `:` is illegal in an NTFS name, and a `/` would nest one target's
        // workspace inside another's. Each resolves to exactly one directory
        // below the project base, and distinct targets stay distinct.
        let project = Path::new("/home/user/myproj");
        let qualified = workspace_dir(project, "ns::Class::method");
        let file_scoped = workspace_dir(project, "src/parser.c::parse_header");

        for ws in [&qualified, &file_scoped] {
            let leaf = ws
                .strip_prefix(base(project))
                .expect("workspace is below the project base");
            assert_eq!(leaf.components().count(), 1, "{}", ws.display());
            assert!(
                leaf.to_string_lossy()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')),
                "{}",
                ws.display()
            );
        }
        assert_ne!(qualified, file_scoped);
    }

    #[test]
    fn plain_identifier_target_keeps_its_directory_name() {
        // Every symbol the scanners emit is a plain identifier, so sanitizing
        // must leave existing on-disk workspaces exactly where they were.
        let project = Path::new("/home/user/myproj");
        assert_eq!(
            workspace_dir(project, "parse_json"),
            base(project).join("parse_json")
        );
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
    fn degenerate_targets_fall_back_without_colliding() {
        // An empty target, a pure-traversal target, and a target literally
        // named `default` are three different targets. Each needs a usable
        // directory, and none may share one with the others.
        let project = Path::new("/home/user/myproj");
        let empty = workspace_dir(project, "");
        let traversal = workspace_dir(project, "../..");
        let literal = workspace_dir(project, "default");

        for ws in [&empty, &traversal, &literal] {
            let leaf = ws
                .strip_prefix(base(project))
                .expect("workspace is below the project base");
            assert_eq!(leaf.components().count(), 1, "{}", ws.display());
        }
        assert_eq!(literal, base(project).join("default"));
        assert_ne!(empty, traversal);
        assert_ne!(empty, literal);
        assert_ne!(traversal, literal);
    }

    #[test]
    fn explicit_override_without_a_manifest_is_never_adopted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("explicit");
        std::fs::create_dir_all(root.join("legacy-project")).expect("legacy artifact");

        let adopted = prepare_managed_workspace_root_with_adoption(&root, false);

        assert!(
            adopted.is_err(),
            "an explicit override must not adopt unmanaged artifacts"
        );
    }

    #[test]
    fn implicit_default_adopts_pre_manifest_artifacts() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("implicit");
        std::fs::create_dir_all(root.join("legacy-project")).expect("legacy artifact");

        let adopted =
            prepare_managed_workspace_root_with_adoption(&root, true).expect("adoption allowed");

        // Compare against the canonicalized root, not the raw tempdir path: on
        // macOS `$TMPDIR` resolves through a `/var` -> `/private/var` symlink,
        // and `prepare_managed_workspace_root_with_adoption` always returns the
        // canonical form (see the sibling `managed_workspace_preparation_*`
        // tests above, which canonicalize for the same reason).
        assert_eq!(adopted, std::fs::canonicalize(&root).unwrap());
        assert!(
            workspace_manifest(&root).is_file(),
            "manifest written on adoption"
        );
    }
}
