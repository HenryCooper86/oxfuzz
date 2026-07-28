//! Service-owned Semgrep source snapshot support.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Pinned Semgrep Community Edition version in the sandbox image.
pub const SEMGREP_VERSION: &str = "1.169.0";
/// Pinned `0xdea/semgrep-rules` revision bundled in the sandbox image.
pub const RULES_COMMIT: &str = "4d66ecf30bfb1809a984085f2c86a8c3915bfc71";
/// Version of the fixed Semgrep sandbox command contract.
pub const COMMAND_SCHEMA_VERSION: u32 = 1;

/// A service-owned immutable source tree prepared for one Semgrep operation.
#[derive(Debug)]
pub struct SourceSnapshot {
    /// Exact `<managed-workspace>/semgrep/<operation-uuid>` ownership root.
    pub operation_root: PathBuf,
    /// Read-only container input tree populated with normalized relative paths.
    pub source_dir: PathBuf,
    /// Operation-owned writable container output directory.
    pub output_dir: PathBuf,
    /// Sorted staged project-relative source manifest.
    pub relative_paths: BTreeSet<PathBuf>,
    /// Stable ordered path-and-content SHA-256 revision.
    pub source_sha256: String,
    /// Number of regular source files in the complete snapshot.
    pub file_count: usize,
    /// Aggregate source bytes in the complete snapshot.
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct SnapshotLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_relative_path_bytes: usize,
}

const SNAPSHOT_LIMITS: SnapshotLimits = SnapshotLimits {
    max_files: 25_000,
    max_file_bytes: 2 * 1024 * 1024,
    max_total_bytes: 512 * 1024 * 1024,
    max_relative_path_bytes: 4_096,
};

/// Stage the canonical C/C++ discovery source set below the managed workspace.
///
/// # Errors
/// Returns an error if the project or any source is unsafe, unstable, or over
/// the fixed bounds, or if an operation-owned directory cannot be created.
pub fn stage_source_snapshot(
    canonical_project: &Path,
    language: TargetLanguage,
    operation_id: Uuid,
) -> Result<SourceSnapshot, ClassifiedError> {
    let workspace = crate::container::initialize_workspace_root()?;
    stage_source_snapshot_at_with_limits(
        canonical_project,
        language,
        operation_id,
        &workspace,
        SNAPSHOT_LIMITS,
    )
}

/// Digest the live canonical C/C++ discovery source set without staging it.
///
/// # Errors
/// Returns an error if the source set is unsupported, unsafe, unstable, or
/// exceeds the same fixed limits used for staging.
pub fn digest_live_sources(
    canonical_project: &Path,
    language: TargetLanguage,
) -> Result<String, ClassifiedError> {
    digest_live_sources_with_limits(canonical_project, language, SNAPSHOT_LIMITS)
}

/// Remove one validated Semgrep operation directory below the managed workspace.
///
/// # Errors
/// Returns an error if the managed path is absent, symlinked, ambiguous, or
/// does not have the exact `<workspace>/semgrep/<uuid>` ownership shape.
pub fn cleanup_operation_root(operation_root: &Path) -> Result<(), ClassifiedError> {
    let workspace = crate::container::initialize_workspace_root()?;
    cleanup_operation_root_in(&workspace, operation_root)
}

fn stage_source_snapshot_at_with_limits(
    canonical_project: &Path,
    language: TargetLanguage,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
) -> Result<SourceSnapshot, ClassifiedError> {
    let selected = hf_discovery::discoverable_source_files(canonical_project, language)?;
    stage_selected_paths_at_with_limits(
        canonical_project,
        selected,
        operation_id,
        managed_workspace,
        limits,
    )
}

fn stage_selected_paths_at_with_limits(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
) -> Result<SourceSnapshot, ClassifiedError> {
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        |_| {},
        || {},
    )
}

#[cfg(test)]
fn stage_selected_paths_at_with_hook<F>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    after_read: F,
) -> Result<SourceSnapshot, ClassifiedError>
where
    F: FnOnce(),
{
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        |_| {},
        after_read,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageMutationPoint {
    SemgrepRoot,
    OperationRoot,
    SourceRoot,
    DestinationParent,
}

#[cfg(test)]
fn stage_selected_paths_at_with_stage_hook<H>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    stage_hook: H,
) -> Result<SourceSnapshot, ClassifiedError>
where
    H: FnMut(StageMutationPoint),
{
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        stage_hook,
        || {},
    )
}

fn stage_selected_paths_at_with_hooks<H, F>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    mut stage_hook: H,
    after_read: F,
) -> Result<SourceSnapshot, ClassifiedError>
where
    H: FnMut(StageMutationPoint),
    F: FnOnce(),
{
    validate_canonical_directory(canonical_project, "project root")?;
    if relative_paths.len() > limits.max_files {
        return Err(snapshot_validation(format!(
            "snapshot file count exceeds {}",
            limits.max_files
        )));
    }

    let mut selected = BTreeMap::new();
    for relative in relative_paths {
        let normalized = normalized_relative_path_bytes(&relative)?;
        if normalized.len() > limits.max_relative_path_bytes {
            return Err(snapshot_validation(format!(
                "snapshot relative path exceeds {} bytes",
                limits.max_relative_path_bytes
            )));
        }
        if selected.insert(normalized, relative).is_some() {
            return Err(snapshot_validation(
                "snapshot source set contains a duplicate relative path",
            ));
        }
    }

    let workspace = validate_canonical_directory(managed_workspace, "managed workspace")?;
    let workspace_descriptor = open_directory_path_nofollow(&workspace, "managed workspace")?;
    verify_directory_path_identity(&workspace, &workspace_descriptor, "managed workspace")?;
    let semgrep_root = workspace.join("semgrep");
    let semgrep_descriptor = open_or_create_directory_at(&workspace_descriptor, "semgrep", true)?;
    stage_hook(StageMutationPoint::SemgrepRoot);
    verify_directory_path_identity(&workspace, &workspace_descriptor, "managed workspace")?;
    verify_directory_path_identity(&semgrep_root, &semgrep_descriptor, "Semgrep workspace")?;
    let operation_root = semgrep_root.join(operation_id.to_string());
    let source_dir = operation_root.join("source");
    let output_dir = operation_root.join("output");
    let operation_descriptor = create_new_directory_at(
        &semgrep_descriptor,
        operation_id.to_string().as_str(),
        "Semgrep operation directory",
    )?;

    let staged = (|| {
        stage_hook(StageMutationPoint::OperationRoot);
        verify_staging_directory_chain(
            &workspace,
            &workspace_descriptor,
            &semgrep_root,
            &semgrep_descriptor,
            &operation_root,
            &operation_descriptor,
        )?;
        let source_descriptor =
            create_new_directory_at(&operation_descriptor, "source", "snapshot source directory")?;
        stage_hook(StageMutationPoint::SourceRoot);
        verify_staging_directory_chain(
            &workspace,
            &workspace_descriptor,
            &semgrep_root,
            &semgrep_descriptor,
            &operation_root,
            &operation_descriptor,
        )?;
        verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
        let output_descriptor =
            create_new_directory_at(&operation_descriptor, "output", "snapshot output directory")?;
        verify_directory_path_identity(&output_dir, &output_descriptor, "snapshot output")?;
        let mut hasher = Sha256::new();
        let mut total_bytes = 0_u64;
        let mut after_read = Some(after_read);
        let mut manifest = BTreeSet::new();

        for (normalized_path, relative) in selected {
            let remaining = limits
                .max_total_bytes
                .checked_sub(total_bytes)
                .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
            let allowance = limits.max_file_bytes.min(remaining);
            let bytes = if let Some(hook) = after_read.take() {
                read_stable_source(canonical_project, &relative, allowance, hook)?
            } else {
                read_stable_source(canonical_project, &relative, allowance, || {})?
            };
            let file_bytes = u64::try_from(bytes.len())
                .map_err(|_| snapshot_validation("snapshot file length cannot be represented"))?;
            total_bytes = total_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
            let (parent_descriptor, parent_path, leaf) =
                open_or_create_destination_parent(&source_descriptor, &source_dir, &relative)?;
            stage_hook(StageMutationPoint::DestinationParent);
            verify_staging_directory_chain(
                &workspace,
                &workspace_descriptor,
                &semgrep_root,
                &semgrep_descriptor,
                &operation_root,
                &operation_descriptor,
            )?;
            verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
            verify_directory_path_identity(
                &parent_path,
                &parent_descriptor,
                "snapshot destination parent",
            )?;
            write_new_owned_file_at(&parent_descriptor, &leaf, &bytes)?;
            verify_directory_path_identity(
                &parent_path,
                &parent_descriptor,
                "snapshot destination parent",
            )?;
            hash_path_and_bytes(&mut hasher, &normalized_path, &bytes);
            manifest.insert(relative);
        }
        verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
        verify_directory_path_identity(&output_dir, &output_descriptor, "snapshot output")?;

        Ok(SourceSnapshot {
            operation_root: operation_root.clone(),
            source_dir,
            output_dir,
            file_count: manifest.len(),
            total_bytes,
            relative_paths: manifest,
            source_sha256: hex::encode(hasher.finalize()),
        })
    })();

    match staged {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => match cleanup_operation_root_in(&workspace, &operation_root) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(append_error_context(
                error,
                &format!("snapshot cleanup failed: {cleanup}"),
            )),
        },
    }
}

fn digest_live_sources_with_limits(
    canonical_project: &Path,
    language: TargetLanguage,
    limits: SnapshotLimits,
) -> Result<String, ClassifiedError> {
    digest_live_sources_with_limits_and_read_hook(canonical_project, language, limits, |_| {})
}

fn digest_live_sources_with_limits_and_read_hook<H>(
    canonical_project: &Path,
    language: TargetLanguage,
    limits: SnapshotLimits,
    mut before_read: H,
) -> Result<String, ClassifiedError>
where
    H: FnMut(&Path),
{
    validate_canonical_directory(canonical_project, "project root")?;
    let relative_paths = hf_discovery::discoverable_source_files(canonical_project, language)?;
    if relative_paths.len() > limits.max_files {
        return Err(snapshot_validation(format!(
            "snapshot file count exceeds {}",
            limits.max_files
        )));
    }

    let mut sources = Vec::with_capacity(relative_paths.len());
    let mut total_bytes = 0_u64;
    for relative in relative_paths {
        let normalized = normalized_relative_path_bytes(&relative)?;
        if normalized.len() > limits.max_relative_path_bytes {
            return Err(snapshot_validation(format!(
                "snapshot relative path exceeds {} bytes",
                limits.max_relative_path_bytes
            )));
        }
        let remaining = limits
            .max_total_bytes
            .checked_sub(total_bytes)
            .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
        let allowance = limits.max_file_bytes.min(remaining);
        let bytes = read_stable_source_with_hooks(
            canonical_project,
            &relative,
            allowance,
            || before_read(&relative),
            || {},
        )?;
        let file_bytes = u64::try_from(bytes.len())
            .map_err(|_| snapshot_validation("snapshot file length cannot be represented"))?;
        total_bytes = total_bytes
            .checked_add(file_bytes)
            .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
        sources.push((relative, bytes));
    }
    digest_ordered_sources(sources)
}

fn digest_ordered_sources(sources: Vec<(PathBuf, Vec<u8>)>) -> Result<String, ClassifiedError> {
    let mut ordered = BTreeMap::new();
    for (path, bytes) in sources {
        let normalized = normalized_relative_path_bytes(&path)?;
        if ordered.insert(normalized, bytes).is_some() {
            return Err(snapshot_validation(
                "snapshot digest input contains a duplicate path",
            ));
        }
    }
    let mut hasher = Sha256::new();
    for (path, bytes) in ordered {
        hash_path_and_bytes(&mut hasher, &path, &bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_path_and_bytes(hasher: &mut Sha256, path: &[u8], bytes: &[u8]) {
    hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(path);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn normalized_relative_path_bytes(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(snapshot_validation("snapshot relative path is unsafe"));
    }
    let mut normalized = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(snapshot_validation("snapshot relative path is unsafe"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| snapshot_validation("snapshot relative path is not UTF-8"))?;
        if name.is_empty() {
            return Err(snapshot_validation("snapshot relative path is unsafe"));
        }
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(name.as_bytes());
    }
    if normalized.is_empty() {
        return Err(snapshot_validation("snapshot relative path is unsafe"));
    }
    Ok(normalized)
}

fn validate_canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        snapshot_validation(format!("inspect {label} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(snapshot_validation(format!(
            "{label} is not a regular directory: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        snapshot_validation(format!("resolve {label} {}: {error}", path.display()))
    })?;
    if canonical != path {
        return Err(snapshot_validation(format!(
            "{label} is not canonical: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn open_directory_path_nofollow(path: &Path, label: &str) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = open(path, flags, Mode::empty())
        .map_err(|error| snapshot_validation(format!("open {label} without links: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_directory_path_nofollow(_path: &Path, _label: &str) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn open_or_create_directory_at(
    parent: &File,
    name: &str,
    allow_existing: bool,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(parent, name, flags, Mode::empty()) {
        Ok(descriptor) if allow_existing => Ok(File::from(descriptor)),
        Ok(_) => Err(snapshot_validation(
            "snapshot directory already exists unexpectedly",
        )),
        Err(rustix::io::Errno::NOENT) => {
            mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|error| {
                snapshot_validation(format!("create snapshot directory: {error}"))
            })?;
            let descriptor = openat(parent, name, flags, Mode::empty()).map_err(|error| {
                snapshot_validation(format!("open created snapshot directory: {error}"))
            })?;
            Ok(File::from(descriptor))
        }
        Err(error) => Err(snapshot_validation(format!(
            "open snapshot directory without links: {error}"
        ))),
    }
}

#[cfg(not(unix))]
fn open_or_create_directory_at(
    _parent: &File,
    _name: &str,
    _allow_existing: bool,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn create_new_directory_at(
    parent: &File,
    name: &str,
    label: &str,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};

    mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(|error| snapshot_validation(format!("create {label}: {error}")))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = openat(parent, name, flags, Mode::empty())
        .map_err(|error| snapshot_validation(format!("open created {label}: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn create_new_directory_at(
    _parent: &File,
    _name: &str,
    _label: &str,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

fn open_or_create_destination_parent(
    source_descriptor: &File,
    source_path: &Path,
    relative_file: &Path,
) -> Result<(File, PathBuf, std::ffi::OsString), ClassifiedError> {
    let mut components: Vec<_> = relative_file
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(snapshot_validation("snapshot relative path is unsafe")),
        })
        .collect::<Result<_, _>>()?;
    let leaf = components
        .pop()
        .ok_or_else(|| snapshot_validation("snapshot relative path is empty"))?;
    let mut current = source_descriptor.try_clone().map_err(|error| {
        snapshot_validation(format!("retain snapshot source directory: {error}"))
    })?;
    let mut current_path = source_path.to_path_buf();
    for component in components {
        current = open_or_create_directory_at(
            &current,
            component
                .to_str()
                .ok_or_else(|| snapshot_validation("snapshot relative path is not UTF-8"))?,
            true,
        )?;
        current_path.push(component);
    }
    Ok((current, current_path, leaf))
}

#[cfg(unix)]
fn write_new_owned_file_at(
    parent: &File,
    name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<(), ClassifiedError> {
    use rustix::fs::{openat, Mode, OFlags};

    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = openat(parent, name, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|error| snapshot_validation(format!("create staged source: {error}")))?;
    let mut file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|error| snapshot_validation(format!("inspect staged source: {error}")))?
        .file_type()
        .is_file()
    {
        return Err(snapshot_validation("staged source is not a regular file"));
    }
    file.write_all(bytes)
        .map_err(|error| snapshot_validation(format!("write staged source: {error}")))?;
    file.sync_all()
        .map_err(|error| snapshot_validation(format!("sync staged source: {error}")))
}

#[cfg(not(unix))]
fn write_new_owned_file_at(
    _parent: &File,
    _name: &std::ffi::OsStr,
    _bytes: &[u8],
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

fn verify_staging_directory_chain(
    workspace_path: &Path,
    workspace: &File,
    semgrep_path: &Path,
    semgrep: &File,
    operation_path: &Path,
    operation: &File,
) -> Result<(), ClassifiedError> {
    verify_directory_path_identity(workspace_path, workspace, "managed workspace")?;
    verify_directory_path_identity(semgrep_path, semgrep, "Semgrep workspace")?;
    verify_directory_path_identity(operation_path, operation, "Semgrep operation")
}

#[cfg(unix)]
fn verify_directory_path_identity(
    path: &Path,
    descriptor: &File,
    label: &str,
) -> Result<(), ClassifiedError> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| snapshot_validation(format!("inspect {label} path: {error}")))?;
    let descriptor_metadata = descriptor
        .metadata()
        .map_err(|error| snapshot_validation(format!("inspect open {label}: {error}")))?;
    if !same_directory_identity(&path_metadata, &descriptor_metadata) {
        return Err(snapshot_validation(format!(
            "{label} pathname changed during staging"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_directory_path_identity(
    _path: &Path,
    _descriptor: &File,
    _label: &str,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires filesystem identity checks".to_owned(),
    ))
}

fn read_stable_source<F>(
    canonical_project: &Path,
    relative: &Path,
    maximum: u64,
    after_read: F,
) -> Result<Vec<u8>, ClassifiedError>
where
    F: FnOnce(),
{
    read_stable_source_with_hooks(canonical_project, relative, maximum, || {}, after_read)
}

fn read_stable_source_with_hooks<B, A>(
    canonical_project: &Path,
    relative: &Path,
    maximum: u64,
    before_allocate: B,
    after_read: A,
) -> Result<Vec<u8>, ClassifiedError>
where
    B: FnOnce(),
    A: FnOnce(),
{
    let _ = normalized_relative_path_bytes(relative)?;
    let mut file = open_source_beneath(canonical_project, relative)?;
    let before = file.metadata().map_err(|error| {
        snapshot_validation(format!(
            "inspect open snapshot source {}: {error}",
            relative.display()
        ))
    })?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(snapshot_validation(format!(
            "snapshot source must be a regular file no larger than {maximum} bytes"
        )));
    }
    before_allocate();
    let capacity = usize::try_from(before.len())
        .map_err(|_| snapshot_validation("snapshot source length cannot be allocated"))?;
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| snapshot_validation("snapshot read bound overflowed"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            snapshot_validation(format!(
                "read snapshot source {}: {error}",
                relative.display()
            ))
        })?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > maximum {
        return Err(snapshot_validation(format!(
            "snapshot source exceeds {maximum} bytes"
        )));
    }
    after_read();
    let after = file.metadata().map_err(|error| {
        snapshot_validation(format!(
            "reinspect open snapshot source {}: {error}",
            relative.display()
        ))
    })?;
    if before.len() != observed || !stable_file_metadata(&before, &after) {
        return Err(snapshot_validation(
            "snapshot source changed while it was read",
        ));
    }
    verify_open_source_path_identity(canonical_project, relative, &after)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_source_beneath(canonical_project: &Path, relative: &Path) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let components: Vec<_> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(snapshot_validation("snapshot relative path is unsafe")),
        })
        .collect::<Result<_, _>>()?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| snapshot_validation("snapshot relative path is empty"))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(
        open(canonical_project, directory_flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!("open canonical project directory: {error}"))
        })?,
    );
    for component in parents {
        directory = File::from(
            openat(&directory, *component, directory_flags, Mode::empty()).map_err(|error| {
                snapshot_validation(format!("open snapshot source parent: {error}"))
            })?,
        );
    }
    let descriptor = openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| snapshot_validation(format!("open snapshot source: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_source_beneath(
    _canonical_project: &Path,
    _relative: &Path,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep snapshots require descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn stable_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.file_type().is_file()
        && right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn stable_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn verify_open_source_path_identity(
    canonical_project: &Path,
    relative: &Path,
    opened: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    use std::os::unix::fs::MetadataExt;

    let path = canonical_project.join(relative);
    let current = std::fs::symlink_metadata(&path).map_err(|error| {
        snapshot_validation(format!(
            "reinspect snapshot source path {}: {error}",
            relative.display()
        ))
    })?;
    if !current.file_type().is_file()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || !stable_file_metadata(opened, &current)
    {
        return Err(snapshot_validation(
            "snapshot source path changed while it was read",
        ));
    }
    let resolved = std::fs::canonicalize(&path).map_err(|error| {
        snapshot_validation(format!(
            "resolve snapshot source path {}: {error}",
            relative.display()
        ))
    })?;
    if resolved != path || !resolved.starts_with(canonical_project) {
        return Err(snapshot_validation(
            "snapshot source escaped its canonical project",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_open_source_path_identity(
    _canonical_project: &Path,
    _relative: &Path,
    _opened: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep snapshots require filesystem identity checks".to_owned(),
    ))
}

fn cleanup_operation_root_in(
    managed_workspace: &Path,
    operation_root: &Path,
) -> Result<(), ClassifiedError> {
    cleanup_operation_root_in_with_hook(managed_workspace, operation_root, || {})
}

fn cleanup_operation_root_in_with_hook<F>(
    managed_workspace: &Path,
    operation_root: &Path,
    before_remove: F,
) -> Result<(), ClassifiedError>
where
    F: FnOnce(),
{
    let workspace = validate_canonical_directory(managed_workspace, "managed workspace")?;
    let semgrep_root = workspace.join("semgrep");
    let semgrep_metadata = std::fs::symlink_metadata(&semgrep_root).map_err(|error| {
        snapshot_validation(format!(
            "inspect Semgrep workspace {}: {error}",
            semgrep_root.display()
        ))
    })?;
    if !semgrep_metadata.file_type().is_dir() {
        return Err(snapshot_validation(
            "Semgrep workspace is not a regular directory",
        ));
    }
    let resolved_semgrep = std::fs::canonicalize(&semgrep_root).map_err(|error| {
        snapshot_validation(format!(
            "resolve Semgrep workspace {}: {error}",
            semgrep_root.display()
        ))
    })?;
    if resolved_semgrep != semgrep_root {
        return Err(snapshot_validation(
            "Semgrep workspace has an ambiguous ancestor",
        ));
    }
    let operation_name = operation_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| snapshot_validation("Semgrep operation path has no UTF-8 UUID"))?;
    let operation_id = Uuid::parse_str(operation_name)
        .map_err(|_| snapshot_validation("Semgrep operation path is not UUID-owned"))?;
    let expected = semgrep_root.join(operation_id.to_string());
    if operation_root != expected {
        return Err(snapshot_validation(
            "Semgrep cleanup target is not the exact owned operation directory",
        ));
    }
    let metadata = std::fs::symlink_metadata(operation_root).map_err(|error| {
        snapshot_validation(format!(
            "inspect Semgrep operation directory {}: {error}",
            operation_root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(snapshot_validation(
            "Semgrep cleanup target is not a regular directory",
        ));
    }
    let resolved = std::fs::canonicalize(operation_root).map_err(|error| {
        snapshot_validation(format!(
            "resolve Semgrep operation directory {}: {error}",
            operation_root.display()
        ))
    })?;
    if resolved != expected || !resolved.starts_with(&semgrep_root) {
        return Err(snapshot_validation(
            "Semgrep cleanup target escaped its owned workspace",
        ));
    }
    before_remove();
    remove_owned_operation_nofollow(&semgrep_root, operation_name, &semgrep_metadata, &metadata)
}

#[cfg(unix)]
fn remove_owned_operation_nofollow(
    semgrep_root: &Path,
    operation_name: &str,
    expected_semgrep: &std::fs::Metadata,
    expected_operation: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    use rustix::fs::{open, openat, unlinkat, AtFlags, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let semgrep = File::from(open(semgrep_root, flags, Mode::empty()).map_err(|error| {
        snapshot_validation(format!("open Semgrep workspace without links: {error}"))
    })?);
    let open_semgrep = semgrep.metadata().map_err(|error| {
        snapshot_validation(format!("reinspect open Semgrep workspace: {error}"))
    })?;
    if !same_directory_identity(expected_semgrep, &open_semgrep) {
        return Err(snapshot_validation(
            "Semgrep workspace changed before cleanup",
        ));
    }
    let operation = File::from(
        openat(&semgrep, operation_name, flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!(
                "open Semgrep operation directory without links: {error}"
            ))
        })?,
    );
    let open_operation = operation.metadata().map_err(|error| {
        snapshot_validation(format!(
            "reinspect open Semgrep operation directory: {error}"
        ))
    })?;
    if !same_directory_identity(expected_operation, &open_operation) {
        return Err(snapshot_validation(
            "Semgrep operation directory changed before cleanup",
        ));
    }
    remove_open_directory_contents(&operation)?;
    let current = File::from(
        openat(&semgrep, operation_name, flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!(
                "reopen Semgrep operation directory before removal: {error}"
            ))
        })?,
    );
    let current_metadata = current.metadata().map_err(|error| {
        snapshot_validation(format!(
            "inspect reopened Semgrep operation directory: {error}"
        ))
    })?;
    if !same_directory_identity(&open_operation, &current_metadata) {
        return Err(snapshot_validation(
            "Semgrep operation pathname changed during cleanup",
        ));
    }
    unlinkat(&semgrep, operation_name, AtFlags::REMOVEDIR).map_err(|error| {
        snapshot_validation(format!("remove owned Semgrep operation directory: {error}"))
    })
}

#[cfg(unix)]
fn remove_open_directory_contents(directory: &File) -> Result<(), ClassifiedError> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};

    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)
        .map_err(|error| snapshot_validation(format!("read Semgrep cleanup directory: {error}")))?
    {
        let entry = entry.map_err(|error| {
            snapshot_validation(format!("read Semgrep cleanup directory entry: {error}"))
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for name in names {
        match openat(directory, &name, directory_flags, Mode::empty()) {
            Ok(child) => {
                let child = File::from(child);
                remove_open_directory_contents(&child)?;
                unlinkat(directory, &name, AtFlags::REMOVEDIR).map_err(|error| {
                    snapshot_validation(format!(
                        "remove owned Semgrep cleanup subdirectory: {error}"
                    ))
                })?;
            }
            Err(rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
                unlinkat(directory, &name, AtFlags::empty()).map_err(|error| {
                    snapshot_validation(format!("remove owned Semgrep cleanup file: {error}"))
                })?;
            }
            Err(error) => {
                return Err(snapshot_validation(format!(
                    "open Semgrep cleanup entry without links: {error}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_directory_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.file_type().is_dir()
        && right.file_type().is_dir()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn remove_owned_operation_nofollow(
    _semgrep_root: &Path,
    _operation_name: &str,
    _expected_semgrep: &std::fs::Metadata,
    _expected_operation: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep cleanup requires descriptor-relative filesystem access".to_owned(),
    ))
}

fn snapshot_validation(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(format!("Semgrep snapshot: {}", message.into()))
}

fn append_error_context(error: ClassifiedError, context: &str) -> ClassifiedError {
    let append = |message: String| format!("{message}; {context}");
    match error {
        ClassifiedError::Provider(message) => ClassifiedError::Provider(append(message)),
        ClassifiedError::Sandbox(message) => ClassifiedError::Sandbox(append(message)),
        ClassifiedError::Engine(message) => ClassifiedError::Engine(append(message)),
        ClassifiedError::Harness(message) => ClassifiedError::Harness(append(message)),
        ClassifiedError::Storage(message) => ClassifiedError::Storage(append(message)),
        ClassifiedError::Validation(message) => ClassifiedError::Validation(append(message)),
        ClassifiedError::Internal(message) => ClassifiedError::Internal(append(message)),
        ClassifiedError::Timeout => ClassifiedError::Timeout,
    }
}

#[cfg(test)]
mod snapshot_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use hf_core::target::TargetLanguage;
    use uuid::Uuid;

    use super::{
        cleanup_operation_root_in, digest_live_sources_with_limits,
        digest_live_sources_with_limits_and_read_hook, digest_ordered_sources,
        stage_selected_paths_at_with_limits, stage_selected_paths_at_with_stage_hook,
        stage_source_snapshot_at_with_limits, SnapshotLimits, StageMutationPoint,
        COMMAND_SCHEMA_VERSION, RULES_COMMIT, SEMGREP_VERSION, SNAPSHOT_LIMITS,
    };

    fn write(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn tiny_limits() -> SnapshotLimits {
        SnapshotLimits {
            max_files: 8,
            max_file_bytes: 64,
            max_total_bytes: 256,
            max_relative_path_bytes: 64,
        }
    }

    #[test]
    fn pinned_snapshot_contract_values_are_exact() {
        assert_eq!(SEMGREP_VERSION, "1.169.0");
        assert_eq!(RULES_COMMIT, "4d66ecf30bfb1809a984085f2c86a8c3915bfc71");
        assert_eq!(COMMAND_SCHEMA_VERSION, 1);
        assert_eq!(SNAPSHOT_LIMITS.max_files, 25_000);
        assert_eq!(SNAPSHOT_LIMITS.max_file_bytes, 2 * 1024 * 1024);
        assert_eq!(SNAPSHOT_LIMITS.max_total_bytes, 512 * 1024 * 1024);
        assert_eq!(SNAPSHOT_LIMITS.max_relative_path_bytes, 4_096);
    }

    #[test]
    fn snapshot_uses_discovery_source_set_and_preserves_relative_paths() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        write(
            project.path(),
            ".gitignore",
            b"build/\nfuzz_workspace/\nvendor/\n",
        );
        write(
            project.path(),
            "src/parser.c",
            b"int parse(const char *s) { return s[0]; }\n",
        );
        write(
            project.path(),
            "include/parser.h",
            b"int parse(const char *s);\n",
        );
        write(
            project.path(),
            "src/not_cpp.cpp",
            b"int cpp_only(int x) { return x; }\n",
        );
        write(
            project.path(),
            ".git/hidden.c",
            b"int hidden(int x) { return x; }\n",
        );
        write(
            project.path(),
            "build/generated.c",
            b"int built(int x) { return x; }\n",
        );
        write(
            project.path(),
            "fuzz_workspace/runtime.c",
            b"int runtime(int x) { return x; }\n",
        );
        write(
            project.path(),
            "vendor/third_party.c",
            b"int vendored(int x) { return x; }\n",
        );

        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let selected =
            hf_discovery::discoverable_source_files(&canonical, TargetLanguage::C).unwrap();
        assert_eq!(
            selected,
            vec![
                PathBuf::from("include/parser.h"),
                PathBuf::from("src/parser.c")
            ]
        );

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();
        assert_eq!(
            snapshot.relative_paths,
            selected.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            std::fs::read(snapshot.source_dir.join("src/parser.c")).unwrap(),
            b"int parse(const char *s) { return s[0]; }\n"
        );
        assert!(snapshot.output_dir.is_dir());
        assert_eq!(snapshot.file_count, 2);
        assert_eq!(snapshot.total_bytes, 68);
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[test]
    fn digest_is_stable_by_sorted_path_and_changes_with_path_or_bytes() {
        let first = vec![
            (PathBuf::from("z.c"), b"z".to_vec()),
            (PathBuf::from("a.c"), b"a".to_vec()),
        ];
        let reversed = vec![
            (PathBuf::from("a.c"), b"a".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let path_changed = vec![
            (PathBuf::from("b.c"), b"a".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let bytes_changed = vec![
            (PathBuf::from("a.c"), b"A".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let baseline = digest_ordered_sources(first).unwrap();
        assert_eq!(baseline, digest_ordered_sources(reversed).unwrap());
        assert_ne!(baseline, digest_ordered_sources(path_changed).unwrap());
        assert_ne!(baseline, digest_ordered_sources(bytes_changed).unwrap());
    }

    #[test]
    fn live_digest_matches_staged_digest_without_creating_artifacts() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "b.c", b"bbb");
        write(project.path(), "a.h", b"aaa");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();
        let entries_before = std::fs::read_dir(workspace.path()).unwrap().count();
        let digest =
            digest_live_sources_with_limits(&canonical, TargetLanguage::C, tiny_limits()).unwrap();
        assert_eq!(digest, snapshot.source_sha256);
        assert_eq!(
            std::fs::read_dir(workspace.path()).unwrap().count(),
            entries_before
        );
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[test]
    fn injected_limits_reject_one_over_each_bound() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "a.c", b"aaa");
        write(project.path(), "b.h", b"bbb");
        let canonical = std::fs::canonicalize(project.path()).unwrap();

        let cases = [
            SnapshotLimits {
                max_files: 1,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_file_bytes: 2,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_total_bytes: 5,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_relative_path_bytes: 2,
                ..tiny_limits()
            },
        ];
        for limits in cases {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            let error = stage_source_snapshot_at_with_limits(
                &canonical,
                TargetLanguage::C,
                Uuid::new_v4(),
                &canonical_workspace,
                limits,
            )
            .unwrap_err();
            assert!(error.to_string().contains("snapshot"), "{error}");
            assert!(
                !workspace.path().join("semgrep").exists()
                    || std::fs::read_dir(workspace.path().join("semgrep"))
                        .unwrap()
                        .next()
                        .is_none(),
                "failed staging left an operation directory"
            );
        }
    }

    #[test]
    fn unsafe_selected_paths_and_outside_files_fail_closed() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(project.path(), "safe.c", b"safe");
        write(outside.path(), "outside.c", b"outside");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let absolute = outside.path().join("outside.c");
        let unsafe_paths = [
            vec![PathBuf::from("../outside.c")],
            vec![absolute],
            vec![PathBuf::from(".")],
        ];
        for paths in unsafe_paths {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            assert!(stage_selected_paths_at_with_limits(
                &canonical,
                paths,
                Uuid::new_v4(),
                &canonical_workspace,
                tiny_limits(),
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_special_file_and_identity_replacement_fail_closed() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let project = tempfile::tempdir().unwrap();
        write(project.path(), "real.c", b"real");
        symlink(project.path().join("real.c"), project.path().join("link.c")).unwrap();
        let listener = UnixListener::bind(project.path().join("socket.c")).unwrap();
        let canonical = std::fs::canonicalize(project.path()).unwrap();

        for relative in ["link.c", "socket.c"] {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            assert!(stage_selected_paths_at_with_limits(
                &canonical,
                vec![PathBuf::from(relative)],
                Uuid::new_v4(),
                &canonical_workspace,
                tiny_limits(),
            )
            .is_err());
        }

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let original = canonical.join("real.c");
        let moved = canonical.join("moved.c");
        assert!(super::stage_selected_paths_at_with_hook(
            &canonical,
            vec![PathBuf::from("real.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
            || {
                std::fs::rename(&original, &moved).unwrap();
                std::fs::write(&original, b"real").unwrap();
            },
        )
        .is_err());

        write(project.path(), "mutable.c", b"same");
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let mutable = canonical.join("mutable.c");
        assert!(super::stage_selected_paths_at_with_hook(
            &canonical,
            vec![PathBuf::from("mutable.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
            || std::fs::write(&mutable, b"changed").unwrap(),
        )
        .is_err());

        let outside_parent = tempfile::tempdir().unwrap();
        write(outside_parent.path(), "outside.c", b"outside");
        symlink(outside_parent.path(), canonical.join("linked-parent")).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        assert!(stage_selected_paths_at_with_limits(
            &canonical,
            vec![PathBuf::from("linked-parent/outside.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .is_err());
        drop(listener);
    }

    #[test]
    fn staging_never_overwrites_an_existing_operation_directory() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "input.c", b"input");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation_id = Uuid::new_v4();
        let operation = canonical_workspace
            .join("semgrep")
            .join(operation_id.to_string());
        std::fs::create_dir_all(&operation).unwrap();
        write(&operation, "owner-marker", b"existing");

        assert!(stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            operation_id,
            &canonical_workspace,
            tiny_limits(),
        )
        .is_err());
        assert_eq!(
            std::fs::read(operation.join("owner-marker")).unwrap(),
            b"existing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_directories_and_files_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        write(project.path(), "src/input.c", b"input");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();

        for directory in [
            &snapshot.operation_root,
            &snapshot.source_dir,
            &snapshot.output_dir,
            &snapshot.source_dir.join("src"),
        ] {
            let mode = std::fs::metadata(directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "unexpected mode for {}", directory.display());
        }
        let mode = std::fs::metadata(snapshot.source_dir.join("src/input.c"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_swapped_owned_directory_paths_without_touching_external_trees() {
        use std::os::unix::fs::symlink;

        for point in [
            StageMutationPoint::SemgrepRoot,
            StageMutationPoint::OperationRoot,
            StageMutationPoint::SourceRoot,
            StageMutationPoint::DestinationParent,
        ] {
            let project = tempfile::tempdir().unwrap();
            write(project.path(), "nested/input.c", b"input");
            let canonical = std::fs::canonicalize(project.path()).unwrap();
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            let outside = tempfile::tempdir().unwrap();
            write(outside.path(), "must-survive", b"external");
            let operation_id = Uuid::new_v4();
            let semgrep = canonical_workspace.join("semgrep");
            let operation = semgrep.join(operation_id.to_string());
            let source = operation.join("source");
            let nested = source.join("nested");
            let mut swapped = false;

            let result = stage_selected_paths_at_with_stage_hook(
                &canonical,
                vec![PathBuf::from("nested/input.c")],
                operation_id,
                &canonical_workspace,
                tiny_limits(),
                |observed| {
                    if observed != point || swapped {
                        return;
                    }
                    swapped = true;
                    let (target, held) = match point {
                        StageMutationPoint::SemgrepRoot => {
                            (semgrep.clone(), canonical_workspace.join("semgrep-held"))
                        }
                        StageMutationPoint::OperationRoot => (
                            operation.clone(),
                            semgrep.join(format!("{operation_id}-held")),
                        ),
                        StageMutationPoint::SourceRoot => {
                            (source.clone(), operation.join("source-held"))
                        }
                        StageMutationPoint::DestinationParent => {
                            (nested.clone(), source.join("nested-held"))
                        }
                    };
                    std::fs::rename(&target, held).unwrap();
                    symlink(outside.path(), target).unwrap();
                },
            );

            assert!(swapped, "test did not reach {point:?}");
            assert!(result.is_err(), "{point:?} swap must fail closed");
            assert_eq!(
                std::fs::read(outside.path().join("must-survive")).unwrap(),
                b"external"
            );
            let external_entries = std::fs::read_dir(outside.path()).unwrap().count();
            assert_eq!(
                external_entries, 1,
                "{point:?} staging wrote through a replacement pathname"
            );
        }
    }

    #[test]
    fn aggregate_limit_rejects_before_allocating_or_reading_the_next_file() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "a.c", b"aaaa");
        write(project.path(), "b.c", b"bbbb");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let mut read_paths = Vec::new();
        let limits = SnapshotLimits {
            max_total_bytes: 4,
            ..tiny_limits()
        };

        let result = digest_live_sources_with_limits_and_read_hook(
            &canonical,
            TargetLanguage::C,
            limits,
            |path| read_paths.push(path.to_path_buf()),
        );

        assert!(result.is_err());
        assert_eq!(
            read_paths,
            vec![PathBuf::from("a.c")],
            "the second file reached the allocation/read boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_without_a_writer_fails_promptly_and_cleans_the_operation() {
        use std::time::{Duration, Instant};

        let project = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(project.path().join("blocked.c"))
            .status()
            .unwrap()
            .success());
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation_id = Uuid::new_v4();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("semgrep::snapshot_tests::fifo_stage_child")
            .env("OXFUZZ_FIFO_TEST_PROJECT", &canonical)
            .env("OXFUZZ_FIFO_TEST_WORKSPACE", &canonical_workspace)
            .env("OXFUZZ_FIFO_TEST_OPERATION", operation_id.to_string())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "opening a FIFO without O_NONBLOCK did not fail promptly"
        );
        assert!(
            !canonical_workspace.join("semgrep").exists()
                || std::fs::read_dir(canonical_workspace.join("semgrep"))
                    .unwrap()
                    .next()
                    .is_none(),
            "FIFO failure left an operation directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_stage_child() {
        let Ok(project) = std::env::var("OXFUZZ_FIFO_TEST_PROJECT") else {
            return;
        };
        let workspace = PathBuf::from(std::env::var("OXFUZZ_FIFO_TEST_WORKSPACE").unwrap());
        let operation_id =
            Uuid::parse_str(&std::env::var("OXFUZZ_FIFO_TEST_OPERATION").unwrap()).unwrap();
        let result = stage_selected_paths_at_with_limits(
            Path::new(&project),
            vec![PathBuf::from("blocked.c")],
            operation_id,
            &workspace,
            tiny_limits(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn cleanup_removes_only_owned_operation_directory() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let semgrep = canonical_workspace.join("semgrep");
        std::fs::create_dir(&semgrep).unwrap();
        let operation_id = Uuid::new_v4();
        let sibling_id = Uuid::new_v4();
        let operation = semgrep.join(operation_id.to_string());
        let sibling = semgrep.join(sibling_id.to_string());
        std::fs::create_dir(&operation).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        write(&operation, "source/input.c", b"data");

        cleanup_operation_root_in(&canonical_workspace, &operation).unwrap();
        assert!(!operation.exists());
        assert!(sibling.is_dir());
        assert!(
            cleanup_operation_root_in(&canonical_workspace, &canonical_workspace).is_err(),
            "the managed root itself is not an operation"
        );
        assert!(
            cleanup_operation_root_in(&canonical_workspace, &sibling.join("nested")).is_err(),
            "nested or absent targets are ambiguous"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_symlinked_ancestors_and_targets() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), canonical_workspace.join("semgrep")).unwrap();
        assert!(cleanup_operation_root_in(
            &canonical_workspace,
            &canonical_workspace
                .join("semgrep")
                .join(Uuid::new_v4().to_string())
        )
        .is_err());

        std::fs::remove_file(canonical_workspace.join("semgrep")).unwrap();
        std::fs::create_dir(canonical_workspace.join("semgrep")).unwrap();
        let target = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());
        symlink(outside.path(), &target).unwrap();
        assert!(cleanup_operation_root_in(&canonical_workspace, &target).is_err());
        assert!(outside.path().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_an_ancestor_replaced_after_validation() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let semgrep = canonical_workspace.join("semgrep");
        std::fs::create_dir(&semgrep).unwrap();
        let operation_id = Uuid::new_v4();
        let operation = semgrep.join(operation_id.to_string());
        std::fs::create_dir(&operation).unwrap();
        write(&operation, "source/original.c", b"original");

        let outside = tempfile::tempdir().unwrap();
        let external_operation = outside.path().join(operation_id.to_string());
        std::fs::create_dir(&external_operation).unwrap();
        write(&external_operation, "must-survive", b"external");
        let held_semgrep = canonical_workspace.join("semgrep-held");

        let result =
            super::cleanup_operation_root_in_with_hook(&canonical_workspace, &operation, || {
                std::fs::rename(&semgrep, &held_semgrep).unwrap();
                symlink(outside.path(), &semgrep).unwrap();
            });
        assert!(result.is_err(), "an ancestor swap must fail closed");
        assert_eq!(
            std::fs::read(external_operation.join("must-survive")).unwrap(),
            b"external",
            "cleanup followed a replacement ancestor outside the managed workspace"
        );
    }
}
