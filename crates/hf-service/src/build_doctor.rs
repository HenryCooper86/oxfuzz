//! Retained project build diagnosis and profile-bound sandbox execution.
pub use crate::build_profiles::{
    BuildDependency, BuildDependencyKind, BuildProfileView, ProfileBuildSystem,
    SaveBuildProfileRequest,
};
use hf_core::error::ClassifiedError;
pub use hf_storage::{
    BuildDependencyStatus, BuildDiagnosisEvidence as ProjectBuildDiagnosis, BuildProfileState,
    BuildTerminalStatus as BuildPlanRunStatus,
};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};
mod diagnosis;
mod execution;
/// Legacy database output directory searched for unconfigured projects.
pub const OXFUZZ_BUILD_DIR: &str = ".oxfuzz-build";
/// Detection and exact reviewed plans share the retained evidence types.
pub use hf_storage::{
    BuildPlanEvidence as BuildPlan, BuildPlanStepEvidence as BuildPlanStep,
    BuildSystemEvidence as BuildSystemDiagnosis, DetectedBuildStatus as BuildSystemStatus,
    DetectedBuildSystem as BuildSystem,
};

/// Inspect root markers and legacy context without preparing a runnable plan.
#[must_use]
pub fn detect_build_systems(project: &Path) -> Vec<BuildSystemDiagnosis> {
    let mut detected = diagnosis::detected(project, ".");
    if has_usable_build_context(project) {
        for system in &mut detected {
            if !matches!(
                system.build_system,
                BuildSystem::Cargo | BuildSystem::Unknown
            ) {
                system.status = BuildSystemStatus::Ready;
            }
        }
    }
    detected
}

/// Whether a regular file with this exact name sits at the project root.
fn is_root_file(project: &Path, name: &str) -> bool {
    project
        .join(name)
        .symlink_metadata()
        .is_ok_and(|meta| meta.is_file())
}

/// Whether the first compile database selected by the service resolves into
/// usable, allowlisted build context.
fn has_usable_build_context(project: &Path) -> bool {
    matches!(
        crate::container::build_context::resolve_project_build_context(project),
        Ok(Some(_))
    )
}

/// Execute the saved profile the operator actually reviewed.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunBuildPlanRequest {
    pub project: String,
    pub expected_profile_sha256: String,
}
/// Retained result and validated published compile context.
#[derive(Debug, Clone, Serialize)]
pub struct BuildPlanRunOutcome {
    pub status: BuildPlanRunStatus,
    pub build_system: ProfileBuildSystem,
    pub steps_run: usize,
    pub build_context: Option<hf_core::build::BuildContext>,
    pub diagnosis: ProjectBuildDiagnosis,
}
const MAX_SNAPSHOT_FILES: usize = 20_000;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_SKIP_NAMES: [&str; 5] =
    [".git", OXFUZZ_BUILD_DIR, "build", "node_modules", "target"];

struct BuildStagingGuard {
    path: PathBuf,
}

impl Drop for BuildStagingGuard {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                "failed to remove Build Doctor staging directory: {error}"
            ),
        }
    }
}

fn stage_project_snapshot(
    project: &Path,
    staging: &Path,
) -> Result<(), hf_core::error::ClassifiedError> {
    use hf_core::error::ClassifiedError;

    let project = std::fs::canonicalize(project).map_err(|error| {
        ClassifiedError::Validation(format!("resolve Build Doctor project: {error}"))
    })?;
    let staging = std::fs::canonicalize(staging).map_err(|error| {
        ClassifiedError::Internal(format!("resolve Build Doctor staging: {error}"))
    })?;
    if staging.starts_with(&project) {
        return Err(ClassifiedError::Validation(
            "the managed workspace must not be inside the project being diagnosed".to_owned(),
        ));
    }

    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut pending = vec![(project, staging)];
    while let Some((source_dir, destination_dir)) = pending.pop() {
        let entries = std::fs::read_dir(&source_dir).map_err(|error| {
            ClassifiedError::Validation(format!(
                "read Build Doctor snapshot directory {}: {error}",
                source_dir.display()
            ))
        })?;
        let mut entries = entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ClassifiedError::Validation(format!("read project entry: {error}")))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name();
            if SNAPSHOT_SKIP_NAMES
                .iter()
                .any(|skipped| name == std::ffi::OsStr::new(skipped))
            {
                continue;
            }
            let source = entry.path();
            let destination = destination_dir.join(&name);
            let kind = entry.file_type().map_err(|error| {
                ClassifiedError::Validation(format!(
                    "inspect Build Doctor snapshot entry {}: {error}",
                    source.display()
                ))
            })?;
            if kind.is_symlink() {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor snapshot refuses symbolic link {}",
                    source.display()
                )));
            }
            if kind.is_dir() {
                std::fs::create_dir(&destination).map_err(|error| {
                    ClassifiedError::Internal(format!(
                        "create Build Doctor staging directory {}: {error}",
                        destination.display()
                    ))
                })?;
                pending.push((source, destination));
                continue;
            }
            if !kind.is_file() {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor snapshot refuses special file {}",
                    source.display()
                )));
            }
            let metadata = entry.metadata().map_err(|error| {
                ClassifiedError::Validation(format!(
                    "inspect Build Doctor snapshot file {}: {error}",
                    source.display()
                ))
            })?;
            if metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor snapshot file {} exceeds {MAX_SNAPSHOT_FILE_BYTES} bytes",
                    source.display()
                )));
            }
            if files >= MAX_SNAPSHOT_FILES {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor snapshot exceeds {MAX_SNAPSHOT_FILES} files"
                )));
            }
            bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                ClassifiedError::Validation(
                    "Build Doctor snapshot byte count overflowed".to_owned(),
                )
            })?;
            if bytes > MAX_SNAPSHOT_BYTES {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes"
                )));
            }
            let copied = std::fs::copy(&source, &destination).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "stage Build Doctor file {}: {error}",
                    source.display()
                ))
            })?;
            if copied != metadata.len() {
                return Err(ClassifiedError::Validation(format!(
                    "Build Doctor source changed while staging {}",
                    source.display()
                )));
            }
            files += 1;
        }
    }
    Ok(())
}

fn rewrite_path_prefix(text: &str, staging: &Path, project: &Path) -> String {
    for prefix in [staging.to_string_lossy().as_ref(), "/work"] {
        if text == prefix {
            return project.to_string_lossy().into_owned();
        }
        if let Some(relative) = text
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            return format!("{}/{relative}", project.display());
        }
    }
    text.to_owned()
}

fn rewrite_argument(text: &str, staging: &Path, project: &Path) -> String {
    if let Some(path) = text.strip_prefix("-I") {
        format!("-I{}", rewrite_path_prefix(path, staging, project))
    } else {
        rewrite_path_prefix(text, staging, project)
    }
}

fn rewrite_execution_paths(
    value: &mut serde_json::Value,
    parsed: &[hf_core::build::CompileEntry],
    staging: &Path,
    project: &Path,
) {
    let Some(entries) = value.as_array_mut() else {
        return;
    };
    for (entry, parsed) in entries.iter_mut().zip(parsed) {
        for key in ["directory", "file", "output"] {
            if let Some(serde_json::Value::String(text)) = entry.get_mut(key) {
                *text = rewrite_path_prefix(text, staging, project);
            }
        }
        if let Some(object) = entry.as_object_mut() {
            let arguments = parsed
                .arguments
                .iter()
                .map(|token| serde_json::Value::String(rewrite_argument(token, staging, project)))
                .collect();
            object.insert("arguments".into(), serde_json::Value::Array(arguments));
            object.remove("command");
        }
    }
}

/// Reject oversized normalized JSON while it is being serialized.
#[derive(Default)]
struct CompileDatabaseWriter {
    bytes: Vec<u8>,
}

impl std::io::Write for CompileDatabaseWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        use crate::container::build_context::MAX_COMPILE_DATABASE_BYTES;
        if buffer.len() as u64 > MAX_COMPILE_DATABASE_BYTES - self.bytes.len() as u64 {
            return Err(std::io::Error::other(format!(
                "normalized compile database exceeds {MAX_COMPILE_DATABASE_BYTES} bytes"
            )));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn normalize_compile_database(
    artifact: &Path,
    staging: &Path,
    project: &Path,
) -> Result<(String, hf_core::build::BuildContext), hf_core::error::ClassifiedError> {
    use hf_core::error::ClassifiedError;

    let raw = crate::container::build_context::read_compile_database_text(artifact)?;
    let mut value: serde_json::Value = serde_json::from_str(&raw).map_err(|error| {
        ClassifiedError::Validation(format!("parse Build Doctor compile database: {error}"))
    })?;
    let parsed = hf_discovery::build_context::parse_compile_database(&raw)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    rewrite_execution_paths(&mut value, &parsed, staging, project);
    let mut writer = CompileDatabaseWriter::default();
    serde_json::to_writer_pretty(&mut writer, &value).map_err(|error| {
        ClassifiedError::Validation(format!("serialize normalized compile database: {error}"))
    })?;
    let normalized = String::from_utf8(writer.bytes).map_err(|error| {
        ClassifiedError::Internal(format!("normalized compile database encoding: {error}"))
    })?;
    let entries = hf_discovery::build_context::parse_compile_database(&normalized)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    let context = hf_discovery::build_context::extract_build_context(&entries, project);
    if context.entry_count == 0 {
        return Err(ClassifiedError::Validation(
            "normalized compile database contains no entries".to_owned(),
        ));
    }
    Ok((normalized, context))
}

fn publish_compile_database(
    project: &Path,
    relative: &str,
    normalized: &str,
) -> Result<(), ClassifiedError> {
    let destination = crate::build_profiles::validate_project_path(project, relative, false, true)?;
    let directory = destination
        .parent()
        .ok_or_else(|| ClassifiedError::Validation("compile database has no parent".into()))?;
    std::fs::create_dir_all(directory).map_err(|error| {
        ClassifiedError::Internal(format!("create database output directory: {error}"))
    })?;
    crate::build_profiles::validate_project_path(project, relative, false, true)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(|error| {
        ClassifiedError::Internal(format!("create temporary compile database: {error}"))
    })?;
    temporary
        .write_all(normalized.as_bytes())
        .map_err(|error| {
            ClassifiedError::Internal(format!("write normalized compile database: {error}"))
        })?;
    temporary.as_file().sync_all().map_err(|error| {
        ClassifiedError::Internal(format!("sync normalized compile database: {error}"))
    })?;
    crate::build_profiles::validate_project_path(project, relative, false, true)?;
    temporary.persist(&destination).map_err(|error| {
        ClassifiedError::Internal(format!(
            "install normalized compile database: {}",
            error.error
        ))
    })?;
    Ok(())
}
/// Stable lowercase identifier, matching the serde wire form.
#[must_use]
pub const fn build_system_id(build_system: BuildSystem) -> &'static str {
    match build_system {
        BuildSystem::CMake => "cmake",
        BuildSystem::Meson => "meson",
        BuildSystem::Autotools => "autotools",
        BuildSystem::Make => "make",
        BuildSystem::Bazel => "bazel",
        BuildSystem::Cargo => "cargo",
        BuildSystem::Unknown => "unknown",
    }
}
