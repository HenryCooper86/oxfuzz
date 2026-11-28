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
pub(crate) use crate::build_profiles::BUILD_STEP_CPUS;
const MAX_SNAPSHOT_FILES: usize = 20_000;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_SKIP_NAMES: [&str; 3] = [".git", OXFUZZ_BUILD_DIR, "node_modules"];

/// Directory names that are usually -- but not always -- build output.
/// `LibTIFF`, for one, tracks `build/Makefile.am` and its build requires it, so
/// these are left out only when [`is_build_output_tree`] recognizes them.
const SNAPSHOT_BUILD_OUTPUT_NAMES: [&str; 2] = ["build", "target"];

/// Files a generated build tree carries at its top: `CMake`, Ninja, Meson,
/// Cargo (and other tools that mark caches with `CACHEDIR.TAG`), and an
/// out-of-tree Autotools configure.
const BUILD_OUTPUT_MARKERS: [&str; 6] = [
    "CMakeCache.txt",
    "build.ninja",
    "meson-private",
    "CACHEDIR.TAG",
    ".rustc_info.json",
    "config.status",
];

/// Whether `directory` is a generated build tree rather than project source.
fn is_build_output_tree(directory: &Path) -> bool {
    BUILD_OUTPUT_MARKERS
        .iter()
        .any(|marker| directory.join(marker).symlink_metadata().is_ok())
}

/// The link Bazel keeps inside a vendor directory, pointing into the output
/// base of the machine that vendored.
const BAZEL_VENDOR_LINK: &str = "bazel-external";
/// Prefix of the convenience links (`bazel-bin`, `bazel-out`, ...) Bazel
/// writes into a workspace root.
const BAZEL_CONVENIENCE_LINK_PREFIX: &str = "bazel-";
const BAZEL_WORKSPACE_FILES: [&str; 3] = ["MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"];

/// Whether a symbolic link is one Bazel itself maintains: the vendor
/// directory's link anywhere, or a convenience link in a workspace root.
/// Such a link points into an output base outside the project, so the
/// snapshot leaves it out instead of refusing the project; it is never
/// followed, and Bazel recreates what it needs in the sandbox.
fn is_bazel_own_link(name: &std::ffi::OsStr, directory: &Path) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name == BAZEL_VENDOR_LINK
        || (name.starts_with(BAZEL_CONVENIENCE_LINK_PREFIX)
            && BAZEL_WORKSPACE_FILES
                .iter()
                .any(|marker| is_root_file(directory, marker)))
}

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
            if SNAPSHOT_BUILD_OUTPUT_NAMES
                .iter()
                .any(|candidate| name == std::ffi::OsStr::new(candidate))
                && is_build_output_tree(&source)
            {
                continue;
            }
            let destination = destination_dir.join(&name);
            let kind = entry.file_type().map_err(|error| {
                ClassifiedError::Validation(format!(
                    "inspect Build Doctor snapshot entry {}: {error}",
                    source.display()
                ))
            })?;
            if kind.is_symlink() && is_bazel_own_link(&name, &source_dir) {
                continue;
            }
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

fn rewrite_path_prefix(
    text: &str,
    staging: &Path,
    project: &Path,
) -> Result<String, ClassifiedError> {
    for prefix in [staging.to_string_lossy().as_ref(), "/work"] {
        if text == prefix {
            return Ok(project.to_string_lossy().into_owned());
        }
        if let Some(relative) = text
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            if relative.starts_with('/')
                || relative.starts_with('\\')
                || matches!(relative.as_bytes(), [drive, b':', ..] if drive.is_ascii_alphabetic())
            {
                return Err(ClassifiedError::Validation(
                    "compile database execution path requires a relative path suffix".into(),
                ));
            }
            return Ok(project.join(relative).to_string_lossy().into_owned());
        }
    }
    Ok(text.to_owned())
}

fn rewrite_argument(text: &str, staging: &Path, project: &Path) -> Result<String, ClassifiedError> {
    if let Some(path) = text.strip_prefix("-I") {
        Ok(format!(
            "-I{}",
            rewrite_path_prefix(path, staging, project)?
        ))
    } else {
        rewrite_path_prefix(text, staging, project)
    }
}

fn rewrite_execution_paths(
    value: &mut serde_json::Value,
    parsed: &[hf_core::build::CompileEntry],
    staging: &Path,
    project: &Path,
) -> Result<(), ClassifiedError> {
    let Some(entries) = value.as_array_mut() else {
        return Ok(());
    };
    for (entry, parsed) in entries.iter_mut().zip(parsed) {
        for key in ["directory", "file", "output"] {
            if let Some(serde_json::Value::String(text)) = entry.get_mut(key) {
                *text = rewrite_path_prefix(text, staging, project)?;
            }
        }
        if let Some(object) = entry.as_object_mut() {
            let arguments = parsed
                .arguments
                .iter()
                .map(|token| {
                    rewrite_argument(token, staging, project).map(serde_json::Value::String)
                })
                .collect::<Result<Vec<_>, _>>()?;
            object.insert("arguments".into(), serde_json::Value::Array(arguments));
            object.remove("command");
        }
    }
    Ok(())
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
    rewrite_execution_paths(&mut value, &parsed, staging, project)?;
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

#[cfg(all(test, unix))]
mod snapshot_tests {
    use super::stage_project_snapshot;

    fn staged(project: &std::path::Path) -> Result<tempfile::TempDir, String> {
        let staging = tempfile::tempdir().unwrap();
        stage_project_snapshot(project, staging.path())
            .map(|()| staging)
            .map_err(|error| error.to_string())
    }

    #[test]
    fn a_build_directory_holding_project_sources_is_staged() {
        // LibTIFF 4.0.4 tracks `build/Makefile.am`, and its top-level
        // Makefile.am lists `build` in SUBDIRS: leaving the directory out
        // fails `autoreconf` at its first step.
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("build")).unwrap();
        std::fs::write(
            project.path().join("build/Makefile.am"),
            "EXTRA_DIST = README\n",
        )
        .unwrap();
        std::fs::create_dir(project.path().join("target")).unwrap();
        std::fs::write(project.path().join("target/defs.h"), "#define X 1\n").unwrap();

        let staging = staged(project.path()).unwrap();

        assert!(staging.path().join("build/Makefile.am").is_file());
        assert!(staging.path().join("target/defs.h").is_file());
    }

    #[test]
    fn build_output_trees_are_still_left_out() {
        let project = tempfile::tempdir().unwrap();
        for (directory, marker) in [
            ("build", "CMakeCache.txt"),
            ("target", "CACHEDIR.TAG"),
            ("out/build", "build.ninja"),
        ] {
            let tree = project.path().join(directory);
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join(marker), "").unwrap();
            std::fs::write(tree.join("stale.o"), "").unwrap();
        }
        std::fs::create_dir_all(project.path().join("node_modules/x")).unwrap();
        std::fs::write(project.path().join("node_modules/x/i.js"), "").unwrap();

        let staging = staged(project.path()).unwrap();

        assert!(!staging.path().join("build").exists());
        assert!(!staging.path().join("target").exists());
        assert!(!staging.path().join("out/build").exists());
        assert!(!staging.path().join("node_modules").exists());
    }

    #[test]
    fn the_links_bazel_maintains_are_left_out_and_never_followed() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.h"), "outside").unwrap();
        let project = tempfile::tempdir().unwrap();
        let vendor = project.path().join("third_party/bazel");
        std::fs::create_dir_all(vendor.join("rules_cc+")).unwrap();
        std::fs::write(
            project.path().join("MODULE.bazel"),
            "module(name = \"demo\")\n",
        )
        .unwrap();
        std::fs::write(vendor.join("rules_cc+/defs.bzl"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), vendor.join("bazel-external")).unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("bazel-bin")).unwrap();
        std::os::unix::fs::symlink(outside.path(), project.path().join("bazel-out")).unwrap();

        let staging = staged(project.path()).unwrap();

        assert!(staging.path().join("MODULE.bazel").is_file());
        assert!(staging
            .path()
            .join("third_party/bazel/rules_cc+/defs.bzl")
            .is_file());
        for link in ["third_party/bazel/bazel-external", "bazel-bin", "bazel-out"] {
            assert!(
                staging.path().join(link).symlink_metadata().is_err(),
                "{link} is not staged"
            );
        }
    }

    #[test]
    fn any_other_link_still_refuses_the_project() {
        let outside = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("MODULE.bazel"), "").unwrap();
        // A convenience-style name below the workspace root is not Bazel's.
        std::os::unix::fs::symlink(outside.path(), project.path().join("src/bazel-bin")).unwrap();
        let error = staged(project.path()).unwrap_err();
        assert!(error.contains("refuses symbolic link"), "{error}");

        let plain = tempfile::tempdir().unwrap();
        // Without a Bazel workspace file the same name at the root is refused.
        std::os::unix::fs::symlink(outside.path(), plain.path().join("bazel-bin")).unwrap();
        let error = staged(plain.path()).unwrap_err();
        assert!(error.contains("refuses symbolic link"), "{error}");

        let linked = tempfile::tempdir().unwrap();
        std::fs::write(linked.path().join("MODULE.bazel"), "").unwrap();
        std::os::unix::fs::symlink(outside.path(), linked.path().join("include")).unwrap();
        let error = staged(linked.path()).unwrap_err();
        assert!(error.contains("refuses symbolic link"), "{error}");
    }
}
