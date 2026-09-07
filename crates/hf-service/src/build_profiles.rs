//! Saved project build assumptions and filesystem checks, available with every feature set.
//!
//! These checks execute no commands. Runtime-backed diagnosis and mutation are
//! enabled separately by `build-doctor`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hf_core::error::ClassifiedError;
use hf_core::runtime::ImmutableImageReference;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{valid_cmake_option_name, BuildProfileSettings};
pub use hf_storage::{
    BuildDependency, BuildDependencyKind, ProfileBuildSystem,
    ProjectBuildProfileRecord as BuildProfileView,
};

pub(crate) mod evidence;
mod plan;
use evidence::validate_profile_evidence_capacity;
pub(crate) use plan::{profile_build_plan, required_build_dependencies};

/// Explicit profile configuration supplied by an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveBuildProfileRequest {
    /// Existing project directory, resolved to its canonical identity on save.
    pub project: String,
    /// Project-relative component directory; `.` selects the project root.
    pub component_root: String,
    /// Selected supported build system, confirmed by the component marker.
    pub build_system: ProfileBuildSystem,
    /// Project-relative output ending in `compile_commands.json`.
    pub compile_database_path: String,
    /// Explicit definitions; an empty map remains empty after normalization.
    pub cmake_definitions: BTreeMap<String, String>,
    /// Required command or package-module probes, never installation requests.
    pub dependencies: Vec<BuildDependency>,
}

const MAX_MARKER_BYTES: u64 = 64 * 1024 * 1024;
/// Recognized systems in specificity order; Make markers follow GNU selection order.
pub(crate) const BUILD_SYSTEM_MARKERS: [(hf_storage::DetectedBuildSystem, &[&str]); 6] = [
    (hf_storage::DetectedBuildSystem::CMake, &["CMakeLists.txt"]),
    (hf_storage::DetectedBuildSystem::Meson, &["meson.build"]),
    (
        hf_storage::DetectedBuildSystem::Bazel,
        &[
            "WORKSPACE",
            "WORKSPACE.bazel",
            "MODULE.bazel",
            "BUILD.bazel",
        ],
    ),
    (hf_storage::DetectedBuildSystem::Cargo, &["Cargo.toml"]),
    (
        hf_storage::DetectedBuildSystem::Autotools,
        &["configure.ac", "configure.in", "Makefile.am"],
    ),
    (
        hf_storage::DetectedBuildSystem::Make,
        &["GNUmakefile", "makefile", "Makefile"],
    ),
];

fn normalize_profile(
    request: &SaveBuildProfileRequest,
    settings: &BuildProfileSettings,
    image: &ImmutableImageReference,
    now: DateTime<Utc>,
) -> Result<BuildProfileView, ClassifiedError> {
    validate_options(request.build_system, &request.cmake_definitions, settings)?;
    let project = crate::container::canonical_project_root(Path::new(&request.project))?;
    let project_root = project
        .to_str()
        .ok_or_else(|| invalid("project root must be UTF-8"))?;
    if project_root.chars().any(char::is_control) {
        return Err(invalid("project root contains control characters"));
    }
    let component_root = normalize_relative(&request.component_root, true)?;
    let compile_database_path = normalize_relative(&request.compile_database_path, false)?;
    if compile_database_path.rsplit('/').next() != Some("compile_commands.json") {
        return Err(invalid(
            "build database filename must be compile_commands.json",
        ));
    }
    validate_project_path(&project, &component_root, true, false)?;
    validate_project_path(&project, &compile_database_path, false, true)?;
    let marker_path = select_marker(&project, &component_root, request.build_system)?;
    let marker_sha256 = marker_digest(&project, &marker_path)?;
    let mut dependencies = request.dependencies.clone();
    for dependency in &dependencies {
        let name = &dependency.name;
        if !(1..=64).contains(&name.len())
            || !name.as_bytes()[0].is_ascii_alphanumeric()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.+-".contains(&byte))
        {
            return Err(invalid(&format!(
                "invalid build dependency identifier '{name}'"
            )));
        }
    }
    dependencies.sort();
    dependencies.dedup();
    let mut profile = BuildProfileView {
        project_root: project_root.to_owned(),
        component_root,
        build_system: request.build_system,
        compile_database_path,
        cmake_definitions: request.cmake_definitions.clone(),
        dependencies,
        sandbox_image_tag: hf_runtime::SANDBOX_IMAGE.to_owned(),
        sandbox_image_id: image.reference().to_owned(),
        marker_path,
        marker_sha256,
        profile_sha256: String::new(),
        created_at: now,
        updated_at: now,
    };
    profile.profile_sha256 = profile_digest(&profile)?;
    validate_profile_evidence_capacity(&profile)?;
    Ok(profile)
}

fn validate_options(
    system: ProfileBuildSystem,
    definitions: &BTreeMap<String, String>,
    settings: &BuildProfileSettings,
) -> Result<(), ClassifiedError> {
    settings.validate().map_err(ClassifiedError::Validation)?;
    if system == ProfileBuildSystem::Make && !definitions.is_empty() {
        return Err(invalid("Make profiles cannot contain CMake definitions"));
    }
    for (name, value) in definitions {
        if !valid_cmake_option_name(name) || !settings.allowed_cmake_options.contains(name) {
            return Err(invalid(&format!(
                "CMake option '{name}' is not allowed by build_profiles.allowed_cmake_options"
            )));
        }
        if !(1..=128).contains(&value.len())
            || value.starts_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_+.,:/-".contains(&byte))
        {
            return Err(invalid(&format!("invalid value for CMake option '{name}'")));
        }
    }
    Ok(())
}

fn normalize_relative(value: &str, root_allowed: bool) -> Result<String, ClassifiedError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains(['\\', ':'])
        || value.chars().any(char::is_control)
        || value.split('/').any(|part| part == "..")
    {
        return Err(invalid(
            "build paths must be project-relative without parent traversal",
        ));
    }
    let parts: Vec<_> = value
        .split('/')
        .filter(|part| !matches!(*part, "" | "."))
        .collect();
    if parts.is_empty() {
        return if root_allowed {
            Ok(".".to_owned())
        } else {
            Err(invalid("build database path must name a file"))
        };
    }
    Ok(parts.join("/"))
}

/// Validate each existing ancestor, accepting absent output ancestors only.
/// Re-canonicalization narrows ancestor replacement races; sandbox execution
/// remains responsible for isolation and callers must repeat checks at access.
pub(crate) fn validate_project_path(
    project: &Path,
    relative: &str,
    directory: bool,
    allow_missing: bool,
) -> Result<PathBuf, ClassifiedError> {
    if normalize_relative(relative, directory)? != relative {
        return Err(invalid("stored build path is not normalized"));
    }
    let mut path = project.to_path_buf();
    let parts: Vec<_> = relative.split('/').filter(|part| *part != ".").collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(invalid(&format!(
                    "inspect build path {}: {error}",
                    path.display()
                )))
            }
        };
        let expects_directory = index + 1 < parts.len() || directory;
        if (expects_directory && !metadata.is_dir()) || (!expects_directory && !metadata.is_file())
        {
            return Err(invalid(&format!(
                "build path refuses symlink, special file, or incorrect file type: {}",
                path.display()
            )));
        }
        let resolved = std::fs::canonicalize(&path)
            .map_err(|error| invalid(&format!("resolve build path: {error}")))?;
        if !resolved.starts_with(project) {
            return Err(invalid("build path escapes canonical project"));
        }
        path = resolved;
    }
    Ok(path)
}

fn component_path(component: &str, file: &str) -> String {
    if component == "." {
        file.to_owned()
    } else {
        format!("{component}/{file}")
    }
}

fn marker_present(project: &Path, relative: &str) -> Result<bool, ClassifiedError> {
    match std::fs::symlink_metadata(project.join(relative)) {
        Ok(_) => {
            validate_project_path(project, relative, false, false)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(invalid(&format!("inspect build marker: {error}"))),
    }
}

fn select_marker(
    project: &Path,
    component: &str,
    system: ProfileBuildSystem,
) -> Result<String, ClassifiedError> {
    let selected = match system {
        ProfileBuildSystem::CMake => hf_storage::DetectedBuildSystem::CMake,
        ProfileBuildSystem::Make => hf_storage::DetectedBuildSystem::Make,
    };
    for (detected, markers) in BUILD_SYSTEM_MARKERS {
        for marker in markers {
            if detected != selected && system != ProfileBuildSystem::Make {
                continue;
            }
            let relative = component_path(component, marker);
            if marker_present(project, &relative)? {
                if detected != selected {
                    return Err(invalid(&format!(
                        "plain Make profile conflicts with higher-level marker '{relative}'"
                    )));
                }
                return Ok(relative);
            }
        }
    }
    Err(invalid(
        "selected component has no matching build-system marker",
    ))
}

pub(crate) fn marker_digest(project: &Path, relative: &str) -> Result<String, ClassifiedError> {
    use std::io::Read as _;
    let path = validate_project_path(project, relative, false, false)?;
    let file = std::fs::File::open(path)
        .map_err(|error| invalid(&format!("open build marker: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| invalid(&format!("inspect opened build marker: {error}")))?;
    if !metadata.is_file() || metadata.len() > MAX_MARKER_BYTES {
        return Err(invalid(
            "build marker must be a regular file of at most 64 MiB",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(&format!("read build marker: {error}")))?;
    if bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(invalid("build marker exceeds 64 MiB"));
    }
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn profile_digest(profile: &BuildProfileView) -> Result<String, ClassifiedError> {
    #[derive(Serialize)]
    struct Assumptions<'a> {
        schema_version: u32,
        project_root: &'a str,
        component_root: &'a str,
        build_system: ProfileBuildSystem,
        compile_database_path: &'a str,
        cmake_definitions: &'a BTreeMap<String, String>,
        dependencies: &'a [BuildDependency],
        sandbox_image_tag: &'a str,
        sandbox_image_id: &'a str,
        marker_path: &'a str,
        marker_sha256: &'a str,
    }
    let canonical = serde_json::to_vec(&Assumptions {
        schema_version: 1,
        project_root: &profile.project_root,
        component_root: &profile.component_root,
        build_system: profile.build_system,
        compile_database_path: &profile.compile_database_path,
        cmake_definitions: &profile.cmake_definitions,
        dependencies: &profile.dependencies,
        sandbox_image_tag: &profile.sandbox_image_tag,
        sandbox_image_id: &profile.sandbox_image_id,
        marker_path: &profile.marker_path,
        marker_sha256: &profile.marker_sha256,
    })
    .map_err(|error| ClassifiedError::Internal(format!("serialize build profile: {error}")))?;
    Ok(hex::encode(Sha256::digest(canonical)))
}

/// Check saved assumptions using only files and supplied deployment settings.
///
/// An empty result means marker and configured image tag assumptions match.
/// Nonempty reasons mean `Stale`. Invalid configuration/files return an error.
/// Missing output is accepted; database parsing, probes and live image identity
/// checks belong to the caller. This never executes a command or resolves images.
pub fn check_build_profile(
    profile: &BuildProfileView,
    settings: &BuildProfileSettings,
) -> Result<Vec<String>, ClassifiedError> {
    validate_options(profile.build_system, &profile.cmake_definitions, settings)?;
    validate_saved_profile(profile)?;
    let image = ImmutableImageReference::from_sha256_id(&profile.sandbox_image_id)?;
    let current = normalize_profile(
        &SaveBuildProfileRequest {
            project: profile.project_root.clone(),
            component_root: profile.component_root.clone(),
            build_system: profile.build_system,
            compile_database_path: profile.compile_database_path.clone(),
            cmake_definitions: profile.cmake_definitions.clone(),
            dependencies: profile.dependencies.clone(),
        },
        settings,
        &image,
        profile.updated_at,
    )?;
    if current.project_root != profile.project_root
        || current.component_root != profile.component_root
        || current.compile_database_path != profile.compile_database_path
        || current.dependencies != profile.dependencies
    {
        return Err(invalid("saved build profile is not canonical"));
    }
    let mut reasons = Vec::new();
    if current.marker_path != profile.marker_path || current.marker_sha256 != profile.marker_sha256
    {
        reasons.push("selected build marker changed; review and save the profile".to_owned());
    }
    if current.sandbox_image_tag != profile.sandbox_image_tag {
        reasons
            .push("configured sandbox image tag changed; review and save the profile".to_owned());
    }
    Ok(reasons)
}

fn validate_saved_profile(profile: &BuildProfileView) -> Result<(), ClassifiedError> {
    if profile_digest(profile)? != profile.profile_sha256 {
        return Err(invalid(
            "saved build profile digest does not match its assumptions",
        ));
    }
    validate_profile_evidence_capacity(profile)
}

fn invalid(message: &str) -> ClassifiedError {
    ClassifiedError::Validation(message.to_owned())
}

#[cfg(test)]
mod tests;

impl crate::ServiceContainer {
    /// Read a saved profile through current strict deployment settings.
    ///
    /// Current option allowance and filesystem staleness are assessed by
    /// [`check_build_profile`], so diagnosis and editors can display a saved
    /// profile whose old option is now disallowed or whose marker is missing.
    /// Storage and configuration failures are errors, never optional absence.
    #[tracing::instrument(skip(self))]
    pub async fn build_profile(
        &self,
        project: &Path,
    ) -> Result<Option<BuildProfileView>, ClassifiedError> {
        crate::config::effective_build_profile_settings().map_err(ClassifiedError::Validation)?;
        let root = crate::container::canonical_project_root(project)?;
        let project = root
            .to_str()
            .ok_or_else(|| invalid("project root must be UTF-8"))?;
        let profile = self
            .profile_store()?
            .project_build_profile(project)
            .await
            .map_err(|error| ClassifiedError::Internal(format!("read build profile: {error}")))?;
        if let Some(profile) = &profile {
            validate_saved_profile(profile)?;
        }
        Ok(profile)
    }

    /// Save explicit normalized assumptions with the actual immutable image identity.
    ///
    /// Resolves the sandbox image but runs neither project code nor probes.
    /// The store returns the persisted timestamps, including identical saves.
    #[cfg(feature = "build-doctor")]
    #[tracing::instrument(skip(self, request), fields(project = %request.project))]
    pub async fn save_build_profile(
        &self,
        request: SaveBuildProfileRequest,
    ) -> Result<BuildProfileView, ClassifiedError> {
        let settings = crate::config::effective_build_profile_settings()
            .map_err(ClassifiedError::Validation)?;
        validate_options(request.build_system, &request.cmake_definitions, &settings)?;
        let store = self.profile_store()?;
        let image = self
            .runtime_adapter()
            .resolve_image_reference(hf_runtime::SANDBOX_IMAGE)
            .await?
            .ok_or_else(|| {
                ClassifiedError::Sandbox(
                    "saving a build profile requires an immutable sandbox image identity"
                        .to_owned(),
                )
            })?;
        let profile = normalize_profile(&request, &settings, &image, Utc::now())?;
        store
            .set_project_build_profile(&profile)
            .await
            .map_err(|error| ClassifiedError::Internal(format!("save build profile: {error}")))
    }

    /// Clear the current profile without deleting historical diagnosis evidence.
    ///
    /// Clearing remains possible when the saved marker or option allowance has
    /// changed; only the project identity and storage are needed for removal.
    #[cfg(feature = "build-doctor")]
    #[tracing::instrument(skip(self))]
    pub async fn clear_build_profile(&self, project: &Path) -> Result<(), ClassifiedError> {
        let root = crate::container::canonical_project_root(project)?;
        let project = root
            .to_str()
            .ok_or_else(|| invalid("project root must be UTF-8"))?;
        self.profile_store()?
            .clear_project_build_profile(project)
            .await
            .map_err(|error| ClassifiedError::Internal(format!("clear build profile: {error}")))
    }

    fn profile_store(&self) -> Result<&hf_storage::Store, ClassifiedError> {
        self.store()
            .map(std::convert::AsRef::as_ref)
            .ok_or_else(|| {
                ClassifiedError::Internal("build profile storage is unavailable".to_owned())
            })
    }
}
