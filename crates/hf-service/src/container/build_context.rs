//! Resolving a project's compile database into validated compile context.
//!
//! A C/C++ project that ships a `compile_commands.json` states exactly which
//! include directories, defines, and language standard its sources need. Reading
//! it costs one file read and removes the largest source of first-draft harness
//! build failures, which are otherwise paid for in LLM repair rounds.
//!
//! Only an existing database is consumed. Generating one means running the
//! project's own build system, which is untrusted execution and belongs behind
//! `hf-runtime` and a guardrail action rather than here.

use std::path::Path;

use hf_core::build::BuildContext;
use hf_core::error::ClassifiedError;

use super::ServiceContainer;

/// Where a compile database is looked for, in order. The project root is the
/// conventional location; `CMake` and Bear commonly write into a build tree, and
/// an approved Build Doctor plan writes into the oxfuzz-owned build directory.
pub(super) const COMPILE_DATABASE_PATHS: [&str; 4] = [
    "compile_commands.json",
    "build/compile_commands.json",
    "out/compile_commands.json",
    // Written by an approved Build Doctor plan run.
    ".oxfuzz-build/compile_commands.json",
];

/// Shared cap for compile database reads and normalized publication.
pub(crate) const MAX_COMPILE_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

/// Resolve the first configured compile database into validated build context.
///
/// # Errors
/// Returns a validation error when a present database is malformed, unsafe, or
/// unreadable.
pub(crate) fn resolve_project_build_context(
    project: &Path,
) -> Result<Option<BuildContext>, ClassifiedError> {
    for relative in COMPILE_DATABASE_PATHS {
        let path = project.join(relative);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return read_compile_database(&path, project),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect compile database: {error}"
                )))
            }
        }
    }
    Ok(None)
}

/// Parse one selected database without falling back to another location.
pub(crate) fn read_compile_database(
    path: &Path,
    project: &Path,
) -> Result<Option<BuildContext>, ClassifiedError> {
    let context = parse_build_context(path, project)?;
    Ok((!context.is_empty()).then_some(context))
}

/// Read a bounded regular database once, preserving exact UTF-8 bytes.
pub(crate) fn read_compile_database_text(path: &Path) -> Result<String, ClassifiedError> {
    String::from_utf8(read_bounded_build_bytes(path)?).map_err(|error| {
        ClassifiedError::Validation(format!("read compile database UTF-8: {error}"))
    })
}

/// Read one bounded regular build input while retaining its exact bytes.
pub(crate) fn read_bounded_build_bytes(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    use std::io::Read as _;
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect compile database {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(format!(
            "compile database is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > MAX_COMPILE_DATABASE_BYTES {
        return Err(ClassifiedError::Validation(format!(
            "compile database {} exceeds {MAX_COMPILE_DATABASE_BYTES} bytes",
            path.display()
        )));
    }

    let file = std::fs::File::open(path)
        .map_err(|error| ClassifiedError::Validation(format!("open compile database: {error}")))?;
    let opened = file.metadata().map_err(|error| {
        ClassifiedError::Validation(format!("inspect opened compile database: {error}"))
    })?;
    if !opened.is_file() || opened.len() > MAX_COMPILE_DATABASE_BYTES {
        return Err(ClassifiedError::Validation(
            "compile database is not a bounded regular file".into(),
        ));
    }
    let mut json = Vec::new();
    file.take(MAX_COMPILE_DATABASE_BYTES + 1)
        .read_to_end(&mut json)
        .map_err(|error| ClassifiedError::Validation(format!("read compile database: {error}")))?;
    if json.len() as u64 > MAX_COMPILE_DATABASE_BYTES {
        return Err(ClassifiedError::Validation(
            "compile database exceeds 64 MiB".into(),
        ));
    }
    Ok(json)
}

fn parse_build_context(path: &Path, project: &Path) -> Result<BuildContext, ClassifiedError> {
    let json = read_compile_database_text(path)?;
    let entries = hf_discovery::build_context::parse_compile_database(&json)
        .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
    let context = hf_discovery::build_context::extract_build_context(&entries, project);

    if !context.dropped.is_empty() {
        tracing::info!(
            database = %path.display(),
            dropped = ?context.dropped,
            "compile database flags outside the allowlist were not replayed"
        );
    }
    Ok(context)
}

impl ServiceContainer {
    /// Resolve the project's compile database, if it ships one, into validated
    /// compile context.
    ///
    /// Unconfigured projects keep the four-location search and return `None`
    /// for a missing database or one yielding no extra flags. A saved profile
    /// selects only its configured database, accepting a nonempty parsed entry
    /// list even when the replayed extra-flag vector is empty.
    ///
    /// Executes nothing and needs no separate authorization: it reads one file
    /// inside a project the caller has already been authorized to build.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when a database exists but cannot
    /// be read or parsed. A present-but-broken database is a configuration
    /// fault the operator must see, not something to silently ignore.
    pub async fn resolve_build_context(
        &self,
        project: &Path,
    ) -> Result<Option<BuildContext>, ClassifiedError> {
        if self.persistence_availability() == super::PersistenceAvailability::NotConfigured {
            return resolve_project_build_context(project);
        }
        let root = super::canonical_project_root(project)?;
        if let Some(profile) = self.build_profile(&root).await? {
            let settings = crate::config::effective_build_profile_settings()
                .map_err(ClassifiedError::Validation)?;
            let stale = crate::build_profiles::check_build_profile(&profile, &settings)?;
            if !stale.is_empty() {
                return Err(ClassifiedError::Validation(format!(
                    "saved build profile is stale: {}",
                    stale.join("; ")
                )));
            }
            return resolve_profile_build_context(&profile);
        }
        resolve_project_build_context(&root)
    }
}

/// Read exactly the configured output, allowing absent output ancestors.
pub(crate) fn resolve_profile_build_context(
    profile: &crate::BuildProfileView,
) -> Result<Option<BuildContext>, ClassifiedError> {
    let root = Path::new(&profile.project_root);
    let path = crate::build_profiles::validate_project_path(
        root,
        &profile.compile_database_path,
        false,
        true,
    )?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ClassifiedError::Validation(format!(
            "inspect configured compile database: {error}"
        ))),
        Ok(_) => {
            let context = parse_build_context(&path, root)?;
            if context.entry_count == 0 {
                return Err(ClassifiedError::Validation(
                    "configured compile database contains no entries".into(),
                ));
            }
            Ok(Some(context))
        }
    }
}
