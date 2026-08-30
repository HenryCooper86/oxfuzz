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
const COMPILE_DATABASE_PATHS: [&str; 4] = [
    "compile_commands.json",
    "build/compile_commands.json",
    "out/compile_commands.json",
    // Written by an approved Build Doctor plan run.
    ".oxfuzz-build/compile_commands.json",
];

/// Cap on the compile database read. A real database for a large project runs to
/// a few megabytes; past this it is not one, and the file sits inside an
/// untrusted project.
const MAX_COMPILE_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

/// Resolve the first configured compile database into validated build context.
///
/// # Errors
/// Returns a validation error when a present database is malformed, unsafe, or
/// unreadable.
pub(crate) fn resolve_project_build_context(
    project: &Path,
) -> Result<Option<BuildContext>, ClassifiedError> {
    let Some(path) = COMPILE_DATABASE_PATHS
        .iter()
        .map(|relative| project.join(relative))
        .find(|candidate| std::fs::symlink_metadata(candidate).is_ok())
    else {
        return Ok(None);
    };

    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
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

    let json = std::fs::read_to_string(&path).map_err(|error| {
        ClassifiedError::Validation(format!("read compile database {}: {error}", path.display()))
    })?;
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
    if context.is_empty() {
        tracing::debug!(
            database = %path.display(),
            entries = context.entry_count,
            "compile database carried nothing usable for a harness build"
        );
        return Ok(None);
    }
    Ok(Some(context))
}

impl ServiceContainer {
    /// Resolve the project's compile database, if it ships one, into validated
    /// compile context.
    ///
    /// Returns `Ok(None)` when no database is present, and also when one parsed
    /// cleanly but yielded no include directory, define, standard, or flag:
    /// both leave nothing for the compiler or the harness prompt to use, so
    /// callers treat them the same.
    ///
    /// Executes nothing and needs no separate authorization: it reads one file
    /// inside a project the caller has already been authorized to build.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when a database exists but cannot
    /// be read or parsed. A present-but-broken database is a configuration
    /// fault the operator must see, not something to silently ignore.
    pub fn resolve_build_context(
        &self,
        project: &Path,
    ) -> Result<Option<BuildContext>, ClassifiedError> {
        resolve_project_build_context(project)
    }
}
