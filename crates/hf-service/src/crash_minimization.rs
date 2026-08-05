//! Run-owned crash-minimization staging and publication.

use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{SandboxMount, SandboxOptions};
use uuid::Uuid;

/// Maximum number of native minimizer invocations in one triage pass.
pub(crate) const MAX_CRASH_MINIMIZATIONS: usize = 20;

const MAX_MINIMIZED_CRASH_BYTES: u64 = hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes;

/// A minimization request may be unsupported, already complete, or ready to run.
pub(crate) enum PreparedMinimization {
    Unsupported,
    Complete(PathBuf),
    Run(Box<MinimizationRun>),
}

/// One sandbox command and its unpublished derived output.
pub(crate) struct MinimizationRun {
    pub(crate) command: Vec<String>,
    pub(crate) sandbox: SandboxOptions,
    partial_path: PathBuf,
    final_path: PathBuf,
    published: bool,
}

impl MinimizationRun {
    /// Atomically publish a non-empty, bounded regular output file.
    pub(crate) fn publish(mut self) -> Result<PathBuf, ClassifiedError> {
        validate_output(&self.partial_path)?;
        std::fs::File::open(&self.partial_path)
            .and_then(|file| file.sync_all())
            .map_err(|error| {
                ClassifiedError::Storage(format!(
                    "sync minimized crash {}: {error}",
                    self.partial_path.display()
                ))
            })?;

        if self.final_path.exists() {
            validate_output(&self.final_path)?;
            std::fs::remove_file(&self.partial_path).map_err(|error| {
                ClassifiedError::Storage(format!(
                    "remove redundant minimized crash {}: {error}",
                    self.partial_path.display()
                ))
            })?;
        } else {
            std::fs::rename(&self.partial_path, &self.final_path).map_err(|error| {
                ClassifiedError::Storage(format!(
                    "publish minimized crash {}: {error}",
                    self.final_path.display()
                ))
            })?;
        }
        sync_parent(self.final_path.parent().ok_or_else(|| {
            ClassifiedError::Internal("minimized crash has no parent directory".to_owned())
        })?)?;
        validate_output(&self.final_path)?;
        self.published = true;
        Ok(self.final_path.clone())
    }
}

impl Drop for MinimizationRun {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_file(&self.partial_path);
        }
    }
}

/// Validate exact run-owned inputs and construct an argv-only minimizer command.
pub(crate) fn prepare(
    workspace: &Path,
    run_id: Uuid,
    engine: EngineKind,
    binary: &Path,
    crash_input: &Path,
    crash_id: Uuid,
) -> Result<PreparedMinimization, ClassifiedError> {
    if !matches!(engine, EngineKind::LibFuzzer | EngineKind::AflPlusPlus) {
        return Ok(PreparedMinimization::Unsupported);
    }

    let workspace = canonical_directory(workspace, "workspace")?;
    let run_root = canonical_directory(
        &workspace.join("runs").join(run_id.to_string()),
        "run evidence",
    )?;
    require_below(&workspace, &run_root, "run evidence")?;

    let expected_binary = run_root.join("input").join("harness");
    let binary = canonical_regular_file(binary, "run harness")?;
    if binary != canonical_regular_file(&expected_binary, "run harness")? {
        return Err(ClassifiedError::Validation(format!(
            "crash minimization binary is not owned by run {run_id}"
        )));
    }

    let output_root = canonical_directory(&run_root.join("out"), "run output")?;
    let crash_input = canonical_regular_file(crash_input, "crash input")?;
    require_below(&output_root, &crash_input, "crash input")?;
    let input_size = std::fs::metadata(&crash_input)
        .map_err(|error| {
            ClassifiedError::Validation(format!(
                "inspect crash input {}: {error}",
                crash_input.display()
            ))
        })?
        .len();
    if input_size == 0 || input_size > MAX_MINIMIZED_CRASH_BYTES {
        return Err(ClassifiedError::Validation(format!(
            "crash input must contain 1..={MAX_MINIMIZED_CRASH_BYTES} bytes"
        )));
    }

    let triage = ensure_child_directory(&run_root, "triage")?;
    let minimized = ensure_child_directory(&triage, "minimized")?;
    let final_path = minimized.join(format!("{crash_id}.min"));
    match std::fs::symlink_metadata(&final_path) {
        Ok(_) => {
            validate_output(&final_path)?;
            return Ok(PreparedMinimization::Complete(final_path));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect minimized crash {}: {error}",
                final_path.display()
            )));
        }
    }

    let partial_path = minimized.join(format!(".{crash_id}.{}.partial", Uuid::new_v4()));
    let binary_container = container_path(&workspace, &binary)?;
    let input_container = container_path(&workspace, &crash_input)?;
    let output_container = container_path(&workspace, &partial_path)?;
    let command = hf_crash::build_minimize_args(
        engine,
        &binary_container,
        &input_container,
        &output_container,
    )
    .ok_or_else(|| ClassifiedError::Validation("engine has no crash minimizer".to_owned()))?;
    let minimized_container = container_path(&workspace, &minimized)?;
    Ok(PreparedMinimization::Run(Box::new(MinimizationRun {
        command,
        sandbox: SandboxOptions {
            extra_mounts: vec![SandboxMount::writable(minimized, minimized_container)],
            workspace_read_only: true,
            max_file_size_bytes: Some(MAX_MINIMIZED_CRASH_BYTES),
            ..SandboxOptions::default()
        },
        partial_path,
        final_path,
        published: false,
    })))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!("inspect {label} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "{label} is not a regular directory: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|error| {
        ClassifiedError::Validation(format!("resolve {label} {}: {error}", path.display()))
    })
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!("inspect {label} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(ClassifiedError::Validation(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    std::fs::canonicalize(path).map_err(|error| {
        ClassifiedError::Validation(format!("resolve {label} {}: {error}", path.display()))
    })
}

fn ensure_child_directory(parent: &Path, name: &str) -> Result<PathBuf, ClassifiedError> {
    let candidate = parent.join(name);
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(ClassifiedError::Validation(format!(
                "derived crash path is not a regular directory: {}",
                candidate.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&candidate).map_err(|create_error| {
                ClassifiedError::Storage(format!(
                    "create derived crash directory {}: {create_error}",
                    candidate.display()
                ))
            })?;
        }
        Err(error) => {
            return Err(ClassifiedError::Validation(format!(
                "inspect derived crash directory {}: {error}",
                candidate.display()
            )));
        }
    }
    let resolved = canonical_directory(&candidate, "derived crash directory")?;
    require_below(parent, &resolved, "derived crash directory")?;
    Ok(resolved)
}

fn require_below(root: &Path, path: &Path, label: &str) -> Result<(), ClassifiedError> {
    if path == root || !path.starts_with(root) {
        return Err(ClassifiedError::Validation(format!(
            "{label} escapes its approved root: {}",
            path.display()
        )));
    }
    Ok(())
}

fn container_path(workspace: &Path, host: &Path) -> Result<String, ClassifiedError> {
    let relative = host.strip_prefix(workspace).map_err(|_| {
        ClassifiedError::Validation(format!(
            "minimization path escapes workspace: {}",
            host.display()
        ))
    })?;
    if relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "minimization path is unsafe: {}",
            host.display()
        )));
    }
    Ok(format!(
        "/work/{}",
        hf_core::runtime::posix_relative(relative)
    ))
}

fn validate_output(path: &Path) -> Result<(), ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        ClassifiedError::Validation(format!(
            "inspect minimized crash {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MINIMIZED_CRASH_BYTES
    {
        return Err(ClassifiedError::Validation(format!(
            "minimized crash is not a non-empty bounded regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn sync_parent(parent: &Path) -> Result<(), ClassifiedError> {
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            ClassifiedError::Storage(format!(
                "sync minimized crash directory {}: {error}",
                parent.display()
            ))
        })
}
