//! Workspace initialization: scaffold config + database.

use std::path::{Path, PathBuf};

use hf_core::error::ClassifiedError;

use crate::container::repo_root;
use hf_storage::Store;

/// A summary of what `init` created.
#[derive(Debug, Clone, Default)]
pub struct InitReport {
    /// The resolved config directory.
    pub config_dir: PathBuf,
    /// Config files materialized from `*.example.toml` templates this run.
    pub created_configs: Vec<String>,
    /// The database path.
    pub db_path: PathBuf,
}

/// Resolve the config directory: `<repo>/config`, else `./config`.
#[must_use]
pub fn config_dir() -> PathBuf {
    repo_root().map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("config")
        },
        |r| r.join("config"),
    )
}

/// Resolve the database path the same way [`Store::connect_from_env`] does.
fn db_path() -> PathBuf {
    PathBuf::from(std::env::var("HF_DB_PATH").unwrap_or_else(|_| "data/hobot_fuzz.db".to_owned()))
}

/// Initialize a workspace: materialize any missing config files from their
/// `*.example.toml` templates and create + migrate the database.
///
/// Idempotent: existing config files are left untouched.
///
/// # Errors
/// Returns `ClassifiedError` if the config directory cannot be read or the
/// database cannot be created.
pub async fn init_workspace() -> Result<InitReport, ClassifiedError> {
    init_at(&config_dir(), &db_path()).await
}

/// Initialize a workspace at explicit paths (the testable core of
/// [`init_workspace`]).
///
/// # Errors
/// See [`init_workspace`].
pub async fn init_at(config_dir: &Path, db_path: &Path) -> Result<InitReport, ClassifiedError> {
    std::fs::create_dir_all(config_dir)
        .map_err(|e| ClassifiedError::Internal(format!("create config dir: {e}")))?;

    let mut created = Vec::new();
    let entries = std::fs::read_dir(config_dir)
        .map_err(|e| ClassifiedError::Internal(format!("read config dir: {e}")))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(stem) = name.strip_suffix(".example.toml") else {
            continue;
        };
        let target = config_dir.join(format!("{stem}.toml"));
        if !target.exists() {
            std::fs::copy(entry.path(), &target)
                .map_err(|e| ClassifiedError::Internal(format!("copy {name}: {e}")))?;
            created.push(format!("{stem}.toml"));
        }
    }

    // Connect (creating + migrating) the database.
    let _store = Store::connect(db_path).await?;

    Ok(InitReport {
        config_dir: config_dir.to_path_buf(),
        created_configs: created,
        db_path: db_path.to_path_buf(),
    })
}
