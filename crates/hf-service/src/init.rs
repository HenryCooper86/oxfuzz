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
    // 1. Explicit override (e.g. set by the desktop shell or for tests).
    if let Some(dir) = std::env::var_os("HF_CONFIG_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    // 2. Source checkout: keep config next to the tree for `cargo run`/CLI dev.
    if let Some(root) = repo_root() {
        return root.join("config");
    }
    // 3. Installed app: a writable per-user directory. We must NOT fall back to
    //    `current_dir()/config` -- a Finder-launched .app has cwd `/`, so that
    //    resolves to `/config` on the read-only system volume and every write
    //    fails with EROFS (os error 30).
    user_app_dir().join("config")
}

/// A writable, per-user application directory used when not running from a
/// source checkout. Platform conventions:
/// - macOS:   `~/Library/Application Support/hobot_fuzz`
/// - Linux:   `$XDG_DATA_HOME/hobot_fuzz` or `~/.local/share/hobot_fuzz`
/// - Windows: `%APPDATA%\hobot_fuzz`
///
/// Falls back to a temp directory so writes always land on a writable volume.
#[must_use]
pub fn user_app_dir() -> PathBuf {
    let candidate =
        platform_user_app_dir().unwrap_or_else(|| std::env::temp_dir().join("hobot_fuzz"));
    writable_or_temp(candidate)
}

fn platform_user_app_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("hobot_fuzz"),
        );
    }
    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return Some(PathBuf::from(appdata).join("hobot_fuzz"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join("hobot_fuzz"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("hobot_fuzz"),
            );
        }
    }
    None
}

fn writable_or_temp(candidate: PathBuf) -> PathBuf {
    if writable_dir(&candidate) {
        candidate
    } else {
        std::env::temp_dir().join("hobot_fuzz")
    }
}

pub(crate) fn writable_dir(path: &Path) -> bool {
    if std::fs::create_dir_all(path).is_err() {
        return false;
    }

    let probe = path.join(format!(".write-probe-{}", uuid::Uuid::new_v4()));
    match std::fs::create_dir(&probe) {
        Ok(()) => {
            let _ = std::fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolve the database path the same way [`Store::connect_from_env`] does.
fn db_path() -> PathBuf {
    PathBuf::from(std::env::var("HF_DB_PATH").unwrap_or_else(|_| "data/hobot_fuzz.db".to_owned()))
}

/// Initialize a workspace: materialize any missing config files from their
/// `*.example.toml` templates and create + migrate the database.
///
/// Idempotent: existing config contents are left untouched. On Unix, private
/// config permissions are tightened to owner-only on every initialization.
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
        if crate::config::copy_private_config_if_missing(&entry.path(), &target)
            .map_err(|e| ClassifiedError::Internal(format!("create {name}: {e}")))?
        {
            created.push(format!("{stem}.toml"));
        }
    }
    crate::config::secure_config_directory(config_dir)
        .map_err(|error| ClassifiedError::Internal(format!("secure configs: {error}")))?;

    // Connect (creating + migrating) the database.
    let _store = Store::connect(db_path).await?;

    Ok(InitReport {
        config_dir: config_dir.to_path_buf(),
        created_configs: created,
        db_path: db_path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writable_or_temp_keeps_writable_directory() {
        let dir = tempfile::tempdir().unwrap();

        assert_eq!(writable_or_temp(dir.path().to_path_buf()), dir.path());
    }

    #[test]
    fn writable_or_temp_falls_back_when_candidate_is_not_a_directory() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let resolved = writable_or_temp(file.path().to_path_buf());

        assert_eq!(resolved, std::env::temp_dir().join("hobot_fuzz"));
    }
}
