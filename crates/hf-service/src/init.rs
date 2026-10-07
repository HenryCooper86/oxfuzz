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
/// - macOS:   `~/Library/Application Support/oxfuzz`
/// - Linux:   `$XDG_DATA_HOME/oxfuzz` or `~/.local/share/oxfuzz`
/// - Windows: `%APPDATA%\oxfuzz`
///
/// Falls back to a temp directory so writes always land on a writable volume.
#[must_use]
pub fn user_app_dir() -> PathBuf {
    let candidate = platform_user_app_dir().unwrap_or_else(|| std::env::temp_dir().join("oxfuzz"));
    writable_or_temp(candidate)
}

fn platform_user_app_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return Some(
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("oxfuzz"),
        );
    }
    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return Some(PathBuf::from(appdata).join("oxfuzz"));
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join("oxfuzz"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("oxfuzz"),
            );
        }
    }
    None
}

fn writable_or_temp(candidate: PathBuf) -> PathBuf {
    if writable_dir(&candidate) {
        candidate
    } else {
        std::env::temp_dir().join("oxfuzz")
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
    PathBuf::from(std::env::var("HF_DB_PATH").unwrap_or_else(|_| "data/oxfuzz.db".to_owned()))
}

/// Config templates compiled into the binary, one per [`CONFIG_SECTIONS`] entry.
///
/// An installed binary ships no repository `config/` tree, so `init` cannot copy
/// a template it cannot find. The repository `config/*.example.toml` files stay
/// the single source of truth -- these are read at build time -- and an on-disk
/// template still wins at runtime, so a developer editing the repository copy
/// sees that edit.
///
/// [`CONFIG_SECTIONS`]: crate::config::CONFIG_SECTIONS
const EMBEDDED_TEMPLATES: &[(&str, &str)] = &[
    (
        "oxfuzz",
        include_str!("../../../config/oxfuzz.example.toml"),
    ),
    (
        "providers",
        include_str!("../../../config/providers.example.toml"),
    ),
    (
        "defectdojo",
        include_str!("../../../config/defectdojo.example.toml"),
    ),
    (
        "issue_tracker",
        include_str!("../../../config/issue_tracker.example.toml"),
    ),
];

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
    for section in crate::config::CONFIG_SECTIONS {
        let Some((_, embedded)) = EMBEDDED_TEMPLATES.iter().find(|(name, _)| name == section)
        else {
            return Err(ClassifiedError::Internal(format!(
                "no embedded template for config section {section}"
            )));
        };
        let template = config_dir.join(format!("{section}.example.toml"));
        let target = config_dir.join(format!("{section}.toml"));
        // A source checkout keeps its templates on disk, so a local edit is
        // honored; an installed binary has none and uses the embedded copy.
        let written = if template.is_file() {
            crate::config::copy_private_config_if_missing(&template, &target)
        } else {
            crate::config::write_private_config_if_missing(embedded, &target)
        }
        .map_err(|e| ClassifiedError::Internal(format!("create {section}.toml: {e}")))?;
        if written {
            created.push(format!("{section}.toml"));
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

        assert_eq!(resolved, std::env::temp_dir().join("oxfuzz"));
    }

    #[tokio::test]
    async fn init_ignores_templates_for_unsupported_config_sections() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let database = dir.path().join("data.db");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("providers.example.toml"),
            "providers = []\n",
        )
        .unwrap();
        std::fs::write(config_dir.join("session.example.toml"), "max_depth = 10\n").unwrap();

        let report = init_at(&config_dir, &database).await.unwrap();

        // Every declared section is materialized even though the on-disk
        // template set covers only one of them, and the stray template is not a
        // declared section so it is never materialized.
        let expected: Vec<String> = crate::config::CONFIG_SECTIONS
            .iter()
            .map(|section| format!("{section}.toml"))
            .collect();
        assert_eq!(report.created_configs, expected);
        assert!(config_dir.join("providers.toml").is_file());
        assert!(!config_dir.join("session.toml").exists());
    }

    #[tokio::test]
    async fn init_prefers_an_on_disk_template_over_the_embedded_copy() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let database = dir.path().join("data.db");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("providers.example.toml"), "local = true\n").unwrap();

        init_at(&config_dir, &database).await.unwrap();

        assert_eq!(
            std::fs::read_to_string(config_dir.join("providers.toml")).unwrap(),
            "local = true\n"
        );
    }

    #[test]
    fn embedded_templates_cover_exactly_the_declared_config_sections() {
        let embedded: Vec<&str> = EMBEDDED_TEMPLATES.iter().map(|(name, _)| *name).collect();

        assert_eq!(embedded, crate::config::CONFIG_SECTIONS);
        for (section, template) in EMBEDDED_TEMPLATES {
            assert!(
                !template.trim().is_empty(),
                "section {section} has an empty embedded template"
            );
        }
    }

    #[tokio::test]
    async fn init_materializes_embedded_templates_when_the_directory_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        let database = dir.path().join("data.db");
        assert!(!config_dir.exists());

        let report = init_at(&config_dir, &database).await.unwrap();

        // An installed binary has no `config/` tree to copy from, so an empty
        // directory must still yield every declared section.
        let expected: Vec<String> = crate::config::CONFIG_SECTIONS
            .iter()
            .map(|section| format!("{section}.toml"))
            .collect();
        assert_eq!(report.created_configs, expected);
        for (section, template) in EMBEDDED_TEMPLATES {
            assert_eq!(
                std::fs::read_to_string(config_dir.join(format!("{section}.toml"))).unwrap(),
                *template,
                "section {section} must match the repository template"
            );
        }
    }
}
