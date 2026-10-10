//! Workspace initialization: scaffold config + database.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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

/// Which source supplied the effective config directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigDirSource {
    /// The `--config <dir>` global CLI flag.
    CliFlag,
    /// The `HF_CONFIG_DIR` environment variable.
    Environment,
    /// The per-user config dir (`user_app_dir()/config`), used because it holds
    /// at least one live `<section>.toml`.
    UserConfig,
    /// The legacy walk-up from the current directory / executable path that
    /// found a source checkout (`Cargo.toml` + `config/`).
    SourceCheckout,
    /// The per-user config dir as the last-resort default (nothing live yet).
    UserConfigDefault,
}

/// The effective config directory plus how it was chosen.
///
/// `warning` is set when an implicit source shadowed another candidate (a
/// source checkout bound instead of the per-user config, or a live per-user
/// config shadowing a discovered checkout): a presentation layer with a
/// terminal should print it so the binding is never silent. Explicit sources
/// never warn -- the operator already said what they meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDirResolution {
    /// The effective config directory.
    pub dir: PathBuf,
    /// Which source supplied it.
    pub source: ConfigDirSource,
    /// A one-line operator note when an implicit source shadowed a candidate.
    pub warning: Option<String>,
}

/// The CLI's `--config <dir>` value, installed once by the CLI entry point
/// before dispatch. Only the CLI has argv, so only it can set this; the GUI
/// pins `HF_CONFIG_DIR` instead.
static CLI_CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Install the CLI's `--config <dir>` override for this process.
///
/// # Errors
/// Returns `ClassifiedError::Internal` when called twice (a CLI programming
/// error, not an operator one).
pub fn set_cli_config_dir(dir: PathBuf) -> Result<(), ClassifiedError> {
    CLI_CONFIG_DIR.set(dir).map_err(|_| {
        ClassifiedError::Internal("--config may only be installed once per process".to_owned())
    })
}

/// An explicit (flag/env) config directory must name a directory or a path
/// that does not exist yet. A missing directory is accepted: `init` and
/// bootstrap create it on demand, which is exactly what the test isolation
/// pattern and first-run flows rely on. An existing non-directory is a
/// misconfiguration and must error rather than degrade into confusing I/O
/// failures or silently fall through to a lower-precedence source
/// (Engineering Protocol 2.16).
fn validate_explicit_config_dir(dir: &Path, source: &str) -> Result<(), ClassifiedError> {
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(ClassifiedError::Validation(format!(
            "{source} points at '{}', which is not a directory",
            dir.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ClassifiedError::Validation(format!(
            "{source} points at '{}', which cannot be inspected: {error}",
            dir.display()
        ))),
    }
}

/// Resolve the config directory from explicit candidates, in precedence
/// order: `--config`, `HF_CONFIG_DIR`, a per-user config dir that holds live
/// config files, a source-checkout walk-up (with a warning), and finally the
/// per-user config dir as the default.
///
/// `user_config_live` is whether `user_config_dir` holds at least one live
/// `<section>.toml`: bare existence is not enough because bootstrap creates
/// the directory on every run, and an empty directory must not shadow the
/// source-checkout dev flow. `source_checkout` is the walk-up's config dir
/// (`<root>/config`), when a checkout was found.
fn resolve_config_dir(
    cli_flag: Option<PathBuf>,
    environment: Option<PathBuf>,
    user_config_dir: PathBuf,
    user_config_live: bool,
    source_checkout: Option<PathBuf>,
) -> Result<ConfigDirResolution, ClassifiedError> {
    if let Some(dir) = cli_flag {
        validate_explicit_config_dir(&dir, "--config")?;
        return Ok(ConfigDirResolution {
            dir,
            source: ConfigDirSource::CliFlag,
            warning: None,
        });
    }
    if let Some(dir) = environment {
        validate_explicit_config_dir(&dir, "HF_CONFIG_DIR")?;
        return Ok(ConfigDirResolution {
            dir,
            source: ConfigDirSource::Environment,
            warning: None,
        });
    }
    if user_config_live {
        let warning = source_checkout
            .filter(|checkout| *checkout != user_config_dir)
            .map(|checkout| {
                format!(
                    "config directory '{}' (per-user) shadows the source tree config at '{}'; set HF_CONFIG_DIR to pin one explicitly",
                    user_config_dir.display(),
                    checkout.display()
                )
            });
        return Ok(ConfigDirResolution {
            dir: user_config_dir,
            source: ConfigDirSource::UserConfig,
            warning,
        });
    }
    if let Some(dir) = source_checkout {
        let warning = (dir != user_config_dir).then(|| {
            format!(
                "config directory '{}' comes from the source tree discovered above the current directory or executable; set HF_CONFIG_DIR to pin one explicitly",
                dir.display()
            )
        });
        return Ok(ConfigDirResolution {
            dir,
            source: ConfigDirSource::SourceCheckout,
            warning,
        });
    }
    Ok(ConfigDirResolution {
        dir: user_config_dir,
        source: ConfigDirSource::UserConfigDefault,
        warning: None,
    })
}

/// Resolve the effective config directory for this process, applying the
/// documented precedence over the real environment: the CLI's `--config`
/// override, `HF_CONFIG_DIR`, a live per-user config dir, the source-checkout
/// walk-up, and the per-user default.
///
/// # Errors
/// Returns `ClassifiedError::Validation` when an explicit source
/// (`--config`/`HF_CONFIG_DIR`) names an existing path that is not a
/// directory, or one that cannot be inspected.
pub fn config_resolution() -> Result<ConfigDirResolution, ClassifiedError> {
    let cli_flag = CLI_CONFIG_DIR.get().cloned();
    let environment = std::env::var_os("HF_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let user_config_dir = user_app_dir().join("config");
    let user_config_live = crate::config::CONFIG_SECTIONS
        .iter()
        .any(|section| user_config_dir.join(format!("{section}.toml")).is_file());
    let source_checkout = repo_root().map(|root| root.join("config"));
    resolve_config_dir(
        cli_flag,
        environment,
        user_config_dir,
        user_config_live,
        source_checkout,
    )
}

/// The effective config directory (see [`config_resolution`] for the
/// precedence order).
///
/// Presentation layers validate the resolution at startup
/// (`config_resolution()` in the CLI entry point and the desktop shell), so an
/// invalid explicit source fails before any command runs.
///
/// # Panics
/// Panics when an explicit source (`--config`/`HF_CONFIG_DIR`) names an
/// invalid directory and the caller skipped startup validation. This is the
/// fail-closed backstop: a misconfigured explicit override must never be
/// silently ignored (Engineering Protocol 2.16).
#[must_use]
pub fn config_dir() -> PathBuf {
    config_resolution()
        .unwrap_or_else(|error| panic!("{error}"))
        .dir
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
/// Config files land in the resolved config directory ([`config_resolution`]):
/// `--config`/`HF_CONFIG_DIR` when set, else a live per-user config dir, else
/// the source-checkout walk-up, else the per-user default (created here).
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

    /// The precedence resolver is exercised with injected candidates so the
    /// rules are tested without mutating process-global environment.
    mod config_resolution {
        use super::super::*;
        use std::path::PathBuf;

        fn user_dir() -> PathBuf {
            PathBuf::from("/user/config")
        }

        fn checkout_dir() -> PathBuf {
            PathBuf::from("/foreign-tree/config")
        }

        #[test]
        fn cli_flag_wins_over_every_other_source() {
            let resolution = resolve_config_dir(
                Some(PathBuf::from("/flag/config")),
                Some(PathBuf::from("/env/config")),
                user_dir(),
                true,
                Some(checkout_dir()),
            )
            .unwrap();

            assert_eq!(resolution.dir, PathBuf::from("/flag/config"));
            assert_eq!(resolution.source, ConfigDirSource::CliFlag);
            assert_eq!(resolution.warning, None);
        }

        #[test]
        fn environment_wins_over_user_config_and_checkout() {
            let resolution = resolve_config_dir(
                None,
                Some(PathBuf::from("/env/config")),
                user_dir(),
                true,
                Some(checkout_dir()),
            )
            .unwrap();

            assert_eq!(resolution.dir, PathBuf::from("/env/config"));
            assert_eq!(resolution.source, ConfigDirSource::Environment);
            assert_eq!(resolution.warning, None);
        }

        #[test]
        fn a_live_user_config_dir_wins_over_a_source_checkout_and_says_so() {
            let resolution =
                resolve_config_dir(None, None, user_dir(), true, Some(checkout_dir())).unwrap();

            assert_eq!(resolution.dir, user_dir());
            assert_eq!(resolution.source, ConfigDirSource::UserConfig);
            let warning = resolution.warning.expect("shadowing must be named");
            assert!(warning.contains("/user/config"), "{warning}");
            assert!(warning.contains("/foreign-tree/config"), "{warning}");
            assert!(warning.contains("HF_CONFIG_DIR"), "{warning}");
        }

        #[test]
        fn a_user_config_dir_without_live_files_does_not_shadow_a_checkout() {
            let resolution =
                resolve_config_dir(None, None, user_dir(), false, Some(checkout_dir())).unwrap();

            assert_eq!(resolution.dir, checkout_dir());
            assert_eq!(resolution.source, ConfigDirSource::SourceCheckout);
        }

        #[test]
        fn the_checkout_fallback_warns_with_the_dir_and_the_override() {
            let resolution =
                resolve_config_dir(None, None, user_dir(), false, Some(checkout_dir())).unwrap();

            let warning = resolution.warning.expect("the walk-up fallback must warn");
            assert!(warning.contains("/foreign-tree/config"), "{warning}");
            assert!(warning.contains("HF_CONFIG_DIR"), "{warning}");
            assert_eq!(warning.lines().count(), 1, "one line: {warning}");
        }

        #[test]
        fn without_any_candidate_the_user_config_dir_is_the_default() {
            let resolution = resolve_config_dir(None, None, user_dir(), false, None).unwrap();

            assert_eq!(resolution.dir, user_dir());
            assert_eq!(resolution.source, ConfigDirSource::UserConfigDefault);
            assert_eq!(resolution.warning, None);
        }

        #[test]
        fn a_checkout_identical_to_the_user_config_dir_needs_no_warning() {
            let resolution =
                resolve_config_dir(None, None, user_dir(), false, Some(user_dir())).unwrap();

            assert_eq!(resolution.source, ConfigDirSource::SourceCheckout);
            assert_eq!(resolution.warning, None);
        }

        #[test]
        fn an_explicit_source_naming_a_regular_file_is_rejected() {
            let file = tempfile::NamedTempFile::new().unwrap();
            let path = file.path().to_path_buf();

            let flag_error =
                resolve_config_dir(Some(path.clone()), None, user_dir(), false, None).unwrap_err();
            assert!(flag_error.to_string().contains("--config"), "{flag_error}");
            assert!(
                flag_error.to_string().contains("not a directory"),
                "{flag_error}"
            );

            let env_error =
                resolve_config_dir(None, Some(path), user_dir(), false, None).unwrap_err();
            assert!(
                env_error.to_string().contains("HF_CONFIG_DIR"),
                "{env_error}"
            );
            assert!(
                env_error.to_string().contains("not a directory"),
                "{env_error}"
            );
        }

        #[test]
        fn an_explicit_source_naming_a_missing_directory_is_accepted() {
            // Created on demand by `init`/bootstrap; the binary-test isolation
            // pattern relies on pointing HF_CONFIG_DIR at a fresh temp path.
            let missing =
                std::env::temp_dir().join(format!("oxfuzz-absent-{}", uuid::Uuid::new_v4()));

            for (flag, env) in [(Some(missing.clone()), None), (None, Some(missing.clone()))] {
                let resolution = resolve_config_dir(flag, env, user_dir(), false, None).unwrap();
                assert_eq!(resolution.dir, missing);
            }
        }
    }
}
