//! Application state managed by Tauri.

use std::path::PathBuf;

use hf_service::ServiceContainer;

/// Shared application state injected into every Tauri command handler.
pub struct AppState {
    /// The service container holding all wired domain services.
    pub container: ServiceContainer,
    /// Path to the repo root (for config + Dockerfile discovery).
    #[allow(dead_code)]
    pub repo_root: Option<PathBuf>,
}

impl AppState {
    /// Create a new `AppState`.
    #[must_use]
    pub fn new(container: ServiceContainer) -> Self {
        Self {
            container,
            repo_root: hf_service::repo_root(),
        }
    }
}

/// Resolve the `config/` directory next to the repo root (or CWD).
#[must_use]
pub fn config_dir() -> PathBuf {
    hf_service::repo_root().map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("config")
        },
        |r| r.join("config"),
    )
}
