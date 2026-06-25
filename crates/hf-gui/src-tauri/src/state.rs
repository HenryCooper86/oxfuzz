//! Application state managed by Tauri.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use hf_service::ServiceContainer;
use tokio::sync::{oneshot, Mutex};
use uuid::Uuid;

/// A registry of in-flight human-in-the-loop approval requests.
///
/// The guardrail gate registers a request (emitting `chat:permission_request`)
/// and awaits the receiver; the `chat_answer_permission` command resolves it.
#[derive(Default)]
pub struct PendingApprovals {
    inner: Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
}

impl PendingApprovals {
    /// Register a new pending request and return the receiver to await on.
    pub async fn register(&self, id: Uuid) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().await.insert(id, tx);
        rx
    }

    /// Resolve a pending request with the user's decision. Returns `true` if a
    /// matching request was waiting.
    pub async fn resolve(&self, id: Uuid, approved: bool) -> bool {
        if let Some(tx) = self.inner.lock().await.remove(&id) {
            let _ = tx.send(approved);
            true
        } else {
            false
        }
    }
}

/// Shared application state injected into every Tauri command handler.
pub struct AppState {
    /// The service container holding all wired domain services.
    pub container: ServiceContainer,
    /// Path to the repo root (for config + Dockerfile discovery).
    #[allow(dead_code)]
    pub repo_root: Option<PathBuf>,
    /// In-flight HITL approval requests awaiting a user decision.
    pub pending_approvals: Arc<PendingApprovals>,
}

impl AppState {
    /// Create a new `AppState`.
    #[must_use]
    pub fn new(container: ServiceContainer) -> Self {
        Self {
            container,
            repo_root: hf_service::repo_root(),
            pending_approvals: Arc::new(PendingApprovals::default()),
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
