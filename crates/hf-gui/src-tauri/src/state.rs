//! Application state managed by Tauri.

use std::collections::HashMap;
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

    /// Await the user's decision for a registered request, denying (and dropping
    /// the stale entry) if it is not answered within `timeout`.
    ///
    /// Without this bound an unanswered request blocks the agent turn forever:
    /// the only frontend listener lives in the Chat view, so navigating away
    /// while an approval is pending would leave `request_approval` awaiting a
    /// receiver that is never resolved. Timing out fails safe (denied) and frees
    /// the turn and its held guardrails/container.
    pub async fn await_decision(
        &self,
        id: Uuid,
        rx: oneshot::Receiver<bool>,
        timeout: std::time::Duration,
    ) -> bool {
        if let Ok(Ok(approved)) = tokio::time::timeout(timeout, rx).await {
            approved
        } else {
            // Timed out, or the sender was dropped: remove any lingering entry
            // and deny by default.
            self.inner.lock().await.remove(&id);
            false
        }
    }
}

/// Shared application state injected into every Tauri command handler.
pub struct AppState {
    /// The service container holding all wired domain services.
    pub container: ServiceContainer,
    /// In-flight HITL approval requests awaiting a user decision.
    pub pending_approvals: Arc<PendingApprovals>,
    /// Background scheduler driving recurring/one-time fuzz campaigns.
    pub scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
}

impl AppState {
    /// Create a new `AppState`.
    #[must_use]
    pub fn new(
        container: ServiceContainer,
        scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
    ) -> Self {
        Self {
            container,
            pending_approvals: Arc::new(PendingApprovals::default()),
            scheduler,
        }
    }
}

#[cfg(test)]
mod pending_approval_tests {
    use super::PendingApprovals;
    use std::time::Duration;
    use uuid::Uuid;

    #[tokio::test]
    async fn await_decision_returns_the_users_answer() {
        let pending = PendingApprovals::default();
        let id = Uuid::new_v4();
        let rx = pending.register(id).await;
        assert!(pending.resolve(id, true).await);
        assert!(pending.await_decision(id, rx, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn await_decision_denies_and_cleans_up_on_timeout() {
        let pending = PendingApprovals::default();
        let id = Uuid::new_v4();
        let rx = pending.register(id).await;
        // Nobody resolves it (user navigated away): the wait must not hang.
        assert!(
            !pending
                .await_decision(id, rx, Duration::from_millis(20))
                .await,
            "an unanswered request must deny on timeout"
        );
        // The stale entry is gone, so a late answer finds nothing pending.
        assert!(
            !pending.resolve(id, true).await,
            "the timed-out request must have been removed"
        );
    }
}
