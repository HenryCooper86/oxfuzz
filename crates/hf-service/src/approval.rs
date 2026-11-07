//! Interactive human-in-the-loop approval, shared by every presentation layer
//! that asks a person rather than a terminal or an environment flag.
//!
//! The gate registers each request in [`PendingApprovals`], announces it
//! through an [`ApprovalNotifier`] (a Tauri event in the desktop shell, an SSE
//! event in the web server), and waits for [`PendingApprovals::resolve`] or the
//! timeout. Whatever ends the wait -- an answer, the timeout, or the waiting
//! future being dropped because its chat turn was cancelled -- removes the
//! request and announces it closed, so no prompt outlives the request it shows.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use hf_guardrails::{Action, ApprovalGate};
use serde::Serialize;
use tokio::sync::oneshot;
use uuid::Uuid;

/// Event that announces a new approval request.
pub const PERMISSION_REQUEST_EVENT: &str = "chat:permission_request";

/// Event that announces an approval request is no longer pending.
pub const PERMISSION_CLOSED_EVENT: &str = "chat:permission_closed";

/// How long a request waits for an answer before it is denied, so an
/// unattended prompt cannot hold a chat turn open indefinitely.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_mins(5);

/// The body of [`PERMISSION_REQUEST_EVENT`]: the action (its label includes the
/// arguments), the reason, the risk tier, and the seconds until auto-denial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionRequest {
    pub id: String,
    pub action: String,
    pub reason: String,
    pub risk: String,
    pub timeout_secs: u64,
}

impl PermissionRequest {
    /// Describe one request for a prompt.
    #[must_use]
    pub fn new(id: Uuid, action: &Action, reason: &str, timeout: Duration) -> Self {
        Self {
            id: id.to_string(),
            action: action.label(),
            reason: reason.to_owned(),
            risk: action.risk().as_str().to_owned(),
            timeout_secs: timeout.as_secs(),
        }
    }
}

/// The body of [`PERMISSION_CLOSED_EVENT`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionClosed {
    pub id: String,
}

/// Delivers approval prompts to the person who answers them.
pub trait ApprovalNotifier: Send + Sync {
    /// A request is waiting for an answer.
    fn requested(&self, request: &PermissionRequest);

    /// A request was answered, timed out, or was withdrawn.
    fn closed(&self, closed: &PermissionClosed);
}

/// Registry of approval requests waiting for an answer.
#[derive(Default)]
pub struct PendingApprovals {
    inner: std::sync::Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
}

impl PendingApprovals {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, oneshot::Sender<bool>>> {
        // The map holds only senders; a panic while it was held cannot leave a
        // half-updated entry, so the poisoned guard is still consistent.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn register(&self, id: Uuid) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        self.entries().insert(id, sender);
        receiver
    }

    fn withdraw(&self, id: Uuid) {
        self.entries().remove(&id);
    }

    /// Answer a pending request. Returns `false` when no request with `id` is
    /// waiting (already answered, timed out, or withdrawn).
    pub fn resolve(&self, id: Uuid, approved: bool) -> bool {
        let Some(sender) = self.entries().remove(&id) else {
            return false;
        };
        // A send fails only when the waiter was dropped between the removal
        // above and this send; the request is then already withdrawn.
        sender.send(approved).is_ok()
    }

    /// Number of requests currently waiting.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.entries().len()
    }
}

/// An [`ApprovalGate`] that asks a person through an [`ApprovalNotifier`].
pub struct InteractiveApprovalGate {
    pending: Arc<PendingApprovals>,
    notifier: Arc<dyn ApprovalNotifier>,
    timeout: Duration,
}

impl InteractiveApprovalGate {
    /// A gate that waits [`APPROVAL_TIMEOUT`] for each answer.
    #[must_use]
    pub fn new(pending: Arc<PendingApprovals>, notifier: Arc<dyn ApprovalNotifier>) -> Self {
        Self {
            pending,
            notifier,
            timeout: APPROVAL_TIMEOUT,
        }
    }

    /// Wait `timeout` instead of [`APPROVAL_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Withdraws a request and announces it closed however its wait ends,
/// including the waiting future being dropped.
struct OpenRequest<'a> {
    gate: &'a InteractiveApprovalGate,
    id: Uuid,
}

impl Drop for OpenRequest<'_> {
    fn drop(&mut self) {
        self.gate.pending.withdraw(self.id);
        self.gate.notifier.closed(&PermissionClosed {
            id: self.id.to_string(),
        });
    }
}

#[async_trait::async_trait]
impl ApprovalGate for InteractiveApprovalGate {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        let id = Uuid::new_v4();
        let receiver = self.pending.register(id);
        let _open = OpenRequest { gate: self, id };
        self.notifier
            .requested(&PermissionRequest::new(id, action, reason, self.timeout));
        // A timeout, or a sender dropped without an answer, denies.
        matches!(
            tokio::time::timeout(self.timeout, receiver).await,
            Ok(Ok(true))
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        requested: std::sync::Mutex<Vec<PermissionRequest>>,
        closed: std::sync::Mutex<Vec<String>>,
    }

    impl ApprovalNotifier for Recorder {
        fn requested(&self, request: &PermissionRequest) {
            self.requested.lock().unwrap().push(request.clone());
        }

        fn closed(&self, closed: &PermissionClosed) {
            self.closed.lock().unwrap().push(closed.id.clone());
        }
    }

    fn gate(
        timeout: Duration,
    ) -> (
        Arc<InteractiveApprovalGate>,
        Arc<PendingApprovals>,
        Arc<Recorder>,
    ) {
        let pending = Arc::new(PendingApprovals::default());
        let recorder = Arc::new(Recorder::default());
        let gate = InteractiveApprovalGate::new(Arc::clone(&pending), recorder.clone())
            .with_timeout(timeout);
        (Arc::new(gate), pending, recorder)
    }

    fn action() -> Action {
        Action::ShellExec {
            command: "make fuzz".to_owned(),
        }
    }

    async fn first_request(recorder: &Recorder) -> Uuid {
        for _ in 0..200 {
            if let Some(request) = recorder.requested.lock().unwrap().first() {
                return Uuid::parse_str(&request.id).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("no approval request was announced");
    }

    #[test]
    fn a_request_carries_the_risk_tier_and_the_auto_deny_deadline() {
        let request = PermissionRequest::new(
            Uuid::nil(),
            &action(),
            "agent wants to build",
            Duration::from_mins(5),
        );
        let payload = serde_json::to_value(&request).unwrap();

        assert_eq!(payload["id"], Uuid::nil().to_string());
        assert_eq!(payload["action"], "shell: make fuzz");
        assert_eq!(payload["reason"], "agent wants to build");
        assert_eq!(payload["risk"], "critical");
        assert_eq!(payload["timeout_secs"], 300);
    }

    #[tokio::test]
    async fn an_answer_reaches_the_waiting_gate_and_closes_the_prompt() {
        let (gate, pending, recorder) = gate(Duration::from_secs(10));
        let waiting = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.request_approval(&action(), "why").await })
        };
        let id = first_request(&recorder).await;

        assert!(pending.resolve(id, true));
        assert!(waiting.await.unwrap());
        assert_eq!(pending.pending_count(), 0);
        assert_eq!(*recorder.closed.lock().unwrap(), vec![id.to_string()]);
        assert!(!pending.resolve(id, true), "an answered request is gone");
    }

    #[tokio::test]
    async fn an_unanswered_request_is_denied_at_its_deadline_and_closed() {
        let (gate, pending, recorder) = gate(Duration::from_millis(20));

        assert!(!gate.request_approval(&action(), "why").await);
        assert_eq!(pending.pending_count(), 0);
        assert_eq!(recorder.closed.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_dropped_wait_withdraws_the_request_and_closes_the_prompt() {
        let (gate, pending, recorder) = gate(Duration::from_secs(10));
        let waiting = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move { gate.request_approval(&action(), "why").await })
        };
        let id = first_request(&recorder).await;

        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(pending.pending_count(), 0);
        assert_eq!(*recorder.closed.lock().unwrap(), vec![id.to_string()]);
        assert!(!pending.resolve(id, true));
    }

    #[test]
    fn resolving_an_unknown_request_reports_that_nothing_was_waiting() {
        assert!(!PendingApprovals::default().resolve(Uuid::new_v4(), true));
    }
}
