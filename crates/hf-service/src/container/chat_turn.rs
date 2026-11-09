//! Operator control over one running chat turn: which provider answers it,
//! and cancelling it.
//!
//! Cancel semantics: a cancelled turn is rolled back. Nothing it produced is
//! written to the transcript and no checkpoint is created -- the same state the
//! existing failure path leaves -- so the transcript never holds a question
//! without its answer, and rollback/branching keep counting whole turns. The
//! cancel decision is linearized against the commit: a cancel either lands
//! before the turn claims its commit (the turn returns
//! [`hf_core::error::ClassifiedError::Cancelled`] and persists nothing) or after it
//! ([`OperationCancelOutcome::NotRunning`], and the answer stands).

use std::sync::Arc;

use super::operation_registry::OperationCancelOutcome;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
    RouteRequest,
};
use hf_core::types::ProviderId;
use hf_guardrails::{Action, ApprovalGate};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Denies at once when the turn is cancelled, including a request already
/// waiting: the inner wait is dropped, which withdraws its prompt.
pub(crate) struct CancellableApprovalGate {
    pub(crate) inner: Arc<dyn ApprovalGate>,
    pub(crate) cancel: CancellationToken,
}

#[async_trait::async_trait]
impl ApprovalGate for CancellableApprovalGate {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => false,
            approved = self.inner.request_approval(action, reason) => approved,
        }
    }
}

/// Which provider served the most recent model call of the turn.
#[derive(Debug, Clone, Default)]
pub(crate) struct ServedBy {
    pub(crate) provider: Option<ProviderId>,
    pub(crate) model: Option<String>,
}

/// The provider pool seen by every model call of one chat turn.
///
/// With a selection, every route is pinned to it, so the agent's steps,
/// compaction, delegated sub-agents, and the service tools the turn runs are
/// all answered by that provider or fail naming it; the pool's router refuses
/// a pinned provider that is unknown or frozen rather than substituting one.
pub(crate) struct TurnPool {
    inner: Arc<dyn ProviderPool>,
    pin: Option<ProviderId>,
    served: std::sync::Mutex<ServedBy>,
}

impl TurnPool {
    pub(crate) fn new(inner: Arc<dyn ProviderPool>, pin: Option<ProviderId>) -> Self {
        Self {
            inner,
            pin,
            served: std::sync::Mutex::new(ServedBy::default()),
        }
    }

    pub(crate) fn pin(&self) -> Option<&ProviderId> {
        self.pin.as_ref()
    }

    pub(crate) fn served(&self) -> ServedBy {
        self.served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn route(&self, route: &RouteRequest) -> RouteRequest {
        let mut route = route.clone();
        if let Some(pin) = &self.pin {
            route.pinned_provider_id = Some(pin.clone());
        }
        route
    }
}

#[async_trait::async_trait]
impl ProviderPool for TurnPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        let response = self
            .inner
            .chat_completion(request, &self.route(route))
            .await?;
        *self
            .served
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ServedBy {
            provider: response.provider_id.clone(),
            model: Some(response.model.clone()),
        };
        Ok(response)
    }

    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        self.inner
            .chat_completion_stream(request, &self.route(route))
            .await
    }

    fn report_error(&self, provider_id: &ProviderId, error: &ProviderError) {
        self.inner.report_error(provider_id, error);
    }

    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        self.inner.provider_statuses().await
    }

    async fn freeze(&self, provider_id: &ProviderId, reason: String) {
        self.inner.freeze(provider_id, reason).await;
    }

    async fn thaw(&self, provider_id: &ProviderId) -> Result<(), ProviderError> {
        self.inner.thaw(provider_id).await
    }

    fn health_check_interval(&self) -> std::time::Duration {
        self.inner.health_check_interval()
    }

    async fn thaw_frozen_providers(&self) -> usize {
        self.inner.thaw_frozen_providers().await
    }
}

impl super::ServiceContainer {
    /// Ask the chat turn named `turn_id` to stop.
    ///
    /// The turn's in-flight model request is dropped, any approval it waits
    /// for is denied and its prompt withdrawn, and a fuzz run it started is
    /// cancelled through the run's own token. A tool without cancellation
    /// support finishes its current call; the turn stops at the next step.
    /// The cancelled turn persists nothing (see the module documentation).
    #[must_use]
    pub fn cancel_chat_turn(&self, turn_id: Uuid) -> OperationCancelOutcome {
        self.chat_turns.cancel(turn_id)
    }

    /// A container scoped to one chat turn: its own provider cell holding the
    /// turn's pool, an approval gate that denies once the turn is cancelled,
    /// and the turn token as the parent of every fuzz run the turn starts.
    pub(crate) fn chat_turn_scope(
        &self,
        pool: Option<Arc<dyn ProviderPool>>,
        cancel: &CancellationToken,
    ) -> Self {
        let mut scoped = self.clone();
        scoped.provider_pool = Arc::new(std::sync::RwLock::new(pool));
        let gate = CancellableApprovalGate {
            inner: self.guardrails.approval_gate(),
            cancel: cancel.clone(),
        };
        scoped.guardrails = self.guardrails.clone().with_approval_gate(Arc::new(gate));
        scoped.turn_cancel = Some(cancel.clone());
        scoped
    }

    /// A fresh cancellation token for an operation the container starts; a
    /// child of the chat turn token when this container is scoped to a turn.
    pub(crate) fn operation_cancel_token(&self) -> CancellationToken {
        self.turn_cancel
            .as_ref()
            .map_or_else(CancellationToken::new, CancellationToken::child_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operations_of_a_scoped_container_stop_with_the_turn() {
        let service = super::super::ServiceContainer::stubbed();
        let cancel = CancellationToken::new();
        let scoped = service.chat_turn_scope(None, &cancel);
        let run = scoped.operation_cancel_token();
        let unscoped = service.operation_cancel_token();

        cancel.cancel();
        assert!(run.is_cancelled());
        assert!(!unscoped.is_cancelled());
    }
}
