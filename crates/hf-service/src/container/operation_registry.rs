//! Bounded cancellation registration shared by interactive operations.

use hf_core::error::ClassifiedError;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The result of asking to cancel an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationCancelOutcome {
    /// The operation was running and has received a stop request. A
    /// repeated cancel of an operation that is still winding down is also accepted.
    Accepted,
    /// No operation with that id is running: it never started, already finished,
    /// or has already completed. An operation that has not registered
    /// yet is refused when it does, so an early cancel still stops it.
    NotRunning,
}

/// How long a cancel for an operation that has not registered yet is remembered.
/// Covers the request prelude between the client sending the operation and the
/// operation registering; long enough for that, short enough that a cancel for a
/// finished operation is forgotten before its id could plausibly be reused.
const EARLY_CANCEL_TTL: Duration = Duration::from_secs(30);

/// Upper bound on remembered early cancels; the oldest is evicted first.
const EARLY_CANCEL_CAPACITY: usize = 64;

#[derive(Default)]
struct RegistryState {
    operations: HashMap<Uuid, CancellationToken>,
    /// Cancels that arrived before their operation registered, with arrival time.
    early_cancels: HashMap<Uuid, Instant>,
}

impl RegistryState {
    fn expire_early_cancels(&mut self, now: Instant) {
        self.early_cancels
            .retain(|_, at| now.saturating_duration_since(*at) < EARLY_CANCEL_TTL);
    }

    fn remember_early_cancel(&mut self, id: Uuid, now: Instant) {
        self.expire_early_cancels(now);
        if self.early_cancels.len() >= EARLY_CANCEL_CAPACITY
            && !self.early_cancels.contains_key(&id)
        {
            let oldest = self
                .early_cancels
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(id, _)| *id);
            if let Some(oldest) = oldest {
                self.early_cancels.remove(&oldest);
            }
        }
        self.early_cancels.insert(id, now);
    }
}

/// Cancellation tokens of running operations, keyed by the caller-chosen operation
/// id. Shared by every clone of a container. A cancel for an id that has not
/// registered yet is remembered briefly (bounded) and refuses that id at
/// registration, so a Stop pressed during the request prelude still lands.
#[derive(Clone, Default)]
pub(crate) struct OperationRegistry {
    state: Arc<std::sync::Mutex<RegistryState>>,
}

impl OperationRegistry {
    fn state(&self) -> std::sync::MutexGuard<'_, RegistryState> {
        // Entries are inserted and removed whole, so a poisoned map is still
        // consistent.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register a starting operation.
    ///
    /// # Errors
    /// Rejects an id that names an operation that is still running, so one cancel can
    /// never reach two operations, and an id cancelled before it registered
    /// ([`ClassifiedError::Cancelled`]).
    pub(crate) fn register(&self, id: Uuid) -> Result<OperationRegistration, ClassifiedError> {
        self.register_at(id, Instant::now())
    }

    fn register_at(
        &self,
        id: Uuid,
        now: Instant,
    ) -> Result<OperationRegistration, ClassifiedError> {
        let mut state = self.state();
        state.expire_early_cancels(now);
        if state.early_cancels.remove(&id).is_some() {
            return Err(ClassifiedError::Cancelled);
        }
        if state.operations.contains_key(&id) {
            return Err(ClassifiedError::Validation(format!(
                "operation {id} is already running"
            )));
        }
        let cancel = CancellationToken::new();
        state.operations.insert(id, cancel.clone());
        Ok(OperationRegistration {
            registry: self.clone(),
            id,
            cancel,
            committed: false,
        })
    }

    pub(crate) fn cancel(&self, id: Uuid) -> OperationCancelOutcome {
        self.cancel_at(id, Instant::now())
    }

    fn cancel_at(&self, id: Uuid, now: Instant) -> OperationCancelOutcome {
        let mut state = self.state();
        if let Some(cancel) = state.operations.get(&id) {
            cancel.cancel();
            return OperationCancelOutcome::Accepted;
        }
        // Not registered: it may still be in its request prelude. Remember the
        // cancel so the operation is refused when it registers.
        state.remember_early_cancel(id, now);
        OperationCancelOutcome::NotRunning
    }
}

/// One running operation's place in the registry. Dropping it deregisters the operation.
pub(crate) struct OperationRegistration {
    registry: OperationRegistry,
    id: Uuid,
    cancel: CancellationToken,
    committed: bool,
}

impl OperationRegistration {
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Claim the commit: deregister the operation so later cancels report
    /// [`OperationCancelOutcome::NotRunning`], and report whether a cancel landed
    /// first. The check and the removal happen under the registry lock that
    /// [`OperationRegistry::cancel`] takes, so the two cannot interleave.
    pub(crate) fn commit(&mut self) -> bool {
        let mut state = self.registry.state();
        state.operations.remove(&self.id);
        self.committed = true;
        !self.cancel.is_cancelled()
    }
}

impl Drop for OperationRegistration {
    fn drop(&mut self) {
        if !self.committed {
            self.registry.state().operations.remove(&self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_cancel_after_the_commit_claim_reports_not_running() {
        let registry = OperationRegistry::default();
        let id = Uuid::new_v4();
        let mut operation = registry.register(id).unwrap();

        assert!(operation.commit(), "no cancel landed before the commit");
        assert_eq!(registry.cancel(id), OperationCancelOutcome::NotRunning);
        assert!(!operation.token().is_cancelled());
    }

    #[test]
    fn a_cancel_before_the_commit_claim_wins() {
        let registry = OperationRegistry::default();
        let id = Uuid::new_v4();
        let mut operation = registry.register(id).unwrap();

        assert_eq!(registry.cancel(id), OperationCancelOutcome::Accepted);
        assert!(!operation.commit());
        assert_eq!(registry.cancel(id), OperationCancelOutcome::NotRunning);
    }

    #[test]
    fn an_early_cancel_refuses_the_operation_at_registration() {
        let registry = OperationRegistry::default();
        let id = Uuid::new_v4();

        assert_eq!(registry.cancel(id), OperationCancelOutcome::NotRunning);
        assert!(matches!(
            registry.register(id),
            Err(ClassifiedError::Cancelled)
        ));
        // Consumed: the id is usable afterwards.
        assert!(registry.register(id).is_ok());
    }

    #[test]
    fn an_early_cancel_expires_and_is_bounded() {
        let registry = OperationRegistry::default();
        let start = Instant::now();
        let stale = Uuid::new_v4();
        registry.cancel_at(stale, start);
        let later = start + EARLY_CANCEL_TTL + Duration::from_secs(1);
        assert!(registry.register_at(stale, later).is_ok(), "expired");

        let first = Uuid::new_v4();
        registry.cancel_at(first, start);
        for i in 0..EARLY_CANCEL_CAPACITY {
            registry.cancel_at(Uuid::new_v4(), start + Duration::from_millis(1 + i as u64));
        }
        assert_eq!(registry.state().early_cancels.len(), EARLY_CANCEL_CAPACITY);
        assert!(
            registry.register_at(first, start).is_ok(),
            "the oldest was evicted"
        );
    }

    #[test]
    fn a_dropped_registration_frees_its_id() {
        let registry = OperationRegistry::default();
        let id = Uuid::new_v4();
        drop(registry.register(id).unwrap());

        assert!(registry.register(id).is_ok());
        assert_eq!(
            registry.cancel(Uuid::new_v4()),
            OperationCancelOutcome::NotRunning
        );
    }
}
