//! Scope guards for container-owned state.
//!
//! Each guard exists because the state it manages must be released even on an
//! error path: an in-flight run's cancellation token, a tracked agent turn, a
//! staging directory, a provider health task, and the run journal entry whose
//! durability gates further execution.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::provider::ProviderPool;
use hf_storage::{RunStatus, Store};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Remove a sensitive staging directory even if the async import is aborted.
pub(super) struct StagingDirectoryGuard(pub(super) PathBuf);

impl Drop for StagingDirectoryGuard {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// RAII guard that keeps an agent turn registered in the container's
/// `active_agents` list for its lifetime, removing it on drop (even if the turn
/// panics or is cancelled). Returned by [`super::ServiceContainer::track_agent`].
#[must_use = "the agent turn is only tracked while this guard is alive"]
pub struct AgentTurnGuard {
    pub(super) active_agents: Arc<std::sync::Mutex<Vec<String>>>,
    pub(super) label: String,
}

impl Drop for AgentTurnGuard {
    fn drop(&mut self) {
        if let Ok(mut agents) = self.active_agents.lock() {
            if let Some(pos) = agents.iter().position(|a| a == &self.label) {
                agents.remove(pos);
            }
        }
    }
}

/// RAII guard that removes a run's cancellation token from the active-runs map
/// on drop, so the entry cannot leak if the `run_fuzzer` future is
/// dropped/aborted rather than returning normally (which would otherwise leave
/// a phantom run that `active_run_ids` reports and `cancel_run` can never clear).
pub(super) struct ActiveRunGuard {
    pub(super) active_runs:
        Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    pub(super) run_id: Uuid,
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.remove(&self.run_id);
        }
    }
}

/// Cadence used by the provider health-check loop while no provider pool is
/// configured; matches the `ProviderPool` trait's default interval.
const PROVIDER_HEALTH_CHECK_FALLBACK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

/// RAII guard for the periodic provider health-check task: dropping it cancels
/// the loop and aborts the task, so the background worker never outlives the
/// container that spawned it.
pub(super) struct ProviderHealthTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ProviderHealthTask {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.handle.abort();
    }
}

/// Spawn the periodic provider health-check loop: every pool-configured
/// interval, health-check each frozen provider and thaw the ones that respond
/// ([`ProviderPool::thaw_frozen_providers`]). This is what recovers providers
/// whose freeze has no auto-thaw (permanent freezes from invalid keys or
/// exhausted quota) without a process restart.
///
/// The loop reads the pool from the shared cell on every tick, so a pool
/// swapped in by [`ServiceContainer::reload_providers`] is picked up without
/// respawning the task, and runs an initial check immediately so providers
/// frozen before a restart recover without waiting a full interval.
pub(super) fn spawn_provider_health_checks(
    pool_cell: Arc<std::sync::RwLock<Option<Arc<dyn ProviderPool>>>>,
) -> ProviderHealthTask {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let handle = tokio::spawn(async move {
        loop {
            let pool = pool_cell.read().ok().and_then(|guard| guard.clone());
            let interval = if let Some(pool) = pool {
                let thawed = pool.thaw_frozen_providers().await;
                if thawed > 0 {
                    tracing::info!(
                        thawed,
                        "frozen providers recovered by periodic health check"
                    );
                }
                pool.health_check_interval()
            } else {
                // No provider configured (yet); keep a modest cadence so a
                // pool installed by a later reload starts getting checks.
                PROVIDER_HEALTH_CHECK_FALLBACK_INTERVAL
            };
            tokio::select! {
                () = token.cancelled() => break,
                () = tokio::time::sleep(interval) => {}
            }
        }
    });
    ProviderHealthTask { cancel, handle }
}

pub(super) fn ensure_run_journal_durable(
    journal: &crate::recovery::RunJournal,
) -> Result<(), ClassifiedError> {
    journal.durability_error().map_or(Ok(()), |error| {
        Err(ClassifiedError::Storage(format!(
            "run recovery journal is degraded: {error}"
        )))
    })
}

pub(super) fn close_run_journal(
    journal: &crate::recovery::RunJournal,
    run_id: Uuid,
) -> Result<(), ClassifiedError> {
    journal.close_run(run_id);
    ensure_run_journal_durable(journal)
}

/// Last-resort lifecycle repair for an inserted run. If its async operation is
/// aborted or returns through an unhandled error path, mark the row failed and
/// close its recovery journal instead of leaving a permanent `Running` record.
pub(super) struct PersistedRunGuard {
    store: Arc<Store>,
    journal: Option<Arc<crate::recovery::RunJournal>>,
    run_id: Uuid,
    armed: bool,
}

impl PersistedRunGuard {
    pub(super) fn new(
        store: Arc<Store>,
        journal: Option<Arc<crate::recovery::RunJournal>>,
        run_id: Uuid,
    ) -> Self {
        Self {
            store,
            journal,
            run_id,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PersistedRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(journal) = &self.journal {
            if let Err(error) = close_run_journal(journal, self.run_id) {
                tracing::error!(run_id = %self.run_id, %error, "failed to close aborted run journal");
            }
        }
        let store = Arc::clone(&self.store);
        let run_id = self.run_id;
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = store
                    .set_run_status(run_id, RunStatus::Failed, Some(Utc::now()))
                    .await
                {
                    tracing::error!(%run_id, %error, "failed to repair aborted run status");
                }
            });
        } else {
            tracing::error!(%run_id, "aborted run status could not be repaired without an async runtime");
        }
    }
}

#[cfg(test)]
mod journal_boundary_tests {
    use super::ensure_run_journal_durable;

    #[test]
    fn degraded_recovery_journal_blocks_new_execution() {
        let directory = tempfile::tempdir().unwrap();
        let wal = directory.path().join("run_journal.jsonl");
        std::fs::write(&wal, b"{truncated").unwrap();
        let journal = crate::recovery::RunJournal::open(wal);

        let error = ensure_run_journal_durable(&journal)
            .expect_err("degraded recovery evidence must fail closed");

        assert!(error
            .to_string()
            .contains("run recovery journal is degraded"));
    }
}

#[cfg(test)]
mod provider_health_task_tests {
    use super::spawn_provider_health_checks;
    use hf_core::provider::ProviderPool;
    use std::sync::Arc;
    use std::time::Duration;

    fn mock_pool_with_interval(interval_secs: u64) -> Arc<dyn ProviderPool> {
        let provider: Arc<dyn hf_core::provider::LlmProvider> =
            Arc::new(hf_test_utils::mock_provider::MockProvider::fixed("ok"));
        let config = hf_provider::ProviderPoolConfig {
            health_check_interval_secs: interval_secs,
            ..Default::default()
        };
        let pool: Arc<dyn ProviderPool> = Arc::new(hf_provider::ProviderPoolImpl::from_providers(
            vec![provider],
            &config,
        ));
        pool
    }

    async fn wait_until_thawed(pool: &Arc<dyn ProviderPool>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if !pool.provider_statuses().await[0].is_frozen {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the health task should thaw the provider promptly");
    }

    #[tokio::test]
    async fn health_task_recovers_a_frozen_provider_without_waiting_a_full_interval() {
        let pool = mock_pool_with_interval(60);
        let pid = hf_core::types::ProviderId::from_string("mock-provider");
        pool.freeze(&pid, "test freeze".to_owned()).await;
        assert!(pool.provider_statuses().await[0].is_frozen);

        let cell = Arc::new(std::sync::RwLock::new(Some(Arc::clone(&pool))));
        let task = spawn_provider_health_checks(cell);

        // The loop runs an initial check immediately, so recovery must land
        // well before the pool's 60s interval elapses.
        wait_until_thawed(&pool).await;

        // Dropping the guard cancels and aborts the loop: no leaked task.
        drop(task);
    }

    #[tokio::test]
    async fn health_task_follows_provider_pool_swaps() {
        // Mirrors `reload_providers`: the loop reads the shared cell on every
        // tick, so a pool swapped in later is health-checked without
        // respawning the task.
        let pool_a = mock_pool_with_interval(1);
        let cell = Arc::new(std::sync::RwLock::new(Some(pool_a)));
        let task = spawn_provider_health_checks(Arc::clone(&cell));

        let pool_b = mock_pool_with_interval(1);
        let pid = hf_core::types::ProviderId::from_string("mock-provider");
        pool_b.freeze(&pid, "test freeze".to_owned()).await;
        *cell.write().expect("pool cell poisoned") = Some(Arc::clone(&pool_b));

        wait_until_thawed(&pool_b).await;

        drop(task);
    }
}
