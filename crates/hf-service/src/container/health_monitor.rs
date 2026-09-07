//! Bounded live telemetry owned by the campaign run lifecycle.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hf_core::engine::FuzzProgress;
use uuid::Uuid;

use super::CoverageSample;
use crate::ClassifiedError;

#[cfg(unix)]
pub(crate) fn workspace_available_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    let capacity = rustix::fs::statvfs(path)?;
    capacity
        .f_bavail
        .checked_mul(capacity.f_frsize)
        .ok_or_else(|| std::io::Error::other("workspace capacity exceeds u64"))
}

#[cfg(windows)]
pub(crate) fn workspace_available_bytes(path: &std::path::Path) -> std::io::Result<u64> {
    fs2::available_space(path)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn workspace_available_bytes(_path: &std::path::Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "workspace capacity is unavailable on this platform",
    ))
}

/// A cloned, lock-free view of one run's latest live observations.
#[derive(Debug, Clone, PartialEq)]
pub struct RunTelemetryObservation {
    /// Campaign run being observed.
    pub run_id: Uuid,
    /// Latest valid structured edge or throughput observation.
    pub last_progress_at: Option<DateTime<Utc>>,
    /// Bounded paired edge/throughput series, oldest first.
    pub coverage_series: Vec<CoverageSample>,
    /// Latest finite throughput report.
    pub current_execs: Option<f64>,
    /// Whole-run arithmetic mean of finite throughput reports.
    pub mean_execs: Option<f64>,
    /// Peak finite throughput report.
    pub peak_execs: Option<f64>,
    /// Latest structured edge report.
    pub edges: Option<u64>,
    /// Count used by the whole-run arithmetic mean.
    pub throughput_sample_count: u64,
    /// Sum used by the whole-run arithmetic mean.
    pub throughput_sample_sum: f64,
    /// Service-managed runtime invocations currently expected.
    pub managed_invocations_expected: u32,
    /// Expected invocations still within their runtime await.
    pub managed_invocations_alive: u32,
}

struct LiveRunTelemetry {
    max_live_samples: usize,
    accepts_progress: bool,
    first_observed_at: Option<DateTime<Utc>>,
    last_progress_at: Option<DateTime<Utc>>,
    coverage_series: VecDeque<CoverageSample>,
    current_execs: Option<f64>,
    peak_execs: Option<f64>,
    edges: Option<u64>,
    throughput_sample_count: u64,
    throughput_sample_sum: f64,
    managed_invocations_expected: u32,
    managed_invocations_alive: u32,
}

impl LiveRunTelemetry {
    fn new(max_live_samples: usize) -> Self {
        Self {
            max_live_samples,
            accepts_progress: true,
            first_observed_at: None,
            last_progress_at: None,
            coverage_series: VecDeque::new(),
            current_execs: None,
            peak_execs: None,
            edges: None,
            throughput_sample_count: 0,
            throughput_sample_sum: 0.0,
            managed_invocations_expected: 0,
            managed_invocations_alive: 0,
        }
    }
}

/// Shared, bounded telemetry registry for active campaign runs.
pub struct RunTelemetryRegistry {
    max_live_samples: usize,
    runs: Mutex<HashMap<Uuid, LiveRunTelemetry>>,
}

impl RunTelemetryRegistry {
    /// Create a registry with the validated maximum retained sample count.
    #[must_use]
    pub fn new(max_live_samples: usize) -> Self {
        Self {
            max_live_samples,
            runs: Mutex::new(HashMap::new()),
        }
    }

    /// Prepare a new run entry. Returns `false` when the ID already exists.
    pub fn prepare(&self, run_id: Uuid) -> bool {
        self.prepare_with_limit(run_id, self.max_live_samples)
    }

    pub(crate) fn prepare_with_limit(&self, run_id: Uuid, max_live_samples: usize) -> bool {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if runs.contains_key(&run_id) {
            return false;
        }
        if max_live_samples == 0 || max_live_samples > self.max_live_samples {
            return false;
        }
        runs.insert(run_id, LiveRunTelemetry::new(max_live_samples));
        true
    }

    /// Enter the single service-managed runtime invocation for a run.
    ///
    /// # Errors
    /// Returns a validation error when the run is absent, closed, or already
    /// invoking its runtime adapter.
    pub fn register_invocation(
        self: &Arc<Self>,
        run_id: Uuid,
    ) -> Result<ManagedInvocationGuard, ClassifiedError> {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let run = runs.get_mut(&run_id).ok_or_else(|| {
            ClassifiedError::Validation(format!("campaign telemetry run '{run_id}' is absent"))
        })?;
        if !run.accepts_progress || run.managed_invocations_expected != 0 {
            return Err(ClassifiedError::Validation(format!(
                "campaign telemetry run '{run_id}' cannot admit another invocation"
            )));
        }
        run.managed_invocations_expected = 1;
        run.managed_invocations_alive = 1;
        drop(runs);
        Ok(ManagedInvocationGuard {
            registry: Arc::clone(self),
            run_id,
            active: true,
        })
    }

    /// Observe one structured engine progress item.
    ///
    /// Log, crash-signal, done, negative, and nonfinite throughput values do
    /// not change metric freshness. A late callback for a closed or removed run
    /// is ignored.
    pub fn observe_progress(
        &self,
        run_id: Uuid,
        progress: &FuzzProgress,
        observed_at: DateTime<Utc>,
    ) {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(run) = runs.get_mut(&run_id) else {
            return;
        };
        if !run.accepts_progress {
            return;
        }
        match progress {
            FuzzProgress::EdgesCovered(edges) => {
                run.edges = Some(*edges);
                observe_metric_time(run, observed_at);
            }
            FuzzProgress::ExecsPerSec(execs) if execs.is_finite() && *execs >= 0.0 => {
                let next_sum = run.throughput_sample_sum + execs;
                let Some(next_count) = run.throughput_sample_count.checked_add(1) else {
                    tracing::warn!(%run_id, "ignoring throughput because its sample count overflowed");
                    return;
                };
                if !next_sum.is_finite() {
                    tracing::warn!(%run_id, "ignoring throughput because its whole-run sum overflowed");
                    return;
                }
                observe_metric_time(run, observed_at);
                run.current_execs = Some(*execs);
                run.peak_execs = Some(run.peak_execs.map_or(*execs, |peak| peak.max(*execs)));
                run.throughput_sample_count = next_count;
                run.throughput_sample_sum = next_sum;
                if let (Some(first), Some(edges)) = (run.first_observed_at, run.edges) {
                    let elapsed_secs = observed_at
                        .signed_duration_since(first)
                        .num_milliseconds()
                        .max(0) as f64
                        / 1000.0;
                    run.coverage_series.push_back(CoverageSample {
                        t: elapsed_secs,
                        edges,
                        execs: *execs,
                    });
                    while run.coverage_series.len() > run.max_live_samples {
                        run.coverage_series.pop_front();
                    }
                }
            }
            FuzzProgress::ExecsPerSec(_)
            | FuzzProgress::CrashesFound(_)
            | FuzzProgress::LogLine(_)
            | FuzzProgress::Done => {}
        }
    }

    /// Clone one run's state without retaining the registry lock.
    #[must_use]
    pub fn snapshot(&self, run_id: Uuid) -> Option<RunTelemetryObservation> {
        let runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let run = runs.get(&run_id)?;
        Some(RunTelemetryObservation {
            run_id,
            last_progress_at: run.last_progress_at,
            coverage_series: run.coverage_series.iter().cloned().collect(),
            current_execs: run.current_execs,
            mean_execs: (run.throughput_sample_count > 0)
                .then(|| run.throughput_sample_sum / run.throughput_sample_count as f64),
            peak_execs: run.peak_execs,
            edges: run.edges,
            throughput_sample_count: run.throughput_sample_count,
            throughput_sample_sum: run.throughput_sample_sum,
            managed_invocations_expected: run.managed_invocations_expected,
            managed_invocations_alive: run.managed_invocations_alive,
        })
    }

    /// Reject subsequent progress callbacks while retaining the final snapshot.
    pub fn close_progress(&self, run_id: Uuid) {
        let mut runs = self
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(run) = runs.get_mut(&run_id) {
            run.accepts_progress = false;
        }
    }

    /// Remove a completed or abandoned run's live state.
    pub fn remove(&self, run_id: Uuid) {
        self.runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&run_id);
    }
}

fn observe_metric_time(run: &mut LiveRunTelemetry, observed_at: DateTime<Utc>) {
    if run.first_observed_at.is_none() {
        run.first_observed_at = Some(observed_at);
    }
    run.last_progress_at = Some(
        run.last_progress_at
            .map_or(observed_at, |previous| previous.max(observed_at)),
    );
}

/// RAII ownership of one service-managed runtime invocation.
pub struct ManagedInvocationGuard {
    registry: Arc<RunTelemetryRegistry>,
    run_id: Uuid,
    active: bool,
}

impl ManagedInvocationGuard {
    /// Finish the invocation, atomically clearing expected and alive counts.
    pub fn finish(mut self) {
        self.leave();
    }

    fn leave(&mut self) {
        if !self.active {
            return;
        }
        let mut runs = self
            .registry
            .runs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(run) = runs.get_mut(&self.run_id) {
            run.managed_invocations_expected = 0;
            run.managed_invocations_alive = 0;
        }
        self.active = false;
    }
}

impl Drop for ManagedInvocationGuard {
    fn drop(&mut self) {
        self.leave();
    }
}

pub(crate) struct RunHealthMonitor {
    container: crate::container::ServiceContainer,
    registry: Arc<RunTelemetryRegistry>,
    run_id: Uuid,
    stop: tokio_util::sync::CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
    abort: Option<tokio::task::AbortHandle>,
    settings: crate::config::CampaignHealthSettings,
    source_schedule_id: Option<String>,
    finished: bool,
}

impl RunHealthMonitor {
    pub(crate) fn start(
        container: crate::container::ServiceContainer,
        registry: Arc<RunTelemetryRegistry>,
        run_id: Uuid,
        interval: std::time::Duration,
        settings: crate::config::CampaignHealthSettings,
    ) -> Self {
        let stop = tokio_util::sync::CancellationToken::new();
        let task_stop = stop.clone();
        let task_container = container.clone();
        let task_settings = settings;
        let source_schedule_id = crate::scheduler::dispatching_schedule();
        let task_source_schedule_id = source_schedule_id.clone();
        let task = async move {
            let mut ticks = tokio::time::interval(interval);
            loop {
                tokio::select! {
                    biased;
                    () = task_stop.cancelled() => break,
                    _ = ticks.tick() => {
                        if let Err(error) = task_container
                            .assess_and_emit_campaign_health_with_settings(
                                run_id,
                                Utc::now(),
                                &task_settings,
                            )
                            .await
                        {
                            tracing::warn!(%run_id, %error, "campaign health assessment failed");
                        }
                    }
                }
            }
        };
        let handle = tokio::spawn(crate::scheduler::with_dispatching_schedule(
            task_source_schedule_id,
            task,
        ));
        let abort = handle.abort_handle();
        Self {
            container,
            registry,
            run_id,
            stop,
            handle: Some(handle),
            abort: Some(abort),
            settings,
            source_schedule_id,
            finished: false,
        }
    }

    pub(crate) async fn finish(mut self) {
        self.registry.close_progress(self.run_id);
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            if let Err(error) = handle.await {
                tracing::warn!(run_id = %self.run_id, %error, "join campaign health monitor");
            }
        }
        let assessment = self
            .container
            .assess_and_emit_campaign_health_with_settings(self.run_id, Utc::now(), &self.settings);
        if let Err(error) =
            crate::scheduler::with_dispatching_schedule(self.source_schedule_id.clone(), assessment)
                .await
        {
            tracing::warn!(run_id = %self.run_id, %error, "final campaign health assessment failed");
        }
        self.registry.remove(self.run_id);
        self.abort = None;
        self.finished = true;
    }
}

impl Drop for RunHealthMonitor {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.registry.close_progress(self.run_id);
        self.registry.remove(self.run_id);
        self.stop.cancel();
        if let Some(abort) = self.abort.take() {
            abort.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DropSignal(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::Release);
        }
    }

    #[test]
    fn finite_throughput_that_overflows_the_sum_is_rejected_atomically() {
        let run_id = Uuid::from_u128(35);
        let registry = RunTelemetryRegistry::new(3);
        let start = DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        registry.prepare(run_id);
        registry.observe_progress(run_id, &FuzzProgress::EdgesCovered(9), start);
        registry.observe_progress(
            run_id,
            &FuzzProgress::ExecsPerSec(f64::MAX),
            start + chrono::Duration::seconds(1),
        );
        let before = registry.snapshot(run_id).unwrap();

        registry.observe_progress(
            run_id,
            &FuzzProgress::ExecsPerSec(f64::MAX),
            start + chrono::Duration::seconds(2),
        );

        assert_eq!(registry.snapshot(run_id).unwrap(), before);
    }

    #[test]
    fn workspace_capacity_is_reported_by_a_safe_cross_platform_api() {
        let directory = tempfile::tempdir().unwrap();
        assert!(workspace_available_bytes(directory.path()).unwrap() > 0);
        assert!(workspace_available_bytes(&directory.path().join("missing")).is_err());
    }

    #[tokio::test]
    async fn aborting_finish_still_aborts_the_owned_task_and_removes_live_state() {
        let run_id = Uuid::from_u128(36);
        let registry = Arc::new(RunTelemetryRegistry::new(3));
        assert!(registry.prepare(run_id));
        let task_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signal = DropSignal(Arc::clone(&task_dropped));
        let handle = tokio::spawn(async move {
            let _signal = signal;
            std::future::pending::<()>().await;
        });
        let abort = handle.abort_handle();
        let monitor = RunHealthMonitor {
            container: crate::container::ServiceContainer::stubbed(),
            registry: Arc::clone(&registry),
            run_id,
            stop: tokio_util::sync::CancellationToken::new(),
            handle: Some(handle),
            abort: Some(abort),
            settings: crate::config::CampaignHealthSettings::default(),
            source_schedule_id: None,
            finished: false,
        };

        let finishing = tokio::spawn(monitor.finish());
        tokio::task::yield_now().await;
        finishing.abort();
        let _cancelled = finishing.await.expect_err("finish future is cancelled");
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !task_dropped.load(std::sync::atomic::Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned monitor task aborted");
        assert!(registry.snapshot(run_id).is_none());
    }

    #[tokio::test]
    async fn final_assessment_uses_the_settings_captured_at_run_admission() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("settings.db"))
                .await
                .unwrap(),
        );
        let run_id = Uuid::from_u128(37);
        let mut run = hf_storage::RunRecord::new(
            directory.path().to_string_lossy(),
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            Utc::now(),
        );
        run.id = run_id;
        run.status = hf_storage::RunStatus::Failed;
        store.insert_run(&run).await.unwrap();
        let registry = Arc::new(RunTelemetryRegistry::new(3));
        assert!(registry.prepare(run_id));
        let settings = crate::config::CampaignHealthSettings {
            stale_progress_secs: 37,
            disk_floor_bytes: 1,
            max_live_samples: 3,
            plateau_window: 3,
            ..crate::config::CampaignHealthSettings::default()
        };
        let container =
            crate::container::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
                .with_store(Arc::clone(&store));
        let monitor = RunHealthMonitor::start(
            container,
            registry,
            run_id,
            std::time::Duration::from_secs(3600),
            settings,
        );

        monitor.finish().await;

        let events = store
            .list_campaign_health_events(Some(run_id), 10)
            .await
            .unwrap();
        assert_eq!(events.len(), 1);
        let evidence: hf_storage::CampaignHealthEvidenceRecord =
            serde_json::from_str(&events[0].evidence_json).unwrap();
        assert_eq!(evidence.stale_progress_secs, 37);
        assert_eq!(evidence.disk_floor_bytes, 1);
    }

    #[tokio::test]
    async fn periodic_health_event_keeps_schedule_source_and_reaches_only_other_subscriber_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("scheduled-health.db"))
                .await
                .unwrap(),
        );
        let run_id = Uuid::from_u128(38);
        let mut run = hf_storage::RunRecord::new(
            directory.path().to_string_lossy(),
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            Utc::now(),
        );
        run.id = run_id;
        run.status = hf_storage::RunStatus::Failed;
        store.insert_run(&run).await.unwrap();
        let registry = Arc::new(RunTelemetryRegistry::new(3));
        assert!(registry.prepare(run_id));
        let container =
            crate::container::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
                .with_store(Arc::clone(&store));
        let manager = Arc::new(hf_scheduler::SchedulerManager::with_defaults());
        for id in ["producer", "other"] {
            manager
                .register(hf_scheduler::Schedule::new(
                    id,
                    id,
                    hf_scheduler::TriggerConfig::Event {
                        event_type: crate::scheduler::EVENT_CAMPAIGN_HEALTH.to_owned(),
                        debounce_secs: 0,
                        filter: None,
                    },
                    "test-workflow",
                ))
                .await;
        }
        manager.arm();
        manager.start(std::time::Duration::from_millis(10)).await;
        container.bind_scheduler_events(&manager);

        crate::scheduler::with_dispatching_schedule(Some("producer".to_owned()), async {
            let monitor = RunHealthMonitor::start(
                container,
                registry,
                run_id,
                std::time::Duration::from_secs(3600),
                crate::config::CampaignHealthSettings::default(),
            );
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while manager.execution_history("other").await.is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("other subscriber fired");
            monitor.finish().await;
        })
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        assert!(manager.execution_history("producer").await.is_empty());
        assert_eq!(manager.execution_history("other").await.len(), 1);
        manager.stop().await;
    }

    #[tokio::test]
    async fn live_periodic_monitor_retains_a_plateau_before_the_run_is_terminal() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("live-plateau.db"))
                .await
                .unwrap(),
        );
        let run_id = Uuid::from_u128(39);
        let mut run = hf_storage::RunRecord::new(
            directory.path().to_string_lossy(),
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            Utc::now(),
        );
        run.id = run_id;
        run.status = hf_storage::RunStatus::Running;
        store.insert_run(&run).await.unwrap();
        let container =
            crate::container::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
                .with_store(Arc::clone(&store));
        let registry = Arc::clone(&container.campaign_telemetry);
        assert!(registry.prepare(run_id));
        let started_at = Utc::now();
        for offset in 0..3 {
            let observed_at = started_at + chrono::Duration::seconds(offset);
            registry.observe_progress(run_id, &FuzzProgress::EdgesCovered(7), observed_at);
            registry.observe_progress(run_id, &FuzzProgress::ExecsPerSec(50.0), observed_at);
        }
        let invocation = registry.register_invocation(run_id).unwrap();
        let monitor = RunHealthMonitor::start(
            container,
            registry,
            run_id,
            std::time::Duration::from_secs(3600),
            crate::config::CampaignHealthSettings {
                plateau_window: 3,
                max_live_samples: 3,
                ..crate::config::CampaignHealthSettings::default()
            },
        );

        let events = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let events = store
                    .list_campaign_health_events(Some(run_id), 10)
                    .await
                    .unwrap();
                if !events.is_empty() {
                    break events;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("periodic plateau assessment");
        assert_eq!(
            store.get_run(run_id).await.unwrap().unwrap().status,
            hf_storage::RunStatus::Running
        );
        assert!(events
            .iter()
            .any(|event| event.condition == "coverage_plateau"));

        drop(invocation);
        monitor.finish().await;
    }
}
