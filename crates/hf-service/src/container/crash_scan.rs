//! Interactive classification, independent of minimization and AI reports.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hf_core::crash::Crash;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, SandboxOptions};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{AiPolicy, OperationCancelOutcome, ServiceContainer};

/// The work currently being performed by a crash scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanPhase {
    Queued,
    Staging,
    Casr,
    Fallback,
    Persisting,
    Completed,
    Cancelled,
    Failed,
}

/// Progress belongs to one scan and, once resolved, one retained run.
#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub scan_id: Uuid,
    pub run_id: Option<Uuid>,
    pub phase: ScanPhase,
    pub total_inputs: Option<usize>,
    pub input_limit_reached: bool,
    pub processed_inputs: Option<usize>,
    pub findings: usize,
    pub elapsed_secs: u64,
}

pub(super) struct ScanControl {
    pub(super) cancel: CancellationToken,
    started: Instant,
    progress: Mutex<ScanProgress>,
    listener: Arc<dyn Fn(ScanProgress) + Send + Sync>,
    failure: Mutex<Option<String>>,
}

impl ScanControl {
    pub(super) fn fail(&self, detail: String) {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(detail);
        self.cancel.cancel();
    }

    pub(super) fn update(&self, change: impl FnOnce(&mut ScanProgress)) {
        let event = {
            let mut progress = self
                .progress
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            change(&mut progress);
            progress.elapsed_secs = self.started.elapsed().as_secs();
            progress.clone()
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.listener)(event)))
            .is_err()
        {
            tracing::warn!("crash scan progress listener panicked");
        }
    }

    fn casr_line(&self, line: &str) {
        let Some(counts) = line
            .split_once("[INFO] Progress: ")
            .map(|(_, counts)| counts)
        else {
            return;
        };
        let Some((done, total)) = counts.trim().split_once('/') else {
            return;
        };
        let (Ok(done), Ok(total)) = (done.parse::<usize>(), total.parse::<usize>()) else {
            return;
        };
        self.update(|progress| {
            if progress.phase == ScanPhase::Casr
                && progress.total_inputs == Some(total)
                && done <= total
            {
                progress.processed_inputs = Some(progress.processed_inputs.unwrap_or(0).max(done));
            }
        });
    }
}

impl ServiceContainer {
    /// Classify the latest attributable run without model calls or minimization.
    /// The caller must subscribe to progress before submitting its scan UUID.
    ///
    /// # Errors
    /// Reports invalid evidence, sandbox failures, deadline expiry, or cancellation.
    /// Completed classifications are retained even when cancelled.
    pub async fn scan_crashes(
        &self,
        project: &Path,
        target: &str,
        scan_id: Uuid,
        listener: Arc<dyn Fn(ScanProgress) + Send + Sync>,
    ) -> Result<Vec<Crash>, ClassifiedError> {
        let mut registration = self.crash_scans.register(scan_id)?;
        let control = Arc::new(ScanControl {
            cancel: registration.token().clone(),
            started: Instant::now(),
            progress: Mutex::new(ScanProgress {
                scan_id,
                run_id: None,
                phase: ScanPhase::Queued,
                total_inputs: None,
                input_limit_reached: false,
                processed_inputs: None,
                findings: 0,
                elapsed_secs: 0,
            }),
            listener,
            failure: Mutex::new(None),
        });
        let mut scoped = self.clone();
        scoped.scan_control = Some(control.clone());
        control.update(|_| {});
        let work = scoped.triage(project, target, AiPolicy::Off);
        tokio::pin!(work);
        let deadline = tokio::time::sleep(std::time::Duration::from_mins(5));
        tokio::pin!(deadline);
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(1));
        let result = loop {
            tokio::select! {
                result = &mut work => break result,
                () = &mut deadline => {
                    control.fail("crash scan exceeded its 300 second budget; completed findings were retained".to_owned());
                    // Await runtime teardown and retention of completed classifications.
                    break work.await;
                }
                _ = heartbeat.tick() => control.update(|_| {}),
            }
        };
        let completed = registration.commit();
        let failure = control
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let result = if let Some(detail) = failure {
            Err(ClassifiedError::Sandbox(detail))
        } else if !completed && result.is_ok() {
            Err(ClassifiedError::Cancelled)
        } else {
            result
        };
        control.update(|event| {
            if let Ok(crashes) = &result {
                event.findings = crashes.len();
            }
            event.phase = match &result {
                Ok(_) => ScanPhase::Completed,
                Err(ClassifiedError::Cancelled) => ScanPhase::Cancelled,
                Err(_) => ScanPhase::Failed,
            };
        });
        result
    }

    /// Request a stop; the scan response acknowledges completed sandbox teardown.
    pub fn cancel_crash_scan(&self, scan_id: Uuid) -> OperationCancelOutcome {
        self.crash_scans.cancel(scan_id)
    }

    pub(super) fn scan_cancelled(&self) -> bool {
        self.scan_control
            .as_ref()
            .is_some_and(|control| control.cancel.is_cancelled())
    }

    pub(super) fn scan_progress(&self, change: impl FnOnce(&mut ScanProgress)) {
        if let Some(control) = &self.scan_control {
            control.update(change);
        }
    }

    pub(super) async fn scan_command(
        &self,
        cmd: &[String],
        workspace: &Path,
        limits: &ResourceLimits,
        sandbox: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        let Some(control) = &self.scan_control else {
            return self
                .runtime
                .run_command_opts(cmd, workspace, limits, sandbox)
                .await;
        };
        let on_line = |line: &str| control.casr_line(line);
        self.runtime
            .run_command_streaming_opts(cmd, workspace, limits, sandbox, &control.cancel, &on_line)
            .await
    }
}
