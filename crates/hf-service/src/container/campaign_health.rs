//! Run-scoped gathering, retention, and delivery for Campaign Health.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::campaign_health::{
    assess_campaign_health, CampaignHealthInput, CampaignHealthReport, CampaignHealthSettings,
    HealthEvent,
};
use crate::container::ServiceContainer;
use crate::ClassifiedError;

struct GatheredHealth {
    input: CampaignHealthInput,
    telemetry: Option<hf_storage::RunTelemetryRecord>,
    edges: Option<u64>,
    rejected_as_older: bool,
}

impl ServiceContainer {
    /// Bind the existing presentation event channel to durable health events.
    /// The callback runs only after `SQLite` admits the event.
    pub fn bind_campaign_health_delivery(&self, delivery: super::CampaignHealthDelivery) {
        if let Ok(mut slot) = self.campaign_health_delivery.lock() {
            *slot = Some(delivery);
        }
    }

    /// Read strictly decoded retained health events for one campaign.
    ///
    /// # Errors
    /// Returns an error for a missing/non-campaign run or malformed evidence.
    pub async fn campaign_health_events(
        &self,
        run_id: Uuid,
    ) -> Result<Vec<HealthEvent>, ClassifiedError> {
        Ok(self
            .campaign_health_event_page(
                run_id,
                None,
                hf_storage::MAX_CAMPAIGN_HEALTH_EVENT_PAGE_SIZE,
            )
            .await?
            .events)
    }

    /// Read one deterministic newest-first page of retained health events.
    ///
    /// # Errors
    /// Returns an error for a missing/non-campaign run, invalid/foreign cursor
    /// or limit, or malformed retained evidence.
    pub async fn campaign_health_event_page(
        &self,
        run_id: Uuid,
        cursor: Option<Uuid>,
        limit: u32,
    ) -> Result<crate::campaign_health::CampaignHealthEventPage, ClassifiedError> {
        if !(1..=hf_storage::MAX_CAMPAIGN_HEALTH_EVENT_PAGE_SIZE).contains(&limit) {
            return Err(ClassifiedError::Validation(format!(
                "campaign health event limit must be between 1 and {}",
                hf_storage::MAX_CAMPAIGN_HEALTH_EVENT_PAGE_SIZE
            )));
        }
        let run = self.run_record(run_id).await?;
        if run.kind != hf_storage::RunKind::Campaign {
            return Err(ClassifiedError::Validation(format!(
                "run '{run_id}' is not a campaign"
            )));
        }
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign health requires persistent storage".to_owned())
        })?;
        let page = store
            .campaign_health_event_page(run_id, cursor, limit)
            .await
            .map_err(|error| match error {
                hf_storage::StorageError::InvalidData(message) => {
                    ClassifiedError::Validation(message)
                }
                other => ClassifiedError::Storage(other.to_string()),
            })?;
        let events = page
            .events
            .into_iter()
            .map(health_event_from_record)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(crate::campaign_health::CampaignHealthEventPage {
            events,
            next_cursor: page.next_cursor,
        })
    }

    /// Build retained overnight categories for one canonical project.
    ///
    /// # Errors
    /// Returns an error when storage or retained closeout/event evidence is
    /// malformed.
    pub async fn morning_health_summary(
        &self,
        project: &std::path::Path,
        observed_at: DateTime<Utc>,
    ) -> Result<crate::campaign_health::MorningHealthSummary, ClassifiedError> {
        let settings = resolved_settings()?;
        let hours = i64::try_from(settings.morning_summary_lookback_hours).map_err(|_| {
            ClassifiedError::Validation("campaign health lookback is too large".to_owned())
        })?;
        let lookback = chrono::TimeDelta::try_hours(hours).ok_or_else(|| {
            ClassifiedError::Validation("campaign health lookback is too large".to_owned())
        })?;
        let since = observed_at - lookback;
        let identity = super::project_identity::project_lookup_identity(project);
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign health requires persistent storage".to_owned())
        })?;
        let runs = store
            .list_runs(None)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .filter(|run| {
                run.kind == hf_storage::RunKind::Campaign
                    && run.started_at >= since
                    && super::project_identity::stored_project_matches(
                        std::path::Path::new(&run.project_root),
                        &identity,
                    )
            })
            .collect::<Vec<_>>();
        let interrupted_ids = self
            .interrupted_runs()
            .into_iter()
            .filter_map(|entry| match Uuid::parse_str(&entry.run_id) {
                Ok(run_id) => Some(run_id),
                Err(error) => {
                    tracing::warn!(run_id = %entry.run_id, %error, "ignoring malformed recovery journal run id");
                    None
                }
            })
            .collect::<std::collections::HashSet<_>>();
        let mut summary = crate::campaign_health::MorningHealthSummary {
            schema_version: crate::campaign_health::CAMPAIGN_HEALTH_SCHEMA_VERSION,
            project_root: identity.to_string_lossy().into_owned(),
            since,
            failed: Vec::new(),
            stalled: Vec::new(),
            interrupted: Vec::new(),
            unprocessed: Vec::new(),
        };
        for run in runs {
            if run.status == hf_storage::RunStatus::Failed {
                summary.failed.push(run.id);
            }
            if interrupted_ids.contains(&run.id) {
                summary.interrupted.push(run.id);
            }
            let conditions = store
                .campaign_health_event_conditions(run.id)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
            if conditions.iter().any(|condition| {
                matches!(
                    condition.as_str(),
                    "coverage_plateau" | "managed_invocation_missing" | "worker_stats_stale"
                )
            }) {
                summary.stalled.push(run.id);
            }
            if matches!(
                run.status,
                hf_storage::RunStatus::Done
                    | hf_storage::RunStatus::Failed
                    | hf_storage::RunStatus::Cancelled
            ) && closeout_is_unprocessed(store, run.id).await?
            {
                summary.unprocessed.push(run.id);
            }
        }
        for ids in [
            &mut summary.failed,
            &mut summary.stalled,
            &mut summary.interrupted,
            &mut summary.unprocessed,
        ] {
            ids.sort_unstable();
            ids.dedup();
        }
        Ok(summary)
    }

    /// Return a clone of this process's live telemetry for one run.
    #[must_use]
    pub fn live_campaign_telemetry(
        &self,
        run_id: Uuid,
    ) -> Option<crate::campaign_health::RunTelemetryObservation> {
        self.campaign_telemetry.snapshot(run_id)
    }

    /// Read the authoritative cumulative telemetry for one campaign.
    ///
    /// # Errors
    /// Returns an error for a missing/non-campaign run or malformed retention.
    pub async fn campaign_telemetry(
        &self,
        run_id: Uuid,
    ) -> Result<crate::campaign_health::CampaignTelemetryView, ClassifiedError> {
        let gathered = self.gather_campaign_health(run_id, Utc::now()).await?;
        let edges = gathered.edges;
        let input = gathered.input;
        Ok(crate::campaign_health::CampaignTelemetryView {
            schema_version: crate::campaign_health::CAMPAIGN_HEALTH_SCHEMA_VERSION,
            run_id: input.run_id,
            observed_at: input.observed_at,
            last_progress_at: input.last_progress_at,
            coverage_series: input.coverage_series,
            current_execs: input.current_execs,
            mean_execs: input.mean_execs,
            peak_execs: input.peak_execs,
            throughput_sample_count: input.throughput_sample_count,
            throughput_sample_sum: input.throughput_sample_sum,
            edges,
            managed_invocations_expected: input.managed_invocations_expected,
            managed_invocations_alive: input.managed_invocations_alive,
            free_disk_bytes: input.free_disk_bytes,
        })
    }

    /// Compute a read-only current assessment. Candidate conditions have no
    /// durable event ID until admitted through the periodic emitter.
    ///
    /// # Errors
    /// Returns an error for missing, non-campaign, or malformed retained data.
    pub async fn campaign_health(
        &self,
        run_id: Uuid,
    ) -> Result<CampaignHealthReport, ClassifiedError> {
        let settings = resolved_settings()?;
        let gathered = self.gather_campaign_health(run_id, Utc::now()).await?;
        Ok(assess_campaign_health(&gathered.input, &settings))
    }

    /// Assess, retain, and deliver conditions using the current configuration.
    ///
    /// # Errors
    /// Returns an error for unavailable or malformed state and storage failure.
    pub async fn assess_and_emit_campaign_health(
        &self,
        run_id: Uuid,
        observed_at: DateTime<Utc>,
    ) -> Result<Vec<HealthEvent>, ClassifiedError> {
        let settings = resolved_settings()?;
        self.assess_and_emit_campaign_health_with_settings(run_id, observed_at, &settings)
            .await
    }

    pub(crate) async fn assess_and_emit_campaign_health_with_settings(
        &self,
        run_id: Uuid,
        observed_at: DateTime<Utc>,
        settings: &CampaignHealthSettings,
    ) -> Result<Vec<HealthEvent>, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign health requires persistent storage".to_owned())
        })?;
        let gathered = self.gather_campaign_health(run_id, observed_at).await?;
        if gathered.rejected_as_older {
            return Ok(Vec::new());
        }
        if let Some(telemetry) = &gathered.telemetry {
            if !store
                .upsert_run_telemetry(telemetry)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            {
                return Ok(Vec::new());
            }
        }

        let report = assess_campaign_health(&gathered.input, settings);
        let mut inserted = Vec::new();
        for mut event in report.events {
            let event_id = Uuid::new_v4();
            let record = hf_storage::CampaignHealthEventRecord {
                schema_version: event.schema_version,
                id: event_id,
                run_id: event.run_id,
                dedup_key: event.dedup_key.clone(),
                condition: event.condition.as_str().to_owned(),
                severity: event.severity.as_str().to_owned(),
                detail: event.detail.clone(),
                evidence_json: serde_json::to_string(&event.evidence).map_err(|error| {
                    ClassifiedError::Internal(format!(
                        "serialize campaign health evidence: {error}"
                    ))
                })?,
                observed_at: event.observed_at,
            };
            if store
                .insert_campaign_health_event(&record)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            {
                event.id = Some(event_id);
                self.emit_scheduler_event(
                    crate::scheduler::EVENT_CAMPAIGN_HEALTH,
                    serde_json::json!({
                        "schema_version": event.schema_version,
                        "event_id": event_id,
                        "run_id": event.run_id,
                        "dedup_key": event.dedup_key,
                        "condition": event.condition,
                        "severity": event.severity,
                        "detail": event.detail,
                        "observed_at": event.observed_at,
                    }),
                )
                .await;
                // A poisoned delivery lock skips live delivery; the persisted event remains readable.
                let delivery = self
                    .campaign_health_delivery
                    .lock()
                    .ok()
                    .and_then(|slot| slot.clone());
                if let Some(delivery) = delivery {
                    match self.run_owner(event.run_id).await {
                        Ok(owner) => delivery(owner, event.clone()),
                        Err(error) => {
                            tracing::warn!(run_id = %event.run_id, %error, "health event owner is unavailable");
                        }
                    }
                }
                inserted.push(event);
            }
        }
        let retention_days = i64::try_from(settings.event_retention_days).map_err(|_| {
            ClassifiedError::Validation("campaign health retention is too large".to_owned())
        })?;
        let retention = chrono::TimeDelta::try_days(retention_days).ok_or_else(|| {
            ClassifiedError::Validation("campaign health retention is too large".to_owned())
        })?;
        store
            .prune_campaign_health_events(
                gathered.input.observed_at - retention,
                &self.active_run_ids(),
            )
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(inserted)
    }

    async fn gather_campaign_health(
        &self,
        run_id: Uuid,
        requested_at: DateTime<Utc>,
    ) -> Result<GatheredHealth, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign health requires persistent storage".to_owned())
        })?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run '{run_id}' not found")))?;
        if run.kind != hf_storage::RunKind::Campaign {
            return Err(ClassifiedError::Validation(format!(
                "run '{run_id}' is not a campaign"
            )));
        }

        if let Some(live) = self.live_campaign_telemetry(run_id) {
            let observed_at = live
                .last_progress_at
                .map_or(requested_at, |last| requested_at.max(last));
            let free_disk_bytes = workspace_capacity(run_id);
            let samples = live
                .coverage_series
                .iter()
                .map(|sample| hf_storage::RetainedHealthSample {
                    elapsed_secs: sample.t,
                    edges: sample.edges,
                    execs: sample.execs,
                })
                .collect::<Vec<_>>();
            let telemetry = hf_storage::RunTelemetryRecord {
                run_id,
                observed_at,
                last_progress_at: live.last_progress_at,
                samples_json: serde_json::to_string(&samples).map_err(|error| {
                    ClassifiedError::Internal(format!("serialize health samples: {error}"))
                })?,
                current_execs: live.current_execs,
                mean_execs: live.mean_execs,
                peak_execs: live.peak_execs,
                edges: live.edges,
                throughput_sample_count: live.throughput_sample_count,
                throughput_sample_sum: live.throughput_sample_sum,
                managed_invocations_expected: live.managed_invocations_expected,
                managed_invocations_alive: live.managed_invocations_alive,
                free_disk_bytes,
            };
            let input = input_from_telemetry(&run, &telemetry)?;
            return Ok(GatheredHealth {
                input,
                telemetry: Some(telemetry),
                edges: live.edges,
                rejected_as_older: false,
            });
        }

        if let Some(telemetry) = store
            .run_telemetry(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        {
            let rejected_as_older = requested_at < telemetry.observed_at;
            let input = input_from_telemetry(&run, &telemetry)?;
            return Ok(GatheredHealth {
                input,
                telemetry: None,
                edges: telemetry.edges,
                rejected_as_older,
            });
        }

        let coverage_series = self.run_coverage_series(&run_id.to_string()).await?;
        let progress_stale_secs = legacy_progress_stale_secs(&run, &coverage_series, requested_at);
        Ok(GatheredHealth {
            input: CampaignHealthInput {
                run_id,
                observed_at: requested_at,
                run_status: run.status,
                coverage_series,
                current_execs: None,
                mean_execs: None,
                peak_execs: if run.engine == hf_core::engine::EngineKind::Syzkaller {
                    None
                } else {
                    run.execs
                },
                throughput_sample_count: 0,
                throughput_sample_sum: 0.0,
                managed_invocations_expected: 0,
                managed_invocations_alive: 0,
                last_progress_at: None,
                progress_stale_secs,
                free_disk_bytes: None,
            },
            telemetry: None,
            edges: run.edges,
            rejected_as_older: false,
        })
    }
}

fn health_event_from_record(
    record: hf_storage::CampaignHealthEventRecord,
) -> Result<HealthEvent, ClassifiedError> {
    let condition = serde_json::from_value(serde_json::Value::String(record.condition.clone()))
        .map_err(|error| ClassifiedError::Storage(format!("decode health condition: {error}")))?;
    let severity = serde_json::from_value(serde_json::Value::String(record.severity.clone()))
        .map_err(|error| ClassifiedError::Storage(format!("decode health severity: {error}")))?;
    let evidence = serde_json::from_str(&record.evidence_json)
        .map_err(|error| ClassifiedError::Storage(format!("decode health evidence: {error}")))?;
    Ok(HealthEvent {
        schema_version: record.schema_version,
        id: Some(record.id),
        run_id: record.run_id,
        condition,
        severity,
        dedup_key: record.dedup_key,
        detail: record.detail,
        observed_at: record.observed_at,
        evidence,
    })
}

async fn closeout_is_unprocessed(
    store: &hf_storage::Store,
    run_id: Uuid,
) -> Result<bool, ClassifiedError> {
    let raw = store
        .closeout_steps(run_id)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    let mut decoded = Vec::with_capacity(raw.len());
    for (step, outcome, detail) in raw {
        let step = crate::run_closeout::decode_step(&step)
            .ok_or_else(|| ClassifiedError::Storage("unknown retained closeout step".to_owned()))?;
        let outcome =
            crate::run_closeout::decode_outcome(step, &outcome, detail).ok_or_else(|| {
                ClassifiedError::Storage("invalid retained closeout outcome".to_owned())
            })?;
        decoded.push((step, outcome));
    }
    Ok(!crate::run_closeout::pending_steps(&decoded).is_empty())
}

fn input_from_telemetry(
    run: &hf_storage::RunRecord,
    telemetry: &hf_storage::RunTelemetryRecord,
) -> Result<CampaignHealthInput, ClassifiedError> {
    let samples: Vec<hf_storage::RetainedHealthSample> =
        serde_json::from_str(&telemetry.samples_json).map_err(|error| {
            ClassifiedError::Storage(format!("decode retained campaign telemetry: {error}"))
        })?;
    Ok(CampaignHealthInput {
        run_id: run.id,
        observed_at: telemetry.observed_at,
        run_status: run.status,
        coverage_series: samples
            .into_iter()
            .map(|sample| crate::container::CoverageSample {
                t: sample.elapsed_secs,
                edges: sample.edges,
                execs: sample.execs,
            })
            .collect(),
        current_execs: telemetry.current_execs,
        mean_execs: telemetry.mean_execs,
        peak_execs: telemetry.peak_execs,
        throughput_sample_count: telemetry.throughput_sample_count,
        throughput_sample_sum: telemetry.throughput_sample_sum,
        managed_invocations_expected: telemetry.managed_invocations_expected,
        managed_invocations_alive: telemetry.managed_invocations_alive,
        last_progress_at: telemetry.last_progress_at,
        progress_stale_secs: telemetry
            .last_progress_at
            .and_then(|last| seconds_since(telemetry.observed_at, last)),
        free_disk_bytes: telemetry.free_disk_bytes,
    })
}

fn workspace_capacity(run_id: Uuid) -> Option<u64> {
    match super::health_monitor::workspace_available_bytes(&super::workspace_root()) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            tracing::warn!(%run_id, %error, "workspace capacity is unavailable");
            None
        }
    }
}

fn resolved_settings() -> Result<CampaignHealthSettings, ClassifiedError> {
    crate::config::effective_campaign_health_settings()
        .map_err(|error| ClassifiedError::Validation(format!("campaign health settings: {error}")))
}

fn seconds_since(now: DateTime<Utc>, earlier: DateTime<Utc>) -> Option<u64> {
    // A negative clock interval fails unsigned conversion and remains Unknown.
    u64::try_from(now.signed_duration_since(earlier).num_seconds()).ok()
}

fn legacy_progress_stale_secs(
    run: &hf_storage::RunRecord,
    series: &[crate::container::CoverageSample],
    observed_at: DateTime<Utc>,
) -> Option<u64> {
    let last = series.last()?;
    // A negative clock interval cannot establish elapsed time, so staleness remains Unknown.
    let elapsed = u64::try_from(
        observed_at
            .signed_duration_since(run.started_at)
            .num_seconds(),
    )
    .ok()?;
    Some(elapsed.saturating_sub(last.t.max(0.0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn insert_summary_run(
        store: &hf_storage::Store,
        id: Uuid,
        project: &std::path::Path,
        status: hf_storage::RunStatus,
        kind: hf_storage::RunKind,
        started_at: DateTime<Utc>,
    ) {
        let mut run = hf_storage::RunRecord::new(
            project.to_string_lossy(),
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            started_at,
        );
        run.id = id;
        run.status = status;
        run.kind = kind;
        store.insert_run(&run).await.unwrap();
    }

    async fn complete_closeout(store: &hf_storage::Store, run_id: Uuid) {
        for step in crate::run_closeout::closeout_ladder() {
            store
                .record_closeout_step(run_id, &format!("{step:?}"), "completed", "retained")
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn morning_summary_uses_owner_kind_journal_and_retryable_closeout_state() {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("owned");
        let foreign_project = directory.path().join("foreign");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&foreign_project).unwrap();
        let project = std::fs::canonicalize(project).unwrap();
        let foreign_project = std::fs::canonicalize(foreign_project).unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("summary.db"))
                .await
                .unwrap(),
        );
        let started_at = Utc::now() - chrono::Duration::minutes(5);
        let failed = Uuid::from_u128(50);
        let blocked_closeout = Uuid::from_u128(51);
        let completed_closeout = Uuid::from_u128(52);
        let interrupted = Uuid::from_u128(53);
        let smoke = Uuid::from_u128(54);
        let foreign = Uuid::from_u128(55);
        insert_summary_run(
            &store,
            failed,
            &project,
            hf_storage::RunStatus::Failed,
            hf_storage::RunKind::Campaign,
            started_at,
        )
        .await;
        insert_summary_run(
            &store,
            blocked_closeout,
            &project,
            hf_storage::RunStatus::Done,
            hf_storage::RunKind::Campaign,
            started_at,
        )
        .await;
        insert_summary_run(
            &store,
            completed_closeout,
            &project,
            hf_storage::RunStatus::Done,
            hf_storage::RunKind::Campaign,
            started_at,
        )
        .await;
        insert_summary_run(
            &store,
            interrupted,
            &project,
            hf_storage::RunStatus::Running,
            hf_storage::RunKind::Campaign,
            started_at,
        )
        .await;
        insert_summary_run(
            &store,
            smoke,
            &project,
            hf_storage::RunStatus::Failed,
            hf_storage::RunKind::Smoke,
            started_at,
        )
        .await;
        insert_summary_run(
            &store,
            foreign,
            &foreign_project,
            hf_storage::RunStatus::Failed,
            hf_storage::RunKind::Campaign,
            started_at,
        )
        .await;
        complete_closeout(&store, failed).await;
        store
            .record_closeout_step(blocked_closeout, "Triage", "failed", "retry")
            .await
            .unwrap();
        store
            .record_closeout_step(blocked_closeout, "Minimize", "blocked", "Triage")
            .await
            .unwrap();
        complete_closeout(&store, completed_closeout).await;

        let journal_path = directory.path().join("run-journal.jsonl");
        let journal = crate::recovery::RunJournal::open(journal_path.clone());
        for (run_id, owner) in [
            (interrupted, project.as_path()),
            (smoke, project.as_path()),
            (foreign, foreign_project.as_path()),
        ] {
            journal.open_run(
                run_id,
                owner,
                "target",
                hf_core::engine::EngineKind::LibFuzzer,
            );
        }
        drop(journal);
        let mut container =
            ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
        container.run_journal = Arc::new(crate::recovery::RunJournal::open(journal_path));

        let summary = container
            .morning_health_summary(&project, Utc::now())
            .await
            .unwrap();

        assert_eq!(summary.failed, vec![failed]);
        assert!(summary.stalled.is_empty());
        assert_eq!(summary.interrupted, vec![interrupted]);
        assert_eq!(summary.unprocessed, vec![blocked_closeout]);
    }
}
