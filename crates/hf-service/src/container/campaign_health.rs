//! Gathering for Campaign Health.
//!
//! The assessment itself is pure (`crate::campaign_health`); this reads the
//! retained run state it judges. An unknown figure is passed as unknown, never
//! as its worst case.

use chrono::Utc;
use uuid::Uuid;

use crate::campaign_health::{
    assess_campaign_health, CampaignHealthInput, CampaignHealthReport, CampaignHealthSettings,
};
use crate::container::ServiceContainer;
use crate::ClassifiedError;

impl ServiceContainer {
    /// Assess one run against the operator's health thresholds.
    ///
    /// Reads retained state only. Never stops, restarts, or resizes a
    /// campaign: run control has an approval path (AGENTS.md 2.19).
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the run is unknown, the
    /// store is not configured, or the configured thresholds are invalid.
    pub async fn campaign_health(
        &self,
        run_id: Uuid,
    ) -> Result<CampaignHealthReport, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign health requires the persistent store".to_owned())
        })?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Validation(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run '{run_id}' not found")))?;

        // An invalid manually-edited threshold fails closed rather than
        // silently reverting to a policy the operator did not choose.
        let settings: CampaignHealthSettings = crate::config::effective_campaign_health_settings()
            .map_err(|e| ClassifiedError::Validation(format!("campaign health thresholds: {e}")))?;

        let coverage_series = self.run_coverage_series(&run_id.to_string()).await?;
        let progress_stale_secs = progress_stale_secs(&run, &coverage_series);

        Ok(assess_campaign_health(
            &CampaignHealthInput {
                run_id,
                run_status: run.status,
                coverage_series,
                // Live engine process counts are not retained, and an unknown
                // count must not be reported as a missing worker. Zero expected
                // yields no condition.
                workers_expected: 0,
                workers_alive: 0,
                progress_stale_secs,
                // See docs/design/campaign-health-design.md section 3: free
                // space needs a cross-platform call this workspace has no
                // dependency for yet.
                free_disk_bytes: None,
            },
            &settings,
        ))
    }
}

/// Seconds since the run's progress record last advanced.
///
/// Derived from the last retained coverage sample, whose `t` is seconds since
/// the run started. `None` when there is no sample to measure from, so an
/// absent series never reads as infinitely stale.
fn progress_stale_secs(
    run: &hf_storage::RunRecord,
    series: &[crate::container::CoverageSample],
) -> Option<u64> {
    let last = series.last()?;
    let elapsed = Utc::now()
        .signed_duration_since(run.started_at)
        .num_seconds();
    // A clock that moved backwards yields a negative elapsed; treat that as no
    // measurable staleness rather than as a huge one.
    let elapsed = u64::try_from(elapsed).ok()?;
    let sample_at = last.t.max(0.0) as u64;
    Some(elapsed.saturating_sub(sample_at))
}
