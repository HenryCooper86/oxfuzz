//! Feature-gated fixtures for presentation-layer integration tests.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_scheduler::{ExecutionStatus, Schedule, ScheduleExecution, TriggerConfig};
use hf_storage::{NewScheduleOccurrence, ScheduleOccurrenceTransition, Store};

use crate::scheduler::{CampaignParams, CampaignScheduler};
use crate::ServiceContainer;

/// Owns the resources for a one-time recovery presentation test.
pub struct OneTimeRecoveryTestFixture {
    directory: tempfile::TempDir,
    schedules_path: PathBuf,
    container: ServiceContainer,
    scheduler: Arc<CampaignScheduler>,
}

impl OneTimeRecoveryTestFixture {
    /// Returns the service container wired to the fixture's durable store.
    pub fn container(&self) -> ServiceContainer {
        self.container.clone()
    }

    /// Returns the running scheduler used by presentation tests.
    pub fn scheduler(&self) -> Arc<CampaignScheduler> {
        Arc::clone(&self.scheduler)
    }

    /// Returns the schedule definition file used by the fixture.
    pub fn schedules_path(&self) -> &Path {
        &self.schedules_path
    }

    /// Returns the temporary root used by the fixture.
    pub fn directory_path(&self) -> &Path {
        self.directory.path()
    }
}

/// Builds a service-owned fixture for recovery presentation tests.
pub async fn one_time_recovery_fixture(
    expired: bool,
) -> Result<OneTimeRecoveryTestFixture, Box<dyn Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    let schedules_path = directory.path().join("PRIVATE_PATH_MARKER.json");
    let database_path = directory.path().join("scheduler.db");
    let store = Arc::new(Store::connect(&database_path).await?);
    let triggered_at = chrono::Utc::now() - chrono::Duration::seconds(1);
    let params = CampaignParams {
        project: directory.path().display().to_string(),
        target: Some("parser".to_owned()),
        engine: "libfuzzer".to_owned(),
        lang: "c".to_owned(),
        duration_secs: 1,
        max_runs: Some(1),
        max_total_secs: None,
        schedule_id: "schedule-web".to_owned(),
    };
    let schedule = Schedule::new(
        "schedule-web",
        "web recovery",
        TriggerConfig::OneTime { at: triggered_at },
        "fuzz-campaign",
    )
    .with_params(serde_json::to_value(params)?);
    std::fs::write(&schedules_path, serde_json::to_vec_pretty(&vec![schedule])?)?;

    let pending = ScheduleExecution {
        execution_id: "exec-web".to_owned(),
        schedule_id: "schedule-web".to_owned(),
        triggered_at,
        started_at: None,
        completed_at: None,
        status: ExecutionStatus::Pending,
        workflow_execution_id: None,
        request_summary: serde_json::json!({}),
        response_summary: serde_json::json!({}),
        error_message: None,
    };
    store
        .reserve_schedule_occurrence(&NewScheduleOccurrence {
            id: "occ-web".to_owned(),
            schedule_id: "schedule-web".to_owned(),
            execution_id: "exec-web".to_owned(),
            triggered_at: triggered_at.to_rfc3339(),
            owner_id: "web-fixture".to_owned(),
            lease_expires_at: (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            execution_status: "pending".to_owned(),
            execution_data_json: serde_json::to_string(&pending)?,
        })
        .await?;
    let mut running = pending;
    running.status = ExecutionStatus::Running;
    running.started_at = Some(triggered_at);
    store
        .transition_schedule_occurrence(&ScheduleOccurrenceTransition {
            occurrence_id: "occ-web".to_owned(),
            schedule_id: "schedule-web".to_owned(),
            execution_id: "exec-web".to_owned(),
            owner_id: "web-fixture".to_owned(),
            from_state: "reserved".to_owned(),
            to_state: "running".to_owned(),
            lease_expires_at: Some(
                (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
            ),
            recovery_detail: None,
            execution_status: "running".to_owned(),
            execution_data_json: serde_json::to_string(&running)?,
        })
        .await?;
    if expired {
        store
            .release_schedule_occurrence_lease(
                "occ-web",
                "web-fixture",
                &chrono::Utc::now().to_rfc3339(),
                "terminal outcome is unknown",
            )
            .await?;
    }

    let container = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let scheduler = Arc::new(
        CampaignScheduler::try_start(container.clone(), schedules_path.clone(), None).await?,
    );
    Ok(OneTimeRecoveryTestFixture {
        directory,
        schedules_path,
        container,
        scheduler,
    })
}
