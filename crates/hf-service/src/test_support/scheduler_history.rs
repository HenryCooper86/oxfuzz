//! Retained history fixtures with removed definitions and two project owners.

use std::{
    error::Error,
    path::{Path, PathBuf},
    sync::Arc,
};

use hf_scheduler::{ExecutionStatus, ScheduleExecution};
use hf_storage::Store;

use crate::{
    scheduler::{parse_trigger, CampaignParams, CampaignScheduler},
    ServiceContainer,
};

/// Owns inert project directories and retained execution history for adapter tests.
pub struct SchedulerHistoryTestFixture {
    _directory: tempfile::TempDir,
    approved: PathBuf,
    foreign: PathBuf,
    container: ServiceContainer,
    scheduler: Arc<CampaignScheduler>,
}

impl SchedulerHistoryTestFixture {
    /// Project permitted by the test's web policy.
    pub fn approved_project(&self) -> &Path {
        &self.approved
    }

    /// Project excluded by the test's web policy.
    pub fn foreign_project(&self) -> &Path {
        &self.foreign
    }

    /// Container with the fixture's durable store.
    pub fn container(&self) -> ServiceContainer {
        self.container.clone()
    }

    /// Disarmed scheduler with all fixture definitions removed.
    pub fn scheduler(&self) -> Arc<CampaignScheduler> {
        Arc::clone(&self.scheduler)
    }
}

/// Build retained owned/foreign history without executing a campaign.
///
/// Foreign records are newer and fill more than one storage page.
pub async fn scheduler_history_fixture(
) -> Result<SchedulerHistoryTestFixture, Box<dyn Error + Send + Sync>> {
    let directory = tempfile::tempdir()?;
    let approved = directory.path().join("approved");
    let foreign = directory.path().join("foreign");
    std::fs::create_dir(&approved)?;
    std::fs::create_dir(&foreign)?;
    let store = Arc::new(Store::connect(directory.path().join("history.db")).await?);
    let container = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let scheduler = Arc::new(
        CampaignScheduler::try_start(
            container.clone(),
            directory.path().join("schedules.json"),
            None,
        )
        .await?,
    );
    for (project, name, prefix, count, year) in [
        (&approved, "approved campaign", "approved", 2, 2025),
        (&foreign, "foreign campaign", "foreign", 130, 2026),
    ] {
        let params = CampaignParams {
            project: project.canonicalize()?.display().to_string(),
            duration_secs: 30,
            ..CampaignParams::default()
        };
        let schedule = scheduler
            .try_create(name, &params, parse_trigger("cron", "0 0 1 1 *")?)
            .await?;
        for index in 0..count {
            let execution_id = if prefix == "approved" {
                if index == 0 {
                    "approved-old".to_owned()
                } else {
                    "approved-new".to_owned()
                }
            } else {
                format!("foreign-{index:03}")
            };
            let triggered_at = format!("{year}-01-01T00:00:00Z")
                .parse::<chrono::DateTime<chrono::Utc>>()?
                + chrono::Duration::seconds(index);
            let execution = ScheduleExecution {
                execution_id: execution_id.clone(),
                schedule_id: schedule.id.clone(),
                triggered_at,
                started_at: Some(triggered_at),
                completed_at: Some(triggered_at),
                status: ExecutionStatus::Completed,
                workflow_execution_id: None,
                request_summary: serde_json::json!({"schedule_name": name, "parameter_values": schedule.parameter_values}),
                response_summary: serde_json::json!({"summary": "retained fixture"}),
                error_message: None,
            };
            store
                .upsert_schedule_execution(
                    &execution_id,
                    &schedule.id,
                    &triggered_at.to_rfc3339(),
                    "completed",
                    &serde_json::to_string(&execution)?,
                )
                .await?;
        }
        scheduler.try_remove(&schedule.id).await?;
    }
    Ok(SchedulerHistoryTestFixture {
        _directory: directory,
        approved,
        foreign,
        container,
        scheduler,
    })
}
