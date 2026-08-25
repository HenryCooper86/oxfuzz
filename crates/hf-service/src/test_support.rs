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

/// Owns the resources for a Patch-to-Proof presentation test.
#[cfg(feature = "patch-to-proof")]
pub struct PatchToProofTestFixture {
    directory: tempfile::TempDir,
    container: ServiceContainer,
    operation_id: uuid::Uuid,
    finding_id: uuid::Uuid,
}

#[cfg(feature = "patch-to-proof")]
impl PatchToProofTestFixture {
    /// Returns the service container wired to the fixture's durable store.
    pub fn container(&self) -> ServiceContainer {
        self.container.clone()
    }

    /// Returns the persisted `draft` remediation operation.
    #[must_use]
    pub fn operation_id(&self) -> uuid::Uuid {
        self.operation_id
    }

    /// Returns the finding the draft operation is bound to.
    #[must_use]
    pub fn finding_id(&self) -> uuid::Uuid {
        self.finding_id
    }

    /// Returns the temporary root used by the fixture.
    #[must_use]
    pub fn directory_path(&self) -> &Path {
        self.directory.path()
    }
}

/// Builds a store-backed fixture holding one persisted `draft` remediation
/// operation, so presentation layers can exercise the durable Patch-to-Proof
/// transitions without running a sandbox.
///
/// # Errors
/// Returns an error when the temporary store cannot be created or the draft
/// record cannot be persisted.
#[cfg(feature = "patch-to-proof")]
pub async fn patch_to_proof_fixture(
) -> Result<PatchToProofTestFixture, Box<dyn Error + Send + Sync>> {
    use hf_core::crash::{Crash, CrashKind, CrashOrigin};
    use hf_core::engine::EngineKind;
    use hf_crash::remediation::{RemediationBinding, RemediationVerificationSpec};
    use hf_storage::{
        RemediationOperationRecord, RemediationOperationStage, RemediationOperationStatus,
        RunRecord,
    };

    let directory = tempfile::tempdir()?;
    let project_root = directory.path().display().to_string();
    let store = Arc::new(Store::connect(directory.path().join("remediation.db")).await?);
    let run = RunRecord::new(
        &project_root,
        EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    store.insert_run(&run).await?;
    let finding_id = uuid::Uuid::new_v4();
    store
        .upsert_crash(&Crash {
            id: finding_id,
            run_id: run.id,
            target_id: uuid::Uuid::new_v4(),
            input_path: directory.path().join("crash-input"),
            stack_signature: "parse_packet".to_owned(),
            kind: CrashKind::Asan,
            summary: "heap-buffer-overflow in parse_packet".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin: CrashOrigin::Target,
        })
        .await?;

    let spec = RemediationVerificationSpec {
        schema_version: hf_crash::remediation::REMEDIATION_VERIFICATION_SPEC_VERSION,
        engine: EngineKind::LibFuzzer,
        replay_timeout_secs: 30,
        max_regression_cases: 64,
        follow_up_fuzz_seconds: 60,
        max_mem_mb: 2048,
        max_cpus: 1,
        seed: 7,
    };
    let digest = |label: &str| -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(label.as_bytes()))
    };
    let binding = RemediationBinding {
        finding_id,
        run_id: run.id,
        source_revision_sha256: digest("source"),
        patch_sha256: digest("patch"),
        patch: "--- a/parser.c\n+++ b/parser.c\n".to_owned(),
        reproducer_sha256: digest("reproducer"),
        harness_sha256: digest("harness"),
        original_binary_sha256: digest("original-binary"),
        sandbox_image_sha256: digest("image"),
        evidence_manifest_sha256: digest("manifest"),
        regression_corpus_sha256: digest("corpus"),
        verification_spec_sha256: spec.sha256()?,
        verification_spec: spec,
    };
    let operation_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    store
        .insert_remediation_operation(&RemediationOperationRecord {
            id: operation_id,
            run_id: run.id,
            finding_id,
            project_root,
            target: "parse_packet".to_owned(),
            status: RemediationOperationStatus::Draft,
            current_stage: RemediationOperationStage::Review,
            binding_json: serde_json::to_string(&binding)?,
            approval_json: None,
            verification_json: None,
            artifact_dir: format!("remediations/{operation_id}"),
            created_at: now,
            updated_at: now,
            ended_at: None,
            failure_code: None,
            failure_message: None,
        })
        .await?;

    let container = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    Ok(PatchToProofTestFixture {
        directory,
        container,
        operation_id,
        finding_id,
    })
}
