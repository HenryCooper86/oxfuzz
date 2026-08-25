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

/// Owns the resources for a Change-Aware presentation test.
#[cfg(feature = "change-aware")]
pub struct ChangeAwareTestFixture {
    directory: tempfile::TempDir,
    container: ServiceContainer,
    base_run: uuid::Uuid,
    head_run: uuid::Uuid,
    target_symbol: String,
}

#[cfg(feature = "change-aware")]
impl ChangeAwareTestFixture {
    /// Returns the service container wired to the fixture's durable store.
    pub fn container(&self) -> ServiceContainer {
        self.container.clone()
    }

    /// Returns the retained base run.
    #[must_use]
    pub fn base_run(&self) -> uuid::Uuid {
        self.base_run
    }

    /// Returns the retained head run, which regressed coverage and introduced
    /// one finding relative to the base.
    #[must_use]
    pub fn head_run(&self) -> uuid::Uuid {
        self.head_run
    }

    /// Returns the discovered target's symbol.
    #[must_use]
    pub fn target_symbol(&self) -> &str {
        &self.target_symbol
    }

    /// Returns the project root used by the fixture.
    #[must_use]
    pub fn project_root(&self) -> &Path {
        self.directory.path()
    }
}

/// Builds a store-backed fixture with one discovered target and two comparable
/// retained runs: a base, and a head that introduced a finding and lost
/// coverage. Presentation layers can exercise the comparison without running a
/// campaign.
///
/// # Errors
/// Returns an error when the temporary store or its records cannot be created.
#[cfg(feature = "change-aware")]
pub async fn change_aware_fixture() -> Result<ChangeAwareTestFixture, Box<dyn Error + Send + Sync>>
{
    use hf_core::crash::{Crash, CrashKind, CrashOrigin};
    use hf_core::engine::{EngineKind, FuzzRunConfig};
    use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus};

    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("parser.c"),
        b"int parse_packet(void);\n",
    )?;
    let store = Arc::new(Store::connect(directory.path().join("change.db")).await?);

    let target = TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: directory.path().to_path_buf(),
        symbol: "parse_packet".to_owned(),
        language: TargetLanguage::C,
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: directory.path().join("parser.c"),
            line: 1,
            col: 1,
            end_line: Some(20),
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 3,
        accumulated_complexity: 3,
        reachable_functions: Vec::new(),
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: "fixture".to_owned(),
    };
    store.upsert_target(&target, chrono::Utc::now()).await?;

    let harness = Harness {
        id: uuid::Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: std::path::PathBuf::from("fuzz_parse_packet"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            chrono::Utc::now(),
        )
        .await?;

    let config = FuzzRunConfig {
        harness_id: harness.id,
        engine: EngineKind::LibFuzzer,
        duration: Some(std::time::Duration::from_secs(60)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: Some(7),
        replay_of: None,
    };
    let image = format!("docker-image-id-sha256:{}", "f".repeat(64));
    let make_run = |source: &str, edges: u64| {
        let mut run = RunRecord::new(
            directory.path().to_string_lossy(),
            EngineKind::LibFuzzer,
            Some(config.clone()),
            chrono::Utc::now(),
        );
        run.status = RunStatus::Done;
        run.ended_at = Some(chrono::Utc::now());
        run.edges = Some(edges);
        run.harness_rev = Some("a".repeat(64));
        run.binary_rev = Some("b".repeat(64));
        run.source_rev = Some(source.to_owned());
        run.corpus_rev = Some("2".repeat(64));
        run.sandbox_rev = Some(image.clone());
        run.context_rev = Some("c".repeat(64));
        run
    };
    let base = make_run(&"1".repeat(64), 1000);
    let head = make_run(&"3".repeat(64), 900);
    store.insert_run(&base).await?;
    store.insert_run(&head).await?;

    let crash = |run_id: uuid::Uuid, signature: &str| Crash {
        id: uuid::Uuid::new_v4(),
        run_id,
        target_id: target.id,
        input_path: std::path::PathBuf::from("runs/input/crash"),
        stack_signature: signature.to_owned(),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    store.upsert_crash(&crash(base.id, "shared")).await?;
    store.upsert_crash(&crash(head.id, "shared")).await?;
    store.upsert_crash(&crash(head.id, "fresh")).await?;

    let container = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    Ok(ChangeAwareTestFixture {
        directory,
        container,
        base_run: base.id,
        head_run: head.id,
        target_symbol: target.symbol,
    })
}
