//! Shared presentation fixture built from retained campaign evidence.
pub use super::retained_campaign::retained_campaign;
use chrono::{Duration, Utc};
use hf_storage::{RunStatus, Store};
use uuid::Uuid;

/// Retained proposal plus one later failed campaign for both enabled and disabled adapters.
///
/// # Panics
/// Panics when disposable fixture storage or directories cannot be created.
pub async fn presentation_fixture() -> (
    tempfile::TempDir,
    crate::ServiceContainer,
    hf_storage::CoverageExperimentRecord,
    Uuid,
) {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().canonicalize().unwrap();
    let store = std::sync::Arc::new(
        Store::connect(directory.path().join("experiments.db"))
            .await
            .unwrap(),
    );
    let baseline = retained_campaign(
        &store,
        project.to_str().unwrap(),
        Utc::now() - Duration::minutes(10),
    )
    .await;
    let evidence = store
        .coverage_experiment_run_evidence(baseline.id)
        .await
        .unwrap();
    let created_at = Utc::now() - Duration::minutes(5);
    let record = hf_storage::CoverageExperimentRecord {
        id: Uuid::new_v4(),
        schema_version: 1,
        project_root: project.to_str().unwrap().into(),
        target_id: evidence.target_id,
        target_symbol: evidence.target_symbol.clone(),
        baseline_run_id: baseline.id,
        kind: hf_storage::CoverageExperimentKind::GrowCorpus,
        goal_function: "parse_value".into(),
        hypothesis: "Additional seeds may enter parse_value".into(),
        duration_secs: 60,
        baseline: evidence,
        status: hf_storage::CoverageExperimentStatus::Prepared,
        result: None,
        cancellation_reason: None,
        created_at,
        updated_at: created_at,
        ended_at: None,
    };
    store.insert_coverage_experiment(&record).await.unwrap();
    let mut result = baseline;
    result.id = Uuid::new_v4();
    result.started_at = created_at + Duration::minutes(1);
    result.ended_at = Some(result.started_at + Duration::seconds(60));
    result.status = RunStatus::Failed;
    store.insert_run(&result).await.unwrap();
    let service = crate::ServiceContainer::stubbed().with_store(store);
    (directory, service, record, result.id)
}
