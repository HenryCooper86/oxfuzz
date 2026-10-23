//! Owner-aware recovery of durable experiment reservations, including pre-journal loss.
use std::fs::{File, OpenOptions, TryLockError};
use std::path::PathBuf;

use hf_core::error::ClassifiedError;
use hf_storage::Store;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn lease_path(store: &Store, id: Uuid) -> Result<PathBuf, ClassifiedError> {
    let options = store.pool().connect_options();
    let database = std::fs::canonicalize(options.get_filename()).map_err(|error| {
        ClassifiedError::Storage(format!("resolve guided run ownership database: {error}"))
    })?;
    let directory = database
        .parent()
        .ok_or_else(|| {
            ClassifiedError::Storage("guided run database has no parent directory".into())
        })?
        .join(".oxfuzz-run-locks");
    std::fs::create_dir_all(&directory).map_err(|error| {
        ClassifiedError::Storage(format!("create guided run lease directory: {error}"))
    })?;
    let digest = Sha256::digest(database.as_os_str().as_encoded_bytes());
    Ok(directory.join(format!("guided-{digest:x}-{id}.lock")))
}

/// File lifetime owns the execution; process loss releases the OS lock.
/// Busy ownership is distinct from an inaccessible or invalid lease.
pub(crate) fn try_acquire(store: &Store, id: Uuid) -> Result<Option<File>, ClassifiedError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lease_path(store, id)?)
        .map_err(|error| ClassifiedError::Storage(format!("open guided run lease: {error}")))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(ClassifiedError::Storage(format!(
            "acquire guided run lease: {error}"
        ))),
    }
}

pub(super) async fn recover_unowned(store: &Store) -> Result<usize, ClassifiedError> {
    let mut repaired = 0;
    let mut cursor = String::new();
    loop {
        let runs = store.unfinished_guided_runs_after(&cursor).await?;
        if runs.is_empty() {
            return Ok(repaired);
        }
        for id in runs {
            cursor = id.to_string();
            if let Some(_owner) = try_acquire(store, id)? {
                repaired += usize::from(store.recover_guided_experiment_run(id).await?);
            }
        }
    }
}

#[cfg(all(test, feature = "coverage-experiments"))]
use crate::retained_campaign_fixture;

#[cfg(all(test, feature = "coverage-experiments"))]
mod tests {
    use super::*;
    use crate::coverage_experiments::{CoverageExperimentKind, CreateCoverageExperimentRequest};
    use crate::recovery::{reconcile_interrupted_run_statuses, RunJournal};
    use hf_storage::RunStatus;
    use std::sync::Arc;

    async fn reserved() -> (tempfile::TempDir, Store, Uuid, Uuid, String) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::connect(dir.path().join("guided.db")).await.unwrap());
        let project = dir.path().canonicalize().unwrap();
        let baseline = super::retained_campaign_fixture::retained_campaign(
            &store,
            project.to_str().unwrap(),
            chrono::Utc::now() - chrono::Duration::seconds(120),
        )
        .await;
        let target_id = store
            .coverage_experiment_run_evidence(baseline.id)
            .await
            .unwrap()
            .target_id;
        let service = crate::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(store.clone());
        let experiment = service
            .create_coverage_experiment(CreateCoverageExperimentRequest {
                project: project.clone(),
                target_id,
                baseline_run_id: baseline.id,
                kind: CoverageExperimentKind::GrowCorpus,
                goal_function: "parse_value".into(),
                hypothesis: "Additional seed".into(),
                duration_secs: 60,
            })
            .await
            .unwrap();
        let mut run = baseline.clone();
        run.id = Uuid::new_v4();
        run.started_at = chrono::Utc::now();
        run.status = RunStatus::Running;
        run.ended_at = None;
        let config = run.config.as_mut().unwrap();
        config.replay_of = Some(baseline.id);
        let review = serde_json::to_string(&crate::ReplayReview {
            experiment_id: Some(experiment.id),
            current_input_sha256: Some("a".repeat(64)),
            run_id: baseline.id,
            project,
            target: "parse_value".into(),
            engine: run.engine,
            seed: config.seed.unwrap().to_string(),
            duration_secs: 60,
            max_mem_mb: config.max_mem_mb.to_string(),
            max_cpus: config.max_cpus,
            input_manifest_sha256: None,
            inputs: crate::ReplayInputs::Current,
        })
        .unwrap();
        store
            .insert_coverage_experiment_run(experiment.id, &run, &review)
            .await
            .unwrap();
        let reopened = Store::connect(dir.path().join("guided.db")).await.unwrap();
        (dir, reopened, experiment.id, run.id, review)
    }

    #[tokio::test]
    async fn independent_owner_blocks_empty_and_nonempty_journal_recovery() {
        let (dir, store, experiment, id, review) = reserved().await;
        let owner_store = Store::connect(dir.path().join("guided.db")).await.unwrap();
        let owner = try_acquire(&owner_store, id).unwrap().unwrap();
        assert!(try_acquire(&store, id).unwrap().is_none());
        let path = dir.path().join("journal.jsonl");
        let empty = RunJournal::open(path.clone());
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &empty)
                .await
                .unwrap(),
            0
        );
        empty.open_run(
            id,
            dir.path(),
            "parse_value",
            hf_core::engine::EngineKind::LibFuzzer,
        );
        let reopened = RunJournal::open(path);
        assert_eq!(reopened.interrupted().len(), 1);
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &reopened)
                .await
                .unwrap(),
            0
        );
        let live = store.get_run(id).await.unwrap().unwrap();
        assert_eq!(live.status, RunStatus::Running);
        assert!(live.ended_at.is_none());
        drop(owner);
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &reopened)
                .await
                .unwrap(),
            1
        );
        let execution = store
            .coverage_experiment_execution(experiment)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(execution.run_id, id);
        assert_eq!(execution.review_json, review);
        assert_eq!(
            store.get_run(id).await.unwrap().unwrap().status,
            RunStatus::Failed
        );
    }

    #[tokio::test]
    async fn inaccessible_lease_preserves_unfinished_evidence() {
        let (_dir, store, experiment, id, _) = reserved().await;
        std::fs::create_dir(lease_path(&store, id).unwrap()).unwrap();
        let error = reconcile_interrupted_run_statuses(&store, &RunJournal::in_memory())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("open guided run lease"));
        assert_eq!(
            store.get_run(id).await.unwrap().unwrap().status,
            RunStatus::Running
        );
        assert_eq!(
            store
                .coverage_experiment_execution(experiment)
                .await
                .unwrap()
                .unwrap()
                .run_id,
            id
        );
    }

    #[tokio::test]
    async fn terminal_guided_result_survives_a_missing_journal_close() {
        let (dir, store, _, id, _) = reserved().await;
        store
            .set_run_status(id, RunStatus::Done, Some(chrono::Utc::now()))
            .await
            .unwrap();
        let path = dir.path().join("journal.jsonl");
        RunJournal::open(path.clone()).open_run(
            id,
            dir.path(),
            "parse_value",
            hf_core::engine::EngineKind::LibFuzzer,
        );
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &RunJournal::open(path))
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store.get_run(id).await.unwrap().unwrap().status,
            RunStatus::Done
        );
    }
}
