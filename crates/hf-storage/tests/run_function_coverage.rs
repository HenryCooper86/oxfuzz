use hf_storage::{RunFunctionCoverageRecord, RunRecord, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[tokio::test]
async fn function_evidence_is_owned_by_the_exact_run_and_cannot_be_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("coverage.db"))
        .await
        .unwrap();
    let mut run = RunRecord::new(
        "/project",
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    run.binary_rev = Some("a".repeat(64));
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "b".repeat(64)));
    store.insert_run(&run).await.unwrap();
    let export = r#"{"data":[{"functions":[]}]}"#.to_owned();
    let record = RunFunctionCoverageRecord {
        run_id: run.id,
        binary_sha256: run.binary_rev.unwrap(),
        sandbox_rev: run.sandbox_rev.unwrap(),
        profile_sha256: "c".repeat(64),
        export_sha256: format!("{:x}", Sha256::digest(export.as_bytes())),
        export_json: export,
        collected_at: chrono::Utc::now(),
    };
    let mut wrong = record.clone();
    wrong.run_id = Uuid::new_v4();
    assert!(store.record_run_function_coverage(&wrong).await.is_err());
    wrong = record.clone();
    wrong.binary_sha256 = "d".repeat(64);
    assert!(store.record_run_function_coverage(&wrong).await.is_err());
    store.record_run_function_coverage(&record).await.unwrap();
    store.record_run_function_coverage(&record).await.unwrap();
    wrong = record.clone();
    wrong.profile_sha256 = "e".repeat(64);
    assert!(store.record_run_function_coverage(&wrong).await.is_err());
    assert_eq!(
        store.run_function_coverage(run.id).await.unwrap(),
        Some(record)
    );
}
