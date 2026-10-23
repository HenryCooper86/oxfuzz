use hf_storage::{HarnessBehaviorRecord, RunRecord, Store};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn behavioral_evidence_rejects_substitution_and_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("behavior.db"))
        .await
        .unwrap();
    let mut run = RunRecord::new(
        "/project",
        hf_core::engine::EngineKind::AflPlusPlus,
        None,
        chrono::Utc::now(),
    );
    run.harness_rev = Some("a".repeat(64));
    run.binary_rev = Some("b".repeat(64));
    run.sandbox_rev = Some("image".to_owned());
    store.insert_run(&run).await.unwrap();
    let report_json = "{\"version\":1}".to_owned();
    let record = HarnessBehaviorRecord {
        run_id: run.id,
        source_sha256: run.harness_rev.unwrap(),
        binary_sha256: run.binary_rev.unwrap(),
        sandbox_rev: run.sandbox_rev.unwrap(),
        report_sha256: format!("{:x}", Sha256::digest(report_json.as_bytes())),
        report_json,
    };
    let mut wrong = record.clone();
    wrong.source_sha256 = "c".repeat(64);
    assert!(store.record_harness_behavior(&wrong).await.is_err());
    store.record_harness_behavior(&record).await.unwrap();
    store.record_harness_behavior(&record).await.unwrap();
    wrong = record.clone();
    wrong.report_json = "{\"version\":2}".to_owned();
    wrong.report_sha256 = format!("{:x}", Sha256::digest(wrong.report_json.as_bytes()));
    assert!(store.record_harness_behavior(&wrong).await.is_err());
    assert_eq!(store.harness_behavior(run.id).await.unwrap(), Some(record));
}
