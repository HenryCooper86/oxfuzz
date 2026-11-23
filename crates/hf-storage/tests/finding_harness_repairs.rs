//! Retained finding-driven harness repair requests (migration 0055).

use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_storage::{
    FindingHarnessRepairCompletion, FindingHarnessRepairOutcome, FindingHarnessRepairRecord,
    RunRecord, Store,
};
use std::path::PathBuf;
use uuid::Uuid;

async fn store_with_crash() -> (tempfile::TempDir, Store, Crash) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("repairs.db"))
        .await
        .unwrap();
    let run = RunRecord::new(
        "/project",
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    let crash = Crash {
        control_replay: None,
        reproduction: None,
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("/work/out/crash-1"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "fault".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Harness,
    };
    store
        .upsert_crashes(std::slice::from_ref(&crash))
        .await
        .unwrap();
    (directory, store, crash)
}

fn record(crash: &Crash) -> FindingHarnessRepairRecord {
    FindingHarnessRepairRecord {
        id: Uuid::new_v4(),
        crash_id: crash.id,
        run_id: crash.run_id,
        project_root: "/project".to_owned(),
        prompt_version: 1,
        base_source_sha256: "a".repeat(64),
        prompt: "repair this harness".to_owned(),
        response: None,
        outcome: None,
        detail: None,
        harness_id: None,
        created_at: chrono::Utc::now(),
        completed_at: None,
    }
}

#[tokio::test]
async fn a_repair_is_retained_before_dispatch_and_completed_once() {
    let (_directory, store, crash) = store_with_crash().await;
    let pending = record(&crash);
    store.begin_finding_harness_repair(&pending).await.unwrap();
    let harness_id = Uuid::new_v4();

    store
        .complete_finding_harness_repair(
            pending.id,
            &FindingHarnessRepairCompletion {
                response: Some("```c\nint x;\n```"),
                outcome: FindingHarnessRepairOutcome::Proposed,
                detail: "compiled",
                harness_id: Some(harness_id),
            },
            chrono::Utc::now(),
        )
        .await
        .unwrap();

    let stored = store
        .finding_harness_repairs_for_crash(crash.id)
        .await
        .unwrap();
    assert_eq!(
        stored[0].outcome,
        Some(FindingHarnessRepairOutcome::Proposed)
    );
    assert_eq!(stored[0].harness_id, Some(harness_id));
    assert!(store
        .complete_finding_harness_repair(
            pending.id,
            &FindingHarnessRepairCompletion {
                response: None,
                outcome: FindingHarnessRepairOutcome::Failed,
                detail: "again",
                harness_id: None,
            },
            chrono::Utc::now(),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn only_a_proposal_names_a_revision() {
    let (_directory, store, crash) = store_with_crash().await;
    let pending = record(&crash);
    store.begin_finding_harness_repair(&pending).await.unwrap();

    for (outcome, harness_id) in [
        (FindingHarnessRepairOutcome::Proposed, None),
        (FindingHarnessRepairOutcome::Rejected, Some(Uuid::new_v4())),
    ] {
        assert!(store
            .complete_finding_harness_repair(
                pending.id,
                &FindingHarnessRepairCompletion {
                    response: None,
                    outcome,
                    detail: "invalid",
                    harness_id,
                },
                chrono::Utc::now(),
            )
            .await
            .is_err());
    }
}

#[tokio::test]
async fn an_oversized_prompt_is_not_retained() {
    let (_directory, store, crash) = store_with_crash().await;
    let mut oversized = record(&crash);
    oversized.prompt = "x".repeat(hf_storage::MAX_FINDING_HARNESS_REPAIR_BYTES + 1);

    assert!(store
        .begin_finding_harness_repair(&oversized)
        .await
        .is_err());
}
