//! Retained bug-report drafting requests and responses (migration 0046).

use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_storage::{CrashReportDraftRecord, RunRecord, Store};
use std::path::PathBuf;
use uuid::Uuid;

async fn store_with_crash(project: &str) -> (tempfile::TempDir, Store, Crash) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("drafts.db"))
        .await
        .unwrap();
    let run = RunRecord::new(
        project,
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    let crash = Crash {
        reproduction: None,
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("/work/out/crash-1"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    store
        .upsert_crashes(std::slice::from_ref(&crash))
        .await
        .unwrap();
    (directory, store, crash)
}

fn draft(crash: &Crash, project: &str) -> CrashReportDraftRecord {
    CrashReportDraftRecord {
        id: Uuid::new_v4(),
        crash_id: crash.id,
        run_id: crash.run_id,
        project_root: project.to_owned(),
        prompt_version: 2,
        prompt: "You are the triage-agent for oxfuzz. ...".to_owned(),
        response: None,
        created_at: chrono::Utc::now(),
        completed_at: None,
    }
}

#[tokio::test]
async fn a_draft_is_retained_before_dispatch_and_completed_once() {
    let (_dir, store, crash) = store_with_crash("/project").await;
    let record = draft(&crash, "/project");
    store.begin_crash_report_draft(&record).await.unwrap();
    let pending = store.crash_report_drafts_for_crash(crash.id).await.unwrap();
    assert_eq!(pending, vec![record.clone()]);

    let completed_at = chrono::Utc::now();
    store
        .complete_crash_report_draft(record.id, "{\"title\":\"t\"}", completed_at)
        .await
        .unwrap();
    let done = store.crash_report_drafts_for_crash(crash.id).await.unwrap();
    assert_eq!(done[0].response.as_deref(), Some("{\"title\":\"t\"}"));
    assert_eq!(done[0].completed_at, Some(completed_at));
    assert_eq!(done[0].prompt, record.prompt, "the prompt never changes");

    // The response is written once.
    assert!(store
        .complete_crash_report_draft(record.id, "other", chrono::Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn a_draft_for_an_unknown_crash_is_refused() {
    let (_dir, store, crash) = store_with_crash("/project").await;
    let mut orphan = draft(&crash, "/project");
    orphan.crash_id = Uuid::new_v4();
    assert!(store.begin_crash_report_draft(&orphan).await.is_err());
}

#[tokio::test]
async fn oversized_prompts_and_responses_are_refused() {
    let (_dir, store, crash) = store_with_crash("/project").await;
    let mut big = draft(&crash, "/project");
    big.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_crash_report_draft(&big).await.is_err());
    let record = draft(&crash, "/project");
    store.begin_crash_report_draft(&record).await.unwrap();
    assert!(store
        .complete_crash_report_draft(record.id, &"y".repeat(64 * 1024 + 1), chrono::Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn deleting_the_crash_or_the_project_removes_its_drafts() {
    let (_dir, store, crash) = store_with_crash("/project").await;
    store
        .begin_crash_report_draft(&draft(&crash, "/project"))
        .await
        .unwrap();
    store.delete_run(&crash.run_id.to_string()).await.unwrap();
    assert!(store
        .crash_report_drafts_for_crash(crash.id)
        .await
        .unwrap()
        .is_empty());

    let (_dir2, store, crash) = store_with_crash("/other").await;
    store
        .begin_crash_report_draft(&draft(&crash, "/other"))
        .await
        .unwrap();
    store.delete_project("/other").await.unwrap();
    assert!(store
        .crash_report_drafts_for_crash(crash.id)
        .await
        .unwrap()
        .is_empty());
}
