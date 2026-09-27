//! Process-loss qualification for the service run journal and retained run status.

#![cfg(unix)]

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_service::recovery::{reconcile_interrupted_run_statuses, RunJournal};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

const CHILD_ROOT: &str = "OXFUZZ_RECOVERY_PROCESS_ROOT";

#[test]
fn admitted_run_survives_owner_process_loss_and_reconciles_once() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("admitted");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "recovery_process_child", "--nocapture"])
        .env(CHILD_ROOT, root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !marker.exists() && Instant::now() < deadline {
        assert!(
            child.try_wait().unwrap().is_none(),
            "admission child exited early"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    if !marker.exists() {
        child.kill().expect("stop child after admission deadline");
        child.wait().expect("reap child after admission deadline");
        panic!("durable admission was not observed");
    }
    child.kill().unwrap();
    child.wait().unwrap();

    let run_id = Uuid::parse_str(fs::read_to_string(marker).unwrap().trim()).unwrap();
    let journal = RunJournal::open(root.path().join("run_journal.jsonl"));
    assert!(journal.durability_error().is_none());
    assert_eq!(journal.interrupted().len(), 1);
    assert_eq!(journal.interrupted()[0].run_id, run_id.to_string());

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = Store::connect(root.path().join("runs.db")).await.unwrap();
        assert_eq!(
            store.get_run(run_id).await.unwrap().unwrap().status,
            RunStatus::Running
        );
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &journal)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store.get_run(run_id).await.unwrap().unwrap().status,
            RunStatus::Failed
        );
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &journal)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store.get_run(run_id).await.unwrap().unwrap().status,
            RunStatus::Failed
        );
    });
}

#[test]
fn terminal_row_with_unclosed_journal_is_downgraded() {
    let root = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let store = Store::connect(root.path().join("runs.db")).await.unwrap();
        let mut run = RunRecord::new(
            "/disposable/project",
            EngineKind::LibFuzzer,
            None,
            Utc::now(),
        );
        run.status = RunStatus::Done;
        store.insert_run(&run).await.unwrap();
        let journal = RunJournal::open(root.path().join("run_journal.jsonl"));
        journal.open_run(
            run.id,
            Path::new("/disposable/project"),
            "parser",
            EngineKind::LibFuzzer,
        );
        assert!(journal.durability_error().is_none());
        drop(journal);
        let journal = RunJournal::open(root.path().join("run_journal.jsonl"));
        assert_eq!(
            reconcile_interrupted_run_statuses(&store, &journal)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store.get_run(run.id).await.unwrap().unwrap().status,
            RunStatus::Failed
        );
    });
}

#[test]
fn recovery_process_child() {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let run_id = runtime.block_on(async {
        let store = Store::connect(root.join("runs.db")).await.unwrap();
        let mut run = RunRecord::new(
            root.join("project").to_string_lossy(),
            EngineKind::LibFuzzer,
            None,
            Utc::now(),
        );
        run.status = RunStatus::Running;
        store.insert_run(&run).await.unwrap();
        let journal = RunJournal::open(root.join("run_journal.jsonl"));
        journal.open_run(
            run.id,
            &root.join("project"),
            "parser",
            EngineKind::LibFuzzer,
        );
        assert!(journal.durability_error().is_none());
        run.id
    });
    let mut marker = File::create(root.join("admitted")).unwrap();
    write!(marker, "{run_id}").unwrap();
    marker.sync_all().unwrap();
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
