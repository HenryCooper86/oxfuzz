//! Run Closeout persistence and resume.
//!
//! Step outcomes are durable, so a second pass does not redo terminal work.

#![cfg(feature = "run-closeout")]

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{CloseoutStep, ServiceContainer, StepOutcome};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

async fn container() -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, dir)
}

async fn seeded_run(container: &ServiceContainer) -> Uuid {
    let store = container.store().unwrap().clone();
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/proj"),
        language: TargetLanguage::C,
        symbol: "parse_packet".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/parser.c"),
            line: 42,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("int parse_packet(const uint8_t*, size_t)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 9,
        fit_score: 0.91,
        sanitizers: vec![Sanitizer::Address],
        rationale: "untrusted packet parser".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();

    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::SmokePassed,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();

    let mut run = RunRecord::new(
        "/proj",
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: None,
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        }),
        Utc::now(),
    );
    run.status = RunStatus::Done;
    store.insert_run(&run).await.unwrap();
    run.id
}

#[tokio::test]
async fn a_closeout_records_every_step_and_the_second_pass_resumes() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;

    let first = container.close_out_run(run_id).await.unwrap();
    assert_eq!(
        first.steps.len(),
        hf_service::closeout_ladder().len(),
        "every step is accounted for, including the ones that were skipped"
    );
    assert_eq!(
        first.resumed_at, None,
        "the first pass starts, it does not resume"
    );

    // A run with no crashes has nothing to minimize; that is an answer.
    let minimize = first
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::Minimize)
        .unwrap();
    assert!(
        matches!(minimize.outcome, StepOutcome::Skipped { .. }),
        "expected a skip with a reason, got {:?}",
        minimize.outcome
    );

    // Terminal outcomes are durable, so the second pass repeats none of them.
    let second = container.close_out_run(run_id).await.unwrap();
    for record in &second.steps {
        let before = first
            .steps
            .iter()
            .find(|item| item.step == record.step)
            .unwrap();
        if before.outcome.is_terminal() {
            assert_eq!(
                record.outcome, before.outcome,
                "{:?} reached a terminal outcome and must not be redone",
                record.step
            );
        }
    }
}

#[tokio::test]
async fn an_unknown_run_cannot_be_closed_out() {
    let (container, _dir) = container().await;

    assert!(container.close_out_run(Uuid::from_u128(404)).await.is_err());
}

#[tokio::test]
async fn step_outcomes_survive_a_new_container_over_the_same_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("closeout.db");

    let run_id = {
        let store = Arc::new(Store::connect(&path).await.unwrap());
        let container =
            ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
        let run_id = seeded_run(&container).await;
        container.close_out_run(run_id).await.unwrap();
        run_id
    };

    // A restart reads the recorded outcomes rather than starting over.
    let store = Arc::new(Store::connect(&path).await.unwrap());
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    let resumed = container.close_out_run(run_id).await.unwrap();

    assert_eq!(resumed.steps.len(), hf_service::closeout_ladder().len());
}
