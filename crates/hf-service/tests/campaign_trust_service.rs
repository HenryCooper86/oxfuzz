//! Campaign Trust Report service gathering.
//!
//! The container reads the run, its harness, its corpus, its coverage, and its
//! crashes, and audits exactly the run it was asked about.

#![cfg(feature = "campaign-trust")]

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus, SmokeRunSummary};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{GateVerdict, ServiceContainer, TrustClaim, TrustDetermination};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

async fn container() -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::connect(dir.path().join("trust.db")).await.unwrap());
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, dir)
}

fn target() -> TargetCandidate {
    TargetCandidate {
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
    }
}

fn harness(target_id: Uuid, status: HarnessStatus, smoke_passed: bool) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id,
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
        status,
        smoke_run: smoke_passed.then_some(SmokeRunSummary {
            duration_secs: 10,
            execs_per_sec: 1000.0,
            crashes: 0,
            passed: true,
            source_sha256: None,
            binary_sha256: None,
            run_id: None,
        }),
    }
}

fn run(harness_id: Uuid, status: RunStatus) -> RunRecord {
    let mut record = RunRecord::new(
        "/proj",
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id,
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
    record.status = status;
    record.execs = Some(4200.0);
    record
}

#[tokio::test]
async fn the_report_audits_the_run_it_was_asked_about_and_no_other() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();

    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let good = harness(target.id, HarnessStatus::SmokePassed, true);
    let bad = harness(target.id, HarnessStatus::Draft, false);
    store.upsert_harness(&good).await.unwrap();
    store.upsert_harness(&bad).await.unwrap();

    let good_run = run(good.id, RunStatus::Done);
    let bad_run = run(bad.id, RunStatus::Failed);
    store.insert_run(&good_run).await.unwrap();
    store.insert_run(&bad_run).await.unwrap();

    let report = container.campaign_trust_report(good_run.id).await.unwrap();
    assert_eq!(report.run_id, good_run.id);
    assert_eq!(report.target_id, target.id);
    let harness_gate = report
        .gates
        .iter()
        .find(|g| g.claim == TrustClaim::HarnessExercisesTarget)
        .unwrap();
    assert_eq!(harness_gate.verdict, GateVerdict::Supported);

    // The failed sibling run must not colour the healthy one, and vice versa.
    let other = container.campaign_trust_report(bad_run.id).await.unwrap();
    assert_eq!(other.determination, TrustDetermination::Untrustworthy);
}

#[tokio::test]
async fn an_unknown_run_is_an_error_not_an_empty_report() {
    let (container, _dir) = container().await;

    let result = container.campaign_trust_report(Uuid::from_u128(999)).await;

    assert!(result.is_err(), "an unknown run must not audit as trusted");
}

#[tokio::test]
async fn crash_attribution_reaches_the_triage_gate() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();

    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let h = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&h).await.unwrap();
    let record = run(h.id, RunStatus::Done);
    store.insert_run(&record).await.unwrap();

    // One attributed, one not: the claim that every crash is triaged fails.
    for origin in [CrashOrigin::Target, CrashOrigin::Unknown] {
        let crash = Crash {
            id: Uuid::new_v4(),
            run_id: record.id,
            target_id: target.id,
            input_path: PathBuf::from("in.bin"),
            stack_signature: format!("{origin:?}"),
            kind: CrashKind::Asan,
            summary: "overflow".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin,
        };
        store.upsert_crash(&crash).await.unwrap();
    }

    let report = container.campaign_trust_report(record.id).await.unwrap();

    let gate = report
        .gates
        .iter()
        .find(|g| g.claim == TrustClaim::CrashesTriaged)
        .unwrap();
    assert_eq!(gate.verdict, GateVerdict::Unsupported);
    assert!(report
        .unlicensed_claims
        .contains(&TrustClaim::CrashesTriaged));
}
