//! Campaign Trust Report service gathering.
//!
//! The container reads the run, its harness, its corpus, its coverage, and its
//! crashes, and audits exactly the run it was asked about.

#![cfg(feature = "campaign-trust")]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hf_core::corpus::{CorpusEntry, CorpusSource};
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus, SmokeRunSummary};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{GateVerdict, ServiceContainer, TrustClaim, TrustDetermination};
use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus, Store};
use uuid::Uuid;

#[derive(Default)]
struct CountingRuntime {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CountingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "coverage should not run during an audit".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

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
            source_sha256: Some("a".repeat(64)),
            binary_sha256: Some("b".repeat(64)),
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
    record.crash_count = Some(0);
    record.harness_rev = Some("a".repeat(64));
    record.binary_rev = Some("b".repeat(64));
    record
}

#[tokio::test]
async fn the_report_audits_the_run_it_was_asked_about_and_no_other() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();

    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let mut good = harness(target.id, HarnessStatus::SmokePassed, true);
    let bad = harness(target.id, HarnessStatus::Draft, false);
    store.upsert_harness(&good).await.unwrap();
    good.status = HarnessStatus::Promoted;
    store
        .promote_harness_with_approval(
            &good,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .unwrap();
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
    let mut record = run(h.id, RunStatus::Done);
    record.crash_count = Some(2);
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

#[tokio::test]
async fn failed_crash_ingestion_does_not_turn_an_empty_table_into_zero_crashes() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap();
    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&harness).await.unwrap();
    let run = run(harness.id, RunStatus::Done);
    store.insert_run(&run).await.unwrap();
    store
        .record_closeout_step(run.id, "Triage", "failed", "ingestion failed")
        .await
        .unwrap();

    let report = container.campaign_trust_report(run.id).await.unwrap();

    for claim in [
        TrustClaim::CrashesTriaged,
        TrustClaim::FindingsWorthReporting,
    ] {
        let gate = report
            .gates
            .iter()
            .find(|gate| gate.claim == claim)
            .unwrap();
        assert_eq!(gate.verdict, GateVerdict::Unavailable);
        assert!(gate.detail.contains("ingestion"));
    }
}

#[tokio::test]
async fn audit_with_current_harness_and_empty_cache_never_runs_coverage() {
    common::install_managed_workspace("oxfuzz_trust_audit");
    let project = tempfile::tempdir().unwrap();
    let project_root = std::fs::canonicalize(project.path()).unwrap();
    let store = Arc::new(
        Store::connect(project.path().join("trust-audit.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());

    let mut target = target();
    target.project_root = project_root.clone();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&harness).await.unwrap();
    let mut run = run(harness.id, RunStatus::Done);
    run.project_root = project_root.to_string_lossy().into_owned();
    store.insert_run(&run).await.unwrap();

    let workspace = hf_service::workspace_dir(&project_root, &target.symbol);
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join("harness.c"), &harness.source).unwrap();
    std::fs::write(workspace.join("corpus/seed"), b"seed").unwrap();

    let report = container.campaign_trust_report(run.id).await.unwrap();
    let coverage = report
        .gates
        .iter()
        .find(|gate| gate.claim == TrustClaim::CoverageMeasured)
        .unwrap();

    assert_eq!(coverage.verdict, GateVerdict::Unavailable);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn mutable_current_corpus_is_not_historical_starting_input_evidence() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();
    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&harness).await.unwrap();
    let record = run(harness.id, RunStatus::Done);
    store.insert_run(&record).await.unwrap();
    store
        .upsert_corpus_entry(
            target.id,
            &CorpusEntry {
                path: PathBuf::from("added-after-run"),
                sha256: "a".repeat(64),
                size: 1,
                source: CorpusSource::Seed,
                coverage_hash: None,
            },
        )
        .await
        .unwrap();

    let report = container.campaign_trust_report(record.id).await.unwrap();
    let gate = report
        .gates
        .iter()
        .find(|gate| gate.claim == TrustClaim::FuzzerHadInputs)
        .unwrap();

    assert_eq!(gate.verdict, GateVerdict::Unavailable);
}

#[tokio::test]
async fn mutable_harness_status_without_exact_run_approval_is_unavailable() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();
    let target = target();
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&harness).await.unwrap();
    let mut record = run(harness.id, RunStatus::Done);
    record.harness_rev = Some("a".repeat(64));
    record.binary_rev = Some("b".repeat(64));
    store.insert_run(&record).await.unwrap();

    let report = container.campaign_trust_report(record.id).await.unwrap();
    let gate = report
        .gates
        .iter()
        .find(|gate| gate.claim == TrustClaim::HarnessExercisesTarget)
        .unwrap();

    assert_eq!(gate.verdict, GateVerdict::Unavailable);
}

#[tokio::test]
async fn run_harness_target_project_mismatch_is_rejected() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();
    let mut target = target();
    target.project_root = PathBuf::from("/another-project");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = harness(target.id, HarnessStatus::SmokePassed, true);
    store.upsert_harness(&harness).await.unwrap();
    let record = run(harness.id, RunStatus::Done);
    store.insert_run(&record).await.unwrap();

    let error = container
        .campaign_trust_report(record.id)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("project does not match"));
}
