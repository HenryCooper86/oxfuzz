//! A target's report keeps findings an earlier run confirmed.
//!
//! Found on 2026-11-19: the newest AFL++ run of `utf8_decoder` failed before
//! it reported any figure, and the report for the target said "No crashes were
//! found" although an earlier run had confirmed a heap-buffer-overflow that no
//! later run re-observed.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{Duration, Utc};
use hf_core::crash::{CasrReport, Crash, CrashKind, CrashOrigin, CrashSeverity};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{AiPolicy, ReportLanguage, ServiceContainer};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_report_open_findings_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().unwrap();
        let config = root.join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::env::set_var("HF_CONFIG_DIR", &config);
    });
}

struct Fixture {
    container: ServiceContainer,
    store: Arc<Store>,
    project: tempfile::TempDir,
    _database: tempfile::TempDir,
    target: TargetCandidate,
    harness: Harness,
}

async fn fixture() -> Fixture {
    isolate_workspace();
    let database = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::connect(database.path().join("r.db")).await.unwrap());
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: std::fs::canonicalize(project.path()).unwrap(),
        language: TargetLanguage::C,
        symbol: "decode_utf8".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("utf8.c"),
            line: 23,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 10,
        fit_score: 0.83,
        sanitizers: vec![Sanitizer::Address],
        rationale: "fixture".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 10,
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::AflPlusPlus,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_decode_utf8"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
        custom_mutator: None,
        cmplog: None,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));
    Fixture {
        container,
        store,
        project,
        _database: database,
        target,
        harness,
    }
}

fn run(fixture: &Fixture, status: RunStatus, offset_minutes: i64) -> RunRecord {
    let mut run = RunRecord::new(
        fixture.target.project_root.to_string_lossy(),
        EngineKind::AflPlusPlus,
        Some(FuzzRunConfig {
            harness_id: fixture.harness.id,
            engine: EngineKind::AflPlusPlus,
            duration: Some(std::time::Duration::from_secs(60)),
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
            cmplog: false,
        }),
        Utc::now() + Duration::minutes(offset_minutes),
    );
    run.status = status;
    run.ended_at = Some(run.started_at + Duration::seconds(60));
    run
}

fn finding(run: &RunRecord, target: &TargetCandidate, signature: &str) -> Crash {
    Crash {
        control_replay: None,
        reproduction: None,
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: PathBuf::from(format!("runs/{}/out/crash-1", run.id)),
        stack_signature: signature.to_owned(),
        kind: CrashKind::Asan,
        summary: format!("heap-buffer-overflow(read) at {signature}"),
        minimized: false,
        bug_report: None,
        casr: Some(CasrReport {
            severity: CrashSeverity::NotExploitable,
            severity_short: "heap-buffer-overflow(read)".to_owned(),
            crashline: signature.to_owned(),
            stack: vec![],
            cluster: None,
        }),
        origin: CrashOrigin::Target,
    }
}

async fn report(fixture: &Fixture) -> String {
    fixture
        .container
        .generate_report_for_run(
            fixture.project.path(),
            "decode_utf8",
            ReportLanguage::En,
            None,
            AiPolicy::Off,
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn a_failed_latest_run_does_not_hide_an_earlier_confirmed_finding() {
    let fixture = fixture().await;
    let earlier = run(&fixture, RunStatus::Done, -60);
    let latest = run(&fixture, RunStatus::Failed, 0);
    fixture.store.insert_run(&earlier).await.unwrap();
    fixture.store.insert_run(&latest).await.unwrap();
    fixture
        .store
        .upsert_crash(&finding(&earlier, &fixture.target, "/work/utf8.c:31:27"))
        .await
        .unwrap();

    let md = report(&fixture).await;

    assert!(md.contains("## Findings from earlier runs"), "{md}");
    assert!(md.contains("/work/utf8.c:31:27"), "{md}");
    assert!(md.contains("CWE-125"), "{md}");
    assert!(md.contains("not re-observed"), "{md}");
    // The executive summary does not call the target clean.
    let summary = md.split("## Executive Summary").nth(1).unwrap();
    let summary = summary.split("\n## ").next().unwrap();
    assert!(summary.contains("Findings from earlier runs"), "{summary}");
    // It is still a finding to fix.
    let recommendations = md.split("## Recommendations").nth(1).unwrap();
    assert!(recommendations.contains("Finding 1"), "{recommendations}");
    assert!(
        !recommendations.contains("No crash was found"),
        "{recommendations}"
    );
}

#[tokio::test]
async fn a_finding_the_latest_run_reproduced_is_listed_once() {
    let fixture = fixture().await;
    let earlier = run(&fixture, RunStatus::Done, -60);
    let latest = run(&fixture, RunStatus::Done, 0);
    fixture.store.insert_run(&earlier).await.unwrap();
    fixture.store.insert_run(&latest).await.unwrap();
    for crash in [
        finding(&earlier, &fixture.target, "/work/utf8.c:31:27"),
        finding(&latest, &fixture.target, "/work/utf8.c:31:27"),
    ] {
        fixture.store.upsert_crash(&crash).await.unwrap();
    }

    let md = report(&fixture).await;

    assert!(!md.contains("## Findings from earlier runs"), "{md}");
    assert_eq!(md.matches("### Finding ").count(), 1, "{md}");
}
