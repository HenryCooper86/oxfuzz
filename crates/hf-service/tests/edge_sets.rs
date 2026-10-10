//! Integration tests for per-run edge-set capture and run-to-run edge diffs:
//! closeout captures an AFL++ run's covered edge set from its retained corpus,
//! on-demand capture reuses or produces the same record, and `coverage_diff`
//! computes exact set arithmetic over two retained sets.

#![cfg(feature = "run-closeout")]

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{CloseoutStep, ServiceContainer, StepOutcome};
use hf_storage::{RunKind, RunRecord, RunStatus, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let workspace = common::install_managed_workspace("oxfuzz_edgeset_it");
        let config = workspace.parent().unwrap().join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("oxfuzz.toml"),
            r#"
[fuzzing]
enabled_engines = ["libfuzzer", "afl++", "honggfuzz", "syzkaller"]
default_engine = "libfuzzer"
default_duration_secs = 60

[fuzzing.sandbox]
max_mem_mb = 3072
max_cpus = 3
max_duration_secs = 7200
"#,
        )
        .unwrap();
        std::env::set_var("HF_CONFIG_DIR", config);
    });
}

/// A runtime answering `afl-showmap` with a fixture map keyed by input file
/// name; anything else reports a generic success.
struct ShowmapRuntime {
    /// input file name -> showmap stdout.
    maps: HashMap<String, String>,
    showmap_calls: AtomicUsize,
    fail_showmap: bool,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for ShowmapRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let mut stdout = "DONE exec/s: 64".to_owned();
        if cmd.first().is_some_and(|command| command == "afl-showmap") {
            self.showmap_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_showmap {
                return Err(hf_core::error::ClassifiedError::Sandbox(
                    "showmap unavailable".to_owned(),
                ));
            }
            let input = cmd.last().cloned().unwrap_or_default();
            let name = Path::new(&input)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            stdout = self.maps.get(&name).cloned().unwrap_or_default();
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

fn showmap_runtime(maps: &[(&str, &str)]) -> Arc<ShowmapRuntime> {
    Arc::new(ShowmapRuntime {
        maps: maps
            .iter()
            .map(|(name, map)| ((*name).to_owned(), (*map).to_owned()))
            .collect(),
        showmap_calls: AtomicUsize::new(0),
        fail_showmap: false,
    })
}

struct SeededRun {
    run_id: Uuid,
    binary_sha256: String,
}

/// Seed a terminal campaign run with its retained evidence staged on disk:
/// the digest-pinned binary and the run-local corpus the capture replays.
async fn seed_run(
    store: &Store,
    project: &Path,
    target: &TargetCandidate,
    engine: EngineKind,
    binary_content: &[u8],
    corpus: &[(&str, &[u8])],
) -> SeededRun {
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "afl-clang-fast".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();
    let mut run = RunRecord::new(
        project.to_string_lossy(),
        engine,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine,
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
        }),
        Utc::now(),
    );
    run.kind = RunKind::Campaign;
    run.status = RunStatus::Done;
    run.ended_at = Some(Utc::now());
    let binary_sha256 = format!("{:x}", Sha256::digest(binary_content));
    run.binary_rev = Some(binary_sha256.clone());
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "b".repeat(64)));
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    store.insert_run(&run).await.unwrap();

    let workspace = hf_service::workspace_dir(project, &target.symbol);
    let run_root = workspace.join("runs").join(run.id.to_string());
    std::fs::create_dir_all(run_root.join("input")).unwrap();
    std::fs::write(run_root.join("input/harness"), binary_content).unwrap();
    std::fs::create_dir_all(run_root.join("out")).unwrap();
    let corpus_dir = run_root.join("corpus");
    std::fs::create_dir_all(&corpus_dir).unwrap();
    for (name, bytes) in corpus {
        std::fs::write(corpus_dir.join(name), bytes).unwrap();
    }
    SeededRun {
        run_id: run.id,
        binary_sha256,
    }
}

async fn seed_target(store: &Store, project: &Path, symbol: &str) -> TargetCandidate {
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.to_path_buf(),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: project.join("parser.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "edge-set fixture".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    target
}

#[tokio::test]
async fn capture_persists_a_run_edge_set_and_recapture_reuses_it() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(Store::connect(dir.path().join("edges.db")).await.unwrap());
    let runtime = showmap_runtime(&[("a", "1:1\n2:1\n"), ("b", "2:1\n3:1\n")]);
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_capture").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"input-a"), ("b", b"input-b")],
    )
    .await;

    let capture = container.capture_run_edge_set(run.run_id).await.unwrap();
    assert_eq!(capture.edges, 3);
    assert_eq!(capture.inputs, 2);
    assert_eq!(capture.binary_sha256, run.binary_sha256);
    assert!(!capture.already_retained);
    assert_eq!(runtime.showmap_calls.load(Ordering::SeqCst), 2);

    let retained = store.run_edge_set(run.run_id).await.unwrap().unwrap();
    assert_eq!(retained.edge_count, 3);
    assert_eq!(
        hf_core::coverage::EdgeSet::from_bytes(&retained.edge_map)
            .unwrap()
            .count(),
        3
    );

    // A second capture is a read of retained evidence: no re-measurement.
    let again = container.capture_run_edge_set(run.run_id).await.unwrap();
    assert!(again.already_retained);
    assert_eq!(again.edges, 3);
    assert_eq!(runtime.showmap_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn coverage_diff_computes_exact_set_arithmetic() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(Store::connect(dir.path().join("edges.db")).await.unwrap());
    let runtime = showmap_runtime(&[
        ("a1", "1:1\n2:1\n"),
        ("a2", "2:1\n3:1\n"),
        ("b1", "3:1\n4:1\n"),
    ]);
    let container = ServiceContainer::new(runtime, None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_diff").await;
    let run_a = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a1", b"x"), ("a2", b"y")],
    )
    .await;
    let run_b = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("b1", b"z")],
    )
    .await;
    container.capture_run_edge_set(run_a.run_id).await.unwrap();
    container.capture_run_edge_set(run_b.run_id).await.unwrap();

    let diff = container
        .coverage_diff(run_a.run_id, run_b.run_id)
        .await
        .unwrap();

    assert!(diff.same_binary);
    assert_eq!(diff.edges_a, 3);
    assert_eq!(diff.edges_b, 2);
    assert_eq!(diff.only_a, 2);
    assert_eq!(diff.only_b, 1);
    assert_eq!(diff.common, 1);
    assert_eq!(diff.union, 4);
    assert_eq!(diff.only_a_sample, vec![1, 2]);
    assert_eq!(diff.only_b_sample, vec![4]);
}

#[tokio::test]
async fn coverage_diff_flags_different_binaries_and_rejects_foreign_projects() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(Store::connect(dir.path().join("edges.db")).await.unwrap());
    let container = ServiceContainer::new(showmap_runtime(&[("a", "1:1\n"), ("b", "2:1\n")]), None)
        .with_store(store.clone());
    let target = seed_target(&store, &project, "parse_flag").await;
    let run_a = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"binary one",
        &[("a", b"x")],
    )
    .await;
    let run_b = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"binary two",
        &[("b", b"y")],
    )
    .await;
    container.capture_run_edge_set(run_a.run_id).await.unwrap();
    container.capture_run_edge_set(run_b.run_id).await.unwrap();

    let diff = container
        .coverage_diff(run_a.run_id, run_b.run_id)
        .await
        .unwrap();
    assert!(!diff.same_binary);

    let other_project = dir.path().join("other");
    std::fs::create_dir_all(&other_project).unwrap();
    let foreign_target = seed_target(&store, &other_project, "parse_foreign").await;
    let foreign = seed_run(
        &store,
        &other_project,
        &foreign_target,
        EngineKind::AflPlusPlus,
        b"binary one",
        &[("a", b"x")],
    )
    .await;
    let error = container
        .coverage_diff(run_a.run_id, foreign.run_id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("same project"), "{error}");

    let error = container
        .coverage_diff(run_a.run_id, run_a.run_id)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("distinct"), "{error}");
}

#[tokio::test]
async fn diff_fails_loud_when_a_run_lacks_a_captured_edge_set() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(Store::connect(dir.path().join("edges.db")).await.unwrap());
    let container =
        ServiceContainer::new(showmap_runtime(&[("a", "1:1\n")]), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_missing").await;
    let measured = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"x")],
    )
    .await;
    let unmeasured = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"x")],
    )
    .await;
    container
        .capture_run_edge_set(measured.run_id)
        .await
        .unwrap();

    let error = container
        .coverage_diff(measured.run_id, unmeasured.run_id)
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("no captured edge set"), "{message}");
    assert!(
        message.contains(&unmeasured.run_id.to_string()),
        "{message}"
    );
    assert!(message.contains("runs capture-edges"), "{message}");

    let error = container
        .coverage_diff(unmeasured.run_id, measured.run_id)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("no captured edge set"),
        "{error}"
    );
}

#[tokio::test]
async fn capture_refuses_a_run_whose_binary_has_no_afl_map() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(Store::connect(dir.path().join("edges.db")).await.unwrap());
    let runtime = showmap_runtime(&[("a", "1:1\n")]);
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_libfuzzer").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::LibFuzzer,
        b"libfuzzer binary",
        &[("a", b"x")],
    )
    .await;

    let error = container
        .capture_run_edge_set(run.run_id)
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("afl-showmap"), "{message}");
    assert!(message.contains("libfuzzer"), "{message}");
    assert_eq!(
        runtime.showmap_calls.load(Ordering::SeqCst),
        0,
        "an ineligible run must not reach the sandbox"
    );
}

#[tokio::test]
async fn closeout_captures_the_edge_set_and_a_second_pass_reuses_it() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let runtime = showmap_runtime(&[("a", "10:1\n"), ("b", "11:1\n12:1\n")]);
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_closeout").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"x"), ("b", b"y")],
    )
    .await;

    let report = container.close_out_run(run.run_id).await.unwrap();
    let record = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::EdgeSet)
        .expect("the ladder covers the edge-set step");
    match &record.outcome {
        StepOutcome::Completed { detail } => {
            assert!(detail.contains('3'), "{detail}");
            assert!(detail.contains('2'), "{detail}");
        }
        other => panic!("edge-set capture should complete, got {other:?}"),
    }
    assert_eq!(runtime.showmap_calls.load(Ordering::SeqCst), 2);
    assert!(store.run_edge_set(run.run_id).await.unwrap().is_some());

    let second = container.close_out_run(run.run_id).await.unwrap();
    let record = second
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::EdgeSet)
        .unwrap();
    // The terminal outcome is durable: the second pass reports the recorded
    // result rather than re-measuring.
    match &record.outcome {
        StepOutcome::Completed { detail } => assert!(detail.contains("captured 3"), "{detail}"),
        other => panic!("a retained edge set must not be re-measured, got {other:?}"),
    }
    assert_eq!(
        runtime.showmap_calls.load(Ordering::SeqCst),
        2,
        "the second closeout pass must not re-measure"
    );
}

#[tokio::test]
async fn closeout_reuses_an_edge_set_captured_before_it_ran() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let runtime = showmap_runtime(&[("a", "10:1\n")]);
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_reuse").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"x")],
    )
    .await;

    // The run-end/on-demand path already captured the set.
    let capture = container.capture_run_edge_set(run.run_id).await.unwrap();
    assert_eq!(runtime.showmap_calls.load(Ordering::SeqCst), 1);

    let report = container.close_out_run(run.run_id).await.unwrap();
    let record = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::EdgeSet)
        .unwrap();
    match &record.outcome {
        StepOutcome::Completed { detail } => {
            assert!(detail.contains("retained"), "{detail}");
            assert!(detail.contains(&capture.edges.to_string()), "{detail}");
        }
        other => panic!("a pre-captured edge set is reused, got {other:?}"),
    }
    assert_eq!(
        runtime.showmap_calls.load(Ordering::SeqCst),
        1,
        "closeout must not re-measure a retained edge set"
    );
}

#[tokio::test]
async fn closeout_skips_edge_capture_for_a_run_without_an_afl_map() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let runtime = showmap_runtime(&[]);
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_skip").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::LibFuzzer,
        b"libfuzzer binary",
        &[("a", b"x")],
    )
    .await;

    let report = container.close_out_run(run.run_id).await.unwrap();
    let record = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::EdgeSet)
        .unwrap();
    match &record.outcome {
        StepOutcome::Skipped { reason } => {
            assert!(reason.contains("afl-showmap"), "{reason}");
        }
        other => panic!("a non-AFL++ run skips capture with a reason, got {other:?}"),
    }
    assert_eq!(runtime.showmap_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn closeout_records_a_failed_capture_without_stopping_the_chain() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(ShowmapRuntime {
        maps: HashMap::new(),
        showmap_calls: AtomicUsize::new(0),
        fail_showmap: true,
    });
    let container = ServiceContainer::new(runtime, None).with_store(store.clone());
    let target = seed_target(&store, &project, "parse_fail").await;
    let run = seed_run(
        &store,
        &project,
        &target,
        EngineKind::AflPlusPlus,
        b"afl binary",
        &[("a", b"x")],
    )
    .await;

    let report = container.close_out_run(run.run_id).await.unwrap();

    let record = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::EdgeSet)
        .unwrap();
    assert!(
        matches!(record.outcome, StepOutcome::Failed { .. }),
        "a sandbox failure is a failed, retryable step: {:?}",
        record.outcome
    );
    // A failed capture never aborts the chain: every later step still records.
    let trust = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::TrustReport)
        .expect("the trust report runs even after a failed capture");
    assert!(trust.outcome.is_terminal());
    assert!(store.run_edge_set(run.run_id).await.unwrap().is_none());
}
