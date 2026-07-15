//! Tests for `ServiceContainer` construction and persistence wiring.

use std::sync::Arc;

use hf_service::ServiceContainer;

/// Redirect the fuzz workspace to a temp dir for the duration of the test
/// process, so tests that compile harnesses / seed corpora don't pollute (or
/// collide with) the real per-user data dir now that the workspace is
/// persistent. `HF_WORKSPACE_DIR` takes precedence in `workspace_root`; the
/// `Once` sets it before any workspace-touching test proceeds.
fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var(
            "HF_WORKSPACE_DIR",
            std::env::temp_dir().join("hobot_fuzz_it_workspace"),
        );
    });
}

fn stored_target(project: &std::path::Path, symbol: &str) -> hf_core::target::TargetCandidate {
    hf_core::target::TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: project.to_path_buf(),
        language: hf_core::target::TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: hf_core::target::TargetKind::Parser,
        location: hf_core::target::SourceLocation {
            file: std::path::PathBuf::from(format!("{symbol}.c")),
            line: 1,
            col: 1,
        },
        signature: Some(format!("int {symbol}(const char *, size_t)")),
        input_surface: hf_core::target::InputSurface::Bytes,
        complexity: 1,
        fit_score: 0.9,
        sanitizers: vec![hf_core::target::Sanitizer::Address],
        rationale: "test target".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    }
}

fn stored_harness(target_id: uuid::Uuid, symbol: &str) -> hf_core::harness::Harness {
    hf_core::harness::Harness {
        id: uuid::Uuid::new_v4(),
        target_id,
        engine: hf_core::engine::EngineKind::LibFuzzer,
        source: format!("int LLVMFuzzerTestOneInput(void) {{ return {symbol}[0]; }}"),
        language: hf_core::target::TargetLanguage::C,
        build_cmd: hf_core::harness::BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: std::path::PathBuf::from(format!("fuzz_{symbol}")),
        },
        sanitizer: hf_core::target::Sanitizer::Address,
        status: hf_core::harness::HarnessStatus::Promoted,
        smoke_run: Some(hf_core::harness::SmokeRunSummary {
            duration_secs: 60,
            execs_per_sec: 10.0,
            crashes: 0,
            passed: true,
        }),
    }
}

fn stored_run(
    project: &std::path::Path,
    harness_id: uuid::Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
) -> hf_storage::RunRecord {
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        hf_core::engine::EngineKind::LibFuzzer,
        Some(hf_core::engine::FuzzRunConfig {
            harness_id,
            engine: hf_core::engine::EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_mins(1)),
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
        }),
        started_at,
    );
    run.status = hf_storage::RunStatus::Done;
    run.ended_at = Some(started_at);
    run
}

fn stored_crash(run_id: uuid::Uuid, target_id: uuid::Uuid, marker: &str) -> hf_core::crash::Crash {
    hf_core::crash::Crash {
        id: uuid::Uuid::new_v4(),
        run_id,
        target_id,
        input_path: std::path::PathBuf::from(format!("out/crash-{marker}")),
        stack_signature: format!("stack-{marker}"),
        kind: hf_core::crash::CrashKind::Asan,
        summary: format!("{marker} crash summary"),
        minimized: false,
        bug_report: None,
        casr: None,
    }
}

/// A runtime whose streamed command blocks until the run is cancelled, so a
/// test can observe and drive the cancellation path deterministically.
struct BlockingRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for BlockingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
        })
    }

    async fn run_command_streaming(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        // Run until the caller cancels, mimicking a live fuzzer.
        cancel.cancelled().await;
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
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

#[tokio::test]
async fn cancel_run_stops_an_in_flight_fuzz_run() {
    use std::fs;
    isolate_workspace();

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("cancel_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";
    fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();

    // run_fuzzer requires a compiled harness binary and a corpus dir.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("c.db"))
            .await
            .expect("connect store"),
    );
    let container = Arc::new(
        ServiceContainer::new(Arc::new(BlockingRuntime), None).with_store(Arc::clone(&store)),
    );
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::LibFuzzer,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("compile harness");
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::LibFuzzer,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::LibFuzzer)
        .await
        .expect("promote harness");

    // Start the run; it will block in the runtime until cancelled.
    let runner = {
        let container = Arc::clone(&container);
        let project = project.clone();
        tokio::spawn(async move {
            container
                .run_fuzzer(
                    &project,
                    target,
                    hf_core::engine::EngineKind::LibFuzzer,
                    60,
                    &|_| {},
                )
                .await
        })
    };

    // Wait for the run to register, then cancel it.
    let mut run_id = None;
    for _ in 0..200 {
        if let Some(id) = container.active_run_ids().into_iter().next() {
            run_id = Some(id);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let run_id = run_id.expect("run should register as active");
    assert!(container.cancel_run(run_id), "cancel should find the run");

    // The run returns promptly and is recorded as cancelled.
    let summary = tokio::time::timeout(std::time::Duration::from_secs(5), runner)
        .await
        .expect("run should finish after cancel")
        .expect("task join")
        .expect("run_fuzzer ok");
    assert_eq!(summary.crashes, 0);
    assert!(container.active_run_ids().is_empty(), "registry cleaned up");

    let run = store.get_run(run_id).await.unwrap().expect("run persisted");
    assert_eq!(run.status, hf_storage::RunStatus::Cancelled);

    let _ = fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn store_wiring_is_optional() {
    let rt = Arc::new(hf_runtime::StubRuntime);

    // A plain container has no store and no provider pool.
    let bare = ServiceContainer::new(rt.clone(), None);
    assert!(bare.store().is_none());
    assert!(bare.provider_pool().is_none());

    // Attaching a store makes it observable through the accessor.
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("t.db"))
            .await
            .expect("connect store"),
    );
    let with_store = ServiceContainer::new(rt, None).with_store(store);
    assert!(with_store.store().is_some());
}

#[tokio::test]
async fn project_auto_revert_override_rejects_invalid_percentages() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("policy.db"))
            .await
            .expect("connect store"),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store.clone());
    let project = dir.path().join("project");

    for invalid in [0.0, 100.1, f64::INFINITY, f64::NAN] {
        let result = container
            .set_project_auto_revert_override(&project, true, invalid, false)
            .await;
        assert!(result.is_err(), "invalid threshold {invalid} was accepted");
    }
    assert_eq!(
        store
            .project_auto_revert(&project.to_string_lossy())
            .await
            .unwrap(),
        None
    );
}

/// A no-op provider pool, just enough to occupy the container's pool cell.
struct MockPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for MockPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "mock".to_owned(),
        })
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "mock".to_owned(),
        })
    }
    fn report_error(
        &self,
        _provider_id: &hf_core::types::ProviderId,
        _error: &hf_core::provider::ProviderError,
    ) {
    }
    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}
    async fn thaw(
        &self,
        _provider_id: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}

#[tokio::test]
async fn session_turn_lock_is_shared_per_session_across_clones() {
    use hf_core::types::SessionId;

    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let clone = container.clone();
    let a = SessionId("session-a".to_owned());
    let b = SessionId("session-b".to_owned());

    // The same session resolves to the same underlying lock, even from a
    // different clone of the container -- so two turns on one session serialize.
    assert!(std::sync::Arc::ptr_eq(
        &container.session_turn_lock(&a),
        &clone.session_turn_lock(&a)
    ));
    // Distinct sessions get distinct locks -- so they still run concurrently.
    assert!(!std::sync::Arc::ptr_eq(
        &container.session_turn_lock(&a),
        &container.session_turn_lock(&b)
    ));
}

#[tokio::test]
async fn session_turn_lock_serializes_concurrent_holders() {
    use hf_core::types::SessionId;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let id = SessionId("busy".to_owned());
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let lock = container.session_turn_lock(&id);
        let in_flight = Arc::clone(&in_flight);
        let max_seen = Arc::clone(&max_seen);
        handles.push(tokio::spawn(async move {
            let _guard = lock.lock_owned().await;
            let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            max_seen.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            in_flight.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(
        max_seen.load(Ordering::SeqCst),
        1,
        "at most one turn per session may hold the lock at a time"
    );
}

#[tokio::test]
async fn provider_pool_swap_is_visible_across_container_clones() {
    // Live reload swaps the pool in a shared cell, so a change applied to one
    // handle must be observed by every clone (every consumer) -- the property
    // that lets a Settings save take effect app-wide without a restart.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let clone = container.clone();
    assert!(clone.provider_pool().is_none(), "no provider initially");

    let updated = container.with_provider_pool(Arc::new(MockPool));
    assert!(updated.provider_pool().is_some());
    assert!(
        clone.provider_pool().is_some(),
        "the earlier clone observes the swapped-in pool"
    );
}

#[tokio::test]
async fn corpus_minimize_leaves_corpus_untouched_when_sandbox_unavailable() {
    use std::fs;
    isolate_workspace();

    // A unique project name keeps this test's workspace isolated.
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("minimize_fallback_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    // Lay down a workspace with a harness and a two-entry corpus.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    fs::create_dir_all(&corpus).unwrap();
    fs::write(workspace.join("harness.c"), b"int main(){return 0;}").unwrap();
    fs::write(corpus.join("a"), b"aaa").unwrap();
    fs::write(corpus.join("b"), b"bbb").unwrap();

    // The stub runtime errors on every sandbox command, so minimization cannot
    // run; the corpus must be preserved rather than wiped.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let outcome = container.corpus_minimize(&project, target).await.unwrap();

    assert_eq!(outcome.before, 2);
    assert_eq!(outcome.after, 2, "corpus preserved on tooling failure");
    assert!(corpus.join("a").exists());
    assert!(corpus.join("b").exists());

    let _ = fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn system_snapshot_reports_memory_and_empty_providers_without_a_pool() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("s.db"))
            .await
            .expect("connect store"),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);

    let snap = container.system_snapshot().await;

    // No provider pool -> no provider cards; agent pool empty by default.
    assert!(snap.providers.is_empty());
    assert_eq!(snap.agents.active_instances, 0);
    assert!(snap.agents.instances.is_empty());
    // Memory counters are real and start at zero on a fresh store.
    assert_eq!(snap.memory.pending_runs, 0);
    assert_eq!(snap.memory.targets, 0);
    assert_eq!(snap.memory.crashes, 0);
}

#[tokio::test]
async fn verify_regressions_replays_stored_crash_inputs() {
    use std::fs;
    isolate_workspace();

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("regress_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "demo";

    // A workspace with a harness binary and a staged crash input.
    let ws = hf_service::workspace_dir(&project, target);
    let out = ws.join("out");
    fs::create_dir_all(&out).unwrap();
    fs::write(ws.join(format!("fuzz_{target}")), b"bin").unwrap();
    fs::write(out.join("crash-1"), b"boom").unwrap();

    // Stub runtime can't actually reproduce, so replay yields no crash -> the
    // crash is reported as fixed. (The real value is the replay plumbing.)
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let results = container
        .verify_regressions(&project, target)
        .await
        .unwrap();
    assert_eq!(results.len(), 1, "the staged crash input is replayed");
    assert!(!results[0].still_crashes);
    assert!(results[0].input.ends_with("crash-1"));

    // Without a compiled harness it errors clearly.
    let bare = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let err = bare.verify_regressions(&project, "missing").await;
    assert!(err.is_err());

    let _ = fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn artifact_summary_reports_on_disk_state() {
    use std::fs;
    isolate_workspace();

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("artifact_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "demo";

    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    // Nothing on disk yet.
    let empty = container.artifact_summary(&project, target);
    assert!(!empty.harness_built);
    assert_eq!(empty.corpus_count, 0);
    assert_eq!(empty.crash_count, 0);

    // Lay down a harness binary, two corpus inputs, and a crash input.
    let ws = hf_service::workspace_dir(&project, target);
    fs::create_dir_all(ws.join("corpus")).unwrap();
    fs::create_dir_all(ws.join("out")).unwrap();
    fs::write(ws.join(format!("fuzz_{target}")), b"bin").unwrap();
    fs::write(ws.join("corpus").join("a"), b"a").unwrap();
    fs::write(ws.join("corpus").join("b"), b"b").unwrap();
    fs::write(ws.join("out").join("crash-1"), b"boom").unwrap();

    let s = container.artifact_summary(&project, target);
    assert!(s.harness_built, "harness detected");
    assert_eq!(s.corpus_count, 2);
    assert_eq!(s.crash_count, 1);

    let _ = fs::remove_dir_all(&ws);
}

#[tokio::test]
async fn corpus_absorb_crashes_feeds_reproducers_back_in() {
    use std::fs;
    isolate_workspace();

    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("absorb_proj");
    fs::create_dir_all(&project).unwrap();
    let target = "parse_entry";

    // Seed a workspace: an existing corpus plus crash inputs under out/.
    let workspace = hf_service::workspace_dir(&project, target);
    let corpus = workspace.join("corpus");
    let out = workspace.join("out");
    fs::create_dir_all(&corpus).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(corpus.join("seed"), b"seed-input").unwrap();
    fs::write(out.join("crash-abc"), b"crashing-bytes").unwrap();
    // Engine bookkeeping that must be ignored.
    fs::write(out.join("fuzzer_stats"), b"stats").unwrap();

    // No store: absorb falls back to scanning the run output directory.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let added = container
        .corpus_absorb_crashes(&project, target)
        .await
        .unwrap();

    assert_eq!(added, 1, "the one crash input is absorbed, stats ignored");
    let entries = container.corpus_list(&project, target).unwrap().entries;
    assert_eq!(entries.len(), 2, "seed + absorbed crash");
    assert!(
        entries
            .iter()
            .any(|e| fs::read(&e.path).unwrap() == b"crashing-bytes"),
        "crash reproducer now in corpus"
    );

    let _ = fs::remove_dir_all(&workspace);
}

#[tokio::test]
async fn generate_report_produces_a_titled_markdown_doc() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("report_proj");
    std::fs::create_dir_all(&project).unwrap();

    // A store-less, stub-runtime container still produces an honest report:
    // headings present, missing data rendered as "not available" sections.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let md = container
        .generate_report(&project, "some_target")
        .await
        .unwrap();

    assert!(md.starts_with("# Fuzzing Report"), "has an H1 title");
    assert!(md.contains("some_target"));
    assert!(md.contains("## Findings"));
    assert!(
        md.contains("No crashes were found"),
        "honest empty findings"
    );
}

#[tokio::test]
async fn target_scoped_exports_include_cancelled_run_and_ignore_newer_other_target() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("multi_target_project");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("runs.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let target_a = stored_target(&project, "parse_a");
    let target_b = stored_target(&project, "parse_b");
    let harness_a = stored_harness(target_a.id, &target_a.symbol);
    let harness_b = stored_harness(target_b.id, &target_b.symbol);
    let mut run_a = stored_run(
        &project,
        harness_a.id,
        chrono::Utc::now() - chrono::Duration::minutes(1),
    );
    run_a.status = hf_storage::RunStatus::Cancelled;
    let run_b = stored_run(&project, harness_b.id, chrono::Utc::now());
    let mut run_a_inflight = stored_run(
        &project,
        harness_a.id,
        chrono::Utc::now() + chrono::Duration::minutes(1),
    );
    run_a_inflight.status = hf_storage::RunStatus::Running;
    run_a_inflight.ended_at = None;
    let workspace_a = hf_service::workspace_dir(&project, "parse_a");
    let workspace_b = hf_service::workspace_dir(&project, "parse_b");
    std::fs::create_dir_all(workspace_a.join("out")).unwrap();
    std::fs::create_dir_all(workspace_b.join("out")).unwrap();
    std::fs::write(workspace_a.join("fuzz_parse_a"), b"binary").unwrap();
    let input_a = workspace_a.join("out").join("crash-TARGET_A");
    let input_b = workspace_b.join("out").join("crash-TARGET_B");
    std::fs::write(&input_a, b"target-a-input").unwrap();
    std::fs::write(&input_b, b"target-b-input").unwrap();
    let mut crash_a = stored_crash(run_a.id, target_a.id, "TARGET_A");
    crash_a.input_path = input_a.clone();
    let mut crash_b = stored_crash(run_b.id, target_b.id, "TARGET_B");
    crash_b.input_path = input_b;

    store
        .upsert_target(&target_a, chrono::Utc::now())
        .await
        .unwrap();
    store
        .upsert_target(&target_b, chrono::Utc::now())
        .await
        .unwrap();
    store.upsert_harness(&harness_a).await.unwrap();
    store.upsert_harness(&harness_b).await.unwrap();
    store.insert_run(&run_a).await.unwrap();
    store.insert_run(&run_b).await.unwrap();
    store.insert_run(&run_a_inflight).await.unwrap();
    store.upsert_crash(&crash_a).await.unwrap();
    store.upsert_crash(&crash_b).await.unwrap();

    let report = container
        .generate_report(&project, "parse_a")
        .await
        .unwrap();
    assert!(report.contains("TARGET_A crash summary"));
    assert!(!report.contains("TARGET_B crash summary"));

    let sarif = container.export_sarif(&project, "parse_a").await.unwrap();
    assert!(sarif.contains("TARGET_A crash summary"));
    assert!(!sarif.contains("TARGET_B crash summary"));

    let replays = container
        .verify_regressions(&project, "parse_a")
        .await
        .unwrap();
    assert_eq!(replays.len(), 1);
    assert_eq!(std::path::Path::new(&replays[0].input), input_a);

    let added = container
        .corpus_absorb_crashes(&project, "parse_a")
        .await
        .unwrap();
    assert_eq!(added, 1);
    let corpus = container.corpus_list(&project, "parse_a").unwrap();
    assert!(corpus
        .entries
        .iter()
        .any(|entry| std::fs::read(&entry.path).unwrap() == b"target-a-input"));
    assert!(!corpus
        .entries
        .iter()
        .any(|entry| std::fs::read(&entry.path).unwrap() == b"target-b-input"));

    std::fs::remove_dir_all(workspace_a).ok();
    std::fs::remove_dir_all(workspace_b).ok();
}

#[tokio::test]
async fn triage_rejects_crashes_without_a_completed_attributable_run() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("unattributed_triage_project");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("triage.db"))
            .await
            .unwrap(),
    );
    let target = stored_target(&project, "parse_unattributed");
    store
        .upsert_target(&target, chrono::Utc::now())
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, &target.symbol);
    std::fs::create_dir_all(workspace.join("out")).unwrap();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let error = container
        .triage(&project, &target.symbol)
        .await
        .expect_err("persistent triage must not fabricate a run identity");
    assert!(error.to_string().contains("terminal run"));

    std::fs::remove_dir_all(workspace).ok();
}

#[tokio::test]
async fn session_manager_persists_chat_transcript() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("s.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager wired");

    // Create a chat session (created Active) and append a turn.
    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Chat".to_owned()),
        })
        .await
        .expect("create session");
    manager
        .append_message(&node.id, &Message::user("hello"))
        .await
        .expect("append user");
    manager
        .append_message(&node.id, &Message::assistant("hi there"))
        .await
        .expect("append assistant");

    // The context transcript round-trips the conversation.
    let transcript = manager.read_transcript(&node.id).await.expect("read");
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[0].content, "hello");
    assert_eq!(transcript[1].content, "hi there");
}

#[tokio::test]
async fn chat_rollback_undoes_last_turn() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cp.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager");

    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Chat".to_owned()),
        })
        .await
        .expect("create session");

    // Turn 1: checkpoint before (0 messages), then append the exchange.
    container.chat_create_checkpoint(&node.id, 0).await.unwrap();
    manager
        .append_message(&node.id, &Message::user("q1"))
        .await
        .unwrap();
    manager
        .append_message(&node.id, &Message::assistant("a1"))
        .await
        .unwrap();

    // Turn 2: checkpoint before (2 messages), then append.
    container.chat_create_checkpoint(&node.id, 2).await.unwrap();
    manager
        .append_message(&node.id, &Message::user("q2"))
        .await
        .unwrap();
    manager
        .append_message(&node.id, &Message::assistant("a2"))
        .await
        .unwrap();

    assert_eq!(manager.read_transcript(&node.id).await.unwrap().len(), 4);

    // Roll back the last turn -> back to the turn-1 state.
    let removed = container.chat_rollback_last(&node.id).await.unwrap();
    assert_eq!(removed, 2, "should remove the two turn-2 messages");
    let transcript = manager.read_transcript(&node.id).await.unwrap();
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[1].content, "a1");
}

#[tokio::test]
async fn chat_checkpoint_picker_rolls_back_to_turn() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("pick.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().expect("session manager");

    let node = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: None,
        })
        .await
        .unwrap();

    // Three turns, each checkpointed before its messages are appended.
    for (i, (q, a)) in [("q1", "a1"), ("q2", "a2"), ("q3", "a3")]
        .iter()
        .enumerate()
    {
        container
            .chat_create_checkpoint(&node.id, u32::try_from(i * 2).unwrap())
            .await
            .unwrap();
        manager
            .append_message(&node.id, &Message::user(*q))
            .await
            .unwrap();
        manager
            .append_message(&node.id, &Message::assistant(*a))
            .await
            .unwrap();
    }

    // The picker lists three turns, each previewing its user message.
    let checkpoints = container.chat_checkpoints(&node.id).await.unwrap();
    assert_eq!(checkpoints.len(), 3);
    assert_eq!(checkpoints[0].turn_number, 1);
    assert_eq!(checkpoints[0].preview, "q1");
    assert_eq!(checkpoints[1].preview, "q2");

    // Roll back to turn 2 -> keep turn 1, drop turns 2 and 3.
    let turn2 = &checkpoints[1];
    let removed = container
        .chat_rollback_to(&node.id, &turn2.checkpoint_id)
        .await
        .unwrap();
    assert_eq!(removed, 4, "turns 2 and 3 (4 messages) removed");
    let transcript = manager.read_transcript(&node.id).await.unwrap();
    assert_eq!(transcript.len(), 2);
    assert_eq!(transcript[1].content, "a1");

    // Only turn 1's checkpoint remains valid.
    assert_eq!(container.chat_checkpoints(&node.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn chat_branch_forks_an_independent_conversation() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::{Message, SessionId};

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("br.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().unwrap();

    let main = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: Some("Main".to_owned()),
        })
        .await
        .unwrap();

    // Two turns on the main thread.
    for (q, a) in [("q1", "a1"), ("q2", "a2")] {
        manager
            .append_message(&main.id, &Message::user(q))
            .await
            .unwrap();
        manager
            .append_message(&main.id, &Message::assistant(a))
            .await
            .unwrap();
    }

    // Branch after turn 1 (copy the first 2 messages) and diverge.
    let branch_id = container
        .chat_branch(&main.id, 2, Some("Experiment".to_owned()))
        .await
        .expect("branch created");
    let branch = SessionId(branch_id);
    manager
        .append_message(&branch, &Message::user("q-alt"))
        .await
        .unwrap();
    manager
        .append_message(&branch, &Message::assistant("a-alt"))
        .await
        .unwrap();

    // The branch has the fork point + its own divergence; main is untouched.
    let branch_hist = container.chat_history(&branch).await.unwrap();
    assert_eq!(branch_hist.len(), 4);
    assert_eq!(branch_hist[0].content, "q1");
    assert_eq!(branch_hist[3].content, "a-alt");

    let main_hist = container.chat_history(&main.id).await.unwrap();
    assert_eq!(main_hist.len(), 4);
    assert_eq!(main_hist[3].content, "a2");

    // The tree lists both sessions, main flagged.
    let tree = container.chat_branches(&main.id).await.unwrap();
    assert_eq!(tree.len(), 2);
    assert!(tree.iter().any(|b| b.is_main && b.title == "Main"));
    assert!(tree.iter().any(|b| !b.is_main && b.title == "Experiment"));
}

#[tokio::test]
async fn persistent_chat_operations_reject_unknown_sessions() {
    use hf_core::types::SessionId;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("chat-errors.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let unknown = SessionId::from_string("missing-session");

    assert!(container.chat_history(&unknown).await.is_err());
    assert!(container.chat_checkpoints(&unknown).await.is_err());
    assert!(container.chat_branches(&unknown).await.is_err());
    assert!(container.chat_rollback_last(&unknown).await.is_err());
    assert!(container
        .chat_rollback_to(&unknown, "missing-checkpoint")
        .await
        .is_err());
    assert!(container
        .chat_branch(&unknown, 2, Some("Branch".to_owned()))
        .await
        .is_err());
    assert!(container.delete_chat_session(&unknown).await.is_err());
}

#[tokio::test]
async fn chat_rollback_waits_for_the_shared_session_mutation_lock() {
    use hf_core::session::{CreateSessionOptions, SessionType};
    use hf_core::types::Message;

    let rt = Arc::new(hf_runtime::StubRuntime);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("chat-lock.db"))
            .await
            .expect("connect store"),
    );
    let container = ServiceContainer::new(rt, None).with_store(store);
    let manager = container.session_manager().unwrap();
    let session = manager
        .create_session(CreateSessionOptions {
            parent_id: None,
            session_type: SessionType::Main,
            agent_id: None,
            title: None,
        })
        .await
        .unwrap();
    container
        .chat_create_checkpoint(&session.id, 0)
        .await
        .unwrap();
    manager
        .append_messages(
            &session.id,
            &[Message::user("question"), Message::assistant("answer")],
        )
        .await
        .unwrap();

    let guard = container.session_turn_lock(&session.id).lock_owned().await;
    let worker = container.clone();
    let session_id = session.id.clone();
    let mut rollback = tokio::spawn(async move { worker.chat_rollback_last(&session_id).await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), &mut rollback)
            .await
            .is_err(),
        "rollback must wait while another mutation owns the session lock"
    );

    drop(guard);
    assert_eq!(rollback.await.unwrap().unwrap(), 2);
}
