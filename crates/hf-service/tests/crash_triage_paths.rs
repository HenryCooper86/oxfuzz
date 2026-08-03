//! Coverage for the crash-triage strategies in `hf-service` that the existing
//! suite leaves untested: the default CASR-clustered path (`run_casr_triage` ->
//! `bucket_by_cluster`), the built-in fallback's signature-stagnation early
//! break (`legacy_triage`), and LLM bug-report drafting with its per-pass cap.
//!
//! No Docker, no network, no real LLM: the sandbox is a stub runtime scripted
//! per command (casr-*, reproduce replay, minimize) and the LLM a fixed-reply
//! pool. These tests assert existing behavior only.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use hf_core::crash::{CrashKind, CrashSeverity};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const RUN_BINARY: &[u8] = b"immutable run binary";

/// A CASR `.casrep` for cluster 1: an exploitable heap overflow (kind `Asan`).
const CASREP_CLUSTER1: &str = r##"{
    "CrashSeverity": {"Type": "EXPLOITABLE", "ShortDescription": "heap-buffer-overflow(write)"},
    "CrashLine": "parse.c:10:5",
    "Stacktrace": ["#0 0x1 in parse_a parse.c:10:5", "#1 0x2 in LLVMFuzzerTestOneInput harness.c:6:5"]
}"##;

/// A CASR `.casrep` for cluster 2: a probably-exploitable SEGV (kind `Segv`).
const CASREP_CLUSTER2: &str = r##"{
    "CrashSeverity": {"Type": "PROBABLY_EXPLOITABLE", "ShortDescription": "SEGV on unknown address"},
    "CrashLine": "parse.c:20:1",
    "Stacktrace": ["#0 0x3 in deref parse.c:20:1"]
}"##;

/// A CASR `.casrep` CASR did not cluster: a not-exploitable abort (kind `Abort`).
const CASREP_UNCLUSTERED: &str = r##"{
    "CrashSeverity": {"Type": "NOT_EXPLOITABLE", "ShortDescription": "assertion failed"},
    "CrashLine": "parse.c:30:3",
    "Stacktrace": ["#0 0x4 in check parse.c:30:3"]
}"##;

/// A fixed, well-formed bug-report JSON carrying a root cause and a suggested
/// fix, so the parsed [`hf_core::crash::BugReport`] populates both fields.
const BUG_REPORT_JSON: &str = r#"{
    "title": "Heap overflow in parse_input",
    "summary": "heap-buffer-overflow reachable from the fuzz entrypoint",
    "repro_steps": "replay the crash input through the harness",
    "stack": "parse_input -> LLVMFuzzerTestOneInput",
    "severity_guess": "high",
    "root_cause": "the parser reads one byte past the end of the heap buffer",
    "suggested_fix": "--- a/parse.c\n+++ b/parse.c\n@@ clamp the index to the buffer length"
}"#;

const ROOT_CAUSE: &str = "the parser reads one byte past the end of the heap buffer";

fn completed(exit_code: i32, stdout: &str, stderr: &str, cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
    }
}

fn timed_out(cwd: &Path) -> CommandResult {
    CommandResult {
        termination: CommandTermination::TimedOut,
        ..completed(1, "", "", cwd)
    }
}

/// A persisted, terminal run whose evidence (immutable harness binary + crash
/// inputs) is staged on disk, ready for `triage_run`.
struct TriageFixture {
    _root: tempfile::TempDir,
    project: PathBuf,
    symbol: String,
    run_id: Uuid,
    store: Arc<hf_storage::Store>,
}

/// Build a triage fixture with one persisted libFuzzer run and the named crash
/// inputs staged into its run-owned output directory. Modeled on the
/// `crash_minimization.rs` fixture: `binary_rev` is set (so the minimization
/// phase engages) but `harness_rev` is not (no source context).
async fn triage_fixture(name: &str, crash_files: &[String]) -> TriageFixture {
    common::install_managed_workspace("oxfuzz_crash_triage_paths");
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join(format!("{name}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    let symbol = "parse_input".to_owned();

    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.clone(),
        language: TargetLanguage::C,
        symbol: symbol.clone(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("parse.c"),
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
        rationale: "test".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return n && d[0]; }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_input"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(1)),
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
    run.status = hf_storage::RunStatus::Done;
    run.ended_at = Some(Utc::now());
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    run.binary_rev = Some(format!("{:x}", Sha256::digest(RUN_BINARY)));

    let workspace = hf_service::workspace_dir(&project, &symbol);
    let input_dir = workspace
        .join("runs")
        .join(run.id.to_string())
        .join("input");
    let out_dir = workspace.join("runs").join(run.id.to_string()).join("out");
    std::fs::create_dir_all(&input_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(input_dir.join("harness"), RUN_BINARY).unwrap();
    for file in crash_files {
        std::fs::write(out_dir.join(file), format!("input for {file}").as_bytes()).unwrap();
    }

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("service.db"))
            .await
            .unwrap(),
    );
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();

    TriageFixture {
        _root: root,
        project,
        symbol,
        run_id: run.id,
        store,
    }
}

fn is_casr(cmd: &[String]) -> bool {
    cmd.first().is_some_and(|part| part.starts_with("casr-"))
}

fn is_minimize(cmd: &[String]) -> bool {
    cmd.iter()
        .any(|part| part.starts_with("-exact_artifact_path="))
}

/// The writable CASR-output mount the sandbox exposes for `.casrep` reports.
fn casr_out_mount(opts: &SandboxOptions) -> &hf_core::runtime::SandboxMount {
    opts.extra_mounts
        .iter()
        .find(|mount| !mount.read_only)
        .expect("CASR triage exposes a writable output mount")
}

// --- Test 1: CASR-clustered triage (the default strategy) ------------------

/// CASR is AVAILABLE and writes `.casrep` reports across cluster dirs: two in
/// `cl1/`, one in `cl2/`, and one un-clustered report at the top level.
struct CasrClusterRuntime;

#[async_trait]
impl RuntimeAdapter for CasrClusterRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if is_casr(cmd) {
            let host = &casr_out_mount(opts).host_path;
            std::fs::create_dir_all(host.join("cl1")).unwrap();
            std::fs::write(host.join("cl1").join("crash-a.casrep"), CASREP_CLUSTER1).unwrap();
            std::fs::write(host.join("cl1").join("crash-b.casrep"), CASREP_CLUSTER1).unwrap();
            std::fs::create_dir_all(host.join("cl2")).unwrap();
            std::fs::write(host.join("cl2").join("crash-c.casrep"), CASREP_CLUSTER2).unwrap();
            std::fs::write(host.join("crash-d.casrep"), CASREP_UNCLUSTERED).unwrap();
            return Ok(completed(0, "", "", cwd));
        }
        if is_minimize(cmd) {
            // Minimization does not converge, so classification is untouched.
            return Ok(timed_out(cwd));
        }
        Ok(completed(0, "", "", cwd))
    }
}

#[tokio::test]
async fn casr_clustered_triage_end_to_end() {
    let crash_files: Vec<String> = ["crash-a", "crash-b", "crash-c", "crash-d"]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let fixture = triage_fixture("casr-clustered", &crash_files).await;
    let container = ServiceContainer::new(Arc::new(CasrClusterRuntime), None)
        .with_store(Arc::clone(&fixture.store));

    let crashes = container
        .triage_run(&fixture.project, &fixture.symbol, fixture.run_id)
        .await
        .unwrap();

    // Four `.casrep` reports -> one representative per cluster (cl1 collapses
    // its two) plus the un-clustered report passes through: three crashes.
    assert_eq!(
        crashes.len(),
        3,
        "one per cluster + un-clustered passthrough"
    );
    assert!(
        crashes.iter().all(|c| c.casr.is_some()),
        "every crash carries its CASR report, proving the CASR path (not fallback) ran"
    );

    let by_cluster = |cluster: Option<u32>| {
        crashes
            .iter()
            .find(|c| c.casr.as_ref().unwrap().cluster == cluster)
            .unwrap_or_else(|| panic!("expected a crash for cluster {cluster:?}"))
    };

    // cl1: exactly one representative kept, classified from the CASR report.
    assert_eq!(
        crashes
            .iter()
            .filter(|c| c.casr.as_ref().unwrap().cluster == Some(1))
            .count(),
        1,
        "bucket_by_cluster keeps exactly one crash per cluster"
    );
    let c1 = by_cluster(Some(1));
    assert_eq!(c1.kind, CrashKind::Asan);
    assert_eq!(
        c1.casr.as_ref().unwrap().severity,
        CrashSeverity::Exploitable
    );

    // cl2: severity and kind come from the CASR report, not the fallback.
    let c2 = by_cluster(Some(2));
    assert_eq!(c2.kind, CrashKind::Segv);
    assert_eq!(
        c2.casr.as_ref().unwrap().severity,
        CrashSeverity::ProbablyExploitable
    );

    // The un-clustered crash (cluster = None) is retained.
    let cu = by_cluster(None);
    assert_eq!(cu.kind, CrashKind::Abort);
    assert_eq!(
        cu.casr.as_ref().unwrap().severity,
        CrashSeverity::NotExploitable
    );

    // The same three, with their CASR reports, are persisted.
    let persisted = fixture
        .store
        .list_crashes_by_run(fixture.run_id)
        .await
        .unwrap();
    assert_eq!(persisted.len(), 3);
    assert!(persisted.iter().all(|c| c.casr.is_some()));
}

// --- Tests 3 & 4: built-in (legacy) triage fallback ------------------------

/// CASR is UNAVAILABLE (its command errors), forcing the built-in reproduce/
/// classify/dedup path. Each replay yields a sanitizer trace; when `distinct`
/// is set the trace embeds the input name so every crash gets its own stack
/// signature, otherwise all replays share one signature.
struct LegacyReplayRuntime {
    distinct: bool,
    reproduce_calls: AtomicUsize,
}

impl LegacyReplayRuntime {
    fn new(distinct: bool) -> Self {
        Self {
            distinct,
            reproduce_calls: AtomicUsize::new(0),
        }
    }

    fn trace(&self, input: &str) -> String {
        let frame = if self.distinct {
            format!("frame_{input}")
        } else {
            "shared_frame".to_owned()
        };
        format!(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n\
             #0 0x1 in {frame} /work/parse.c:7:9\n\
             #1 0x2 in LLVMFuzzerTestOneInput /work/harness.c:6:5\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /work/parse.c:7:9\n"
        )
    }
}

#[async_trait]
impl RuntimeAdapter for LegacyReplayRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if is_casr(cmd) {
            // Force the built-in fallback: CASR errors, triage degrades.
            return Err(ClassifiedError::Sandbox(
                "CASR unavailable in test".to_owned(),
            ));
        }
        if is_minimize(cmd) {
            return Ok(timed_out(cwd));
        }
        if cmd.len() == 2 {
            // Crash reproduction: `[binary, input]`. The trace is the stderr.
            self.reproduce_calls.fetch_add(1, Ordering::SeqCst);
            let input = cmd[1].rsplit('/').next().unwrap_or_default();
            return Ok(completed(1, "", &self.trace(input), cwd));
        }
        Ok(completed(0, "", "", cwd))
    }
}

#[tokio::test]
async fn legacy_triage_saturates_on_repeated_signatures() {
    // Mirror of triage::legacy_triage's SIGNATURE_STAGNATION (40): after this
    // many consecutive replays with no new stack signature the loop breaks.
    const SIGNATURE_STAGNATION: usize = 40;

    // Stage well beyond the stagnation window; every replay yields ONE repeated
    // signature, so the early break must fire before all inputs are replayed.
    let crash_files: Vec<String> = (0..50).map(|i| format!("crash-{i:04}")).collect();
    let fixture = triage_fixture("legacy-saturation", &crash_files).await;
    let runtime = Arc::new(LegacyReplayRuntime::new(false));
    let container =
        ServiceContainer::new(runtime.clone(), None).with_store(Arc::clone(&fixture.store));

    let crashes = container
        .triage_run(&fixture.project, &fixture.symbol, fixture.run_id)
        .await
        .unwrap();

    // The first replay records the signature; each of the next 40 is a repeat,
    // and the 42nd iteration hits the stagnation break -> 41 replays total.
    assert_eq!(
        runtime.reproduce_calls.load(Ordering::SeqCst),
        SIGNATURE_STAGNATION + 1,
        "reproduction stops at the stagnation window, not after all 50 inputs"
    );
    // All replays share one signature, so dedup collapses them to one crash.
    assert_eq!(crashes.len(), 1, "repeated signatures dedup to one crash");
    assert!(
        crashes[0].casr.is_none(),
        "the fallback path carries no CASR report"
    );

    let persisted = fixture
        .store
        .list_crashes_by_run(fixture.run_id)
        .await
        .unwrap();
    assert_eq!(
        persisted.len(),
        1,
        "only the single deduped crash is persisted"
    );
}

/// A provider pool that answers every completion with the fixed bug-report JSON
/// and counts how many drafts it was asked for.
struct BugReportPool {
    drafts: AtomicUsize,
}

#[async_trait]
impl hf_core::provider::ProviderPool for BugReportPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.drafts.fetch_add(1, Ordering::SeqCst);
        Ok(hf_test_utils::fixtures::make_chat_response(BUG_REPORT_JSON))
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "unused".to_owned(),
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
async fn triage_drafts_and_persists_bug_report_with_root_cause() {
    // Mirror of triage's MAX_BUG_REPORT_DRAFTS: only the first 20 unique crashes
    // per pass get a drafted report.
    const MAX_BUG_REPORT_DRAFTS: usize = 20;

    // 25 distinct-signature crashes: more than the draft cap, none deduped.
    let crash_files: Vec<String> = (0..25).map(|i| format!("crash-{i:04}")).collect();
    let fixture = triage_fixture("bug-report-drafts", &crash_files).await;
    let pool = Arc::new(BugReportPool {
        drafts: AtomicUsize::new(0),
    });
    let container =
        ServiceContainer::new(Arc::new(LegacyReplayRuntime::new(true)), Some(pool.clone()))
            .with_store(Arc::clone(&fixture.store));

    let crashes = container
        .triage_run(&fixture.project, &fixture.symbol, fixture.run_id)
        .await
        .unwrap();

    // Distinct signatures -> no dedup: all 25 crashes survive.
    assert_eq!(crashes.len(), 25, "distinct signatures are not deduped");
    // The draft cap holds: exactly 20 model calls and 20 populated reports.
    assert_eq!(
        pool.drafts.load(Ordering::SeqCst),
        MAX_BUG_REPORT_DRAFTS,
        "bug-report drafting is capped per pass"
    );
    let drafted = crashes.iter().filter(|c| c.bug_report.is_some()).count();
    assert_eq!(
        drafted, MAX_BUG_REPORT_DRAFTS,
        "only the capped prefix is drafted"
    );

    // A drafted crash carries the parsed root cause and suggested fix.
    let sample = crashes
        .iter()
        .find(|c| c.bug_report.is_some())
        .expect("at least one drafted report");
    let report = sample.bug_report.as_ref().unwrap();
    assert_eq!(report.root_cause.as_deref(), Some(ROOT_CAUSE));
    assert!(
        report
            .suggested_fix
            .as_deref()
            .is_some_and(|fix| fix.contains("clamp the index")),
        "the suggested fix is parsed from the report"
    );

    // Persistence round-trips the bug report: 25 rows, 20 with a report.
    let persisted = fixture
        .store
        .list_crashes_by_run(fixture.run_id)
        .await
        .unwrap();
    assert_eq!(persisted.len(), 25);
    assert_eq!(
        persisted.iter().filter(|c| c.bug_report.is_some()).count(),
        MAX_BUG_REPORT_DRAFTS
    );
    let persisted_report = persisted
        .iter()
        .find_map(|c| c.bug_report.as_ref())
        .expect("a persisted bug report");
    assert_eq!(persisted_report.root_cause.as_deref(), Some(ROOT_CAUSE));
}
