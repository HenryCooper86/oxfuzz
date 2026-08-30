//! End-to-end pipeline integration test with a fully mocked engine: one test
//! drives discover -> harness draft -> compile -> smoke -> promote -> bounded
//! run -> triage through the `ServiceContainer`, asserting the persisted
//! target/harness/run/crash chain holds together. No Docker, no network, no
//! real LLM: the sandbox is a stub runtime and the LLM a fixed-reply pool.

mod common;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use hf_core::crash::CrashKind;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};

/// Fixture C project: a parser-shaped fuzz target plus a second function, so
/// the project persists more than one target and crash linkage can be checked
/// against the wrong one.
const FIXTURE: &str = r"
#include <stddef.h>
#include <stdint.h>

// A parser-shaped function: a byte buffer + length is an obvious fuzz target.
int parse_value(const uint8_t *data, size_t len) {
    if (len >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        return 1;
    }
    return 0;
}

int helper_add(int a, int b) { return a + b; }
";

/// Fixed LLM reply for the harness draft: a fenced C block the draft parser
/// accepts, driving the discovered `parse_value`.
const HARNESS_REPLY: &str = r"```c
#include <stddef.h>
#include <stdint.h>

int parse_value(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)parse_value(data, size);
    return 0;
}
```";

/// What the stubbed harness prints when the crashing input is replayed: an
/// `ASan` heap-buffer-overflow with a symbolized stack into `parse_value`.
const ASAN_TRACE: &str = r"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011
    #0 0x000055f0deadbeef in parse_value /work/parser.c:7:9
    #1 0x000055f0cafebabe in LLVMFuzzerTestOneInput /work/harness.c:6:12
    #2 0x000055f0feedface in main /work/harness.c:10:2
SUMMARY: AddressSanitizer: heap-buffer-overflow /work/parser.c:7:9 in parse_value
";

/// Artifact layout the stub campaign drops into the run-owned output mount: a
/// libFuzzer `crash-` input plus its stem-matched sanitizer report.
const CRASH_ARTIFACT: &str = "crash-e2e-deadbeef";
const CRASH_REPORT: &str = "log-e2e-deadbeef.txt";
const CRASH_INPUT: &[u8] = b"FUZZ";
/// What the stubbed minimizer publishes: strictly smaller than `CRASH_INPUT`.
const MINIMIZED_INPUT: &[u8] = b"F";

fn completed(exit_code: i32, stdout: &str, stderr: &str, cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
    }
}

/// Whether the stubbed crash minimizer converges.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Minimize {
    /// The minimizer runs out its budget, so triage retains the original
    /// reproducer.
    NeverConverges,
    /// The minimizer publishes a smaller input that still reproduces.
    Converges,
}

/// One stub runtime covering every pipeline stage: compilation leaves a
/// harness binary in the workspace, smoke qualification is a clean measured
/// libFuzzer pass, the bounded campaign writes one crash artifact into its
/// run-owned output mount, crash reproduction replays the `ASan` trace, and
/// CASR is unavailable (forcing the built-in triage path). Minimization is the
/// one stage the two pipeline arms disagree on, so it is a parameter.
struct PipelineRuntime {
    minimize: Minimize,
    /// How many times the sandboxed minimizer was actually invoked. A second
    /// triage pass over an already-published artifact must not add to this.
    minimize_calls: std::sync::Mutex<usize>,
}

impl PipelineRuntime {
    fn new(minimize: Minimize) -> Self {
        Self {
            minimize,
            minimize_calls: std::sync::Mutex::new(0),
        }
    }
}

#[async_trait]
impl RuntimeAdapter for PipelineRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        // Harness compilation: the stubbed compiler leaves a binary behind.
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_value"), b"mock compiled harness").unwrap();
        Ok(completed(0, "", "", cwd))
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if cmd.first().is_some_and(|part| part.starts_with("casr-")) {
            return Err(ClassifiedError::Sandbox(
                "CASR unavailable in test".to_owned(),
            ));
        }
        if let Some(output) = cmd
            .iter()
            .find_map(|part| part.strip_prefix("-exact_artifact_path="))
        {
            *self.minimize_calls.lock().unwrap() += 1;
            if self.minimize == Minimize::NeverConverges {
                // Minimization does not converge: triage keeps the original input.
                return Ok(CommandResult {
                    termination: CommandTermination::TimedOut,
                    ..completed(1, "", "", cwd)
                });
            }
            // Write through the writable derived-artifact mount the sandbox
            // exposes, exactly as a real minimizer would: the container path
            // triage passed must resolve back to a host path under it.
            let mount = opts
                .extra_mounts
                .iter()
                .find(|mount| output.starts_with(&mount.container_path))
                .expect("minimized output must use the writable derived-artifact mount");
            let relative = output
                .strip_prefix(&mount.container_path)
                .unwrap()
                .trim_start_matches('/');
            std::fs::write(mount.host_path.join(relative), MINIMIZED_INPUT).unwrap();
            return Ok(completed(0, "", "", cwd));
        }
        if cmd.len() == 2 && cmd[1].contains("crash-") {
            // Crash reproduction: the stubbed harness reports the ASan error.
            return Ok(completed(1, "", ASAN_TRACE, cwd));
        }
        // Smoke qualification: a clean, measured libFuzzer pass.
        Ok(completed(
            0,
            "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128",
            "",
            cwd,
        ))
    }

    async fn run_command_streaming_opts(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        // The bounded campaign: stream libFuzzer progress and drop the crash
        // artifact into the run-owned output directory.
        let out = opts
            .extra_mounts
            .iter()
            .find(|mount| mount.container_path.ends_with("/out"))
            .expect("run output mount");
        std::fs::write(out.host_path.join(CRASH_ARTIFACT), CRASH_INPUT).unwrap();
        std::fs::write(out.host_path.join(CRASH_REPORT), ASAN_TRACE).unwrap();
        on_line("#1 pulse cov: 42 ft: 84 exec/s: 256");
        on_line("Test unit written to /work/runs/e2e/out/crash-e2e-deadbeef");
        on_line("DONE cov: 42 ft: 84 corp: 3/24b exec/s: 256");
        Ok(completed(0, "", "", cwd))
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// A pool that answers every completion with the fixed harness-source reply.
struct HarnessDraftPool;

#[async_trait]
impl hf_core::provider::ProviderPool for HarnessDraftPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(HARNESS_REPLY))
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
async fn discover_harness_run_triage_end_to_end() {
    common::install_managed_workspace("oxfuzz_e2e_pipeline_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("e2e_project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("e2e.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(PipelineRuntime::new(Minimize::NeverConverges)),
        Some(Arc::new(HarnessDraftPool)),
    )
    .with_store(Arc::clone(&store));

    // 1. Discovery: the fixture parser lands in the inventory and is persisted.
    let inventory = container
        .discover(&project, TargetLanguage::C)
        .await
        .unwrap();
    let candidate = inventory
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_value")
        .expect("parse_value should be discovered");
    let other = inventory
        .candidates
        .iter()
        .find(|c| c.symbol == "helper_add")
        .expect("helper_add should be discovered");
    let persisted_targets = store
        .list_targets(&inventory.project_root.to_string_lossy())
        .await
        .unwrap();
    assert!(
        persisted_targets.iter().any(|t| t.id == candidate.id),
        "discovered target must be persisted"
    );

    // 2. Harness: LLM draft -> stubbed compile -> stubbed smoke -> promote.
    let draft = container
        .harness_draft(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert!(draft.source.contains("parse_value"));
    let source_rev = format!("{:x}", Sha256::digest(draft.source.as_bytes()));

    let compiled = container
        .harness_compile(
            draft.source,
            &project,
            EngineKind::LibFuzzer,
            "parse_value",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert_eq!(compiled.status, HarnessStatus::Compiled);

    let smoke = container
        .harness_smoke(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert!(smoke.summary.passed);

    let promoted = container
        .harness_promote(&project, "parse_value", EngineKind::LibFuzzer)
        .await
        .unwrap();
    assert_eq!(promoted.status, HarnessStatus::Promoted);
    assert_eq!(promoted.target_id, candidate.id);

    // 3. Bounded campaign: the stub engine writes a crash artifact; the run is
    // recorded with its termination and metrics.
    let summary = container
        .run_fuzzer(&project, "parse_value", EngineKind::LibFuzzer, 60, &|_| {})
        .await
        .unwrap();
    assert_eq!(summary.termination, CommandTermination::Completed);
    assert_eq!(summary.crashes, 1);
    assert_eq!(summary.edges, 42);
    assert!(summary.execs > 0.0);

    let run = store.get_run(summary.run_id).await.unwrap().unwrap();
    assert_eq!(run.status, hf_storage::RunStatus::Done);
    assert_eq!(run.kind, hf_storage::RunKind::Campaign);
    assert!(run.ended_at.is_some());
    assert_eq!(run.edges, Some(42));
    assert_eq!(run.execs, Some(256.0));
    assert_eq!(run.crash_count, Some(1));
    // The run is bound to the exact promoted harness revision.
    assert_eq!(run.harness_rev.as_deref(), Some(source_rev.as_str()));
    assert_eq!(run.binary_rev.as_deref().map(str::len), Some(64));
    let evidence_dir = format!("runs/{}/out", summary.run_id);
    assert_eq!(run.evidence_dir.as_deref(), Some(evidence_dir.as_str()));
    let run_config = run.config.as_ref().expect("campaign run config");
    assert_eq!(run_config.harness_id, promoted.id);

    // 4. Triage: the crash is ingested, classified, and attributed to the
    // exact target and run that produced it.
    let crashes = container.triage(&project, "parse_value").await.unwrap();
    assert_eq!(crashes.len(), 1);
    let crash = &crashes[0];
    assert_eq!(crash.kind, CrashKind::Asan);
    assert!(!crash.stack_signature.is_empty());
    assert_eq!(crash.run_id, summary.run_id);
    assert_eq!(crash.target_id, candidate.id);
    assert_ne!(
        crash.target_id, other.id,
        "crash must not leak onto the other target in the same project"
    );
    let workspace = hf_service::workspace_dir(&project, "parse_value");
    assert!(crash.input_path.starts_with(workspace.join(&evidence_dir)));

    let persisted = store.list_crashes_by_run(summary.run_id).await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].id, crash.id);

    // A second triage pass over the same evidence dedups: the deterministic
    // crash id is re-derived and the row replaced, not duplicated.
    let reprises = container.triage(&project, "parse_value").await.unwrap();
    assert_eq!(reprises.len(), 1);
    let after = store.list_crashes_by_run(summary.run_id).await.unwrap();
    assert_eq!(
        after.len(),
        1,
        "second triage pass must not duplicate the crash"
    );
    assert_eq!(after[0].id, persisted[0].id);

    std::fs::remove_dir_all(&workspace).ok();
}

/// The full pipeline, ending in a crash that minimization actually reduced.
///
/// The sibling arm above runs the same discovery -> harness -> campaign ->
/// triage loop but with a minimizer that never converges, so it asserts the
/// original reproducer is retained. Successful minimization was covered only
/// from a hand-staged run record, never from a run this pipeline produced, so
/// nothing tied a reduced artifact back to the campaign that found it.
#[tokio::test]
async fn full_pipeline_minimizes_the_crash_it_found() {
    common::install_managed_workspace("oxfuzz_e2e_minimize_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("e2e_minimize_project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("e2e_minimize.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(PipelineRuntime::new(Minimize::Converges));
    let container = ServiceContainer::new(
        Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>,
        Some(Arc::new(HarnessDraftPool)),
    )
    .with_store(Arc::clone(&store));

    let inventory = container
        .discover(&project, TargetLanguage::C)
        .await
        .unwrap();
    assert!(
        inventory
            .candidates
            .iter()
            .any(|c| c.symbol == "parse_value"),
        "the fixture parser is discovered"
    );

    let draft = container
        .harness_draft(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_compile(
            draft.source.clone(),
            &project,
            EngineKind::LibFuzzer,
            "parse_value",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, "parse_value", EngineKind::LibFuzzer)
        .await
        .unwrap();

    let summary = container
        .run_fuzzer(&project, "parse_value", EngineKind::LibFuzzer, 1, &|_| {})
        .await
        .unwrap();
    assert_eq!(summary.crashes, 1);

    let crashes = container.triage(&project, "parse_value").await.unwrap();
    assert_eq!(crashes.len(), 1);
    let crash = &crashes[0];

    // The classification is taken from the replay of the original input, before
    // minimization, so reducing the input must not change the verdict.
    assert_eq!(crash.kind, CrashKind::Asan);
    assert!(!crash.stack_signature.is_empty());
    assert_eq!(crash.run_id, summary.run_id);

    assert!(crash.minimized, "the converged minimizer must be recorded");
    assert_eq!(
        std::fs::read(&crash.input_path).unwrap(),
        MINIMIZED_INPUT,
        "the crash must point at the reduced input, not the original"
    );

    // The reduced artifact lives in the run's own triage directory, and the
    // original stays exactly where the campaign wrote it.
    let workspace = std::fs::canonicalize(hf_service::workspace_dir(&project, "parse_value"))
        .expect("workspace exists after the run");
    let run_root = workspace.join("runs").join(summary.run_id.to_string());
    assert!(
        crash
            .input_path
            .starts_with(run_root.join("triage/minimized")),
        "reduced artifact escaped the run-owned triage directory: {}",
        crash.input_path.display()
    );
    assert_eq!(
        std::fs::read(run_root.join("out").join(CRASH_ARTIFACT)).unwrap(),
        CRASH_INPUT,
        "minimization must not consume the original reproducer"
    );

    let persisted = store.list_crashes_by_run(summary.run_id).await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert!(
        persisted[0].minimized,
        "the minimized flag must survive to storage, not just the returned value"
    );
    assert_eq!(persisted[0].id, crash.id);
    assert_eq!(*runtime.minimize_calls.lock().unwrap(), 1);

    // Re-triage reuses the published artifact instead of minimizing again: the
    // deterministic crash id is re-derived, the row is replaced rather than
    // duplicated, and the sandbox is not entered a second time.
    let reprises = container.triage(&project, "parse_value").await.unwrap();
    assert_eq!(reprises.len(), 1);
    assert!(reprises[0].minimized);
    assert_eq!(reprises[0].id, crash.id);
    assert_eq!(
        std::fs::read(&reprises[0].input_path).unwrap(),
        MINIMIZED_INPUT
    );
    assert_eq!(
        *runtime.minimize_calls.lock().unwrap(),
        1,
        "a published minimized artifact must be reused, not recomputed"
    );
    let after = store.list_crashes_by_run(summary.run_id).await.unwrap();
    assert_eq!(after.len(), 1, "re-triage must not duplicate the crash");
    assert!(after[0].minimized);

    std::fs::remove_dir_all(&workspace).ok();
}
