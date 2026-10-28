//! Per-operation [`hf_service::AiPolicy`] semantics for the six
//! provider-dispatching operations that previously decided by "is a pool
//! configured" alone: smoke repair, plateau refinement, the AI report
//! narrative, triage bug reports, crash verification, and run dictionaries.
//!
//! `Auto` equals today's behavior (the pre-existing suites are that evidence);
//! these tests pin the two new policies per operation: `Off` never dispatches,
//! and `Require` converts the specified silent outcomes into errors.

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{CasrReport, Crash, CrashKind, CrashSeverity};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{AiPolicy, HarnessReviewBypass, ServiceContainer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Shared scripted provider pools
// ---------------------------------------------------------------------------

/// Counts dispatches and answers every completion with a fixed reply.
struct CountingPool {
    calls: AtomicUsize,
    reply: &'static str,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CountingPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(hf_test_utils::fixtures::make_chat_response(self.reply))
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "streaming is unused here".to_owned(),
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

/// Counts dispatches and fails every one: any provider call that succeeds here
/// is a bug in the test, and a `Require` failure must surface the error.
struct RefusingPool {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for RefusingPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(hf_core::provider::ProviderError::Other {
            message: "scripted provider outage".to_owned(),
        })
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "streaming is unused here".to_owned(),
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

/// A pool that approves the mandatory pre-execution harness review and fails
/// every other prompt, counting those failures.
struct ReviewOnlyPool {
    failures: AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for ReviewOnlyPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        self.failures.fetch_add(1, Ordering::SeqCst);
        Err(hf_core::provider::ProviderError::Other {
            message: "scripted repair outage".to_owned(),
        })
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "streaming is unused here".to_owned(),
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

// ---------------------------------------------------------------------------
// Smoke repair: harness_smoke_with_repair
// ---------------------------------------------------------------------------

const SMOKE_SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";
const SILENT_ENGINE_OUTPUT: &str = "INFO: Seed: 1\n[!] the entry point returned non-zero";

/// Compiles every harness; every smoke run produces no fuzzer activity.
struct SilentSmokeRuntime {
    smokes: AtomicUsize,
}

impl SilentSmokeRuntime {
    fn respond(&self, cmd: &[String], cwd: &Path) -> CommandResult {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        let smoke = cmd.iter().any(|arg| arg.starts_with("-max_total_time"));
        let stdout = if smoke {
            self.smokes.fetch_add(1, Ordering::SeqCst);
            SILENT_ENGINE_OUTPUT.to_owned()
        } else {
            std::fs::create_dir_all(cwd).unwrap();
            std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
            String::new()
        };
        CommandResult {
            exit_code: 0,
            stdout,
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        }
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for SilentSmokeRuntime {
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
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(self.respond(cmd, cwd))
    }
    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(self.respond(cmd, cwd))
    }
    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        std::fs::write(path, content).unwrap();
        Ok(())
    }
    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// A compiled silent-smoke harness whose repair attempts can be counted.
async fn smoke_repair_fixture(
    pool: Option<Arc<dyn hf_core::provider::ProviderPool>>,
) -> (tempfile::TempDir, ServiceContainer) {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = tempfile::tempdir().unwrap();
    let config = project.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\nenabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\", \"syzkaller\"]\n\
         default_engine = \"libfuzzer\"\ndefault_duration_secs = 60\n\
         [fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 600\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("policy.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(SilentSmokeRuntime {
            smokes: AtomicUsize::new(0),
        }),
        pool,
    )
    .with_store(store);
    container
        .harness_compile(
            SMOKE_SOURCE.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap();
    (project, container)
}

/// `Off` makes no repair attempt: the smoke outcome stands and no model call
/// happens, even though a provider is configured and the failure is repairable.
#[tokio::test]
async fn smoke_repair_with_off_leaves_the_smoke_failure_standing() {
    let pool = hf_test_utils::RecordingHarnessPool::new(|_, _| {
        "```c\nint parse_entry(const unsigned char *, unsigned long);\nint LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { parse_entry(data, size); return 0; }\n```".to_owned()
    });
    let (project, container) = smoke_repair_fixture(Some(
        Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>
    ))
    .await;

    let error = container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            2,
            &|_, _| panic!("off makes no repair attempt"),
            AiPolicy::Off,
        )
        .await
        .expect_err("the silent smoke run must not qualify");

    assert!(
        hf_harness::repairable_smoke_failure(&error).is_some(),
        "the smoke outcome stands instead of a repair-specific error: {error}"
    );
    assert!(
        pool.prompts_containing("A previous attempt").is_empty(),
        "off dispatches no repair prompt"
    );
}

/// `Require` without a provider is an error naming the missing model, not the
/// generic "could not be repaired" skip.
#[tokio::test]
async fn smoke_repair_with_require_and_no_pool_is_an_error() {
    let (project, container) = smoke_repair_fixture(None).await;

    let error = container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            2,
            &|_, _| {},
            AiPolicy::Require,
        )
        .await
        .expect_err("a required repair without a provider must fail loud");

    assert!(
        error.to_string().contains("no LLM provider"),
        "the error names the missing model: {error}"
    );
}

/// `Require` surfaces a failed repair call instead of skipping it.
#[tokio::test]
async fn smoke_repair_with_require_surfaces_a_failed_repair_call() {
    let pool = Arc::new(ReviewOnlyPool {
        failures: AtomicUsize::new(0),
    });
    let (project, container) = smoke_repair_fixture(Some(
        Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>
    ))
    .await;

    let error = container
        .harness_smoke_with_repair(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::NotRequested,
            2,
            &|_, _| {},
            AiPolicy::Require,
        )
        .await
        .expect_err("a required repair that fails must surface the failure");

    assert!(
        error.to_string().contains("repair call failed"),
        "the error names the failed repair call: {error}"
    );
    assert!(pool.failures.load(Ordering::SeqCst) >= 1);
}

// ---------------------------------------------------------------------------
// Plateau refinement: harness_refine
// ---------------------------------------------------------------------------

/// Refinement is model-only: `Off` is refused by the operation itself with an
/// error naming that nature (the decision moved out of the CLI parser, 2.19).
#[tokio::test]
async fn refine_with_off_is_refused_by_the_operation() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = tempfile::tempdir().unwrap();

    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let error = container
        .harness_refine(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            AiPolicy::Off,
        )
        .await
        .expect_err("refinement has no no-model path");

    assert!(
        error.to_string().contains("model-only"),
        "the error names the model-only nature: {error}"
    );
}

// ---------------------------------------------------------------------------
// Harness generation draft + compile repair: harness_generate
// ---------------------------------------------------------------------------

/// Every compile fails (`exit 1`), so a repair budget would be spent.
struct FailingCompileRuntime {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RuntimeAdapter for FailingCompileRuntime {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "harness.c:2:5: error: implicit declaration of function 'frob'".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

fn generation_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size) {\n\
         \x20 if (size > 0 && data[0] == 'A') { return 1; }\n\
         \x20 return 0; }\n",
    )
    .unwrap();
    dir
}

/// `Off` drafts the heuristic template and attempts no repair, so a counting
/// pool sees zero dispatches even though a compile failed repairably.
#[tokio::test]
async fn generate_with_off_never_dispatches_for_draft_or_repair() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = generation_project();
    let pool = hf_test_utils::RecordingHarnessPool::new(|_, _| {
        panic!("off must not consult the model for the draft or a repair")
    });
    let runtime = Arc::new(FailingCompileRuntime {
        calls: AtomicUsize::new(0),
    });
    let container = ServiceContainer::new(
        runtime,
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    )
    .with_store(Arc::new(
        hf_storage::Store::connect(project.path().join("gen.db"))
            .await
            .unwrap(),
    ));

    let error = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            2,
            None,
            false,
            false,
            AiPolicy::Off,
        )
        .await
        .expect_err("a compile that never succeeds must fail");

    assert!(
        error.to_string().contains("0 repair attempt"),
        "no repair was attempted under off: {error}"
    );
    assert!(
        pool.prompts().is_empty(),
        "off dispatched nothing: {:?}",
        pool.prompts()
    );
}

/// `Require` without a provider stops at the draft instead of silently
/// substituting the template.
#[tokio::test]
async fn generate_with_require_and_no_pool_errors_at_the_draft() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = generation_project();
    let container = ServiceContainer::new(
        Arc::new(FailingCompileRuntime {
            calls: AtomicUsize::new(0),
        }),
        None,
    )
    .with_store(Arc::new(
        hf_storage::Store::connect(project.path().join("gen.db"))
            .await
            .unwrap(),
    ));

    let error = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            2,
            None,
            false,
            false,
            AiPolicy::Require,
        )
        .await
        .expect_err("a required draft without a provider must fail loud");

    assert!(
        error.to_string().contains("no LLM provider"),
        "the error names the missing model: {error}"
    );
}

// ---------------------------------------------------------------------------
// AI report narrative: generate_report_for_run
// ---------------------------------------------------------------------------

/// A project whose report can be composed deterministically: the target
/// resolves and an (empty) corpus directory exists beside the harness.
fn report_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let workspace = hf_service::workspace_dir(dir.path(), "parse_entry");
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    dir
}

/// `Off` composes the deterministic fact-sheet and dispatches nothing.
#[tokio::test]
async fn report_with_off_composes_the_fact_sheet_without_a_dispatch() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = report_project();
    let pool = Arc::new(CountingPool {
        calls: AtomicUsize::new(0),
        reply: "a narrative no fact-sheet would contain",
    });
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    );

    let markdown = container
        .generate_report_for_run(
            project.path(),
            "parse_entry",
            hf_service::ReportLanguage::En,
            None,
            AiPolicy::Off,
        )
        .await
        .expect("the fact-sheet always composes");

    assert!(
        markdown.starts_with("# ") && markdown.contains("## Executive Summary"),
        "the deterministic fact-sheet answered, not a narrative: {markdown}"
    );
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "off dispatches no composition call"
    );
}

/// `Require` without a provider is an error rather than a silent fact-sheet.
#[tokio::test]
async fn report_with_require_and_no_pool_is_an_error() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = report_project();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let error = container
        .generate_report_for_run(
            project.path(),
            "parse_entry",
            hf_service::ReportLanguage::En,
            None,
            AiPolicy::Require,
        )
        .await
        .expect_err("a required narrative without a provider must fail loud");

    assert!(
        error.to_string().contains("no LLM provider"),
        "the error names the missing model: {error}"
    );
}

/// `Require` surfaces a failed composition instead of downgrading to the
/// fact-sheet.
#[tokio::test]
async fn report_with_require_surfaces_a_failed_composition() {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let project = report_project();
    let pool = Arc::new(RefusingPool {
        calls: AtomicUsize::new(0),
    });
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    );

    let error = container
        .generate_report_for_run(
            project.path(),
            "parse_entry",
            hf_service::ReportLanguage::En,
            None,
            AiPolicy::Require,
        )
        .await
        .expect_err("a required narrative whose call failed must surface it");

    assert!(
        error.to_string().contains("composition failed"),
        "the error names the failed composition: {error}"
    );
}

// ---------------------------------------------------------------------------
// Triage bug reports: triage_run
// ---------------------------------------------------------------------------

const CASREP: &str = r##"{
    "CrashSeverity": {"Type": "EXPLOITABLE", "ShortDescription": "heap-buffer-overflow(write)"},
    "CrashLine": "parse.c:10:5",
    "Stacktrace": ["#0 0x1 in parse_a parse.c:10:5"]
}"##;

const BUG_REPORT_JSON: &str = r#"{
    "title": "Heap overflow in parse_input",
    "summary": "heap-buffer-overflow reachable from the fuzz entrypoint",
    "repro_steps": "replay the crash input through the harness",
    "stack": "parse_input -> LLVMFuzzerTestOneInput",
    "severity_guess": "high",
    "root_cause": "the parser reads one byte past the end of the heap buffer",
    "suggested_fix": "clamp the index"
}"#;

/// Writes one `.casrep` into the CASR output mount.
struct OneCasrRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for OneCasrRuntime {
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
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, _limits, &SandboxOptions::default())
            .await
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if cmd.first().is_some_and(|part| part.starts_with("casr-")) {
            let host = opts
                .extra_mounts
                .iter()
                .find(|mount| !mount.read_only)
                .expect("CASR triage exposes a writable output mount")
                .host_path
                .clone();
            std::fs::write(host.join("crash-a.casrep"), CASREP).unwrap();
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

const RUN_BINARY: &[u8] = b"immutable run binary";

/// One persisted terminal run with a staged binary and one crash input.
async fn triage_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    String,
    Uuid,
    Arc<hf_storage::Store>,
) {
    common::install_managed_workspace("oxfuzz_ai_policy_ops_it");
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("proj");
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
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
        custom_mutator: None,
        cmplog: None,
    };
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy().into_owned(),
        EngineKind::LibFuzzer,
        None,
        Utc::now(),
    );
    run.config = Some(hf_core::engine::FuzzRunConfig {
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
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
        cmplog: false,
    });
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
    std::fs::write(out_dir.join("crash-a"), b"crashing input").unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("triage.db"))
            .await
            .unwrap(),
    );
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();
    let run_id = run.id;
    (root, project, symbol, run_id, store)
}

/// `Off` ingests and persists the crashes with no drafted reports and no
/// dispatch, even though a provider is configured.
#[tokio::test]
async fn triage_with_off_persists_crashes_without_drafts_or_dispatch() {
    let (_root, project, symbol, run_id, store) = triage_fixture().await;
    let pool = Arc::new(CountingPool {
        calls: AtomicUsize::new(0),
        reply: BUG_REPORT_JSON,
    });
    let container = ServiceContainer::new(
        Arc::new(OneCasrRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    )
    .with_store(Arc::clone(&store));

    let crashes = container
        .triage_run(&project, &symbol, run_id, AiPolicy::Off)
        .await
        .expect("off triages without the model");

    assert!(!crashes.is_empty(), "the crash is ingested");
    assert!(
        crashes.iter().all(|crash| crash.bug_report.is_none()),
        "no crash carries a drafted report under off"
    );
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "off dispatches no bug-report draft"
    );
    assert!(
        !store.list_crashes_by_run(run_id).await.unwrap().is_empty(),
        "the classification is persisted exactly as auto persists it"
    );
}

/// `Require` without a provider is an error for the triage operation.
#[tokio::test]
async fn triage_with_require_and_no_pool_errors_for_the_operation() {
    let (_root, project, symbol, run_id, store) = triage_fixture().await;
    let container =
        ServiceContainer::new(Arc::new(OneCasrRuntime), None).with_store(Arc::clone(&store));

    let error = container
        .triage_run(&project, &symbol, run_id, AiPolicy::Require)
        .await
        .expect_err("required bug reports without a provider must fail loud");

    assert!(
        error.to_string().contains("no LLM provider"),
        "the error names the missing model: {error}"
    );
}

/// `Require` without a store is an error for the triage operation: reports
/// cannot be retained (2.13), so none may be drafted.
#[tokio::test]
async fn triage_with_require_and_no_store_errors_for_the_operation() {
    let (_root, project, symbol, run_id, _store) = triage_fixture().await;
    let pool = Arc::new(CountingPool {
        calls: AtomicUsize::new(0),
        reply: BUG_REPORT_JSON,
    });
    let container = ServiceContainer::new(
        Arc::new(OneCasrRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    );

    let error = container
        .triage_run(&project, &symbol, run_id, AiPolicy::Require)
        .await
        .expect_err("required bug reports without a store must fail loud");

    assert!(
        error.to_string().contains("no database configured"),
        "a storeless triage_run fails at its store precondition: {error}"
    );
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "nothing is dispatched when the exchange cannot be retained"
    );
}

// ---------------------------------------------------------------------------
// Crash verification: verify_crashes / verify_crash_by_id
// ---------------------------------------------------------------------------

const VERDICT_REPLY: &str = "{\"reproduces_deterministically\": true, \
                             \"likely_target_bug\": true, \"confidence\": \"high\", \
                             \"reasons\": [\"deterministic ASan overflow\"]}";

fn asan_crash(run_id: Uuid) -> Crash {
    Crash {
        reproduction: None,
        id: Uuid::new_v4(),
        run_id,
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("/work/out/crash-001"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow in parse_header".to_owned(),
        minimized: true,
        bug_report: None,
        casr: Some(CasrReport {
            severity: CrashSeverity::Exploitable,
            severity_short: "heap-buffer-overflow(write)".to_owned(),
            crashline: "src/parse.c:48:5".to_owned(),
            stack: vec!["parse_header".to_owned()],
            cluster: None,
        }),
        origin: hf_core::crash::CrashOrigin::Unknown,
    }
}

async fn crash_fixture() -> (
    tempfile::TempDir,
    PathBuf,
    Uuid,
    Crash,
    Arc<hf_storage::Store>,
) {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("verify.db"))
            .await
            .unwrap(),
    );
    let run = hf_storage::RunRecord::new(
        project.to_string_lossy().into_owned(),
        EngineKind::LibFuzzer,
        None,
        Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    let crash = asan_crash(run.id);
    store
        .upsert_crashes(std::slice::from_ref(&crash))
        .await
        .unwrap();
    let run_id = run.id;
    (directory, project, run_id, crash, store)
}

/// `Off` yields no verdicts, dispatches nothing, and retains no rows.
#[tokio::test]
async fn verify_with_off_yields_no_verdicts_no_dispatch_and_no_rows() {
    let (_dir, project, run_id, crash, store) = crash_fixture().await;
    let pool = Arc::new(CountingPool {
        calls: AtomicUsize::new(0),
        reply: VERDICT_REPLY,
    });
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    )
    .with_store(Arc::clone(&store));

    let verdicts = container
        .verify_crashes(
            "parse_header",
            &project,
            std::slice::from_ref(&crash),
            AiPolicy::Off,
        )
        .await
        .expect("off is not an error");
    assert_eq!(verdicts, vec![None]);

    let by_id = container
        .verify_crash_by_id(&project, crash.id, run_id, "parse_header", AiPolicy::Off)
        .await
        .expect("off is not an error");
    assert!(by_id.is_none());

    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "off dispatches nothing"
    );
    assert!(
        store
            .crash_verify_drafts_for_crash(crash.id)
            .await
            .unwrap()
            .is_empty(),
        "off writes no rows"
    );
}

/// `Require` without a provider is an error.
#[tokio::test]
async fn verify_with_require_and_no_pool_is_an_error() {
    let (_dir, project, _run_id, crash, store) = crash_fixture().await;
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let error = container
        .verify_crashes(
            "parse_header",
            &project,
            std::slice::from_ref(&crash),
            AiPolicy::Require,
        )
        .await
        .expect_err("a required verdict without a provider must fail loud");
    assert!(
        error.to_string().contains("no LLM provider"),
        "the error names the missing model: {error}"
    );
}

/// `Require` surfaces a failed call instead of a silent `None`.
#[tokio::test]
async fn verify_with_require_surfaces_a_failed_call() {
    let (_dir, project, _run_id, crash, store) = crash_fixture().await;
    let pool = Arc::new(RefusingPool {
        calls: AtomicUsize::new(0),
    });
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::clone(&pool) as Arc<dyn hf_core::provider::ProviderPool>),
    )
    .with_store(Arc::clone(&store));

    let error = container
        .verify_crashes(
            "parse_header",
            &project,
            std::slice::from_ref(&crash),
            AiPolicy::Require,
        )
        .await
        .expect_err("a required verdict whose call failed must surface it");
    assert!(
        error.to_string().contains("verification") && error.to_string().contains("failed"),
        "the error names the failed verification call: {error}"
    );
}
