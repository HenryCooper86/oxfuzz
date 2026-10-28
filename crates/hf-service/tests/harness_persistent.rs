//! Integration coverage for AFL++ persistent-mode harnesses: a `--persistent`
//! draft/generate emits the custom-main `__AFL_INIT` + `__AFL_LOOP` structure
//! and compiles it WITHOUT the libFuzzer driver (`-fsanitize=fuzzer`), the
//! flavor is rejected for other engines before any work, a persistent source
//! handed to `harness_compile` builds driver-less whatever its origin, and the
//! resulting harness smoke-qualifies and promotes through the unchanged gates.
//! No Docker, no network, no real LLM: a recording stub runtime and a
//! fixed-reply provider pool.

mod common;

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::{AiPolicy, ServiceContainer};

/// Fixture C project: a length-prefixed record parser.
const FIXTURE: &str = r"
#include <stddef.h>
#include <stdint.h>

int parse_packet(const uint8_t *data, size_t len) {
    if (len >= 2 && data[0] == 'P' && data[1] == 'K') {
        return 1;
    }
    return 0;
}
";

/// Fixed LLM reply for the harness draft: a hand-written persistent-mode
/// harness (custom main, deferred forkserver, SHM loop, standalone replay
/// branch) -- deliberately not the emitted template text, so detection and the
/// build variant prove they work on foreign-shaped persistent sources.
const PERSISTENT_REPLY: &str = r#"```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int parse_packet(const uint8_t *data, size_t len);

__AFL_FUZZ_INIT();

static void oxfuzz_target_setup(void) {
}

static void oxfuzz_target_reset(void) {
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    oxfuzz_target_reset();
    parse_packet((const uint8_t *)data, size);
    return 0;
}

static unsigned int oxfuzz_loop_count(void) {
    const char *env = getenv("AFL_FUZZER_LOOPCOUNT");
    if (env) {
        long n = strtol(env, NULL, 10);
        if (n >= 1 && n <= 100000) {
            return (unsigned int)n;
        }
    }
    return 1000;
}

int main(int argc, char **argv) {
    oxfuzz_target_setup();
#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    if (__afl_fuzz_ptr) {
        unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
        while (__AFL_LOOP(oxfuzz_loop_count())) {
            size_t len = __AFL_FUZZ_TESTCASE_LEN;
            LLVMFuzzerTestOneInput(buf, len);
        }
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        uint8_t input[1048576];
        FILE *f = fopen(argv[i], "rb");
        if (!f) { continue; }
        size_t len = fread(input, 1, sizeof(input), f);
        fclose(f);
        LLVMFuzzerTestOneInput(input, len);
    }
    return 0;
}
```"#;

fn completed(exit_code: i32, stdout: &str, cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
    }
}

/// A runtime that records every command so tests can inspect the exact compile
/// scripts a stage dispatched. Compilations materialize the binary their
/// script names; smoke is a clean measured AFL++ pass.
#[derive(Default)]
struct RecordingRuntime {
    commands: Mutex<Vec<Vec<String>>>,
}

impl RecordingRuntime {
    /// Every recorded `bash -c` compile script.
    fn compile_scripts(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|cmd| cmd.first().is_some_and(|part| part == "bash"))
            .map(|cmd| cmd.join(" "))
            .collect()
    }

    fn command_count(&self) -> usize {
        self.commands.lock().unwrap().len()
    }

    /// Materialize the binary a compile script names (`-o /tmp/<name>`, then
    /// the script copies it into the mounted workspace).
    fn materialize_compile_output(script: &str, cwd: &Path) {
        let marker = "-o /tmp/";
        if let Some(at) = script.find(marker) {
            let name = script[at + marker.len()..]
                .split_whitespace()
                .next()
                .unwrap_or("fuzz_packet")
                .trim_matches('\'')
                .to_owned();
            std::fs::write(cwd.join(&name), format!("binary:{name}")).unwrap();
        }
    }
}

#[async_trait]
impl RuntimeAdapter for RecordingRuntime {
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
        std::fs::create_dir_all(cwd).unwrap();
        Ok(completed(0, "", cwd))
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        self.commands.lock().unwrap().push(cmd.to_vec());
        if cmd.first().is_some_and(|part| part == "bash") {
            Self::materialize_compile_output(&cmd.join(" "), cwd);
            return Ok(completed(0, "", cwd));
        }
        // Smoke qualification: a clean, measured AFL++ pass.
        Ok(completed(0, "exec speed : 512/sec\ncycles done : 1", cwd))
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands.lock().unwrap().push(cmd.to_vec());
        on_line("exec speed : 1024/sec");
        Ok(completed(0, "", cwd))
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

/// A pool that answers the harness draft with the fixed persistent source,
/// approves the mandatory pre-execution review, and records what it was asked.
struct HarnessDraftPool {
    calls: AtomicUsize,
    last_prompt: Mutex<String>,
}

#[async_trait]
impl hf_core::provider::ProviderPool for HarnessDraftPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(message) = request.messages.last() {
            self.last_prompt
                .lock()
                .unwrap()
                .clone_from(&message.content);
        }
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            PERSISTENT_REPLY,
        ))
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

/// A pool whose draft answer contains no code block: generation must fall back
/// to the heuristic persistent template.
struct NonCodePool;

#[async_trait]
impl hf_core::provider::ProviderPool for NonCodePool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response("no code here"))
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

fn write_fuzzing_policy(config_dir: &Path) {
    std::env::set_var("HF_CONFIG_DIR", config_dir);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\"]\n\
         default_engine = \"afl++\"\n\
         default_duration_secs = 30\n\
         [fuzzing.sandbox]\n\
         max_mem_mb = 1024\n\
         max_cpus = 1\n\
         max_duration_secs = 600\n",
    )
    .expect("write fuzzing policy");
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<hf_storage::Store>,
    runtime: Arc<RecordingRuntime>,
    container: ServiceContainer,
}

impl Fixture {
    async fn new(pool: Option<Arc<dyn hf_core::provider::ProviderPool>>) -> Self {
        // The process-global config must outlive every concurrent fixture.
        static ENVIRONMENT: std::sync::Once = std::sync::Once::new();
        ENVIRONMENT.call_once(|| {
            let root = common::install_managed_workspace("oxfuzz_persistent_it");
            write_fuzzing_policy(&root.parent().unwrap().join("config"));
        });
        let dir = tempfile::tempdir().unwrap();
        let project = Self::project_of(dir.path());
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("parser.c"), FIXTURE).unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(dir.path().join("persistent.db"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(RecordingRuntime::default());
        let container = ServiceContainer::new(runtime.clone(), pool).with_store(Arc::clone(&store));
        Self {
            dir,
            store,
            runtime,
            container,
        }
    }

    fn project_of(dir: &Path) -> std::path::PathBuf {
        dir.join("proj")
    }

    /// The fixture project root; reading it through the guard keeps the
    /// temporary directory alive for the test's duration.
    fn project(&self) -> std::path::PathBuf {
        Self::project_of(self.dir.path())
    }
}

/// The persisted harness revision for `parse_packet`, read from the store.
async fn compiled_harness(
    store: &Arc<hf_storage::Store>,
    project: &Path,
) -> hf_core::harness::Harness {
    let target_id = store
        .list_targets(&project.canonicalize().unwrap().to_string_lossy())
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.symbol == "parse_packet")
        .map(|candidate| candidate.id)
        .expect("target persisted");
    store
        .list_harnesses(target_id)
        .await
        .unwrap()
        .into_iter()
        .max_by_key(|harness| match harness.status {
            hf_core::harness::HarnessStatus::Promoted => 4,
            hf_core::harness::HarnessStatus::SmokePassed => 3,
            hf_core::harness::HarnessStatus::Compiled => 2,
            hf_core::harness::HarnessStatus::Draft => 1,
            hf_core::harness::HarnessStatus::Failed => 0,
        })
        .expect("a harness revision exists")
}

#[tokio::test]
async fn persistent_generate_compiles_driverless_and_smoke_qualifies_and_promotes() {
    let pool = Arc::new(HarnessDraftPool {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
    });
    let fixture = Fixture::new(Some(pool.clone())).await;

    let outcome = fixture
        .container
        .harness_generate(
            &fixture.project(),
            "parse_packet",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            1,
            None,
            false,
            true,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("persistent harness generates");
    assert_eq!(outcome.status, hf_core::harness::HarnessStatus::Compiled);
    assert!(
        !hf_harness::has_blocking_finding(&outcome.lint),
        "the persistent source must not draw blocking lint findings: {:?}",
        outcome.lint
    );

    // The draft prompt carried the persistent contract to the model.
    let prompt = pool.last_prompt.lock().unwrap().clone();
    assert!(prompt.contains("persistent mode"), "{prompt}");
    assert!(prompt.contains("__AFL_LOOP"), "{prompt}");

    // Exactly one compile ran, driver-less: the persistent harness owns main.
    let scripts = fixture.runtime.compile_scripts();
    assert_eq!(scripts.len(), 1, "one compile, no companion: {scripts:?}");
    assert!(scripts[0].contains("afl-clang-fast"), "{scripts:?}");
    assert!(
        !scripts[0].contains("-fsanitize=fuzzer"),
        "the libFuzzer driver must not link a persistent harness: {scripts:?}"
    );
    assert!(scripts[0].contains("-fsanitize=address"), "{scripts:?}");

    // The persisted revision records the same driver-less build.
    let harness = compiled_harness(&fixture.store, &fixture.project()).await;
    assert!(
        !harness
            .build_cmd
            .args
            .iter()
            .any(|arg| arg == "-fsanitize=fuzzer"),
        "{:?}",
        harness.build_cmd.args
    );
    assert!(harness.source.contains("__AFL_LOOP"));

    // The unchanged qualification gates accept the persistent harness.
    fixture
        .container
        .harness_smoke(
            &fixture.project(),
            "parse_packet",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
        )
        .await
        .expect("persistent harness smoke-qualifies");

    // The smoke argv is the standard AFL++ run contract: the persistent
    // binary's SHM capability makes afl-fuzz deliver inputs through shared
    // memory, so `-- <binary> @@` needs no flavor-specific change.
    let smoke_argv = {
        let commands = fixture.runtime.commands.lock().unwrap();
        commands
            .iter()
            .find(|cmd| cmd.first().is_some_and(|part| part == "afl-fuzz"))
            .cloned()
            .expect("the smoke run drove afl-fuzz")
    };
    let separator = smoke_argv
        .iter()
        .position(|arg| arg == "--")
        .expect("target separator");
    assert_eq!(smoke_argv[separator + 2], "@@", "{smoke_argv:?}");
    assert!(
        smoke_argv[separator + 1].ends_with("/input/harness"),
        "the staged retained binary is the smoke target: {smoke_argv:?}"
    );

    let promoted = fixture
        .container
        .harness_promote(&fixture.project(), "parse_packet", EngineKind::AflPlusPlus)
        .await
        .expect("persistent harness promotes");
    assert_eq!(promoted.status, hf_core::harness::HarnessStatus::Promoted);
}

#[tokio::test]
async fn persistent_generate_rejects_a_non_afl_engine_before_any_work() {
    let pool = Arc::new(HarnessDraftPool {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
    });
    let fixture = Fixture::new(Some(pool.clone())).await;

    let error = fixture
        .container
        .harness_generate(
            &fixture.project(),
            "parse_packet",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            None,
            false,
            true,
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("afl++"), "{error}");
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "no model call may be spent on an unbuildable flavor"
    );
    assert_eq!(
        fixture.runtime.command_count(),
        0,
        "no sandbox work may start"
    );
}

#[tokio::test]
async fn persistent_generate_falls_back_to_the_heuristic_template() {
    // The provider answers no code block: generation must still produce the
    // canonical persistent skeleton.
    let fixture = Fixture::new(Some(Arc::new(NonCodePool))).await;

    let outcome = fixture
        .container
        .harness_generate(
            &fixture.project(),
            "parse_packet",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            1,
            None,
            false,
            true,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("heuristic fallback generates");
    assert_eq!(outcome.status, hf_core::harness::HarnessStatus::Compiled);
    let harness = compiled_harness(&fixture.store, &fixture.project()).await;
    assert!(harness.source.contains("oxfuzz_target_setup"));
    assert!(harness.source.contains("while (__AFL_LOOP("));
    assert!(
        !harness
            .build_cmd
            .args
            .iter()
            .any(|arg| arg == "-fsanitize=fuzzer"),
        "{:?}",
        harness.build_cmd.args
    );
}

#[tokio::test]
async fn persistent_draft_records_the_driverless_build() {
    let fixture = Fixture::new(Some(Arc::new(HarnessDraftPool {
        calls: AtomicUsize::new(0),
        last_prompt: Mutex::new(String::new()),
    })))
    .await;

    let draft = fixture
        .container
        .harness_draft_with_policy(
            &fixture.project(),
            "parse_packet",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            AiPolicy::Auto,
            None,
            true,
        )
        .await
        .expect("persistent draft");
    assert!(draft.source.contains("__AFL_LOOP"));
    assert!(
        !draft
            .build_cmd
            .args
            .iter()
            .any(|arg| arg == "-fsanitize=fuzzer"),
        "{:?}",
        draft.build_cmd.args
    );

    let error = fixture
        .container
        .harness_draft_with_policy(
            &fixture.project(),
            "parse_packet",
            EngineKind::Honggfuzz,
            TargetLanguage::C,
            AiPolicy::Auto,
            None,
            true,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("afl++"), "{error}");
}

#[tokio::test]
async fn harness_compile_derives_the_driverless_build_from_the_source() {
    // The flavor is the source's structure, not a flag: any caller that
    // supplies persistent-structured source (a GUI editor, a work-order
    // import) compiles driver-less without opting in anywhere else.
    let fixture = Fixture::new(None).await;
    let source = PERSISTENT_REPLY
        .trim_start_matches("```c\n")
        .trim_end_matches("```")
        .to_owned();

    let outcome = fixture
        .container
        .harness_compile(
            source,
            &fixture.project(),
            EngineKind::AflPlusPlus,
            "parse_packet",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .expect("persistent source compiles");
    assert_eq!(outcome.status, hf_core::harness::HarnessStatus::Compiled);
    let scripts = fixture.runtime.compile_scripts();
    assert_eq!(scripts.len(), 1, "{scripts:?}");
    assert!(!scripts[0].contains("-fsanitize=fuzzer"), "{scripts:?}");
}

#[tokio::test]
async fn harness_compile_rejects_a_persistent_source_for_a_non_afl_engine() {
    let fixture = Fixture::new(None).await;
    let source = PERSISTENT_REPLY
        .trim_start_matches("```c\n")
        .trim_end_matches("```")
        .to_owned();

    let error = fixture
        .container
        .harness_compile(
            source,
            &fixture.project(),
            EngineKind::LibFuzzer,
            "parse_packet",
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("afl++"), "{error}");
    assert_eq!(fixture.runtime.command_count(), 0, "no sandbox work ran");
}
