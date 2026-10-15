//! Service-owned campaign seed selection invariants: an explicit seed
//! survives policy resolution, every campaign iteration, the persisted
//! `FuzzRunConfig`, and the dispatched engine argv, while a replay keeps the
//! original run's seed and libFuzzer's zero (which *randomizes* its RNG) is
//! refused before any side effect. The per-engine flag mappings themselves
//! (`-seed=`, `-s`, and honggfuzz's honest no-flag) are covered at the
//! adapter level in `hf-engine`. No Docker, no network, no real LLM: the
//! sandbox is a recording stub runtime.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

/// 2^63 + 1: above the JavaScript safe-integer range *and* above `i64::MAX`,
/// so a wire client that rounds through a float or a signed integer cannot
/// carry it. Persistence and the engine argv must keep every bit.
const WIDE_SEED: u64 = 9_223_372_036_854_775_809;

/// A parser-shaped fuzz target the discovery scan can find.
const FIXTURE_TARGET: &str = "parse_entry";

fn fixture_source() -> String {
    "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }"
        .to_owned()
}

fn fuzzing_policy_toml() -> String {
    format!(
        r#"
[fuzzing]
collect_function_coverage = {collect_function_coverage}
enabled_engines = ["libfuzzer", "afl++", "honggfuzz"]
default_engine = "libfuzzer"
default_duration_secs = 30

[fuzzing.sandbox]
max_mem_mb = 1024
max_cpus = 1
max_duration_secs = 120
"#,
        collect_function_coverage = cfg!(feature = "proof-carrying"),
    )
}

/// One process-wide isolation: a managed workspace root and one fuzzing
/// policy admitting every engine under test. Tests within this binary run in
/// parallel, so the policy is written once, never mutated per test, and each
/// test owns its project directory and store database.
fn isolate() {
    static ROOT: LazyLock<PathBuf> = LazyLock::new(|| {
        let root = common::install_managed_workspace("oxfuzz_seed_selection_it");
        std::env::set_var("HF_CONFIG_DIR", root.parent().unwrap().join("config"));
        hf_service::config::write_config("oxfuzz", &fuzzing_policy_toml())
            .expect("write fuzzing policy");
        root
    });
    LazyLock::force(&ROOT);
}

/// A runtime that records every streaming campaign command so tests can
/// inspect the exact argv a run dispatched to the engine. Compilation
/// commands and profiling tooling are answered directly.
#[derive(Default)]
struct RecordingRuntime {
    commands: Mutex<Vec<Vec<String>>>,
}

impl RecordingRuntime {
    /// The recorded campaign argv for one run. The runner addresses run-owned
    /// directories by container path, which embeds the run id.
    fn campaign_args(&self, run_id: uuid::Uuid) -> Vec<String> {
        let marker = format!("/work/runs/{run_id}");
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|cmd| cmd.iter().any(|part| part.contains(&marker)))
            .unwrap_or_else(|| panic!("no recorded command for run {run_id}"))
            .clone()
    }

    fn campaign_count(&self) -> usize {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

fn completed(cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
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
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        Ok(completed(cwd))
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64) {
            return Ok(completed(cwd));
        }
        let mut result = self.run_command(cmd, cwd, limits).await?;
        if cmd
            .first()
            .is_some_and(|program| program.starts_with("/work/"))
        {
            "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".clone_into(&mut result.stdout);
        }
        Ok(result)
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        if hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64) {
            return Ok(completed(cwd));
        }
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(cmd.to_vec());
        on_line("#1 DONE cov: 42 ft: 84 corp: 3/24b exec/s: 256");
        Ok(completed(cwd))
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        std::fs::read_to_string(path)
            .map_err(|error| ClassifiedError::Internal(format!("read {}: {error}", path.display())))
    }
}

struct SeedFixture {
    _dir: tempfile::TempDir,
    project: PathBuf,
    runtime: Arc<RecordingRuntime>,
    container: ServiceContainer,
    store: Arc<hf_storage::Store>,
}

impl SeedFixture {
    /// A project with a promoted harness for `engine`, ready to run.
    async fn new(engine: EngineKind) -> Self {
        isolate();
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("seedproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            "#include <stddef.h>\n#include <stdint.h>\n\
             int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
        )
        .unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(dir.path().join("seed.db"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(RecordingRuntime::default());
        let container = ServiceContainer::new(
            runtime.clone(),
            Some(hf_test_utils::approving_harness_review_pool()),
        )
        .with_store(Arc::clone(&store));

        // The stub compiler leaves no binary behind; stage one so the run
        // path's harness-binary check passes exactly as in the scheduler
        // fixtures.
        let workspace = hf_service::workspace_dir(&project, FIXTURE_TARGET);
        std::fs::create_dir_all(workspace.join("corpus")).unwrap();
        std::fs::write(
            workspace.join(format!("fuzz_{FIXTURE_TARGET}")),
            b"#!/bin/true",
        )
        .unwrap();
        container
            .harness_compile(
                fixture_source(),
                &project,
                engine,
                FIXTURE_TARGET,
                TargetLanguage::C,
                None,
                false,
            )
            .await
            .expect("compile harness");
        container
            .harness_smoke(&project, FIXTURE_TARGET, engine, TargetLanguage::C)
            .await
            .expect("smoke harness");
        container
            .harness_promote(&project, FIXTURE_TARGET, engine)
            .await
            .expect("promote harness");

        Self {
            _dir: dir,
            project,
            runtime,
            container,
            store,
        }
    }
}

#[tokio::test]
async fn an_explicit_seed_is_persisted_dispatched_and_kept_by_replay() {
    let fixture = SeedFixture::new(EngineKind::LibFuzzer).await;
    let summary = fixture
        .container
        .run_fuzzer(
            &fixture.project,
            FIXTURE_TARGET,
            EngineKind::LibFuzzer,
            60,
            None,
            None,
            None,
            None,
            None,
            Some(WIDE_SEED),
            &|_| {},
        )
        .await
        .expect("seeded run completes");
    let run = fixture
        .store
        .get_run(summary.run_id)
        .await
        .unwrap()
        .expect("run row");
    let config = run.config.expect("run config");
    assert_eq!(
        config.seed,
        Some(WIDE_SEED),
        "the explicit seed survives persistence with every bit"
    );
    assert_eq!(config.replay_of, None);
    let run_args = fixture.runtime.campaign_args(summary.run_id);
    assert!(
        run_args
            .iter()
            .any(|arg| arg == &format!("-seed={WIDE_SEED}")),
        "libFuzzer's fixed-seed knob must receive the explicit seed: {}",
        run_args.join(" ")
    );

    // Replay keeps the original run's seed, never a fresh derivation.
    let replay = fixture
        .container
        .replay_run(summary.run_id, &|_| {})
        .await
        .expect("replay completes");
    let replayed = fixture
        .store
        .get_run(replay.run_id)
        .await
        .unwrap()
        .expect("replay row")
        .config
        .expect("replay config");
    assert_eq!(replayed.seed, Some(WIDE_SEED));
    assert_eq!(replayed.replay_of, Some(summary.run_id));
    let replay_args = fixture.runtime.campaign_args(replay.run_id);
    assert!(
        replay_args
            .iter()
            .any(|arg| arg == &format!("-seed={WIDE_SEED}")),
        "the replay dispatches the original seed: {}",
        replay_args.join(" ")
    );
}

#[tokio::test]
async fn an_omitted_seed_still_derives_a_nonzero_seed_per_run() {
    let fixture = SeedFixture::new(EngineKind::LibFuzzer).await;
    let mut seeds = Vec::new();
    for _ in 0..2 {
        let summary = fixture
            .container
            .run_fuzzer(
                &fixture.project,
                FIXTURE_TARGET,
                EngineKind::LibFuzzer,
                60,
                None,
                None,
                None,
                None,
                None,
                None,
                &|_| {},
            )
            .await
            .expect("unseeded run completes");
        let seed = fixture
            .store
            .get_run(summary.run_id)
            .await
            .unwrap()
            .unwrap()
            .config
            .unwrap()
            .seed
            .expect("omission still records a seed");
        assert_ne!(seed, 0, "the derived seed is never zero");
        assert_eq!(
            seed,
            hf_engine::seed::derive_run_seed(summary.run_id),
            "omission derives the run-id seed"
        );
        seeds.push(seed);
    }
    assert_ne!(seeds[0], seeds[1], "each run derives its own seed");
}

#[tokio::test]
async fn a_campaign_seed_reaches_every_iteration_but_not_the_smoke_seed() {
    let fixture = SeedFixture::new(EngineKind::LibFuzzer).await;
    let campaign_seed: u64 = 4_242_424_242_424_242;
    let outcome = fixture
        .container
        .run_campaign(
            &fixture.project,
            Some(FIXTURE_TARGET),
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            None,
            None,
            None,
            None,
            Some(campaign_seed),
            2,
        )
        .await
        .expect("campaign completes");
    assert_eq!(outcome.iterations, 2, "the fixture runs both iterations");

    let records = fixture.store.list_runs(None).await.unwrap();
    let mut campaign_rows = 0;
    for record in &records {
        let seed = record.config.as_ref().and_then(|config| config.seed);
        if seed == Some(campaign_seed) {
            campaign_rows += 1;
            let args = fixture.runtime.campaign_args(record.id);
            assert!(
                args.iter()
                    .any(|arg| arg == &format!("-seed={campaign_seed}")),
                "run {} dispatches the campaign seed: {}",
                record.id,
                args.join(" ")
            );
        }
    }
    assert_eq!(
        campaign_rows, 2,
        "both campaign iterations retain the explicit seed"
    );

    // Smoke qualification keeps its own independently derived seed: the
    // operator pinned a *campaign* seed, not every run on the machine.
    let smoke = records
        .iter()
        .find(|record| record.kind == hf_storage::RunKind::Smoke)
        .expect("smoke run row");
    let smoke_seed = smoke.config.as_ref().and_then(|config| config.seed);
    assert_ne!(smoke_seed, Some(campaign_seed));
    assert_ne!(smoke_seed, Some(0));
}

#[tokio::test]
async fn a_libfuzzer_seed_of_zero_is_rejected_before_any_side_effect() {
    let fixture = SeedFixture::new(EngineKind::LibFuzzer).await;
    let rows_before = fixture.store.list_runs(None).await.unwrap().len();
    let commands_before = fixture.runtime.campaign_count();

    // libFuzzer reads -seed=0 as "generate a random seed", so accepting it
    // would silently record a seed the engine ignores.
    let error = fixture
        .container
        .run_fuzzer(
            &fixture.project,
            FIXTURE_TARGET,
            EngineKind::LibFuzzer,
            60,
            None,
            None,
            None,
            None,
            None,
            Some(0),
            &|_| {},
        )
        .await
        .expect_err("seed zero must be refused for libFuzzer");
    assert!(
        matches!(&error, ClassifiedError::Validation(message)
            if message.contains("seed") && message.to_lowercase().contains("libfuzzer")),
        "{error}"
    );
    assert_eq!(
        fixture.store.list_runs(None).await.unwrap().len(),
        rows_before,
        "no run row is persisted for a rejected seed"
    );
    assert_eq!(
        fixture.runtime.campaign_count(),
        commands_before,
        "no engine command is dispatched for a rejected seed"
    );
}

#[tokio::test]
async fn onboarding_rejects_a_randomizing_seed_before_discovery() {
    isolate();
    let project = tempfile::tempdir().unwrap();
    let stages = std::sync::atomic::AtomicUsize::new(0);
    let container = ServiceContainer::new(Arc::new(RecordingRuntime::default()), None);
    let error = container
        .fuzz_onboard(
            hf_service::FuzzRequest {
                project: &project.path().join("missing"),
                target: Some(FIXTURE_TARGET),
                engine: EngineKind::LibFuzzer,
                lang: Some(TargetLanguage::C),
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: Some(0),
            },
            &|_| {
                stages.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            },
            &|_| {},
        )
        .await
        .expect_err("invalid seed must precede source discovery and harness work");
    assert!(error.to_string().contains("seed"), "{error}");
    assert_eq!(stages.load(std::sync::atomic::Ordering::Relaxed), 0);
}
