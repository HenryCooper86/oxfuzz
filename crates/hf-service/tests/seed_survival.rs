//! Executor tests for seed-survival measurement: seeds that reach past the
//! harness's entry validation count as surviving, seeds whose coverage never
//! leaves the empty input's footprint count as dying at entry, and seeds the
//! map cannot measure are reported separately rather than guessed at.

mod common;

use std::sync::Arc;

use hf_service::ServiceContainer;

fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let workspace = common::install_managed_workspace("oxfuzz_seedsurv_it");
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

/// Canned `afl-showmap` output keyed on the input basename: the empty-input
/// baseline and `shallow` cover only entry edges, `deep` covers one more, and
/// `blind` produces no map (the binary refuses to run on it).
struct SurvivalRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for SurvivalRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let is_showmap = cmd.first().is_some_and(|command| command == "afl-showmap");
        if !is_showmap {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 0,
                stdout: "DONE exec/s: 64".to_owned(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        let input = cmd.last().cloned().unwrap_or_default();
        let (stdout, exit_code) = if input.ends_with("blind") {
            (String::new(), 1)
        } else if input.ends_with("deep") || input.contains("regen_") {
            ("1:1\n2:1\n3:1\n".to_owned(), 0)
        } else {
            // The empty baseline and the shallow seed share the entry edges.
            ("1:1\n2:1\n".to_owned(), 0)
        };
        Ok(hf_core::runtime::CommandResult {
            exit_code,
            stdout,
            stderr: String::new(),
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

struct PromotedFixture {
    _dir: tempfile::TempDir,
    project: std::path::PathBuf,
    container: ServiceContainer,
}

async fn promoted_afl_harness(target: &str) -> PromotedFixture {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("survproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        format!(
            "#include <stddef.h>\nint {target}(const unsigned char *data, size_t size) {{ return size && data[0]; }}\n"
        ),
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("survival.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(SurvivalRuntime),
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, target);
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::AflPlusPlus,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::AflPlusPlus)
        .await
        .unwrap();
    PromotedFixture {
        _dir: dir,
        project,
        container,
    }
}

#[tokio::test]
async fn seed_survival_separates_deep_seeds_from_entry_deaths() {
    let fixture = promoted_afl_harness("parse_surv").await;
    let workspace = hf_service::workspace_dir(&fixture.project, "parse_surv");
    let corpus = workspace.join("corpus");
    std::fs::write(corpus.join("shallow"), b"rejects at validation").unwrap();
    std::fs::write(corpus.join("deep"), b"drives the target").unwrap();
    std::fs::write(corpus.join("blind"), b"binary refuses to run").unwrap();

    let report = fixture
        .container
        .seed_survival(&fixture.project, "parse_surv")
        .await
        .expect("survival measurement should run");

    assert_eq!(report.total, 3);
    assert_eq!(report.survives, 1, "{report:?}");
    assert_eq!(report.dies_at_entry, 1, "{report:?}");
    assert_eq!(report.not_measured, 1, "{report:?}");
    let ratio = report.survival_ratio.expect("a verdict was reached");
    assert!((ratio - 0.5).abs() < f64::EPSILON, "{ratio}");
}

#[tokio::test]
async fn seed_survival_on_an_empty_corpus_reports_nothing_measured() {
    let fixture = promoted_afl_harness("parse_empty").await;
    let report = fixture
        .container
        .seed_survival(&fixture.project, "parse_empty")
        .await
        .expect("an empty corpus is a valid measurement of zero");
    assert_eq!(report.total, 0);
    assert_eq!(report.survival_ratio, None);
}

#[tokio::test]
async fn seed_survival_requires_a_promoted_afl_harness() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("survproj-unpromoted");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\nint parse_gate(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("survival-gate.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(SurvivalRuntime),
        Some(hf_test_utils::approving_harness_review_pool()),
    )
    .with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            "parse_gate",
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();

    let error = container
        .seed_survival(&project, "parse_gate")
        .await
        .expect_err("an unpromoted harness must not be measured");
    assert!(
        error.to_string().contains("promoted"),
        "the denial must name the promotion requirement: {error}"
    );
}

/// Serves a fixed seed-array JSON to seed-generation requests and the
/// approving review verdict to everything else (the qualification calls in
/// the fixture), so both flows share one pool.
struct SeedRegenPool {
    calls: std::sync::atomic::AtomicUsize,
}

const REPLACEMENT_SEEDS: &str = r#"["deadbeef01", "cafebabe02"]"#;
const APPROVING_REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["target receives fuzz input without unsafe side effects"]}"#;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for SeedRegenPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let is_seed_request = request
            .messages
            .last()
            .is_some_and(|message| message.content.contains("seed-corpus author"));
        if is_seed_request {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(hf_test_utils::fixtures::make_chat_response(
                REPLACEMENT_SEEDS,
            ));
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            APPROVING_REVIEW,
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

async fn promoted_afl_harness_with_regen_pool(target: &str) -> PromotedFixture {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("regenproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        format!(
            "#include <stddef.h>\nint {target}(const unsigned char *data, size_t size) {{ return size && data[0]; }}\n"
        ),
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("regen.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(SurvivalRuntime),
        Some(Arc::new(SeedRegenPool {
            calls: std::sync::atomic::AtomicUsize::new(0),
        })),
    )
    .with_store(store);
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::AflPlusPlus,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, target);
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join(format!("fuzz_{target}")), b"#!/bin/true").unwrap();
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::AflPlusPlus,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::AflPlusPlus)
        .await
        .unwrap();
    PromotedFixture {
        _dir: dir,
        project,
        container,
    }
}

#[tokio::test]
async fn regeneration_replaces_only_dying_generated_seeds() {
    let fixture = promoted_afl_harness_with_regen_pool("parse_regen").await;
    let workspace = hf_service::workspace_dir(&fixture.project, "parse_regen");
    let corpus = workspace.join("corpus");
    // Generated seeds (reserved namespace): one dies at entry, one survives.
    hf_corpus::seed(
        uuid::Uuid::new_v4(),
        &corpus,
        vec![
            (b"shallow-bytes".to_vec(), "seed_shallow".to_owned()),
            (b"deep-bytes".to_vec(), "seed_deep".to_owned()),
        ],
    )
    .await
    .unwrap();
    // An earned input the fuzzer found: also dies at entry under this runtime,
    // but regeneration must never touch it.
    std::fs::write(corpus.join("earned"), b"fuzzer found me").unwrap();

    let outcome = fixture
        .container
        .regenerate_dead_seeds(
            &fixture.project,
            "parse_regen",
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("regeneration should run");

    assert_eq!(outcome.removed_dead, 1, "{outcome:?}");
    assert_eq!(outcome.replacements_requested, 1, "{outcome:?}");
    assert_eq!(outcome.replacements_added, 1, "{outcome:?}");
    assert_eq!(outcome.replacement_survives, 1, "{outcome:?}");
    assert!(
        !corpus.join("seed_shallow").exists(),
        "the dead seed is gone"
    );
    assert!(
        corpus.join("seed_deep").exists(),
        "the surviving seed stays"
    );
    assert!(
        corpus.join("earned").exists(),
        "an earned input is never regenerated away"
    );
    assert!(
        corpus.join("regen_0").exists(),
        "the replacement seed is written"
    );
}

#[tokio::test]
async fn regeneration_without_dying_seeds_is_a_no_op() {
    let fixture = promoted_afl_harness_with_regen_pool("parse_noregen").await;
    let workspace = hf_service::workspace_dir(&fixture.project, "parse_noregen");
    let corpus = workspace.join("corpus");
    hf_corpus::seed(
        uuid::Uuid::new_v4(),
        &corpus,
        vec![(b"deep-bytes".to_vec(), "seed_deep".to_owned())],
    )
    .await
    .unwrap();

    let outcome = fixture
        .container
        .regenerate_dead_seeds(
            &fixture.project,
            "parse_noregen",
            hf_core::target::TargetLanguage::C,
        )
        .await
        .expect("regeneration should run");

    assert_eq!(outcome.removed_dead, 0, "{outcome:?}");
    assert_eq!(outcome.replacements_added, 0, "{outcome:?}");
    assert!(corpus.join("seed_deep").exists());
    assert!(!corpus.join("regen_0").exists());
}
