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
        } else if input.ends_with("deep") {
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
