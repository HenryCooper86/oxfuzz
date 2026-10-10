//! Integration coverage for the explicit, audited LLM-review bypass on harness
//! smoke qualification.
//!
//! The fixture config carries no `[harness]` table, so the deployment default
//! (deny) is in force; the per-invocation [`HarnessReviewBypass::Requested`]
//! flag is the only opt-in exercised here. The config-driven opt-in lives in
//! `harness_review_bypass_config.rs` because `HF_CONFIG_DIR` is process-global.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::{HarnessReviewBypass, HarnessReviewBypassSource, ServiceContainer};
use sha2::Digest as _;

const SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

struct QualifyingRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for QualifyingRuntime {
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
        // Leave the host-side artifacts the real collection path reads, so this
        // double exercises collection instead of bypassing it.
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64);
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }

    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
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

/// A compiled harness with no LLM provider pool and the default (denying)
/// deployment config.
async fn unreviewed_fixture() -> (tempfile::TempDir, Arc<hf_storage::Store>, ServiceContainer) {
    common::install_managed_workspace("oxfuzz_review_bypass_it");
    let project = tempfile::tempdir().unwrap();
    let config = project.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\ncollect_function_coverage = true\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\", \"syzkaller\"]\n\
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
        hf_storage::Store::connect(project.path().join("bypass.db"))
            .await
            .unwrap(),
    );
    // No provider pool: without an opt-in, qualification must fail closed.
    let container =
        ServiceContainer::new(Arc::new(QualifyingRuntime), None).with_store(Arc::clone(&store));
    container
        .harness_compile(
            SOURCE.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
            None,
        )
        .await
        .unwrap();
    (project, store, container)
}

async fn compiled_harness_id(store: &hf_storage::Store) -> uuid::Uuid {
    // The fixture compiled exactly one harness.
    let mut harnesses = store.list_all_harnesses().await.unwrap();
    harnesses.pop().expect("the fixture compiled a harness").id
}

#[tokio::test]
async fn bypass_is_denied_by_default_and_the_error_names_the_opt_in_surfaces() {
    let (project, store, container) = unreviewed_fixture().await;

    let error = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("without a provider or an opt-in, smoke must fail closed");
    let message = error.to_string();
    assert!(message.contains("--no-llm-review"), "{message}");
    assert!(
        message.contains("harness.allow_unreviewed_smoke"),
        "{message}"
    );

    let harness_id = compiled_harness_id(&store).await;
    assert!(store.harness_ai_review(harness_id).await.unwrap().is_none());
    assert!(store.list_runs(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_flag_permits_smoke_without_a_provider_and_persists_a_marked_review() {
    let (project, store, container) = unreviewed_fixture().await;

    let smoke = container
        .harness_smoke_with_review_bypass(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::Requested,
        )
        .await
        .expect("the explicit per-invocation opt-in permits smoke without a provider");
    assert!(smoke.summary.passed);

    let harness_id = compiled_harness_id(&store).await;
    let record = store
        .harness_ai_review(harness_id)
        .await
        .unwrap()
        .expect("the bypass persists a review record anyway (Engineering Protocol 2.13)");
    let harness = store.get_harness(harness_id).await.unwrap().unwrap();
    assert_eq!(
        record.source_sha256,
        hex::encode(sha2::Sha256::digest(harness.source.as_bytes()))
    );
    let binary = hf_service::workspace_dir(project.path(), "parse_entry").join("fuzz_parse_entry");
    assert_eq!(
        record.binary_sha256,
        hex::encode(sha2::Sha256::digest(std::fs::read(&binary).unwrap()))
    );

    let evidence: serde_json::Value = serde_json::from_str(&record.review_json).unwrap();
    assert_eq!(evidence["schema_version"], 1);
    assert_eq!(evidence["verdict"], "bypassed");
    assert_eq!(evidence["reviewer"], "none");
    assert_eq!(evidence["bypass_source"], "cli_flag");
    assert_eq!(evidence["target"], "parse_entry");
    assert!(
        evidence["rationale"]
            .as_str()
            .is_some_and(|r| r.contains("--no-llm-review")),
        "{evidence}"
    );
}

#[tokio::test]
async fn a_persisted_bypass_marker_satisfies_later_smoke_runs_without_the_flag() {
    let (project, store, container) = unreviewed_fixture().await;
    container
        .harness_smoke_with_review_bypass(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::Requested,
        )
        .await
        .unwrap();

    // The same revision re-qualified without the flag and still without a
    // provider: the durable marker is the review-of-record for this revision.
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("a persisted bypass marker is review evidence for this exact revision");

    let harness_id = compiled_harness_id(&store).await;
    let record = store.harness_ai_review(harness_id).await.unwrap().unwrap();
    assert!(record.review_json.contains("\"verdict\":\"bypassed\""));
}

#[tokio::test]
async fn the_bypass_writes_a_policy_audit_record() {
    let (project, _store, container) = unreviewed_fixture().await;
    container
        .harness_smoke_with_review_bypass(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::Requested,
        )
        .await
        .unwrap();

    let decisions = container.policy_decisions(20).await.unwrap();
    let audit = decisions
        .iter()
        .find(|row| row.action == "harness_llm_review_bypass")
        .expect("the bypass is a distinct audited policy decision");
    assert_eq!(audit.risk_tier, "high");
    assert_eq!(audit.decision, "allowed");
    assert!(
        audit
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("--no-llm-review")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn promotion_after_a_bypassed_smoke_still_requires_the_human_gate() {
    let (project, _store, container) = unreviewed_fixture().await;
    container
        .harness_smoke_with_review_bypass(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::Requested,
        )
        .await
        .unwrap();

    // The bypass never auto-approves: a denying gate still stops promotion.
    let denied = container
        .clone()
        .with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy::default(),
            Arc::new(hf_guardrails::DenyAll),
        ));
    assert!(
        denied
            .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
            .await
            .is_err(),
        "promotion must remain gated after a bypassed smoke"
    );

    // And with approval the bypassed review satisfies the qualification chain.
    let promoted = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .expect("human approval promotes a bypass-smoked revision");
    assert_eq!(promoted.status, HarnessStatus::Promoted);
}

#[tokio::test]
async fn the_bypassed_review_is_marked_on_the_approval_surface() {
    let (project, _store, container) = unreviewed_fixture().await;
    container
        .harness_smoke_with_review_bypass(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessReviewBypass::Requested,
        )
        .await
        .unwrap();

    let project_root: PathBuf = std::fs::canonicalize(project.path()).unwrap();
    let items = container
        .harness_review_queue(Some(project_root.as_path()), Some("parse_entry"))
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    let review = items[0]
        .ai_review
        .as_ref()
        .expect("the bypass marker is review evidence");
    assert_eq!(
        review.bypass_source,
        Some(HarnessReviewBypassSource::CliFlag),
        "the approval surface must show the bypass, not collapse it into a review: {review:?}"
    );
    assert!(!review.exercises_target);
    assert!(!review.safe_to_execute);
    assert!(
        review
            .reasons
            .iter()
            .any(|reason| reason.contains("--no-llm-review")),
        "{review:?}"
    );
}
