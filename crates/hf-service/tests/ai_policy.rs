//! The generator that writes a harness is an operator decision.
//!
//! Before `AiPolicy` it came from whether a key happened to be exported, and a
//! provider failure quietly substituted the template for the model.

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::harness::DraftGenerator;
use hf_core::target::TargetLanguage;
use hf_service::{AiPolicy, ServiceContainer};

const FIXTURE: &str = "\
#include <stddef.h>
#include <stdint.h>
int parse_record(const uint8_t *data, size_t len) { return len && data[0]; }
";

fn project(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(name);
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parse.c"), FIXTURE).unwrap();
    (dir, project)
}

/// With no provider, `Require` is an error rather than a template harness the
/// caller said it did not want.
#[tokio::test]
async fn require_refuses_to_substitute_the_template() {
    common::install_managed_workspace("oxfuzz_ai_policy_require_it");
    let (_dir, project) = project("req");
    let container = ServiceContainer::new(Arc::new(hf_runtime::adapter::StubRuntime), None);

    let error = container
        .harness_draft_with_policy(
            &project,
            "parse_record",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            AiPolicy::Require,
        )
        .await
        .expect_err("an AI harness was required and none is available");
    let message = error.to_string();
    assert!(
        message.contains("no LLM provider is configured"),
        "the error must say what is missing: {message}"
    );
}

/// `Auto` is the historical behaviour: no provider means the template, and the
/// draft says so rather than leaving the caller to guess.
#[tokio::test]
async fn auto_falls_back_and_records_which_generator_answered() {
    common::install_managed_workspace("oxfuzz_ai_policy_auto_it");
    let (_dir, project) = project("auto");
    let container = ServiceContainer::new(Arc::new(hf_runtime::adapter::StubRuntime), None);

    let draft = container
        .harness_draft_with_policy(
            &project,
            "parse_record",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            AiPolicy::Auto,
        )
        .await
        .expect("auto degrades rather than failing");
    assert_eq!(draft.generator, DraftGenerator::Heuristic);
    assert!(draft.source.contains("LLVMFuzzerTestOneInput"));
}

/// `Off` never calls a model, and the default entry point stays `Auto` so every
/// existing caller is unchanged.
#[tokio::test]
async fn off_uses_the_template_and_the_default_is_auto() {
    common::install_managed_workspace("oxfuzz_ai_policy_off_it");
    let (_dir, project) = project("off");
    let container = ServiceContainer::new(Arc::new(hf_runtime::adapter::StubRuntime), None);

    let off = container
        .harness_draft_with_policy(
            &project,
            "parse_record",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            AiPolicy::Off,
        )
        .await
        .unwrap();
    assert_eq!(off.generator, DraftGenerator::Heuristic);

    let default = container
        .harness_draft(
            &project,
            "parse_record",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert_eq!(default.generator, off.generator);
    assert_eq!(default.source, off.source);
    assert_eq!(AiPolicy::default(), AiPolicy::Auto);
}
