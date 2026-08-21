//! What a scheduled campaign is allowed to run.
//!
//! `run_campaign` refuses any target without a smoke-qualified, human-promoted
//! harness -- creating a schedule is not authorization to fuzz arbitrary code.
//! The Automation view therefore must offer *only* those targets: anything else
//! produces a schedule that fails on every fire, hours later, with nobody
//! watching. These tests pin that contract.

use chrono::Utc;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use hf_storage::Store;
use uuid::Uuid;

const PROJECT: &str = "/tmp/schedulable_project";

async fn test_container() -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("schedulable.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, dir)
}

fn target(symbol: &str, language: TargetLanguage) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from(PROJECT),
        language,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/parser.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 3,
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 3,
    }
}

fn harness(
    target_id: Uuid,
    engine: EngineKind,
    language: TargetLanguage,
    status: HarnessStatus,
) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id,
        engine,
        source: "int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }".to_owned(),
        language,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status,
        smoke_run: None,
    }
}

#[tokio::test]
async fn only_promoted_harnesses_are_schedulable() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();

    let promoted = target("parse_value", TargetLanguage::C);
    let drafted = target("parse_header", TargetLanguage::C);
    store.upsert_target(&promoted, Utc::now()).await.unwrap();
    store.upsert_target(&drafted, Utc::now()).await.unwrap();

    store
        .upsert_harness(&harness(
            promoted.id,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessStatus::Promoted,
        ))
        .await
        .unwrap();
    // Compiled and smoke-passed are *not* enough: a human has to promote.
    store
        .upsert_harness(&harness(
            drafted.id,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            HarnessStatus::SmokePassed,
        ))
        .await
        .unwrap();

    let schedulable = container
        .schedulable_targets(Path::new(PROJECT))
        .await
        .expect("store is configured");

    assert_eq!(
        schedulable.len(),
        1,
        "only the promoted target: {schedulable:?}"
    );
    assert_eq!(schedulable[0].target, "parse_value");
    assert_eq!(schedulable[0].engine, "libfuzzer");
    assert_eq!(schedulable[0].language, "c");
}

#[tokio::test]
async fn engine_and_language_come_from_the_harness_not_a_guess() {
    // A Rust target scheduled as C fails the campaign's language check at fire
    // time. The engine/language shipped with each choice are the harness's own.
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();

    let rust_target = target("fuzz_decode", TargetLanguage::Rust);
    store.upsert_target(&rust_target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&harness(
            rust_target.id,
            EngineKind::LibFuzzer,
            TargetLanguage::Rust,
            HarnessStatus::Promoted,
        ))
        .await
        .unwrap();

    let schedulable = container
        .schedulable_targets(Path::new(PROJECT))
        .await
        .unwrap();

    assert_eq!(schedulable.len(), 1);
    assert_eq!(schedulable[0].language, "rust");
    // Round-trips: the dispatcher parses these strings back into enums.
    assert_eq!(
        schedulable[0].language.parse::<TargetLanguage>(),
        Ok(TargetLanguage::Rust)
    );
    assert_eq!(
        schedulable[0].engine.parse::<EngineKind>(),
        Ok(EngineKind::LibFuzzer)
    );
}

#[tokio::test]
async fn a_target_promoted_for_two_engines_is_schedulable_under_either() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();

    let both = target("parse_value", TargetLanguage::C);
    store.upsert_target(&both, Utc::now()).await.unwrap();
    for engine in [EngineKind::LibFuzzer, EngineKind::AflPlusPlus] {
        store
            .upsert_harness(&harness(
                both.id,
                engine,
                TargetLanguage::C,
                HarnessStatus::Promoted,
            ))
            .await
            .unwrap();
    }

    let schedulable = container
        .schedulable_targets(Path::new(PROJECT))
        .await
        .unwrap();

    let engines: Vec<&str> = schedulable.iter().map(|t| t.engine.as_str()).collect();
    assert_eq!(engines, vec!["afl++", "libfuzzer"], "one entry per engine");
}

#[tokio::test]
async fn a_project_with_no_promoted_harness_is_empty_not_an_error() {
    // The Automation view distinguishes "nothing to schedule yet" from "the
    // backend failed"; an empty list is the former.
    let (container, _dir) = test_container().await;
    let schedulable = container
        .schedulable_targets(Path::new("/tmp/no_such_project"))
        .await
        .expect("an unknown project is empty, not an error");
    assert!(schedulable.is_empty());
}
