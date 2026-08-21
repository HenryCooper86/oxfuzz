//! The native analysis overlay reaches a caller alongside the inventory.
#![cfg(feature = "native-analysis")]

use std::sync::Arc;

use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

fn container() -> ServiceContainer {
    ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
}

#[tokio::test]
async fn discovery_returns_an_overlay_beside_the_inventory() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_line(char *b){\n  gets(b);\n  return 0;\n}\n",
    )
    .unwrap();

    let analyzed = container()
        .discover_analyzed(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    assert!(!analyzed.inventory.candidates.is_empty());
    assert!(
        analyzed.signal_count > 0,
        "no signals for a source calling gets()"
    );
    let boosted = analyzed
        .scores
        .iter()
        .find(|score| score.matched_rule_count > 0)
        .expect("a candidate should carry the finding");
    assert!(boosted.effective_score > boosted.base_score);
}

#[tokio::test]
async fn the_base_score_is_never_overwritten() {
    // The overlay is advisory. A consumer must always be able to see what the
    // candidate scored before any static-analysis signal touched it.
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_line(char *b){\n  gets(b);\n  return 0;\n}\n",
    )
    .unwrap();

    let analyzed = container()
        .discover_analyzed(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    for score in &analyzed.scores {
        let candidate = analyzed
            .inventory
            .candidates
            .iter()
            .find(|candidate| candidate.id == score.target_id)
            .expect("every score names a candidate");
        assert!(
            (candidate.fit_score - score.base_score).abs() < f64::EPSILON,
            "overlay base score drifted from the candidate"
        );
    }
}

#[tokio::test]
async fn a_clean_project_carries_no_boost() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("clean.c"),
        "int add(int a, int b){ return a + b; }\n",
    )
    .unwrap();

    let analyzed = container()
        .discover_analyzed(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    assert_eq!(analyzed.signal_count, 0);
    assert!(analyzed.scores.iter().all(|score| score.boost == 0.0));
}
