//! Native analysis signals reach the enrichment scoring through discovery.
#![cfg(feature = "native-analysis")]

use hf_core::target::TargetLanguage;

#[tokio::test]
async fn discovery_produces_signals_for_a_c_project() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "#include <stdio.h>\n\
         int parse_line(char *b){\n\
         \x20 gets(b);\n\
         \x20 return 0;\n\
         }\n",
    )
    .unwrap();

    let (inventory, signals) =
        hf_discovery::discover_with_signals(project.path(), TargetLanguage::C)
            .await
            .unwrap();

    assert!(
        !signals.is_empty(),
        "no signals for a source calling gets()"
    );

    let overlay = hf_discovery::enrichment::score_overlay(&inventory, &signals);
    let scored = overlay
        .scores
        .iter()
        .find(|score| score.matched_rule_count > 0)
        .expect("a candidate should carry the finding");
    assert!(scored.boost > 0.0);
    assert!(scored.effective_score > scored.base_score);
}

#[tokio::test]
async fn a_clean_project_gets_a_zero_boost() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("clean.c"),
        "int add(int a, int b){ return a + b; }\n",
    )
    .unwrap();

    let (inventory, signals) =
        hf_discovery::discover_with_signals(project.path(), TargetLanguage::C)
            .await
            .unwrap();
    let overlay = hf_discovery::enrichment::score_overlay(&inventory, &signals);

    assert!(overlay.scores.iter().all(|score| score.boost == 0.0));
}

#[tokio::test]
async fn signal_paths_are_relative_so_the_join_can_match_them() {
    // `uniquely_containing_candidate` compares a signal's path against the
    // candidate's path with the project root stripped, so an absolute signal
    // path would silently attribute nothing.
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("src")).unwrap();
    std::fs::write(
        project.path().join("src/parser.c"),
        "int parse_line(char *b){\n  gets(b);\n  return 0;\n}\n",
    )
    .unwrap();

    let (_, signals) = hf_discovery::discover_with_signals(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    assert_eq!(signals.len(), 1, "{signals:?}");
    assert_eq!(
        signals[0].relative_path,
        std::path::PathBuf::from("src/parser.c")
    );
}

#[tokio::test]
async fn a_language_without_rules_produces_no_signals() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("main.go"),
        "package main\nfunc Fuzz(b []byte) {}\n",
    )
    .unwrap();

    let (_, signals) = hf_discovery::discover_with_signals(project.path(), TargetLanguage::Go)
        .await
        .unwrap();

    assert!(signals.is_empty());
}
