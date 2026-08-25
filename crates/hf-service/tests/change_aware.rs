//! Change-Aware Pull-Request Fuzzing domain contract.
//!
//! Covers the pure half of the subsystem: unified-diff parsing, affected-target
//! mapping, base/head comparability, finding classification, and coverage
//! regression. Every case here runs on retained fixtures; nothing executes.

#![cfg(feature = "change-aware")]

use std::path::PathBuf;

use hf_core::target::{InputSurface, SourceLocation, TargetCandidate, TargetKind, TargetLanguage};
use hf_service::change_impact::{
    check_comparability, classify_findings, compare_coverage, map_affected_targets,
    parse_unified_diff, ComparabilityRefusal, CoverageComparison, DiffRejection, FindingChange,
    RunComparisonInput, TargetImpact, MAX_DIFF_BYTES,
};
use uuid::Uuid;

fn target(symbol: &str, file: &str, line: u32, end_line: Option<u32>) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/project"),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from(file),
            line,
            col: 1,
            end_line,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 0.5,
        sanitizers: Vec::new(),
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    }
}

const PARSER_DIFF: &str = "\
diff --git a/src/parser.c b/src/parser.c
--- a/src/parser.c
+++ b/src/parser.c
@@ -10,0 +11,2 @@
+    int extra = 1;
+    use(extra);
";

#[test]
fn a_unified_diff_yields_changed_files_and_new_side_line_ranges() {
    let parsed = parse_unified_diff(PARSER_DIFF).expect("well-formed unified diff");
    assert_eq!(parsed.files.len(), 1);
    let file = &parsed.files[0];
    assert_eq!(file.new_path.as_deref(), Some("src/parser.c"));
    assert_eq!(file.old_path.as_deref(), Some("src/parser.c"));
    assert!(!file.binary);
    assert_eq!(file.ranges.len(), 1);
    assert_eq!(file.ranges[0].start, 11);
    assert_eq!(file.ranges[0].end, 12);
}

#[test]
fn renames_deletions_new_files_and_binaries_keep_both_paths_and_no_invented_ranges() {
    let diff = "\
diff --git a/old/name.c b/new/name.c
--- a/old/name.c
+++ b/new/name.c
@@ -1 +1 @@
-int a;
+int b;
diff --git a/gone.c b/gone.c
deleted file mode 100644
--- a/gone.c
+++ /dev/null
@@ -1,2 +0,0 @@
-int gone;
-int also;
diff --git a/fresh.c b/fresh.c
new file mode 100644
--- /dev/null
+++ b/fresh.c
@@ -0,0 +1 @@
+int fresh;
diff --git a/image.png b/image.png
Binary files a/image.png and b/image.png differ
";
    let parsed = parse_unified_diff(diff).expect("well-formed unified diff");
    assert_eq!(parsed.files.len(), 4);

    let renamed = &parsed.files[0];
    assert_eq!(renamed.old_path.as_deref(), Some("old/name.c"));
    assert_eq!(renamed.new_path.as_deref(), Some("new/name.c"));

    // A deleted file has no new side, so it can carry no new-side range.
    let deleted = &parsed.files[1];
    assert_eq!(deleted.old_path.as_deref(), Some("gone.c"));
    assert_eq!(deleted.new_path, None);
    assert!(deleted.ranges.is_empty());

    let fresh = &parsed.files[2];
    assert_eq!(fresh.old_path, None);
    assert_eq!(fresh.new_path.as_deref(), Some("fresh.c"));
    assert_eq!(fresh.ranges.len(), 1);

    let binary = &parsed.files[3];
    assert!(binary.binary);
    assert!(binary.ranges.is_empty());
}

#[test]
fn malformed_oversized_and_non_unified_input_is_rejected_with_a_named_reason() {
    assert_eq!(
        parse_unified_diff("just some prose, not a diff at all\n"),
        Err(DiffRejection::NotUnified),
    );
    assert_eq!(
        parse_unified_diff(
            "--- a/src/parser.c\n+++ b/src/parser.c\n@@ this is not a hunk header @@\n+x\n"
        ),
        Err(DiffRejection::MalformedHunkHeader),
    );
    // The header promises two added lines; the body supplies one.
    assert_eq!(
        parse_unified_diff("--- a/src/parser.c\n+++ b/src/parser.c\n@@ -1,0 +1,2 @@\n+only one\n"),
        Err(DiffRejection::HunkLengthMismatch),
    );
    let oversized = format!(
        "--- a/src/parser.c\n+++ b/src/parser.c\n@@ -1,0 +1,1 @@\n+{}\n",
        "x".repeat(MAX_DIFF_BYTES)
    );
    assert_eq!(parse_unified_diff(&oversized), Err(DiffRejection::TooLarge));
}

#[test]
fn targets_are_changed_reaching_or_unknown_but_never_unaffected() {
    // parse_packet's definition covers the changed lines 11..12.
    let changed = target("parse_packet", "src/parser.c", 5, Some(20));
    // read_header only reaches the change through the retained call graph.
    let mut reaching = target("read_header", "src/reader.c", 1, Some(9));
    reaching.reachable_functions = vec!["parse_packet".to_owned()];
    // unrelated neither overlaps nor retains a path to the change.
    let unrelated = target("unrelated", "src/other.c", 1, Some(9));
    // no_range has no definition end, so overlap cannot be decided.
    let no_range = target("no_range", "src/parser.c", 11, None);

    let parsed = parse_unified_diff(PARSER_DIFF).unwrap();
    let affected = map_affected_targets(
        &parsed,
        &[
            changed.clone(),
            reaching.clone(),
            unrelated.clone(),
            no_range.clone(),
        ],
    );
    let impact = |id: Uuid| {
        affected
            .iter()
            .find(|entry| entry.target_id == id)
            .map(|entry| entry.impact)
            .expect("every target is classified")
    };

    assert_eq!(impact(changed.id), TargetImpact::Changed);
    assert_eq!(impact(reaching.id), TargetImpact::ReachesChange);
    assert_eq!(impact(unrelated.id), TargetImpact::Unknown);
    assert_eq!(impact(no_range.id), TargetImpact::Unknown);

    // The exact overlap is not approximate; everything else is.
    let entry = |id: Uuid| {
        affected
            .iter()
            .find(|entry| entry.target_id == id)
            .expect("classified")
    };
    assert!(!entry(changed.id).approximate);
    assert!(entry(reaching.id).approximate);
    assert!(entry(unrelated.id).approximate);

    // There is deliberately no "unaffected" determination to report.
    assert!(affected.iter().all(|entry| {
        matches!(
            entry.impact,
            TargetImpact::Changed | TargetImpact::ReachesChange | TargetImpact::Unknown
        )
    }));
}

fn run_input(source: &str, corpus: &str, sandbox: &str) -> RunComparisonInput {
    RunComparisonInput {
        target_id: Uuid::nil(),
        engine: "libfuzzer".to_owned(),
        terminal: true,
        source_rev: Some(source.to_owned()),
        corpus_rev: Some(corpus.to_owned()),
        sandbox_rev: Some(format!("docker-image-id-sha256:{sandbox}")),
        edges: Some(100),
    }
}

#[test]
fn comparability_requires_a_differing_source_over_an_otherwise_identical_context() {
    let base = run_input("base-source", "corpus", "image");
    let head = run_input("head-source", "corpus", "image");
    assert_eq!(check_comparability(&base, &head), Ok(()));

    // The whole-context rule used for coverage baselines would refuse this pair,
    // because a pull request changes the source by definition.
    let same_source = run_input("base-source", "corpus", "image");
    assert_eq!(
        check_comparability(&base, &same_source),
        Err(ComparabilityRefusal::SameSourceRevision),
    );

    let other_corpus = run_input("head-source", "other-corpus", "image");
    assert_eq!(
        check_comparability(&base, &other_corpus),
        Err(ComparabilityRefusal::DifferentCorpus),
    );

    let other_image = run_input("head-source", "corpus", "other-image");
    assert_eq!(
        check_comparability(&base, &other_image),
        Err(ComparabilityRefusal::DifferentSandbox),
    );

    let mut other_engine = run_input("head-source", "corpus", "image");
    other_engine.engine = "afl++".to_owned();
    assert_eq!(
        check_comparability(&base, &other_engine),
        Err(ComparabilityRefusal::DifferentEngine),
    );

    let mut other_target = run_input("head-source", "corpus", "image");
    other_target.target_id = Uuid::new_v4();
    assert_eq!(
        check_comparability(&base, &other_target),
        Err(ComparabilityRefusal::DifferentTarget),
    );

    let mut unfinished = run_input("head-source", "corpus", "image");
    unfinished.terminal = false;
    assert_eq!(
        check_comparability(&base, &unfinished),
        Err(ComparabilityRefusal::HeadNotTerminal),
    );

    let mut untyped_image = run_input("head-source", "corpus", "image");
    untyped_image.sandbox_rev = Some("some-mutable-tag".to_owned());
    assert_eq!(
        check_comparability(&base, &untyped_image),
        Err(ComparabilityRefusal::SandboxNotExact),
    );

    let mut missing = run_input("head-source", "corpus", "image");
    missing.source_rev = None;
    assert_eq!(
        check_comparability(&base, &missing),
        Err(ComparabilityRefusal::MissingRevision),
    );
}

#[test]
fn findings_are_classified_by_stack_signature_and_an_empty_base_is_unknown() {
    let classified = classify_findings(
        &["shared".to_owned(), "gone".to_owned()],
        &["shared".to_owned(), "fresh".to_owned()],
    );
    let change = |signature: &str| {
        classified
            .iter()
            .find(|entry| entry.stack_signature == signature)
            .map(|entry| entry.change)
            .expect("signature is classified")
    };
    assert_eq!(change("fresh"), FindingChange::Introduced);
    assert_eq!(change("shared"), FindingChange::CarriedOver);
    assert_eq!(change("gone"), FindingChange::Resolved);

    // An empty base is indistinguishable from an unexamined one, so nothing is
    // called introduced against it.
    let no_base = classify_findings(&[], &["fresh".to_owned()]);
    assert_eq!(no_base.len(), 1);
    assert_eq!(no_base[0].change, FindingChange::Unknown);
}

#[test]
fn coverage_regression_needs_retained_peak_edges_from_both_runs() {
    assert_eq!(
        compare_coverage(Some(1000), Some(1000), 5.0),
        CoverageComparison::Stable { delta_pct: 0.0 },
    );
    assert_eq!(
        compare_coverage(Some(1000), Some(900), 5.0),
        CoverageComparison::Regressed { delta_pct: -10.0 },
    );
    // A 1% drop is below the configured threshold.
    assert_eq!(
        compare_coverage(Some(1000), Some(990), 5.0),
        CoverageComparison::Stable { delta_pct: -1.0 },
    );
    // Missing evidence is unavailable, never a zero delta.
    assert_eq!(
        compare_coverage(None, Some(900), 5.0),
        CoverageComparison::Unavailable,
    );
    assert_eq!(
        compare_coverage(Some(1000), None, 5.0),
        CoverageComparison::Unavailable,
    );
}
