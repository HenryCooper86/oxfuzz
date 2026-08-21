//! Phase 1c: measure native coverage against the upstream fixture corpus.
mod corpus;

use corpus::{parse_annotations, Expectation};

#[test]
fn an_annotation_applies_to_the_next_code_line() {
    let source = "int f(void){\n\t// ruleid: raptor-double-free\n\tfree(p);\n}";
    let annotations = parse_annotations(source);
    assert_eq!(annotations.len(), 1);
    assert_eq!(
        annotations[0].line, 3,
        "must name the code line, not the comment"
    );
    assert_eq!(annotations[0].expectation, Expectation::Finding);
    assert_eq!(annotations[0].upstream_rule, "raptor-double-free");
}

#[test]
fn an_annotation_skips_blank_and_comment_lines() {
    let source = "// ruleid: raptor-x\n\n// an explanatory comment\nfree(p);";
    assert_eq!(parse_annotations(source)[0].line, 4);
}

#[test]
fn every_annotation_kind_is_recognized() {
    let source = "// ruleid: a\nx();\n// ok: b\ny();\n// todoruleid: c\nz();\n// todook: d\nw();";
    let kinds: Vec<Expectation> = parse_annotations(source)
        .iter()
        .map(|annotation| annotation.expectation)
        .collect();
    assert_eq!(
        kinds,
        vec![
            Expectation::Finding,
            Expectation::Clean,
            Expectation::KnownMiss,
            Expectation::KnownFalsePositive,
        ]
    );
}

#[test]
fn an_unannotated_fixture_yields_nothing() {
    assert!(parse_annotations("int main(void){ return 0; }").is_empty());
}

#[test]
fn a_trailing_annotation_with_no_following_code_is_dropped() {
    // Rather than pointing past the end of the file and corrupting the count.
    assert!(parse_annotations("free(p);\n// ruleid: raptor-x\n").is_empty());
}

use corpus::COVERAGE;

#[test]
fn the_coverage_map_names_every_upstream_rule() {
    assert_eq!(COVERAGE.len(), 49);
    let mut ids: Vec<&str> = COVERAGE.iter().map(|(upstream, _)| *upstream).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 49, "duplicate upstream rows");
}

#[test]
fn the_coverage_map_only_names_rules_that_exist() {
    // A typo here would silently record a covered rule as uncovered and make
    // the measurement look worse than it is.
    let known = hf_analysis::rule_ids();
    for (upstream, ours) in COVERAGE {
        for rule_id in *ours {
            assert!(
                known.contains(rule_id),
                "{upstream} maps to unknown rule {rule_id}"
            );
        }
    }
}

#[test]
fn the_covered_count_matches_the_spec() {
    let covered = COVERAGE.iter().filter(|(_, ours)| !ours.is_empty()).count();
    assert_eq!(covered, 33, "spec 18.5 records 33 of 49 covered");
}

/// Measure native coverage against the annotated upstream corpus.
///
/// Prints a table and asserts only that every fixture was read. The number it
/// produces is the input to a human decision about deleting a subsystem, not a
/// build gate, and a threshold here would also freeze third-party fixtures into
/// the build when the point is to delete them.
#[test]
#[ignore = "measurement against third-party fixtures; run explicitly for the phase 1c gate"]
fn measure_coverage_against_the_upstream_corpus() {
    use hf_core::target::TargetLanguage;
    use std::collections::BTreeMap;

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/semgrep-rules/rules/c");
    let coverage: BTreeMap<&str, &[&str]> = COVERAGE.iter().copied().collect();
    let rules = hf_analysis::rules_for(TargetLanguage::C).expect("C has rules");

    let (mut hit, mut miss, mut not_attempted, mut false_positive, mut improvement) =
        (0_u32, 0_u32, 0_u32, 0_u32, 0_u32);
    let mut misses: Vec<String> = Vec::new();
    let mut false_positives: Vec<String> = Vec::new();
    let mut improvements: Vec<String> = Vec::new();
    let mut fixtures_read = 0_u32;

    let mut paths: Vec<_> = std::fs::read_dir(&root)
        .expect("upstream fixtures are present")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
        .collect();
    paths.sort();

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .expect("tree-sitter-c loads");

    for path in &paths {
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        fixtures_read += 1;
        let Some(tree) = parser.parse(&source, None) else {
            continue;
        };
        let findings = rules.analyze(&tree, &source);
        let name = path.file_stem().unwrap().to_string_lossy().to_string();

        for annotation in parse_annotations(&source) {
            // Annotations name the rule as `raptor-<id>`; the fixture file name
            // is the upstream id.
            let ours = coverage.get(name.as_str()).copied().unwrap_or(&[]);
            let reported = findings
                .iter()
                .any(|f| f.span.start_line == annotation.line && ours.contains(&f.rule_id));
            match annotation.expectation {
                Expectation::Finding if ours.is_empty() => not_attempted += 1,
                Expectation::Finding if reported => hit += 1,
                Expectation::Finding => {
                    miss += 1;
                    misses.push(format!("{name}:{}", annotation.line));
                }
                Expectation::Clean if reported => {
                    false_positive += 1;
                    false_positives.push(format!("{name}:{}", annotation.line));
                }
                Expectation::KnownMiss if reported => {
                    improvement += 1;
                    improvements.push(format!("{name}:{}", annotation.line));
                }
                _ => {}
            }
        }
    }

    println!("\n=== phase 1c coverage measurement ===");
    println!("fixtures read      : {fixtures_read}");
    println!("hit                : {hit}");
    println!("miss               : {miss}");
    println!("not attempted      : {not_attempted}  (upstream rule uncovered by design)");
    println!("false positive     : {false_positive}");
    println!("improvement        : {improvement}  (Semgrep documents these as misses)");
    let attempted = hit + miss;
    if attempted > 0 {
        println!(
            "recall on attempted: {:.1}%",
            f64::from(hit) * 100.0 / f64::from(attempted)
        );
    }
    for (label, items) in [
        ("MISSES", &misses),
        ("FALSE POSITIVES", &false_positives),
        ("IMPROVEMENTS", &improvements),
    ] {
        if !items.is_empty() {
            println!("\n{label} ({}):", items.len());
            for item in items {
                println!("  {item}");
            }
        }
    }

    assert_eq!(fixtures_read, 48, "every upstream fixture must be read");
}

#[test]
#[ignore = "diagnostic for the phase 1c gate"]
fn dump_one_fixture() {
    use hf_core::target::TargetLanguage;
    let name = std::env::var("FIXTURE").unwrap_or_else(|_| "double-free".to_owned());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/semgrep-rules/rules/c")
        .join(format!("{name}.c"));
    let source = std::fs::read_to_string(&path).unwrap();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_c::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&source, None).unwrap();
    let findings = hf_analysis::rules_for(TargetLanguage::C)
        .unwrap()
        .analyze(&tree, &source);
    println!("REPORTED in {name}:");
    for f in &findings {
        println!("  line {} {}", f.span.start_line, f.rule_id);
    }
    println!("EXPECTED:");
    for a in parse_annotations(&source) {
        println!("  line {} {:?} {}", a.line, a.expectation, a.upstream_rule);
    }
}
