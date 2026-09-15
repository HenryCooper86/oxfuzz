//! Tests for parsing `llvm-cov export` totals into a `CoverageSummary`.

use hf_coverage::{parse_llvm_cov_summary, CoverageSummary};

/// A trimmed but structurally faithful `llvm-cov export` JSON document.
const SAMPLE: &str = r#"{
  "data": [
    {
      "totals": {
        "lines": { "count": 200, "covered": 120, "percent": 60.0 },
        "functions": { "count": 10, "covered": 7, "percent": 70.0 },
        "regions": { "count": 80, "covered": 40, "percent": 50.0 }
      }
    }
  ],
  "type": "llvm.coverage.json.export",
  "version": "2.0.1"
}"#;

#[test]
fn parses_line_function_and_region_totals() {
    let s = parse_llvm_cov_summary(SAMPLE).expect("should parse totals");
    assert_eq!(s.lines_total, 200);
    assert_eq!(s.lines_covered, 120);
    assert_eq!(s.functions_total, 10);
    assert_eq!(s.functions_covered, 7);
    assert_eq!(s.regions_total, 80);
    assert_eq!(s.regions_covered, 40);
}

#[test]
fn computes_line_coverage_percent() {
    let s = parse_llvm_cov_summary(SAMPLE).unwrap();
    assert!((s.line_percent() - 60.0).abs() < 0.001);
}

#[test]
fn percent_is_zero_when_no_lines() {
    let s = CoverageSummary::default();
    assert!(s.line_percent().abs() < f64::EPSILON);
}

#[test]
fn returns_none_on_garbage() {
    assert!(parse_llvm_cov_summary("not json").is_none());
    assert!(parse_llvm_cov_summary("{}").is_none());
}

#[test]
fn totals_include_every_export_entry() {
    let mut export: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
    let entry = export["data"][0].clone();
    export["data"].as_array_mut().unwrap().push(entry);
    let summary = parse_llvm_cov_summary(&export.to_string()).unwrap();
    assert_eq!(summary.lines_total, 400);
    assert_eq!(summary.lines_covered, 240);
    assert_eq!(summary.functions_total, 20);
    assert_eq!(summary.functions_covered, 14);
    assert_eq!(summary.regions_total, 160);
    assert_eq!(summary.regions_covered, 80);
}

#[test]
fn contradictory_totals_are_unavailable() {
    for metric in ["lines", "functions", "regions"] {
        let mut export: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
        export["data"][0]["totals"][metric]["covered"] = serde_json::json!(201);
        assert!(
            parse_llvm_cov_summary(&export.to_string()).is_none(),
            "{metric}"
        );
    }
}

#[test]
fn overflowing_combined_totals_are_unavailable() {
    let mut export: serde_json::Value = serde_json::from_str(SAMPLE).unwrap();
    export["data"][0]["totals"]["lines"]["count"] = serde_json::json!(u64::MAX);
    let entry = export["data"][0].clone();
    export["data"].as_array_mut().unwrap().push(entry);
    assert!(parse_llvm_cov_summary(&export.to_string()).is_none());
}

#[test]
fn frontier_includes_every_entry_and_deduplicates_locations() {
    let export = serde_json::json!({"data": [
        {"functions": [{"name": "first", "filenames": ["a.c"], "regions": [[1,1,2,1,0,0,0,0]]}]},
        {"functions": [
            {"name": "first", "filenames": ["a.c"], "regions": [[1,1,2,1,0,0,0,0]]},
            {"name": "second", "filenames": ["b.c"], "regions": [[3,1,4,1,0,0,0,0]]}
        ]}
    ]});
    let frontier = hf_coverage::parse_llvm_cov_uncovered(&export.to_string());
    assert_eq!(frontier.len(), 2);
    assert_eq!(frontier[1].function, "second");
}

#[test]
fn frontier_omits_invalid_source_locations() {
    for region in [
        vec![0, 1, 2, 1, 0, 0, 0, 0],
        vec![1, 0, 2, 1, 0, 0, 0, 0],
        vec![u64::from(u32::MAX) + 1, 1, 2, 1, 0, 0, 0, 0],
        vec![1, u64::from(u32::MAX) + 1, 2, 1, 0, 0, 0, 0],
        vec![1, 1, 2, 1, 0, 9, 0, 0],
    ] {
        let export = serde_json::json!({"data": [{"functions": [{
            "name": "parse", "filenames": ["a.c"], "regions": [region]
        }]}]});
        assert!(
            hf_coverage::parse_llvm_cov_uncovered(&export.to_string()).is_empty(),
            "{export}"
        );
    }
}
