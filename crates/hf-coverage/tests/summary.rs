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
