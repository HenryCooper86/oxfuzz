//! The line walk must agree with `llvm-cov` itself. The fixtures are a real
//! `llvm-cov export` (LLVM 18.1.3, sandbox image 0.2.2) of a small target with
//! an untaken branch, a loop, a switch, a preprocessor-skipped block, a
//! conditional expression, and an unused function, plus the lcov text the same
//! `llvm-cov` wrote for it.

use hf_coverage::parse_llvm_cov_lines;

const EXPORT: &str = include_str!("fixtures/llvm18_export.json");
const REFERENCE: &str = include_str!("fixtures/llvm18_reference.lcov");

fn records<'a>(lcov: &'a str, prefixes: &[&str]) -> Vec<&'a str> {
    lcov.lines()
        .filter(|line| prefixes.iter().any(|prefix| line.starts_with(prefix)))
        .collect()
}

#[test]
fn line_records_match_llvm_cov() {
    let report = parse_llvm_cov_lines(EXPORT).expect("real export parses");
    let ours = report.to_lcov(&str::to_owned);
    let line_prefixes = ["SF:", "DA:", "LF:", "LH:"];
    assert_eq!(
        records(&ours, &line_prefixes),
        records(REFERENCE, &line_prefixes)
    );
}

#[test]
fn function_records_match_llvm_cov() {
    let report = parse_llvm_cov_lines(EXPORT).expect("real export parses");
    let ours = report.to_lcov(&str::to_owned);
    let function_prefixes = ["FN:", "FNDA:", "FNF:", "FNH:"];
    let mut ours = records(&ours, &function_prefixes);
    let mut reference = records(REFERENCE, &function_prefixes);
    ours.sort_unstable();
    reference.sort_unstable();
    assert_eq!(ours, reference);
}
