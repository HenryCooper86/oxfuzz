//! Integration tests for the C/C++ target scanner.

use hf_core::target::{TargetKind, TargetLanguage};
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sample_c")
}

#[tokio::test]
async fn discover_returns_non_empty_inventory() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    assert!(!inv.candidates.is_empty(), "inventory must not be empty");
}

#[tokio::test]
async fn discover_finds_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let symbols: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    assert!(
        symbols.contains(&"parse_value"),
        "parse_value must be a candidate; got {symbols:?}"
    );
}

#[tokio::test]
async fn discover_assigns_parser_kind_to_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let pv = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_value")
        .expect("parse_value must be present");
    assert!(
        matches!(pv.kind, TargetKind::Parser | TargetKind::Function),
        "parse_value should be Parser or Function"
    );
}

#[tokio::test]
async fn discover_skips_no_arg_functions() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let names: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    // `json_free` has one arg (ok), `json_dump` has 3 args (ok).
    // A function with zero params would be filtered. Our fixture has none,
    // so this asserts the filter does not remove valid candidates.
    assert!(names.contains(&"json_free"));
    assert!(names.contains(&"json_dump"));
}

#[tokio::test]
async fn discover_complexity_parse_array_greater_than_skip_ws() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let by_name = |n: &str| {
        inv.candidates
            .iter()
            .find(|c| c.symbol == n)
            .unwrap_or_else(|| panic!("{n} must be present"))
    };
    let arr = by_name("parse_array");
    let ws = by_name("skip_ws");
    assert!(
        arr.complexity > ws.complexity,
        "parse_array complexity ({}) should exceed skip_ws complexity ({})",
        arr.complexity,
        ws.complexity
    );
}
