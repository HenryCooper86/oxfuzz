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
async fn candidates_carry_their_project_root() {
    let root = fixture_root();
    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    // Every candidate must know which project it belongs to, so persistence can
    // dedup by (project, symbol) and reports can attribute targets.
    assert!(
        inv.candidates.iter().all(|c| c.project_root == root),
        "all candidates should carry the project root"
    );
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
async fn candidate_ids_are_stable_across_discovery_passes() {
    // Persistence (harnesses, corpus, crashes, run linkage) is keyed on the
    // target id. If a symbol got a fresh random id on every discovery pass, all
    // of that stored state would be orphaned the next time discovery ran. The id
    // must therefore be deterministic per (project_root, symbol).
    let root = fixture_root();
    let first = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let second = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");

    for c in &first.candidates {
        let again = second
            .candidates
            .iter()
            .find(|o| o.symbol == c.symbol)
            .unwrap_or_else(|| panic!("{} should be found on the second pass", c.symbol));
        assert_eq!(
            c.id, again.id,
            "candidate id for {} must be stable across passes",
            c.symbol
        );
    }

    // Distinct symbols must still get distinct ids.
    let ids: std::collections::HashSet<_> = first.candidates.iter().map(|c| c.id).collect();
    assert_eq!(
        ids.len(),
        first.candidates.len(),
        "each distinct symbol must get its own id"
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
async fn discover_complexity_json_dump_greater_than_parse_value() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let by_name = |n: &str| {
        inv.candidates
            .iter()
            .find(|c| c.symbol == n)
            .unwrap_or_else(|| panic!("{n} must be present"))
    };
    let dump = by_name("json_dump");
    let pv = by_name("parse_value");
    assert!(
        dump.complexity > pv.complexity,
        "json_dump complexity ({}) should exceed parse_value complexity ({})",
        dump.complexity,
        pv.complexity
    );
}

#[tokio::test]
async fn discover_skips_static_functions() {
    let inv = hf_discovery::discover(&fixture_root(), TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let names: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    // These are `static` in json.c -- they have internal linkage and cannot
    // be called from a separately-compiled harness, so the scanner must skip
    // them.
    assert!(
        !names.contains(&"parse_value_inner"),
        "static function parse_value_inner must not be a candidate; got {names:?}"
    );
    assert!(
        !names.contains(&"skip_ws"),
        "static function skip_ws must not be a candidate; got {names:?}"
    );
    assert!(
        !names.contains(&"parse_array"),
        "static function parse_array must not be a candidate; got {names:?}"
    );
}

#[tokio::test]
async fn discover_rust_finds_public_parameterized_functions() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("lib.rs"),
        "pub fn parse_packet(data: &[u8]) -> bool {\n\
         \x20   if data.is_empty() { return false; }\n\
         \x20   data[0] == 0x7f\n\
         }\n\
         fn private_helper(x: u32) -> u32 { x + 1 }\n\
         pub fn getter() -> u32 { 42 }\n",
    )
    .unwrap();

    let inv = hf_discovery::discover(dir.path(), TargetLanguage::Rust)
        .await
        .expect("rust discovery should succeed");

    // The public, byte-taking parser is found and classified as a Parser.
    let parse = inv
        .candidates
        .iter()
        .find(|c| c.symbol == "parse_packet")
        .expect("parse_packet should be discovered");
    assert_eq!(parse.language, TargetLanguage::Rust);
    assert_eq!(parse.kind, TargetKind::Parser);

    // Private functions and zero-arg getters are excluded.
    assert!(inv.candidates.iter().all(|c| c.symbol != "private_helper"));
    assert!(inv.candidates.iter().all(|c| c.symbol != "getter"));
}
