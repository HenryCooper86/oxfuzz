//! Integration tests over the user-facing showcase example suite in the
//! top-level `examples/` directory.
//!
//! These are the ready-to-run demo targets shipped for users to point oxfuzz
//! at (as opposed to the internal fixtures in `tests/fixtures/examples/`, which
//! `examples.rs` guards). Each isolates one bug class across the libFuzzer,
//! AFL++, and honggfuzz engine styles. These assertions cover the
//! deterministic, toolchain-free layer of the pipeline: the discovery scanner
//! must find every documented entry point and classify it as a fuzzable target.
//! Reproducing the actual crash needs a real engine + sanitizer toolchain and
//! is exercised by manual / engine-gated runs (see examples/README.md).

use hf_core::target::{TargetKind, TargetLanguage};
use std::path::PathBuf;

/// The top-level `examples/` directory, two levels up from this crate.
fn examples_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

/// (directory, documented entry-point symbol) for every showcase example.
const EXAMPLES: &[(&str, &str)] = &[
    ("libfuzzer_fuzzme", "FuzzMe"),
    ("honggfuzz_magic", "match_magic"),
    ("aflpp_persistent", "parse_packet"),
    ("json_number_parser", "parse_number"),
    ("utf8_decoder", "decode_utf8"),
];

#[tokio::test]
async fn every_example_directory_exists() {
    for (dir, _) in EXAMPLES {
        let path = examples_root().join(dir);
        assert!(
            path.is_dir(),
            "example directory {} is missing at {}",
            dir,
            path.display()
        );
    }
}

#[tokio::test]
async fn discovery_finds_each_example_entry_point() {
    for (dir, symbol) in EXAMPLES {
        let root = examples_root().join(dir);
        let inv = hf_discovery::discover(&root, TargetLanguage::C)
            .await
            .unwrap_or_else(|e| panic!("discover failed for {dir}: {e}"));

        let symbols: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
        assert!(
            symbols.contains(symbol),
            "example {dir}: entry point `{symbol}` must be discovered; got {symbols:?}"
        );
    }
}

#[tokio::test]
async fn each_entry_point_is_a_fuzzable_kind() {
    // Entry points take a (bytes, len) surface, so the scanner should treat
    // them as either a Parser (name contains "parse") or a plain Function --
    // never an FFI/API-only classification.
    for (dir, symbol) in EXAMPLES {
        let root = examples_root().join(dir);
        let inv = hf_discovery::discover(&root, TargetLanguage::C)
            .await
            .unwrap_or_else(|e| panic!("discover failed for {dir}: {e}"));

        let cand = inv
            .candidates
            .iter()
            .find(|c| c.symbol == *symbol)
            .unwrap_or_else(|| panic!("example {dir}: `{symbol}` must be present"));

        assert!(
            matches!(cand.kind, TargetKind::Parser | TargetKind::Function),
            "example {dir}: `{symbol}` should be Parser or Function, got {:?}",
            cand.kind
        );
    }
}

#[tokio::test]
async fn static_helpers_are_not_discovered() {
    // `number_span` and `is_number_byte` (json_number_parser) are static and
    // must be skipped -- they have internal linkage and cannot be called from a
    // separate harness translation unit.
    let root = examples_root().join("json_number_parser");
    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let symbols: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    for helper in ["number_span", "is_number_byte"] {
        assert!(
            !symbols.contains(&helper),
            "static helper {helper} must not be a candidate; got {symbols:?}"
        );
    }
}
