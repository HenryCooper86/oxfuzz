//! Integration tests over the curated example-target suite in
//! `tests/fixtures/examples/`.
//!
//! Each example isolates one bug class (heap/stack overflow, use-after-free,
//! integer overflow, OOB read, NULL deref, leak, plus the canonical libFuzzer
//! and honggfuzz intro targets). These assertions cover the deterministic,
//! toolchain-free layer of the pipeline: the discovery scanner must find every
//! documented entry point and classify it as a fuzzable target. Reproducing the
//! actual crash needs a real engine + sanitizer toolchain and is exercised by
//! manual / engine-gated runs (see tests/fixtures/examples/README.md).

use hf_core::target::{TargetKind, TargetLanguage};
use std::path::PathBuf;

fn examples_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("examples")
}

/// (directory, documented entry-point symbol) for every curated example.
const EXAMPLES: &[(&str, &str)] = &[
    ("libfuzzer_fuzzme", "FuzzMe"),
    ("honggfuzz_magic", "match_magic"),
    ("heap_overflow", "copy_chunk"),
    ("stack_overflow", "unpack_frame"),
    ("use_after_free", "run_session"),
    ("integer_overflow", "parse_image"),
    ("oob_read_png_crc", "read_chunk"),
    ("null_deref", "parse_optional"),
    ("memory_leak", "parse_token"),
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
    // `lookup_record` (null_deref) is static and must be skipped -- it has
    // internal linkage and cannot be called from a separate harness TU.
    let root = examples_root().join("null_deref");
    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed");
    let symbols: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
    assert!(
        !symbols.contains(&"lookup_record"),
        "static helper lookup_record must not be a candidate; got {symbols:?}"
    );
}
