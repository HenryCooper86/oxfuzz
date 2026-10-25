//! Integration tests over `examples/honggfuzz_upstream/`, a verbatim copy of
//! the self-contained parts of the upstream honggfuzz `examples/` directory.
//!
//! Unlike the clean-room showcase targets (see `showcase_examples.rs`), these
//! files are unmodified upstream code, so they exercise discovery and harness
//! drafting against real-world signatures: a file-path input (`badcode1.c`)
//! and `(char *, int)` protocol handlers (`vulnserver_cov.c`).

use hf_core::target::TargetLanguage;
use std::path::PathBuf;

fn upstream_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("honggfuzz_upstream")
}

/// (subdirectory, symbols that discovery must report) for each vendored target.
const TARGETS: &[(&str, &[&str])] = &[
    ("badcode", &["output"]),
    ("vulnserver", &["handleData1", "handleData2"]),
];

#[test]
fn vendored_code_ships_with_its_apache_license() {
    let license = std::fs::read_to_string(upstream_root().join("LICENSE"))
        .expect("examples/honggfuzz_upstream/LICENSE must exist");
    assert!(
        license.contains("Apache License") && license.contains("Version 2.0"),
        "LICENSE must be the upstream Apache-2.0 text"
    );
}

#[tokio::test]
async fn discovery_finds_each_upstream_entry_point() {
    for (dir, symbols) in TARGETS {
        let root = upstream_root().join(dir);
        let inv = hf_discovery::discover(&root, TargetLanguage::C)
            .await
            .unwrap_or_else(|e| panic!("discover failed for {dir}: {e}"));
        let found: Vec<&str> = inv.candidates.iter().map(|c| c.symbol.as_str()).collect();
        for symbol in *symbols {
            assert!(
                found.contains(symbol),
                "upstream example {dir}: `{symbol}` must be discovered; got {found:?}"
            );
        }
    }
}

#[tokio::test]
async fn reference_harnesses_expose_the_libfuzzer_entry_point() {
    // The reference harnesses are the upstream human-written baselines. Each
    // one defines `LLVMFuzzerTestOneInput`, which honggfuzz's libhfuzz drives
    // in persistent mode.
    let root = upstream_root().join("reference_harnesses");
    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed over the reference harnesses");
    let entry_points = inv
        .candidates
        .iter()
        .filter(|c| c.symbol == "LLVMFuzzerTestOneInput")
        .count();
    assert!(
        entry_points >= 7,
        "expected one LLVMFuzzerTestOneInput per reference harness, got {entry_points}"
    );
}
