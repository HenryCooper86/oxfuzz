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
async fn reference_harness_entry_points_are_not_offered_as_targets() {
    // The reference harnesses are the upstream human-written baselines; each
    // defines `LLVMFuzzerTestOneInput`. That callback is the entry of a harness
    // the project already ships, not code under test: a generated harness for
    // it would define the same symbol, and the harness build leaves shipped
    // harness files out of the link. Discovery therefore does not offer it.
    let root = upstream_root().join("reference_harnesses");
    let harnesses = count_harness_sources(&root);
    assert!(
        harnesses >= 7,
        "fixture: one LLVMFuzzerTestOneInput per reference harness, got {harnesses}"
    );

    let inv = hf_discovery::discover(&root, TargetLanguage::C)
        .await
        .expect("discover should succeed over the reference harnesses");
    let entry_points: Vec<&str> = inv
        .candidates
        .iter()
        .map(|c| c.symbol.as_str())
        .filter(|symbol| symbol.starts_with("LLVMFuzzer"))
        .collect();
    assert!(
        entry_points.is_empty(),
        "harness callbacks are not targets: {entry_points:?}"
    );
}

/// C sources under `dir` (recursively) that define a libFuzzer entry point.
fn count_harness_sources(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir)
        .expect("reference harnesses are vendored")
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                count_harness_sources(&path)
            } else {
                usize::from(
                    path.extension().is_some_and(|ext| ext == "c")
                        && std::fs::read_to_string(&path)
                            .is_ok_and(|source| source.contains("LLVMFuzzerTestOneInput")),
                )
            }
        })
        .sum()
}
