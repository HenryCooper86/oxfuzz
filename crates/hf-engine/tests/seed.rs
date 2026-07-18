//! Tests for deterministic run seeds: the per-engine seed flags the adapters
//! emit, and the run-id-derived fallback seed.
//!
//! Seed support reality check (verified against engine sources/docs):
//! - AFL++: `afl-fuzz -s <seed>` (no `AFL_SEED` environment variable exists).
//! - libFuzzer: `-seed=N` (`-seed=0` means "generate a random seed").
//! - `ClusterFuzzLite`: trailing fuzzer args are forwarded to libFuzzer.
//! - honggfuzz: no user-specified RNG seed exists; nothing may be emitted.

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::target::Sanitizer;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

fn cfg(engine: EngineKind, seed: Option<u64>) -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: Uuid::new_v4(),
        engine,
        duration: Some(Duration::from_secs(3600)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: Some(PathBuf::from("/work/corpus")),
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed,
        replay_of: None,
    }
}

#[test]
fn derive_run_seed_is_deterministic_for_the_same_run_id() {
    let run_id = Uuid::parse_str("3f6b1c2e-9a4d-4e8f-b7a1-0c2d3e4f5a6b").unwrap();
    assert_eq!(
        hf_engine::seed::derive_run_seed(run_id),
        hf_engine::seed::derive_run_seed(run_id),
        "the same run id must always derive the same seed"
    );
    assert_ne!(
        hf_engine::seed::derive_run_seed(run_id),
        0,
        "libFuzzer treats -seed=0 as 'random', so the derived seed must never be 0"
    );
}

#[test]
fn derive_run_seed_varies_with_the_run_id() {
    let first = hf_engine::seed::derive_run_seed(Uuid::new_v4());
    let second = hf_engine::seed::derive_run_seed(Uuid::new_v4());
    assert_ne!(first, second, "distinct run ids must not share a seed");
}

#[test]
fn libfuzzer_args_include_seed_only_when_recorded() {
    let seeded = hf_engine::libfuzzer::build_run_args(
        &cfg(EngineKind::LibFuzzer, Some(1234)),
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        seeded.iter().any(|arg| arg == "-seed=1234"),
        "libFuzzer must receive -seed=1234: {}",
        seeded.join(" ")
    );

    let unseeded = hf_engine::libfuzzer::build_run_args(
        &cfg(EngineKind::LibFuzzer, None),
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        !unseeded.iter().any(|arg| arg.starts_with("-seed=")),
        "an unseeded config must not pin libFuzzer's seed: {}",
        unseeded.join(" ")
    );
}

#[test]
fn afl_args_include_seed_flag_only_when_recorded() {
    let seeded = hf_engine::afl::build_run_args(
        &cfg(EngineKind::AflPlusPlus, Some(42)),
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    let position = seeded
        .iter()
        .position(|arg| arg == "-s")
        .expect("AFL++ must receive its -s seed flag");
    assert_eq!(seeded[position + 1], "42");
    // The seed flag belongs to afl-fuzz itself, not the target after `--`.
    let separator = seeded.iter().position(|arg| arg == "--").expect("--");
    assert!(
        position < separator,
        "the -s flag must precede the target separator: {}",
        seeded.join(" ")
    );

    let unseeded = hf_engine::afl::build_run_args(
        &cfg(EngineKind::AflPlusPlus, None),
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        !unseeded.iter().any(|arg| arg == "-s"),
        "an unseeded config must not pin AFL++'s seed: {}",
        unseeded.join(" ")
    );
}

#[test]
fn honggfuzz_never_emits_a_seed_flag() {
    // honggfuzz seeds its RNG from arc4random//dev/urandom with no override;
    // emitting an invented flag would fail the run, so the adapter must stay
    // silent even when a seed is recorded.
    let args = hf_engine::honggfuzz::build_run_args(
        &cfg(EngineKind::Honggfuzz, Some(42)),
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        !args.iter().any(|arg| arg.contains("seed")),
        "honggfuzz has no seed knob; no seed flag may be emitted: {}",
        args.join(" ")
    );
}

#[test]
fn clusterfuzzlite_forwards_seed_to_libfuzzer() {
    let seeded = hf_engine::clusterfuzzlite::build_run_args(
        &cfg(EngineKind::ClusterFuzzLite, Some(7)),
        "/work/oss-fuzz/project/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        seeded.iter().any(|arg| arg == "-seed=7"),
        "ClusterFuzzLite must forward -seed=7 to libFuzzer: {}",
        seeded.join(" ")
    );

    let unseeded = hf_engine::clusterfuzzlite::build_run_args(
        &cfg(EngineKind::ClusterFuzzLite, None),
        "/work/oss-fuzz/project/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    assert!(
        !unseeded.iter().any(|arg| arg.starts_with("-seed=")),
        "an unseeded config must not pin the forwarded seed: {}",
        unseeded.join(" ")
    );
}
