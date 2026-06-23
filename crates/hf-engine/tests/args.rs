//! Tests for engine run-argument construction.

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::target::Sanitizer;
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

fn cfg(engine: EngineKind, duration_secs: u64) -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: Uuid::new_v4(),
        engine,
        duration: Some(Duration::from_secs(duration_secs)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: Some(PathBuf::from("/work/corpus")),
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
    }
}

#[test]
fn libfuzzer_args_have_max_total_time() {
    let c = cfg(EngineKind::LibFuzzer, 3600);
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("-max_total_time=3600"),
        "libFuzzer must set -max_total_time: {joined}"
    );
    assert!(
        joined.contains("/work/corpus"),
        "libFuzzer must include corpus dir: {joined}"
    );
    assert!(
        joined.contains("/work/fuzz_bin"),
        "libFuzzer must include the binary: {joined}"
    );
}

#[test]
fn afl_args_have_input_and_output_dirs() {
    let c = cfg(EngineKind::AflPlusPlus, 3600);
    let args = hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("-i") && joined.contains("/work/corpus"),
        "AFL++ must set -i corpus: {joined}"
    );
    assert!(
        joined.contains("-o") && joined.contains("/work/out"),
        "AFL++ must set -o out: {joined}"
    );
    assert!(
        joined.contains("-V") && joined.contains("3600"),
        "AFL++ must set -V duration: {joined}"
    );
    assert!(
        joined.contains("/work/fuzz_bin"),
        "AFL++ must include the binary: {joined}"
    );
}

#[test]
fn honggfuzz_args_have_run_time() {
    let c = cfg(EngineKind::Honggfuzz, 3600);
    let args =
        hf_engine::honggfuzz::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("--run_time=3600"),
        "honggfuzz must set --run_time: {joined}"
    );
    assert!(
        joined.contains("/work/fuzz_bin"),
        "honggfuzz must include the binary: {joined}"
    );
    assert!(
        joined.contains("--input") && joined.contains("/work/corpus"),
        "honggfuzz must set --input corpus: {joined}"
    );
}

#[test]
fn libfuzzer_args_include_sanitizer_env() {
    let mut c = cfg(EngineKind::LibFuzzer, 60);
    c.env
        .push(("ASAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned()));
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("ASAN_OPTIONS=abort_on_error=1"),
        "libFuzzer must pass env vars: {joined}"
    );
}

#[test]
fn extra_args_are_appended() {
    let mut c = cfg(EngineKind::LibFuzzer, 60);
    c.extra_args.push("-dict=/work/json.dict".to_owned());
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("-dict=/work/json.dict"),
        "extra_args must be appended: {joined}"
    );
}

#[test]
fn clusterfuzzlite_args_have_helper_py() {
    let c = cfg(EngineKind::ClusterFuzzLite, 3600);
    let args = hf_engine::clusterfuzzlite::build_run_args(
        &c,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    );
    let joined = args.join(" ");
    assert!(
        joined.contains("infra/helper.py"),
        "ClusterFuzzLite must use infra/helper.py: {joined}"
    );
    assert!(
        joined.contains("--timeout=3600"),
        "ClusterFuzzLite must set --timeout: {joined}"
    );
    assert!(
        joined.contains("run_fuzzer"),
        "ClusterFuzzLite must use run_fuzzer subcommand: {joined}"
    );
}
