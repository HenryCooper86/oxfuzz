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
        seed: None,
        replay_of: None,
    }
}

#[test]
fn libfuzzer_enables_value_profile_comparison_feedback() {
    let c = cfg(EngineKind::LibFuzzer, 3600);
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let joined = args.join(" ");
    assert!(
        joined.contains("-use_value_profile=1"),
        "libFuzzer must enable value-profile comparison feedback: {joined}"
    );
    // Overridable: a caller's extra_args wins (libFuzzer takes the last one).
    let off = FuzzRunConfig {
        extra_args: vec!["-use_value_profile=0".to_owned()],
        ..cfg(EngineKind::LibFuzzer, 3600)
    };
    let off_args =
        hf_engine::libfuzzer::build_run_args(&off, "/work/fuzz_bin", "/work/corpus", "/work/out");
    let default_at = off_args.iter().position(|a| a == "-use_value_profile=1");
    let override_at = off_args.iter().position(|a| a == "-use_value_profile=0");
    assert!(
        matches!((default_at, override_at), (Some(d), Some(o)) if d < o),
        "an override must appear after the default so it wins: {off_args:?}"
    );
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
    assert_eq!(
        args.iter()
            .skip_while(|arg| arg.as_str() != "--")
            .skip(1)
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["/work/fuzz_bin", "@@"],
        "AFL++ must use the generated harness's file-input contract"
    );
}

#[test]
fn afl_input_delivery_is_identical_across_lifecycle_builders() {
    use hf_engine::afl::{build_reproduction_args, build_target_args, AflInput};

    let fuzz_target = build_target_args("/work/fuzz_bin", AflInput::FuzzerFile);
    let replay_target =
        build_target_args("/work/fuzz_bin", AflInput::ConcreteFile("/work/crash-1"));
    assert_eq!(fuzz_target, ["/work/fuzz_bin", "@@"]);
    assert_eq!(
        replay_target,
        build_reproduction_args("/work/fuzz_bin", "/work/crash-1")
    );

    let showmap = hf_engine::showmap::build_showmap_args("/work/fuzz_bin", "/work/crash-1");
    let showmap_separator = showmap.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(&showmap[showmap_separator + 1..], replay_target);

    // The `afl-tmin` minimizer command is built by `hf_crash::minimize::
    // build_minimize_args` (the single source), tested in hf-crash.
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
    // Crashes and the report must be directed into the run's `out` dir, or
    // triage (which only scans `out`) never finds honggfuzz crashes.
    let crashdir = args
        .iter()
        .position(|a| a == "--crashdir")
        .expect("--crashdir");
    assert_eq!(
        args.get(crashdir + 1).map(String::as_str),
        Some("/work/out")
    );
    let workspace = args
        .iter()
        .position(|a| a == "--workspace")
        .expect("--workspace");
    assert_eq!(
        args.get(workspace + 1).map(String::as_str),
        Some("/work/out")
    );
}

/// `cfg.env` reaches the fuzzer through the sandbox environment, never through
/// the argument list.
///
/// Both `build_run_args` callers -- `hf_engine::runner` and the harness smoke
/// step -- copy the same map into `ResourceLimits.env`, which the Docker
/// adapter renders as `--env=K=V` on every sandboxed command. An `env K=V`
/// wrapper in the argument list would be a second home for one meaning
/// (AGENTS.md 2.18), and it would displace the fuzzer program from argv[0].
///
/// The surviving home is covered by `hf-runtime`'s `docker_args` tests, which
/// assert the `--env=` rendering and the defaults-plus-overrides overlay.
#[test]
fn engine_args_leave_the_environment_to_the_sandbox() {
    let pair = ("ASAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned());

    let mut libfuzzer = cfg(EngineKind::LibFuzzer, 60);
    libfuzzer.env.push(pair.clone());
    let mut afl = cfg(EngineKind::AflPlusPlus, 60);
    afl.env.push(pair.clone());
    let mut honggfuzz = cfg(EngineKind::Honggfuzz, 60);
    honggfuzz.env.push(pair);

    for (label, args, program) in [
        (
            "libfuzzer",
            hf_engine::libfuzzer::build_run_args(
                &libfuzzer,
                "/work/fuzz_bin",
                "/work/corpus",
                "/work/out",
            ),
            "/work/fuzz_bin",
        ),
        (
            "afl",
            hf_engine::afl::build_run_args(&afl, "/work/fuzz_bin", "/work/corpus", "/work/out"),
            "afl-fuzz",
        ),
        (
            "honggfuzz",
            hf_engine::honggfuzz::build_run_args(
                &honggfuzz,
                "/work/fuzz_bin",
                "/work/corpus",
                "/work/out",
            ),
            "honggfuzz",
        ),
    ] {
        assert_eq!(
            args.first().map(String::as_str),
            Some(program),
            "{label} must keep its program at argv[0], not an env wrapper: {args:?}"
        );
        assert!(
            !args.iter().any(|arg| arg == "env"),
            "{label} must not wrap the command in `env`: {args:?}"
        );
        assert!(
            !args.iter().any(|arg| arg.contains("ASAN_OPTIONS")),
            "{label} must not carry the environment in its argument list: {args:?}"
        );
    }
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
