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
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
    }
}

#[test]
fn libfuzzer_enables_value_profile_comparison_feedback() {
    let c = cfg(EngineKind::LibFuzzer, 3600);
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
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
        hf_engine::libfuzzer::build_run_args(&off, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
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
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
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
    let args =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
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
fn afl_single_cpu_keeps_the_single_instance_argv() {
    let c = cfg(EngineKind::AflPlusPlus, 3600);
    let args =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    assert_eq!(
        args.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "afl-fuzz",
            "-i",
            "/work/corpus",
            "-o",
            "/work/out",
            "-V",
            "3600",
            "--",
            "/work/fuzz_bin",
            "@@",
        ],
        "one CPU must keep the single-instance argv byte-identical"
    );
}

#[test]
fn afl_multi_cpu_orchestrates_primary_and_secondaries() {
    let mut c = cfg(EngineKind::AflPlusPlus, 300);
    c.max_cpus = 3;
    c.seed = Some(42);
    c.extra_args = vec!["-x".to_owned(), "/work/fuzzer.dict".to_owned()];
    let args =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();

    assert_eq!(args.first().map(String::as_str), Some("bash"));
    assert_eq!(args.get(1).map(String::as_str), Some("-c"));
    let script = args.get(2).expect("coordinator script").as_str();

    // One primary, N-1 secondaries, all sharing one output tree. Every
    // instance reads the same staged corpus. (A run opted into `resume`
    // instead continues a copied-forward tree under AFL_AUTORESUME; the argv
    // is identical either way -- see afl_resume_keeps_the_argv_identical_to_a_cold_start.)
    assert_eq!(script.matches("-M main").count(), 1, "{script}");
    assert_eq!(script.matches("-S s1").count(), 1, "{script}");
    assert_eq!(script.matches("-S s2").count(), 1, "{script}");
    assert_eq!(script.matches("-i '/work/corpus'").count(), 3, "{script}");
    // Only the primary pins the recorded RNG seed.
    assert_eq!(script.matches("-s 42").count(), 1, "{script}");
    // Every instance carries the time budget, the dictionary, and the
    // generated harness's file-input contract.
    assert_eq!(script.matches("-V 300").count(), 3, "{script}");
    assert_eq!(
        script.matches("'-x' '/work/fuzzer.dict'").count(),
        3,
        "{script}"
    );
    assert_eq!(
        script.matches("-- '/work/fuzz_bin' @@").count(),
        3,
        "{script}"
    );
    // A cooperative Stop must reach every instance so AFL can flush
    // fuzzer_stats, the wrapper must log each worker's exit, and it must
    // exit with the primary's status.
    assert!(
        script.contains("trap 'kill -TERM $(jobs -p) 2>/dev/null' TERM INT"),
        "coordinator must forward TERM/INT: {script}"
    );
    assert!(
        script.contains("afl-worker $job exited $?"),
        "coordinator must surface worker exit statuses: {script}"
    );
    assert!(
        script.contains("wait \"$primary\"") && script.contains("exit \"$status\""),
        "coordinator must propagate the primary exit status: {script}"
    );
}

#[test]
fn honggfuzz_args_have_run_time() {
    let c = cfg(EngineKind::Honggfuzz, 3600);
    let args =
        hf_engine::honggfuzz::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
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
        Some("/dev/shm")
    );
    let report = args.iter().position(|a| a == "--report").expect("--report");
    assert_eq!(
        args.get(report + 1).map(String::as_str),
        Some("/work/out/HONGGFUZZ.REPORT.TXT")
    );
}

#[test]
fn honggfuzz_workers_follow_the_resolved_cpu_limit() {
    for cpus in [1, 2] {
        let mut c = cfg(EngineKind::Honggfuzz, 10);
        c.max_cpus = cpus;
        let args =
            hf_engine::honggfuzz::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
                .unwrap();
        let threads = args
            .iter()
            .position(|arg| arg == "--threads")
            .expect("--threads");
        assert_eq!(args.get(threads + 1), Some(&cpus.to_string()));
    }
}

/// `cfg.env` reaches the fuzzer through the sandbox environment, never through
/// the argument list.
///
/// Both `build_run_args` callers -- `hf_engine::runner` and the harness smoke
/// step -- copy the same map into `ResourceLimits.env`, which the Docker
/// adapter renders as `--env=K=V` on every sandboxed command. An `env K=V`
/// wrapper in the argument list would be a second home for one meaning
/// (Engineering Protocol 2.18), and it would displace the fuzzer program from argv[0].
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
            )
            .unwrap(),
            "/work/fuzz_bin",
        ),
        (
            "afl",
            hf_engine::afl::build_run_args(&afl, "/work/fuzz_bin", "/work/corpus", "/work/out")
                .unwrap(),
            "afl-fuzz",
        ),
        (
            "honggfuzz",
            hf_engine::honggfuzz::build_run_args(
                &honggfuzz,
                "/work/fuzz_bin",
                "/work/corpus",
                "/work/out",
            )
            .unwrap(),
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
fn libfuzzer_fork_follows_the_resolved_cpu_allocation() {
    // One CPU keeps the historical single-process argv: fork mode is a
    // different execution model even at N=1 (parent-coordinated children,
    // crash-resistant continuation), so the default allocation must not
    // opt a run into it.
    let single = cfg(EngineKind::LibFuzzer, 3600);
    let args = hf_engine::libfuzzer::build_run_args(
        &single,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    assert!(
        !args.iter().any(|arg| arg.starts_with("-fork=")),
        "one CPU must keep the single-process argv: {args:?}"
    );
    assert!(
        !args.iter().any(|arg| arg == "-detect_leaks=0"),
        "single-process runs keep leak detection on: {args:?}"
    );

    // An allocation above one becomes libFuzzer's own multi-process mode.
    let mut parallel = cfg(EngineKind::LibFuzzer, 3600);
    parallel.max_cpus = 4;
    let args = hf_engine::libfuzzer::build_run_args(
        &parallel,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    assert!(
        args.contains(&"-fork=4".to_owned()),
        "a 4-CPU allocation must run libFuzzer fork mode: {args:?}"
    );
    assert!(
        args.contains(&"-detect_leaks=0".to_owned()),
        "fork children misreport the forked heap snapshot as leaked; leak detection must be off in fork mode: {args:?}"
    );

    // Overridable: a caller's extra_args wins (libFuzzer takes the last one).
    parallel.extra_args.push("-fork=2".to_owned());
    let overridden = hf_engine::libfuzzer::build_run_args(
        &parallel,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    let default_at = overridden.iter().position(|a| a == "-fork=4");
    let override_at = overridden.iter().position(|a| a == "-fork=2");
    assert!(
        matches!((default_at, override_at), (Some(d), Some(o)) if d < o),
        "an override must appear after the default so it wins: {overridden:?}"
    );
}

#[test]
fn extra_args_are_appended() {
    let mut c = cfg(EngineKind::LibFuzzer, 60);
    c.extra_args.push("-dict=/work/json.dict".to_owned());
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
    let joined = args.join(" ");
    assert!(
        joined.contains("-dict=/work/json.dict"),
        "extra_args must be appended: {joined}"
    );
}

#[test]
fn libfuzzer_maps_input_timeout_to_seconds_rounding_up() {
    let mut c = cfg(EngineKind::LibFuzzer, 60);
    c.input_timeout = Some(Duration::from_millis(1500));
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
    assert!(
        args.contains(&"-timeout=2".to_owned()),
        "1500ms must round up to whole seconds: {args:?}"
    );

    // A sub-second budget becomes one second, never zero: libFuzzer reads
    // `-timeout=0` as "no timeout".
    c.input_timeout = Some(Duration::from_millis(1));
    let args =
        hf_engine::libfuzzer::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
    assert!(
        args.contains(&"-timeout=1".to_owned()),
        "a sub-second budget must not round down to 0: {args:?}"
    );
}

#[test]
fn afl_maps_input_timeout_to_exact_milliseconds() {
    let mut c = cfg(EngineKind::AflPlusPlus, 60);
    c.input_timeout = Some(Duration::from_millis(250));
    let args =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    let flag = args.iter().position(|a| a == "-t").expect("-t flag");
    assert_eq!(
        args.get(flag + 1).map(String::as_str),
        Some("250"),
        "AFL++ takes the exact millisecond budget: {args:?}"
    );

    // The multi-instance coordinator must hand every instance the same budget.
    c.max_cpus = 3;
    let args =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    let script = args.get(2).expect("coordinator script").as_str();
    assert_eq!(
        script.matches("-t 250").count(),
        3,
        "every afl-fuzz instance carries the per-input timeout: {script}"
    );
}

#[test]
fn honggfuzz_maps_input_timeout_to_seconds_rounding_up() {
    // honggfuzz 2.6 (pinned in docker/sandbox/Dockerfile) takes the per-input
    // timeout as `--timeout`/`-t` in whole seconds (cmdline.c: `case 't':
    // hfuzz->timing.tmOut = atol(optarg)`; help text "Timeout in seconds").
    let mut c = cfg(EngineKind::Honggfuzz, 60);
    c.input_timeout = Some(Duration::from_millis(1500));
    let args =
        hf_engine::honggfuzz::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
    assert!(
        args.contains(&"--timeout=2".to_owned()),
        "1500ms must round up to whole seconds: {args:?}"
    );
}

#[test]
fn absent_input_timeout_emits_no_engine_flag() {
    for engine in [
        EngineKind::LibFuzzer,
        EngineKind::AflPlusPlus,
        EngineKind::Honggfuzz,
    ] {
        let c = cfg(engine, 60);
        let args = hf_engine::adapter_for(engine)
            .build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
            .unwrap();
        let joined = args.join(" ");
        assert!(
            !joined.contains("-timeout=")
                && !joined.contains("--timeout=")
                && !args.iter().any(|a| a == "-t"),
            "{engine:?} without an explicit timeout must keep the engine default: {joined}"
        );
    }
}

#[test]
fn explicit_input_timeout_wins_over_extra_args() {
    // extra_args is the escape hatch when no timeout is configured; an
    // explicit one must not be silently overridden by it. All three engines
    // apply the last occurrence of a repeated flag, so the explicit flag is
    // emitted after extra_args.
    let mut libfuzzer = cfg(EngineKind::LibFuzzer, 60);
    libfuzzer.input_timeout = Some(Duration::from_millis(3000));
    libfuzzer.extra_args.push("-timeout=9".to_owned());
    let args = hf_engine::libfuzzer::build_run_args(
        &libfuzzer,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    let explicit = args.iter().rposition(|a| a == "-timeout=3").unwrap();
    let hatch = args.iter().position(|a| a == "-timeout=9").unwrap();
    assert!(
        hatch < explicit,
        "the explicit timeout must follow extra_args so it wins: {args:?}"
    );

    let mut afl = cfg(EngineKind::AflPlusPlus, 60);
    afl.input_timeout = Some(Duration::from_millis(3000));
    afl.extra_args.extend(["-t".to_owned(), "9".to_owned()]);
    let args = hf_engine::afl::build_run_args(&afl, "/work/fuzz_bin", "/work/corpus", "/work/out")
        .unwrap();
    let explicit = args.iter().rposition(|a| a == "-t").unwrap();
    let hatch = args.iter().position(|a| a == "-t").unwrap();
    assert!(
        hatch < explicit && args.get(explicit + 1).map(String::as_str) == Some("3000"),
        "the explicit timeout must follow extra_args so it wins: {args:?}"
    );

    let mut honggfuzz = cfg(EngineKind::Honggfuzz, 60);
    honggfuzz.input_timeout = Some(Duration::from_millis(3000));
    honggfuzz.extra_args.push("--timeout=9".to_owned());
    let args = hf_engine::honggfuzz::build_run_args(
        &honggfuzz,
        "/work/fuzz_bin",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    let explicit = args.iter().rposition(|a| a == "--timeout=3").unwrap();
    let hatch = args.iter().position(|a| a == "--timeout=9").unwrap();
    assert!(
        hatch < explicit,
        "the explicit timeout must follow extra_args so it wins: {args:?}"
    );
}

#[test]
fn syzkaller_ignores_input_timeout() {
    // syz-manager has no per-input timeout knob in its manager config; the
    // adapter must not fabricate one.
    let mut c = cfg(EngineKind::Syzkaller, 60);
    c.input_timeout = Some(Duration::from_millis(500));
    let with =
        hf_engine::syzkaller::build_run_args(&c, "/work/manager.cfg", "/work/corpus", "/work/out")
            .unwrap();
    c.input_timeout = None;
    let without =
        hf_engine::syzkaller::build_run_args(&c, "/work/manager.cfg", "/work/corpus", "/work/out")
            .unwrap();
    assert_eq!(
        with, without,
        "syzkaller argv must not invent a timeout flag"
    );
}

#[test]
fn go_native_drives_the_compiled_test_binary_with_fixed_flags() {
    let mut c = cfg(EngineKind::GoNative, 300);
    c.max_cpus = 4;
    let args = hf_engine::go_native::build_run_args(
        &c,
        "/work/fuzz_ParseRecord.test",
        "/work/corpus",
        "/work/out",
    )
    .unwrap();
    assert_eq!(
        args.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "/work/fuzz_ParseRecord.test",
            "-test.run=^FuzzParseRecord$",
            "-test.fuzz=^FuzzParseRecord$",
            "-test.fuzztime=300s",
            "-test.parallel=4",
            "/work/corpus",
        ],
        "{args:?}"
    );
}

#[test]
fn go_native_single_cpu_omits_parallel_and_zero_duration_omits_fuzztime() {
    let c = cfg(EngineKind::GoNative, 0);
    let args =
        hf_engine::go_native::build_run_args(&c, "/work/fuzz_T.test", "/work/corpus", "/work/out")
            .unwrap();
    assert_eq!(
        args.iter().map(String::as_str).collect::<Vec<_>>(),
        vec![
            "/work/fuzz_T.test",
            "-test.run=^FuzzT$",
            "-test.fuzz=^FuzzT$",
            "/work/corpus",
        ],
        "the sandbox wall-clock cap bounds an unbounded run: {args:?}"
    );
}

#[test]
fn afl_resume_keeps_the_argv_identical_to_a_cold_start() {
    // Resume is environment-driven: the runner injects AFL_AUTORESUME=1 for a
    // run whose config opted in and whose service staging copied a prior
    // session tree forward. The argv must not change between cold start and
    // resume, in either the single-instance or the coordinator form.
    let mut c = cfg(EngineKind::AflPlusPlus, 300);
    let cold =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    c.resume = true;
    let resumed =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    assert_eq!(cold, resumed, "single-instance argv must not change");

    c.max_cpus = 3;
    let resumed =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    c.resume = false;
    let cold =
        hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out").unwrap();
    assert_eq!(cold, resumed, "coordinator argv must not change");
}

#[test]
fn afl_rejects_a_hand_passed_resume_in_extra_args() {
    // `-i -` (either token form) is AFL++'s in-place resume. The typed
    // `FuzzRunConfig.resume` is the only source of resume truth, so a
    // hand-passed resume is rejected in both states: without `resume` it would
    // be a hidden resume, and with it the flag would duplicate the adapter's
    // own `-i` (afl-fuzz refuses multiple `-i` options).
    for extra_args in [
        vec!["-i".to_owned(), "-".to_owned()],
        vec!["-i-".to_owned()],
        vec![
            "-x".to_owned(),
            "/work/d.dict".to_owned(),
            "-i".to_owned(),
            "-".to_owned(),
        ],
    ] {
        for resume in [false, true] {
            let mut c = cfg(EngineKind::AflPlusPlus, 60);
            c.resume = resume;
            c.extra_args = extra_args.clone();
            let error =
                hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
                    .expect_err("a hand-passed AFL++ resume must be rejected");
            assert!(
                error.to_string().contains("resume"),
                "the error must name the owned resume path: {error}"
            );
        }
    }
}

#[test]
fn afl_resume_accepts_unrelated_extra_args() {
    let mut c = cfg(EngineKind::AflPlusPlus, 60);
    c.resume = true;
    c.extra_args = vec!["-x".to_owned(), "/work/fuzzer.dict".to_owned()];
    let args = hf_engine::afl::build_run_args(&c, "/work/fuzz_bin", "/work/corpus", "/work/out")
        .expect("a resume run keeps ordinary extra args");
    let joined = args.join(" ");
    assert!(
        joined.contains("-i") && joined.contains("/work/corpus"),
        "{joined}"
    );
}
