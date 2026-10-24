//! Minimization command construction.

use std::time::Duration;

use hf_core::engine::EngineKind;

/// The per-execution timeout `build_minimize_args` pins when no resolved
/// policy budget is threaded: `EXEC_TIMEOUT` in the pinned AFL++ 4.09c,
/// 1000 ms. The service-side threading of the resolved policy timeout is a
/// separate follow-up.
const AFL_TMIN_DEFAULT_TIMEOUT: Duration = Duration::from_millis(1000);

/// Construct the minimization command args for an engine at the pinned
/// AFL++ default per-execution timeout.
///
/// Returns `None` if the engine has no built-in minimizer. See
/// [`build_minimize_args_with_timeout`] for the resolved-budget form; the
/// service-side threading of the policy timeout is a separate follow-up.
#[must_use]
pub fn build_minimize_args(
    engine: EngineKind,
    binary: &str,
    crash_input: &str,
    output: &str,
) -> Option<Vec<String>> {
    build_minimize_args_with_timeout(
        engine,
        binary,
        crash_input,
        output,
        AFL_TMIN_DEFAULT_TIMEOUT,
    )
}

/// Construct the minimization command args for an engine under a resolved
/// per-input timeout.
///
/// `timeout` is the resolved per-input budget (the policy's
/// `fuzzing.default_timeout_ms`), threading into `-t <ms>` for afl-tmin and
/// `-timeout=<s>` for libFuzzer the same way hf-engine's `build_cmin_args`
/// threads it for corpus distillation: an `ASan` harness whose crash needs
/// longer than afl-tmin's 1 s default to reproduce would otherwise make the
/// minimizer FATAL ("Target binary times out").
///
/// Returns `None` if the engine has no built-in minimizer.
#[must_use]
pub fn build_minimize_args_with_timeout(
    engine: EngineKind,
    binary: &str,
    crash_input: &str,
    output: &str,
    timeout: Duration,
) -> Option<Vec<String>> {
    match engine {
        // `binary -minimize_crash=1 -exact_artifact_path=<output> <crash>`:
        // libFuzzer takes the crash file as a positional argument and writes the
        // minimized result to `-exact_artifact_path`. `-runs` bounds the search
        // so a stubborn crash cannot minimize forever, and `-timeout=` bounds
        // each execution at the resolved per-input budget.
        EngineKind::LibFuzzer => Some(vec![
            binary.to_owned(),
            "-minimize_crash=1".to_owned(),
            "-runs=10000".to_owned(),
            format!("-timeout={}", timeout_secs_ceil(timeout)),
            format!("-exact_artifact_path={output}"),
            crash_input.to_owned(),
        ]),
        // `afl-tmin -i <crash> -o <output> -t <ms> -- <binary> @@`: the
        // instrumented target and its `@@` file-argument placeholder must
        // follow `--`, or afl-tmin has no program to run; `-t` takes the
        // per-execution timeout in exact milliseconds, like afl-fuzz.
        EngineKind::AflPlusPlus => Some(vec![
            "afl-tmin".to_owned(),
            "-i".to_owned(),
            crash_input.to_owned(),
            "-o".to_owned(),
            output.to_owned(),
            "-t".to_owned(),
            timeout_millis(timeout).to_string(),
            "--".to_owned(),
            binary.to_owned(),
            "@@".to_owned(),
        ]),
        // No built-in raw-binary minimizer for these engines:
        // - honggfuzz has no inline minimizer.
        // - syzkaller uses `syz-repro` on the crash log, driven separately from
        //   a harness binary.
        // - Go's native fuzzer minimizes failing inputs itself during the run.
        EngineKind::Honggfuzz | EngineKind::Syzkaller | EngineKind::GoNative => None,
    }
}

/// Per-input timeout in exact milliseconds (afl-tmin `-t`), mirroring
/// `hf_engine`'s AFL++ rendering of the same budget.
fn timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}

/// Per-input timeout in whole seconds (libFuzzer `-timeout=`). Rounds up so a
/// sub-second budget never becomes 0, which libFuzzer reads as "no timeout".
fn timeout_secs_ceil(timeout: Duration) -> u64 {
    timeout_millis(timeout).div_ceil(1000).max(1)
}
