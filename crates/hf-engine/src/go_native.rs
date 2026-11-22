//! Go native fuzzing engine adapter.
//!
//! See `docs/design/go-native-fuzzing-design.md`. Go's coverage-guided
//! fuzzer runs inside a compiled `go test -c` binary (built with
//! `-fuzz=<name>` so fuzz instrumentation is linked in); the adapter drives
//! that binary directly, matching the qualified direct-test-binary control.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// The pattern that selects the fuzz test. A Go harness binary holds exactly
/// one fuzz test: the harness source is checked to define one, and the
/// module's own `_test.go` files are not staged into the build. The service
/// stages every engine's binary under one fixed name, so the test's own name
/// is not available here; Go refuses `-test.fuzz` when the pattern matches
/// more than one fuzz test, so a binary that broke the contract fails loudly
/// instead of fuzzing the wrong function.
pub const FUZZ_TEST_PATTERN: &str = "^Fuzz";

/// The line `go test` prints when it has saved a failing input, followed by
/// the path relative to the working directory.
pub const FAILING_INPUT_LINE: &str = "Failing input written to ";

/// The directory under a run's output directory that is Go's fuzz cache: one
/// `<FuzzXxx>/` subdirectory of corpus files in Go's encoding.
pub const FUZZ_CACHE_DIR: &str = "go-fuzz-cache";

/// Per-file write ceiling for a Go fuzz run. Go's fuzz coordinator backs each
/// worker's shared memory with a 100 MiB temporary file and fails the run
/// before the first input (`truncate /tmp/fuzz-...: file too large`) under a
/// smaller limit; 128 MiB admits it (verified with Go 1.26.5 in the pinned
/// image, where 64 MiB fails).
pub const SHARED_MEMORY_BYTES: u64 = 128 * 1024 * 1024;

/// Construct the Go native fuzzing argument list for a fuzz run.
///
/// `binary` is the compiled `go test -c` binary. The fixed flags:
///
/// - `-test.run` and `-test.fuzz` select the binary's one fuzz test
///   ([`FUZZ_TEST_PATTERN`]).
/// - `-test.fuzzcachedir=<out>/go-fuzz-cache` ([`FUZZ_CACHE_DIR`]): Go
///   refuses `-test.fuzz` without it. Go reads and keeps its corpus under
///   `<cache>/<FuzzXxx>/` in its own text encoding and ignores raw input
///   files, while the run corpus is a flat directory of raw inputs. The
///   service translates between the two: seeds are encoded into the cache
///   before the run and Go's discoveries are decoded back afterwards.
/// - `-test.fuzzminimizetime=0`: Go's default spends up to 60 seconds
///   minimizing a failing input after the run's own budget is over; with 0
///   the failing input is saved immediately and the run ends inside its
///   resolved duration (verified with Go 1.26.5 in the pinned image).
/// - `-test.parallel=<N>`: the worker count; without it Go uses every CPU it
///   can see rather than the run's allocation.
/// - An explicit duration becomes `-test.fuzztime=<N>s`; without one the
///   fuzzer runs until stopped and the sandbox wall-clock cap bounds it, the
///   same contract as the other engines.
///
/// Go's fuzzer has no user-specified RNG seed and no per-input timeout flag
/// (like honggfuzz for the seed), so a recorded `cfg.seed` or
/// `cfg.input_timeout` is deliberately not translated into an invented flag.
/// Failing inputs are written to `testdata/fuzz/<FuzzXxx>/` under the
/// process working directory, which the service points at the run's output
/// directory.
///
/// `cfg.env` is deliberately absent from the argument list: the Go offline
/// variables are sandbox environment values with one home in
/// [`crate::runner::run_env`].
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `cfg.extra_args` sets one of
/// the flags this adapter owns: a second `-test.fuzz` or cache directory
/// would silently change what is fuzzed or where its inputs go.
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    _corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    const OWNED: [&str; 6] = [
        "-test.run",
        "-test.fuzz",
        "-test.fuzzcachedir",
        "-test.fuzzminimizetime",
        "-test.fuzztime",
        "-test.parallel",
    ];
    for argument in &cfg.extra_args {
        let name = argument.split('=').next().unwrap_or(argument);
        let name = name
            .strip_prefix("--")
            .map_or_else(|| name.to_owned(), |rest| format!("-{rest}"));
        if OWNED.contains(&name.as_str()) {
            return Err(ClassifiedError::Validation(format!(
                "the go-native engine sets {name} itself; remove it from the extra arguments"
            )));
        }
    }
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![
        binary.to_owned(),
        format!("-test.run={FUZZ_TEST_PATTERN}"),
        format!("-test.fuzz={FUZZ_TEST_PATTERN}"),
        format!("-test.fuzzcachedir={out}/{FUZZ_CACHE_DIR}"),
        "-test.fuzzminimizetime=0".to_owned(),
        format!("-test.parallel={}", cfg.max_cpus.max(1)),
    ];
    if duration > 0 {
        args.push(format!("-test.fuzztime={duration}s"));
    }
    args.extend(cfg.extra_args.iter().cloned());
    Ok(args)
}

/// Whether a finished Go fuzz run failed without a finding to triage.
///
/// A Go test binary exits non-zero for every failure. Only a run that also
/// printed [`FAILING_INPUT_LINE`] left an input behind; any other failure (a
/// setup error, a pattern that matches no fuzz test, a failing `f.Add` seed)
/// is a failed run whose output the operator must read.
#[must_use]
pub fn failed_without_finding(exit_code: i32, output: &str) -> bool {
    exit_code != 0 && !output.contains(FAILING_INPUT_LINE)
}

/// The argument list that replays one saved failing input: the test binary
/// runs the fuzz function once on `testdata/fuzz/<fuzz_test>/<input_name>`
/// under its working directory, with no fuzzing.
#[must_use]
pub fn build_replay_args(binary: &str, fuzz_test: &str, input_name: &str) -> Vec<String> {
    vec![
        binary.to_owned(),
        format!("-test.run=^{fuzz_test}$/^{input_name}$"),
        "-test.v".to_owned(),
    ]
}

/// The Go native fuzzing engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct GoNative;
