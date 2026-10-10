//! Go native fuzzing engine adapter.
//!
//! See `docs/design/go-native-fuzzing-design.md`. Go's coverage-guided
//! fuzzer runs inside a compiled `go test -c` binary (built with
//! `-fuzz=<name>` so fuzz instrumentation is linked in); the adapter drives
//! that binary directly, matching the qualified direct-test-binary control.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// Construct the Go native fuzzing argument list for a fuzz run.
///
/// `binary` is the compiled `go test -c` binary for the package owning the
/// fuzz target, staged under the name `fuzz_<Symbol>.test` where `<Symbol>`
/// is the exact exported Go function under test; the fuzz test is named
/// `Fuzz<Symbol>`. The fixed flags
/// select exactly that one test. An explicit duration becomes
/// `-test.fuzztime=<N>s`; without one the fuzzer runs until stopped and the
/// sandbox wall-clock cap bounds it, the same contract as the other engines.
/// An allocation above one maps to `-test.parallel`. Go's fuzzer has no
/// user-specified RNG seed (like honggfuzz), so a recorded `cfg.seed` is
/// deliberately not translated into an invented flag.
///
/// `cfg.env` is deliberately absent from the argument list: the Go offline
/// and cache variables (`GOPROXY=off`, `GOSUMDB=off`, `GOTOOLCHAIN=local`)
/// are sandbox environment values with one home in `ResourceLimits.env`.
///
/// # Errors
/// Currently infallible; the shared adapter signature is fallible because
/// other engines validate flag combinations (see AFL++'s resume rule).
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    corpus: &str,
    _out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let test_name = format!(
        "Fuzz{}",
        go_symbol_from_binary_name(binary).unwrap_or_default()
    );
    let mut args = vec![
        binary.to_owned(),
        format!("-test.run=^{test_name}$"),
        format!("-test.fuzz=^{test_name}$"),
    ];
    if duration > 0 {
        args.push(format!("-test.fuzztime={duration}s"));
    }
    if cfg.max_cpus > 1 {
        args.push(format!("-test.parallel={}", cfg.max_cpus));
    }
    args.push(corpus.to_owned());
    args.extend(cfg.extra_args.iter().cloned());
    Ok(args)
}

/// The staged Go test binary is named `fuzz_<Symbol>.test`, where `<Symbol>`
/// is the exact exported Go function the harness fuzzes. The staging side
/// (the Go build path) owns the name; this is the adapter-side half of that
/// contract, the way AFL++'s `@@` file-input placeholder is.
fn go_symbol_from_binary_name(binary: &str) -> Option<&str> {
    let file = binary.rsplit('/').next()?;
    let stem = file.strip_suffix(".test")?;
    stem.strip_prefix("fuzz_")
}

/// The Go native fuzzing engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct GoNative;
