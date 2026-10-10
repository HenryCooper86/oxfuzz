//! libFuzzer engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// Construct the libFuzzer argument list for a fuzz run.
///
/// libFuzzer runs the harness binary directly (no separate `fuzz` binary),
/// so the first element is the harness binary path itself.
///
/// # Errors
/// Currently infallible; the shared adapter signature is fallible because
/// other engines validate flag combinations (see AFL++'s resume rule).
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![binary.to_owned()];
    if duration > 0 {
        args.push(format!("-max_total_time={duration}"));
    }
    // `-seed=N` pins the RNG seed; libFuzzer's default (-seed=0) is "generate
    // a random seed", so the flag is emitted only when a seed was recorded.
    if let Some(seed) = cfg.seed {
        args.push(format!("-seed={seed}"));
    }
    // Leak detection is left at libFuzzer's default (on). Memory leaks are a bug
    // class the triage pipeline explicitly ingests (`leak-*` artifacts), and the
    // smoke step also runs with leak detection on, so a run must match. A caller
    // that wants it off can append `-detect_leaks=0` via `cfg.extra_args`, which
    // libFuzzer honors (last occurrence wins).
    // libFuzzer writes crashes to the corpus dir by default; use -artifact_prefix
    // to direct them to the out dir. The trailing slash is REQUIRED: libFuzzer
    // concatenates `{prefix}{type}-{hash}`, so without it an artifact lands at
    // `/work/outcrash-...` (workspace root) instead of `/work/out/crash-...`,
    // and triage -- which scans `out/` -- never finds it.
    args.push(format!("-artifact_prefix={}/", out.trim_end_matches('/')));
    // Comparison feedback (value profile): libFuzzer tracks partial progress on
    // each `memcmp`/integer comparison, so it can incrementally solve magic-value
    // and checksum gates that otherwise wall off most of the target. This is one
    // of the highest-yield coverage settings; complements the extracted
    // dictionary. Placed before `extra_args` so a caller can override with
    // `-use_value_profile=0` (libFuzzer takes the last occurrence).
    args.push("-use_value_profile=1".to_owned());
    // An allocation above one runs libFuzzer's own multi-process mode: the
    // parent coordinates N children over the shared corpus directory,
    // continues after a child crash (artifacts still land through
    // `-artifact_prefix`), and stops at `-max_total_time`. One CPU keeps the
    // historical single-process argv, because fork mode is a different
    // execution model even at N=1. Like the flag above, emitted before
    // `extra_args` so a caller can override it.
    if cfg.max_cpus > 1 {
        args.push(format!("-fork={}", cfg.max_cpus));
        // Fork children misreport leaks: after fork(2), heap chunks held only
        // by the parent's other threads are unreachable in the child, so both
        // libFuzzer's in-loop check and the exit-time LeakSanitizer report
        // leaks a single-process run of the same binary does not have. Leak
        // detection stays ON for single-process runs, where leak findings are
        // real and triage ingests `leak-*` artifacts. The exit-time check
        // additionally needs ASAN_OPTIONS in the sandbox environment; the
        // runner sets it for fork runs.
        args.push("-detect_leaks=0".to_owned());
    }
    args.push(corpus.to_owned());
    // `cfg.env` is deliberately absent from the argument list: both callers pass
    // the same map through `ResourceLimits.env`, which the sandbox renders onto
    // the container. An `env K=V` wrapper here would be a second home for one
    // meaning and would displace the fuzzer program from argv[0].
    args.extend(cfg.extra_args.iter().cloned());
    // The explicit per-input timeout is emitted after `extra_args`: libFuzzer
    // applies the last occurrence of a repeated flag, so a configured timeout
    // is never silently overridden by the escape hatch. libFuzzer takes whole
    // seconds, so a sub-second budget rounds up (never to 0, which libFuzzer
    // reads as "no timeout").
    if let Some(timeout) = cfg.input_timeout {
        args.push(format!("-timeout={}", crate::timeout_secs_ceil(timeout)));
    }
    Ok(args)
}

/// The libFuzzer engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct LibFuzzer;
