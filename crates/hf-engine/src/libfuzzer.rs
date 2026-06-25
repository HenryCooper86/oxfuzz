//! libFuzzer engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::FuzzRunConfig;

/// Construct the libFuzzer argument list for a fuzz run.
///
/// libFuzzer runs the harness binary directly (no separate `fuzz` binary),
/// so the first element is the harness binary path itself.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![binary.to_owned()];
    if duration > 0 {
        args.push(format!("-max_total_time={duration}"));
    }
    // Disable leak detection so the fuzzer can run long enough to find
    // coverage (leaks are reported separately via ASan logs).
    args.push("-detect_leaks=0".to_owned());
    // libFuzzer writes crashes to the corpus dir by default; use -artifact_prefix
    // to direct them to the out dir.
    args.push(format!("-artifact_prefix={out}"));
    args.push(corpus.to_owned());
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    args.extend(cfg.extra_args.iter().cloned());
    args
}

/// The libFuzzer engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct LibFuzzer;
