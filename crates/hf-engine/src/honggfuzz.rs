//! honggfuzz engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::FuzzRunConfig;

/// Bounded container shared memory for honggfuzz's fixed-size feedback file.
pub const SHARED_MEMORY_MB: u32 = 192;
/// Per-file ceiling that admits the feedback file and limits scratch writes.
pub const SHARED_MEMORY_BYTES: u64 = SHARED_MEMORY_MB as u64 * 1024 * 1024;

/// Construct the `honggfuzz` argument list for a fuzz run.
///
/// honggfuzz has no user-specified RNG seed (its RNG is seeded from
/// arc4random//dev/urandom with no flag or env override), so a recorded
/// `cfg.seed` is deliberately not translated into an invented flag here.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec!["honggfuzz".to_owned()];
    if duration > 0 {
        args.push(format!("--run_time={duration}"));
    }
    args.push("--threads".to_owned());
    args.push(cfg.max_cpus.to_string());
    args.push("--input".to_owned());
    args.push(corpus.to_owned());
    args.push("--output".to_owned());
    args.push(out.to_owned());
    // Runtime feedback uses bounded container shared memory. Crash artifacts
    // and the report stay in the run output so triage can retain them.
    args.push("--workspace".to_owned());
    args.push("/dev/shm".to_owned());
    args.push("--crashdir".to_owned());
    args.push(out.to_owned());
    args.push("--report".to_owned());
    args.push(format!("{out}/HONGGFUZZ.REPORT.TXT"));
    // `cfg.env` is deliberately absent from the argument list: both callers pass
    // the same map through `ResourceLimits.env`, which the sandbox renders onto
    // the container. An `env K=V` wrapper here would be a second home for one
    // meaning and would displace the fuzzer program from argv[0].
    args.extend(cfg.extra_args.iter().cloned());
    args.push("--".to_owned());
    args.push(binary.to_owned());
    args
}

/// The honggfuzz engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Honggfuzz;
