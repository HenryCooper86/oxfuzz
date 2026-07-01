//! honggfuzz engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::FuzzRunConfig;

/// Construct the `honggfuzz` argument list for a fuzz run.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec!["honggfuzz".to_owned()];
    if duration > 0 {
        args.push(format!("--run_time={duration}"));
    }
    args.push("--input".to_owned());
    args.push(corpus.to_owned());
    args.push("--output".to_owned());
    args.push(out.to_owned());
    // honggfuzz writes crash artifacts (`SIG*.PC.*`) and `HONGGFUZZ.REPORT.TXT`
    // to its workspace/crashdir, which defaults to the container CWD (`/work`),
    // NOT to `--output` (that is the new-coverage corpus dir). Triage only scans
    // the run's `out` dir, so without these flags every honggfuzz crash lands at
    // the workspace root and is never ingested. Point both at `out` so crashes
    // and the report land where `hf_crash::ingest` looks for them.
    args.push("--workspace".to_owned());
    args.push(out.to_owned());
    args.push("--crashdir".to_owned());
    args.push(out.to_owned());
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    args.extend(cfg.extra_args.iter().cloned());
    args.push("--".to_owned());
    args.push(binary.to_owned());
    args
}

/// The honggfuzz engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Honggfuzz;
