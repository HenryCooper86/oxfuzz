//! `ClusterFuzzLite` engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.
//!
//! `ClusterFuzzLite` wraps oss-fuzz build scripts. The `build_run_args`
//! function constructs the `python3 infra/helper.py run_fuzzer` command.

use hf_core::engine::FuzzRunConfig;

/// Construct the `ClusterFuzzLite` run argument list.
///
/// `ClusterFuzzLite` uses `infra/helper.py run_fuzzer <project> <fuzzer_name>
/// --timeout=<seconds>`.
#[must_use]
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    _binary: &str,
    _corpus: &str,
    _out: &str,
) -> Vec<String> {
    let duration = cfg.duration.map_or(3600, |d| d.as_secs());
    let mut args = vec![
        "python3".to_owned(),
        "infra/helper.py".to_owned(),
        "run_fuzzer".to_owned(),
    ];
    if duration > 0 {
        args.push(format!("--timeout={duration}"));
    }
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

/// The `ClusterFuzzLite` engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct ClusterFuzzLite;
