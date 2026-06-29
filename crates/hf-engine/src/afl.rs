//! AFL++ engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::FuzzRunConfig;

/// Construct the `afl-fuzz` argument list for a fuzz run.
///
/// Returns the full command tail: `["afl-fuzz", "-i", corpus, "-o", out, ...]`.
/// The caller (`EngineRunner`) wraps this in a `docker run` invocation.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec![
        "afl-fuzz".to_owned(),
        "-i".to_owned(),
        corpus.to_owned(),
        "-o".to_owned(),
        out.to_owned(),
    ];
    if duration > 0 {
        args.push("-V".to_owned());
        args.push(duration.to_string());
    }
    // Env vars as AFL_ prefixed options are set by the runtime; we pass them
    // as `--env` equivalents via the command environment. Here we emit them
    // as a leading `env` command so the docker exec applies them.
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    // Extra args (e.g. -dict=...).
    args.extend(cfg.extra_args.iter().cloned());
    // The binary to fuzz.
    args.push("--".to_owned());
    args.push(binary.to_owned());
    args
}

/// The AFL++ engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct AflPlusPlus;
