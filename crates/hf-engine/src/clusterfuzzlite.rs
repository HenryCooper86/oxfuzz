//! `ClusterFuzzLite` engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.
//!
//! `ClusterFuzzLite` wraps oss-fuzz build scripts. The `build_run_args`
//! function constructs the `python3 infra/helper.py run_fuzzer` command.

use std::path::Path;

use hf_core::engine::FuzzRunConfig;

/// Construct the `ClusterFuzzLite` run argument list.
///
/// oss-fuzz's `infra/helper.py run_fuzzer` takes its flags, then two positional
/// arguments `<project> <fuzzer_name>`, then trailing `fuzzer_args` forwarded to
/// the fuzzer itself:
/// `run_fuzzer [--corpus-dir DIR] <project> <fuzzer_name> [fuzzer_args...]`.
///
/// `helper.py` has no `--timeout` flag; the time budget is a fuzzer argument, so
/// the duration is forwarded as libFuzzer's `-max_total_time=<secs>` after the
/// positional arguments. (A `--timeout` flag makes `helper.py` exit with an
/// argparse error, which the runner then classifies as an engine failure.)
///
/// The adapter trait only threads through container-internal paths, not a
/// project name, so both are derived from `binary` (the harness path): the
/// fuzzer name is the file name, and the project is the name of its parent
/// directory (oss-fuzz lays binaries out as `.../<project>/<fuzzer>`). When the
/// binary sits directly in the workspace root the project falls back to the
/// fuzzer name so the command is still well-formed and runnable.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, _out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(3600, |d| d.as_secs());

    let bin_path = Path::new(binary);
    let fuzzer_name = bin_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fuzzer");
    let project = bin_path
        .parent()
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .filter(|p| !matches!(*p, "" | "/" | "." | "work" | "out"))
        .unwrap_or(fuzzer_name);

    let mut args = vec![
        "python3".to_owned(),
        "infra/helper.py".to_owned(),
        "run_fuzzer".to_owned(),
    ];
    if !corpus.is_empty() {
        args.push(format!("--corpus-dir={corpus}"));
    }
    // Positional arguments must follow the flags.
    args.push(project.to_owned());
    args.push(fuzzer_name.to_owned());
    // The time budget is a fuzzer argument, not a helper.py flag, so it trails
    // the positionals.
    if duration > 0 {
        args.push(format!("-max_total_time={duration}"));
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
