//! Runtime test double for the run-attributed function-coverage path.
//!
//! `ServiceContainer::collect_run_function_coverage` runs the profiling
//! toolchain through a `RuntimeAdapter` and then reads the results off the
//! host: raw profiles from `<run output>/function-coverage/raw`, and the merged
//! index and export from `<run output>/function-coverage/export`. A stub that
//! only reports success leaves collection unable to find any of them, so a run
//! configured to collect a profile ends with none retained.
//!
//! [`satisfy_function_coverage`] writes those artifacts on the host, which lets
//! the real collection path run unchanged instead of being bypassed. It is
//! deliberately not a `mock` that returns canned output: the service reads
//! files rather than streams, so the files are the interface.
//!
//! Call it from a stub's `RuntimeAdapter::run_command`. The trait's other three
//! command methods default to delegating to that one.

use hf_core::runtime::SandboxOptions;
use std::path::{Path, PathBuf};

/// Engine binary names are `fuzz_<symbol>` or `fuzz_<symbol>_<engine>`.
const BINARY_PREFIX: &str = "fuzz_";
const ENGINE_SUFFIXES: [&str; 5] = ["libfuzzer", "afl++", "aflplusplus", "honggfuzz", "syz"];

/// Write the host-side artifacts for a command dispatched with sandbox options.
///
/// Returns whether the command was profiling tooling that this handled, so a
/// stub whose command path blocks until cancellation can return instead of
/// routing the tooling into that path. Collection cancels nothing here: it
/// passes a fresh token, so a blocking stub deadlocks the run rather than
/// failing it, and the symptom is a test that never finishes.
///
/// Use this from `RuntimeAdapter::run_command_streaming_opts` and
/// `run_command_opts`. It maps the container paths the command names back to
/// their host paths through `extra_mounts`, which is the only place that mapping
/// exists: the profiling tooling is handed `/profiles/output/export.json` and
/// the host directory behind it is decided by the caller, so inferring it from
/// the working directory writes the file somewhere collection never looks.
pub fn satisfy_function_coverage_with_mounts(
    cmd: &[String],
    opts: &SandboxOptions,
    count: u64,
) -> bool {
    let Some(program) = cmd.first() else {
        return false;
    };
    if program.starts_with("llvm-profdata") {
        // `merge ... -o <index>`; command order is fixed by the caller.
        if let Some(host) = cmd
            .windows(2)
            .find(|pair| pair[0] == "-o")
            .and_then(|pair| host_path(&pair[1], opts))
        {
            write_host(&host, &[0u8; 32]);
        }
        true
    } else if program == "sh" {
        // The export is a redirect, so its target is the command's last
        // argument rather than a named option.
        if let Some(host) = cmd.last().and_then(|value| host_path(value, opts)) {
            if let Some(symbol) = target_symbol_from_mounts(opts) {
                write_host(&host, exported_function(&symbol, count).as_bytes());
            }
        }
        true
    } else {
        false
    }
}

/// The target symbol a run belongs to, read from where its output is mounted.
///
/// A workspace is `<root>/<project>/<target>` and holds a `runs` directory, so
/// the symbol is the name of the nearest ancestor of the mounted output that
/// contains one. Walking for that property rather than counting path components
/// avoids depending on the run layout: the output mount sits at
/// `<workspace>/runs/<id>/out/function-coverage/export`, which is five levels
/// below the workspace, and a fixed depth that is off by one silently names the
/// wrong symbol instead of failing.
///
/// Names are sanitized on disk, so a symbol containing characters outside the
/// sanitizer's set will not round trip; no test target does.
fn target_symbol_from_mounts(opts: &SandboxOptions) -> Option<String> {
    let mount = opts
        .extra_mounts
        .iter()
        .find(|mount| mount.container_path == "/profiles/output")?;
    let mut current = mount.host_path.as_path();
    while let Some(parent) = current.parent() {
        if parent.join("runs").is_dir() {
            return parent.file_name()?.to_str().map(str::to_owned);
        }
        current = parent;
    }
    None
}

/// The host path a container path resolves to, when a mount covers it.
fn host_path(container: &str, opts: &SandboxOptions) -> Option<PathBuf> {
    opts.extra_mounts.iter().find_map(|mount| {
        let tail = container.strip_prefix(&mount.container_path)?;
        if !tail.is_empty() && !tail.starts_with('/') {
            return None;
        }
        Some(mount.host_path.join(tail.trim_start_matches('/')))
    })
}

/// Write a file, creating nothing: a mount root that does not exist is a
/// fixture mistake and must not be papered over.
fn write_host(path: &Path, bytes: &[u8]) {
    let _ = std::fs::write(path, bytes);
}

/// Write the host-side artifacts collection reads for one command.
///
/// `count` is the entry count recorded for the target symbol, so a caller can
/// choose a positive entry or a measured miss. Writing nothing at all is how a
/// caller represents a run whose profile was never flushed.
///
/// Does nothing when the directory a write would target does not exist, so a
/// compile or probe command that happens to pass through the same stub is not
/// turned into evidence.
pub fn satisfy_function_coverage(cmd: &[String], cwd: &Path, count: u64) {
    let Some(program) = cmd.first() else {
        return;
    };
    for output in run_output_dirs(cwd) {
        let coverage = output.join("function-coverage");
        if program.starts_with("llvm-profdata") {
            // The service reads this back only to digest it, so its contents
            // are opaque; the digest is computed from whatever is here.
            write_if_directory(&coverage.join("export"), "merged.profdata", &[0u8; 32]);
        } else if program == "sh" {
            let Some(symbol) = target_symbol(cmd) else {
                continue;
            };
            write_if_directory(
                &coverage.join("export"),
                "export.json",
                exported_function(&symbol, count).as_bytes(),
            );
        } else {
            // The engine run itself: leave a raw profile for collection to find.
            write_if_directory(&coverage.join("raw"), "stub.profraw", &[0u8; 16]);
        }
    }
}

/// The run output directories a command could be attributed to.
///
/// The engine run is dispatched with the workspace as its working directory,
/// but the profiling tooling is dispatched with the retained input workspace
/// (`<workspace>/runs/<id>/input/workspace`), which is three levels below it. So
/// the run root is found by walking up rather than by assuming one depth; a
/// fixed depth silently writes nothing for the tooling and the collection then
/// fails with no explanation.
fn run_output_dirs(cwd: &Path) -> Vec<PathBuf> {
    const MAX_DEPTH: usize = 6;
    let mut current = Some(cwd);
    for _ in 0..MAX_DEPTH {
        let Some(directory) = current else {
            break;
        };
        let outputs = outputs_under(&directory.join("runs"));
        if !outputs.is_empty() {
            return outputs;
        }
        current = directory.parent();
    }
    Vec::new()
}

/// Every `runs/<id>/out` directory under a run root.
fn outputs_under(runs: &Path) -> Vec<PathBuf> {
    let mut outputs = Vec::new();
    let Ok(entries) = std::fs::read_dir(runs) else {
        return outputs;
    };
    for run in entries.flatten() {
        let output = run.path().join("out");
        if output.is_dir() {
            outputs.push(output);
        }
    }
    outputs
}

/// The target symbol a command names, read from the engine binary it runs.
///
/// The engine command carries `fuzz_<symbol>`, so the symbol does not have to be
/// threaded through every stub. A command that names no `fuzz_` binary yields
/// nothing, and the export is skipped rather than attributed to a guess.
fn target_symbol(cmd: &[String]) -> Option<String> {
    cmd.iter().find_map(|argument| {
        let name = Path::new(argument).file_name()?.to_str()?;
        let symbol = name.strip_prefix(BINARY_PREFIX)?;
        let symbol = ENGINE_SUFFIXES
            .iter()
            .find_map(|suffix| symbol.strip_suffix(&format!("_{suffix}")))
            .unwrap_or(symbol);
        (!symbol.is_empty()).then(|| symbol.to_owned())
    })
}

/// The LLVM export shape `hf_coverage::parse_llvm_function_coverage` accepts.
fn exported_function(symbol: &str, count: u64) -> String {
    format!(
        r#"{{"data":[{{"functions":[{{"name":"{symbol}","count":{count},"filenames":["/work/target.c"]}}]}}]}}"#
    )
}

/// Write only into a directory that already exists, so this never creates the
/// evidence tree itself and never turns an unrelated command into a measurement.
fn write_if_directory(directory: &Path, name: &str, bytes: &[u8]) {
    if directory.is_dir() {
        let _ = std::fs::write(directory.join(name), bytes);
    }
}
