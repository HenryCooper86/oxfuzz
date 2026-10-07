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

use std::path::{Path, PathBuf};

/// Engine binary names are `fuzz_<symbol>` or `fuzz_<symbol>_<engine>`.
const BINARY_PREFIX: &str = "fuzz_";
const ENGINE_SUFFIXES: [&str; 5] = ["libfuzzer", "afl++", "aflplusplus", "honggfuzz", "syz"];

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
