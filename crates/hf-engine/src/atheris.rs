//! Atheris engine adapter (coverage-guided Python fuzzing).
//!
//! An Atheris harness is a Python script that hands `sys.argv` to the
//! libFuzzer Atheris embeds, so its command line is libFuzzer's. It is still
//! a distinct engine: the counters are Python bytecode events, a finding is
//! an uncaught exception, and one process runs one interpreter.
//! See `docs/design/python-atheris-fuzzing-design.md`.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// The first line of every harness script: the image's interpreter in
/// isolated mode (no user site, no `PYTHON*` environment, no script
/// directory on `sys.path`). The script is executable, so a run, a smoke,
/// and a replay all start it the way they start a compiled harness.
pub const INTERPRETER_LINE: &str = "#!/usr/bin/python3 -I";

/// libFuzzer's diagnostic for a target whose inputs produce no coverage: the
/// selected module was not instrumented, so the run would be blind.
const UNINSTRUMENTED_DIAGNOSTIC: &str = "no interesting inputs were found";

/// Construct the Atheris argument list for a fuzz run.
///
/// `script` is the executable harness script. The run is always one process:
/// libFuzzer's fork mode re-executes the binary it was started as, which for
/// a script is the interpreter, so `cfg.max_cpus` does not add workers.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `extra_args` asks for fork or
/// job mode, which this engine cannot honor.
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    script: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    crate::libfuzzer::build_single_process_args("atheris", cfg, script, corpus, out)
}

/// Whether the output says the selected module produced no coverage.
#[must_use]
pub fn reports_no_instrumentation(output: &str) -> bool {
    output
        .to_ascii_lowercase()
        .contains(UNINSTRUMENTED_DIAGNOSTIC)
}

/// Whether the script stopped before or outside fuzzing: any exit other than
/// a clean finish (0), a finding (77, libFuzzer's error exit code, which
/// Atheris uses for an uncaught exception), or a per-input timeout (70). An
/// import error or a syntax error in the code under test exits 1 with a
/// traceback and is a failed run, never a finding.
#[must_use]
pub const fn exited_outside_fuzzing(exit_code: i32) -> bool {
    !matches!(exit_code, 0 | 70 | 77)
}

/// The Atheris engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Atheris;
