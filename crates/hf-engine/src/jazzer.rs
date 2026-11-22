//! Jazzer engine adapter (coverage-guided JVM fuzzing).
//!
//! A Jazzer harness artifact is one executable file: a shell stub that
//! starts `jazzer` with the file itself as the class path, followed by the
//! jar of the compiled project and harness classes. Jazzer hands the rest of
//! its argv to the libFuzzer it embeds, so the command line is libFuzzer's.
//! See `docs/design/jvm-jazzer-fuzzing-design.md`.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// The generated harness class, in the default package.
pub const TARGET_CLASS: &str = "OxfuzzFuzzTarget";

/// Where Jazzer writes the Java reproducer source it generates for a
/// finding. The default is the working directory, which is read-only in a
/// replay; the reproducer is not an oxfuzz artifact, so it goes to scratch.
const REPRODUCER_DIR: &str = "/tmp";

/// The two lines that precede the jar in a harness artifact. `$0` is the
/// artifact itself: a jar keeps loading as a class path with a prefix.
#[must_use]
pub fn launcher_stub() -> String {
    format!(
        "#!/bin/sh\nexec jazzer --cp=\"$0\" --target_class={TARGET_CLASS} \
         --reproducer_path={REPRODUCER_DIR} \"$@\"\n"
    )
}

/// Construct the Jazzer argument list for a fuzz run. The run is one JVM
/// whatever the CPU allocation.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `extra_args` asks for fork or
/// job mode.
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    artifact: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    crate::libfuzzer::build_single_process_args("jazzer", cfg, artifact, corpus, out)
}

/// Whether the launcher stopped before or outside fuzzing: any exit other
/// than a clean finish (0), a finding (77), or a per-input timeout (70). A
/// class that fails to load exits 1 and is a failed run, never a finding.
#[must_use]
pub const fn exited_outside_fuzzing(exit_code: i32) -> bool {
    !matches!(exit_code, 0 | 70 | 77)
}

/// The Jazzer engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Jazzer;
