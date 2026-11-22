//! Jazzer.js engine adapter (coverage-guided Node.js fuzzing).
//!
//! A Jazzer.js harness artifact is one executable file that is both a shell
//! script and an ES module: its second line is a comment to JavaScript and
//! a command to the shell. Jazzer.js decides how to load a fuzz target from
//! its file name, so the artifact writes its module text to a scratch path
//! ending in `.mjs` and starts the image's launcher on that copy, telling
//! the copy where the artifact lives. Jazzer.js hands the rest of its argv
//! to the libFuzzer it embeds, so the command line is libFuzzer's.
//!
//! The copy is an ES module because that is what lets it `import()` the
//! selected module: Jazzer.js instruments an ES module only when it is
//! imported, and a `CommonJS` module is instrumented either way.
//! See `docs/design/javascript-jazzerjs-fuzzing-design.md`.

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// The image's launcher: the pinned Node.js on the pinned Jazzer.js command
/// line.
pub const LAUNCHER: &str = "jazzer-js";

/// The image's pinned Node.js. The syntax-only build names it directly.
pub const NODE: &str = "/opt/node/bin/node";

/// The pinned Jazzer.js package inside the image. A harness loads the data
/// provider from this absolute path, because module resolution from the
/// workspace would otherwise find a copy the project carries.
pub const API_MODULE: &str = "/opt/jazzerjs/node_modules/@jazzer.js/core";

/// Where the artifact writes its module text before Jazzer.js loads it.
pub const HARNESS_COPY: &str = "/tmp/oxfuzz-harness.mjs";

/// How many lines start the artifact before its module text: the
/// interpreter line and the launcher line. The copy leaves them out, because
/// Jazzer.js's ES module instrumentation does not accept an interpreter line.
const LAUNCHER_LINE_COUNT: u32 = 2;

/// The environment variable that tells the copy which directory the
/// artifact is in: the workspace for a build or a smoke, the run's input
/// directory for a campaign and its replays.
pub const HARNESS_DIR_ENV: &str = "OXFUZZ_HARNESS_DIR";

/// Jazzer.js's own per-input timeout in milliseconds when the run sets none.
/// It replaces libFuzzer's `-timeout`, so the launcher always states it.
const DEFAULT_TIMEOUT_MS: u32 = 5000;

/// The two lines that start a harness artifact. To the shell the second
/// line runs `:` and then the launcher; to JavaScript it is a string
/// statement followed by a comment.
///
/// Jazzer.js is not put in its synchronous mode: the harness returns what
/// the selected function returns, so a function that answers with a promise
/// is awaited and its rejection is a finding, whether or not the function
/// is declared `async`. A function that returns a plain value costs one
/// turn of the event loop per input.
///
/// libFuzzer's `-timeout=<seconds>` is read from the argv and restated as
/// Jazzer.js's `--timeout <milliseconds>`, which would otherwise override
/// it with its default.
#[must_use]
pub fn launcher_lines() -> String {
    format!(
        "#!/bin/sh\n\
         ':' //; t={DEFAULT_TIMEOUT_MS}; for a in \"$@\"; do case \"$a\" in \
         -timeout=*) t=$((${{a#-timeout=}} * 1000));; esac; done; \
         d=\"$(cd \"$(dirname \"$0\")\" && pwd)\" \
         && tail -n +{first} \"$0\" > {HARNESS_COPY} \
         && {HARNESS_DIR_ENV}=\"$d\" exec {LAUNCHER} {HARNESS_COPY} \
         --timeout \"$t\" -- \"$@\"\n",
        first = LAUNCHER_LINE_COUNT + 1,
    )
}

/// Construct the Jazzer.js argument list for a fuzz run. The run is one
/// Node.js process whatever the CPU allocation.
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
    crate::libfuzzer::build_single_process_args(LAUNCHER, cfg, artifact, corpus, out)
}

/// Whether the launcher stopped before or outside fuzzing: any exit other
/// than a clean finish (0), a finding (77), or a per-input timeout (70). A
/// module that fails to load exits 1 and is a failed run, never a finding.
#[must_use]
pub const fn exited_outside_fuzzing(exit_code: i32) -> bool {
    !matches!(exit_code, 0 | 70 | 77)
}

/// The Jazzer.js engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct JazzerJs;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_launcher_line_is_a_shell_command_and_a_javascript_comment() {
        let lines = launcher_lines();
        let mut split = lines.lines();
        assert_eq!(split.next(), Some("#!/bin/sh"));
        let command = split.next().unwrap();
        assert_eq!(split.next(), None, "exactly two lines");
        // JavaScript reads a string statement and then a comment.
        assert!(command.starts_with("':' //; "));
        assert_eq!(
            command,
            "':' //; t=5000; for a in \"$@\"; do case \"$a\" in \
             -timeout=*) t=$((${a#-timeout=} * 1000));; esac; done; \
             d=\"$(cd \"$(dirname \"$0\")\" && pwd)\" \
             && tail -n +3 \"$0\" > /tmp/oxfuzz-harness.mjs \
             && OXFUZZ_HARNESS_DIR=\"$d\" exec jazzer-js /tmp/oxfuzz-harness.mjs \
             --timeout \"$t\" -- \"$@\""
        );
        // A promise the function returns is awaited: no synchronous mode.
        assert!(!command.contains("--sync"));
    }

    #[test]
    fn only_a_clean_finish_a_finding_or_a_timeout_is_fuzzing() {
        for code in [0, 70, 77] {
            assert!(!exited_outside_fuzzing(code), "{code}");
        }
        for code in [1, 2, 126, 127, 137] {
            assert!(exited_outside_fuzzing(code), "{code}");
        }
    }
}
