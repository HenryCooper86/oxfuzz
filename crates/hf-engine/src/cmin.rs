//! Batch corpus distillation via `afl-cmin`.
//!
//! `afl-cmin` reduces a whole corpus to a minimum covering set in one
//! invocation: every input is traced through `afl-showmap` (optionally fanned
//! out over `-T` parallel tasks), and the smallest input covering each
//! remaining tuple is copied to the output directory. This is the batch tier
//! behind `corpus --op afl-cmin`, next to the per-input `afl-showmap`
//! fingerprinting of [`crate::showmap`]: one sandboxed command instead of one
//! container spawn per input.
//!
//! Pinned interface (the sandbox image's Ubuntu `afl++` 4.09c-1ubuntu3
//! package, `/usr/bin/afl-cmin`):
//!
//! ```text
//! afl-cmin [ options ] -- /path/to/target_app [ ... ]
//!   -i dir   - input directory with starting corpus
//!   -o dir   - output directory for minimized files
//!   -T tasks - how many parallel tasks to run (default: 1, all=nproc)
//!   -m megs  - memory limit for child process (default: none)
//!   -t msec  - run time limit for child process (default: 5000)
//!   -A       - allow crashes and timeouts (not recommended)
//!   -C       - keep crashing inputs, reject everything else
//!   -e       - solve for edge coverage only, ignore hit counts
//! ```

use std::time::Duration;

use crate::afl::{build_target_args, AflInput};

/// Build the `afl-cmin` command that distills `input` into `output` in a
/// single invocation. All paths are container-internal; `timeout` is the
/// resolved per-input budget (the policy's `fuzzing.default_timeout_ms` for an
/// internal corpus operation), `tasks` the resolved sandbox CPU allocation.
///
/// Fixed choices, by contract:
///
/// - `-m none` always. Promoted harnesses are sanitizer builds (`ASan` by
///   default); any megabyte cap kills `ASan`'s shadow-memory reservation. The
///   script's own default is also `none`, and an explicit flag cannot be
///   silently re-defaulted.
/// - `-t` in exact milliseconds, the same granularity `afl-fuzz -t` takes.
/// - `-T` only above one CPU: afl-cmin 4.09c rejects `-T 1` (its "between 1
///   and nproc" check reads strictly greater than one), so a one-CPU
///   allocation keeps the sequential default path.
/// - Never `-A`/`-C`: the default drop of crash/timeout inputs is what keeps
///   an entry-crashing binary from tracing everything identically and
///   collapsing the distilled set toward one file; crash reproducers are
///   triage-owned and re-enter the corpus through `corpus absorb`.
/// - Never `-e`: hit-count-sensitive tuples match the bucket-sensitive
///   fingerprints [`crate::showmap::coverage_hash`] uses.
/// - The target argv is the shared file-input contract
///   ([`AflInput::FuzzerFile`], `<binary> @@`), the same form `afl-fuzz` and
///   `afl-tmin` take.
#[must_use]
pub fn build_cmin_args(
    input: &str,
    output: &str,
    timeout: Duration,
    tasks: u32,
    binary: &str,
) -> Vec<String> {
    let mut args = vec![
        "afl-cmin".to_owned(),
        "-i".to_owned(),
        input.to_owned(),
        "-o".to_owned(),
        output.to_owned(),
        "-m".to_owned(),
        "none".to_owned(),
        "-t".to_owned(),
        crate::timeout_millis(timeout).to_string(),
    ];
    if tasks > 1 {
        args.push("-T".to_owned());
        args.push(tasks.to_string());
    }
    args.push("--".to_owned());
    args.extend(build_target_args(binary, AflInput::FuzzerFile));
    args
}
