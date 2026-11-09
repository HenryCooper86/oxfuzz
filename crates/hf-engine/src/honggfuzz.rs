//! honggfuzz engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use hf_core::engine::{EngineStats, FuzzRunConfig, HONGGFUZZ_STATS_FILE};
use hf_core::error::ClassifiedError;

/// Bounded container shared memory for honggfuzz's fixed-size feedback file.
pub const SHARED_MEMORY_MB: u32 = 192;
/// Per-file ceiling that admits the feedback file and limits scratch writes.
pub const SHARED_MEMORY_BYTES: u64 = SHARED_MEMORY_MB as u64 * 1024 * 1024;

const MAX_STATS_TAIL_BYTES: u64 = 4096;

/// Latest complete honggfuzz CSV row, including its engine timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct HonggfuzzStats {
    /// Unix timestamp of this observation, in seconds.
    pub observed_at: u64,
    /// Engine-reported metrics; CSV throughput is the whole-run average.
    pub stats: EngineStats,
}

/// Read the last complete CSV row without loading an unbounded statistics file.
/// Missing files and an unfinished first row yield no observation.
///
/// # Errors
/// Returns an I/O error for unsafe paths, malformed complete rows or read failures.
pub fn read_stats(output: &Path) -> std::io::Result<Option<HonggfuzzStats>> {
    let mut file = match open_stats(output) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "honggfuzz statistics must be a regular file",
        ));
    }
    let start = file.metadata()?.len().saturating_sub(MAX_STATS_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut tail = Vec::new();
    file.take(MAX_STATS_TAIL_BYTES).read_to_end(&mut tail)?;
    let mut rows = tail.split_inclusive(|byte| *byte == b'\n');
    if start > 0 {
        rows.next(); // The seek may have landed inside the oldest row.
    }
    let Some(row) = rows.rfind(|row| row.ends_with(b"\n") && !row.starts_with(b"#")) else {
        return Ok(None);
    };
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid honggfuzz statistics row",
        )
    };
    let text = std::str::from_utf8(row).map_err(|_| invalid())?;
    let values = text
        .split(',')
        .map(|value| value.trim().parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    let [observed_at, last_coverage, executions, average, _crashes, _unique, hangs, edges, _blocks] =
        values.as_slice()
    else {
        return Err(invalid());
    };
    Ok(Some(HonggfuzzStats {
        observed_at: *observed_at,
        stats: EngineStats {
            execs_total: Some(*executions),
            execs_per_sec: Some(*average as f64),
            edges_covered: Some(*edges),
            hangs: Some(*hangs),
            last_find_age_secs: Some(observed_at.saturating_sub(*last_coverage)),
            ..EngineStats::default()
        },
    }))
}

#[cfg(unix)]
fn open_stats(output: &Path) -> std::io::Result<std::fs::File> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let directory = open(
        output,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let file = openat(
        directory,
        HONGGFUZZ_STATS_FILE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Ok(file.into())
}

#[cfg(not(unix))]
fn open_stats(output: &Path) -> std::io::Result<std::fs::File> {
    let path = output.join(HONGGFUZZ_STATS_FILE);
    if !std::fs::symlink_metadata(output)?.is_dir() || !std::fs::symlink_metadata(&path)?.is_file()
    {
        return Err(std::io::Error::other(
            "honggfuzz statistics require a real directory and file",
        ));
    }
    std::fs::File::open(path)
}

/// Construct the `honggfuzz` argument list for a fuzz run.
///
/// honggfuzz has no user-specified RNG seed (its RNG is seeded from
/// arc4random//dev/urandom with no flag or env override), so a recorded
/// `cfg.seed` is deliberately not translated into an invented flag here.
///
/// # Errors
/// Currently infallible; the shared adapter signature is fallible because
/// other engines validate flag combinations (see AFL++'s resume rule).
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec!["honggfuzz".to_owned()];
    if duration > 0 {
        args.push(format!("--run_time={duration}"));
    }
    args.push("--threads".to_owned());
    args.push(cfg.max_cpus.to_string());
    args.push("--input".to_owned());
    args.push(corpus.to_owned());
    args.push("--output".to_owned());
    args.push(out.to_owned());
    // Runtime feedback uses bounded container shared memory. Crash artifacts
    // and the report stay in the run output so triage can retain them.
    args.push("--workspace".to_owned());
    args.push("/dev/shm".to_owned());
    args.push("--crashdir".to_owned());
    args.push(out.to_owned());
    args.push("--report".to_owned());
    args.push(format!("{out}/HONGGFUZZ.REPORT.TXT"));
    // `cfg.env` is deliberately absent from the argument list: both callers pass
    // the same map through `ResourceLimits.env`, which the sandbox renders onto
    // the container. An `env K=V` wrapper here would be a second home for one
    // meaning and would displace the fuzzer program from argv[0].
    args.extend(cfg.extra_args.iter().cloned());
    // Keep telemetry in the retained run output even when extra args name a
    // different statistics destination (honggfuzz uses the final occurrence).
    args.push("--statsfile".to_owned());
    args.push(format!("{out}/{HONGGFUZZ_STATS_FILE}"));
    // The explicit per-input timeout follows `extra_args` so it wins under
    // honggfuzz's last-occurrence-wins parsing (`case 't'` reassigns
    // `timing.tmOut`). honggfuzz takes whole seconds (its `-t`/`--timeout`
    // default is 1s in the pinned 2.6 release), so a sub-second budget rounds
    // up, never to 0.
    if let Some(timeout) = cfg.input_timeout {
        args.push(format!("--timeout={}", crate::timeout_secs_ceil(timeout)));
    }
    args.push("--".to_owned());
    args.push(binary.to_owned());
    Ok(args)
}

/// The honggfuzz engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Honggfuzz;
