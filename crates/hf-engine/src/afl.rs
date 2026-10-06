//! AFL++ engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use std::io::Read;
use std::path::{Path, PathBuf};

use hf_core::engine::FuzzRunConfig;

/// Maximum accepted size of one run-owned AFL++ `fuzzer_stats` snapshot.
pub const MAX_FUZZER_STATS_BYTES: usize = 64 * 1024;

const AFL_INPUT_PLACEHOLDER: &str = "@@";
const AFL_FUZZER_STATS_FILE: &str = "fuzzer_stats";

/// The one supported AFL++ harness input-delivery contract.
///
/// Generated harnesses expose `LLVMFuzzerTestOneInput` through AFL++'s
/// libFuzzer-compatible driver. Fuzzing/minimization therefore use AFL++'s
/// substituted file placeholder, while replay/showmap use an exact file path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AflInput<'a> {
    /// AFL++ replaces `@@` with its current input file.
    FuzzerFile,
    /// A concrete input file used for replay or coverage measurement.
    ConcreteFile(&'a str),
}

impl<'a> AflInput<'a> {
    fn argument(self) -> &'a str {
        match self {
            Self::FuzzerFile => AFL_INPUT_PLACEHOLDER,
            Self::ConcreteFile(path) => path,
        }
    }
}

/// Build the target portion shared by all AFL++ lifecycle commands.
#[must_use]
pub fn build_target_args(binary: &str, input: AflInput<'_>) -> Vec<String> {
    vec![binary.to_owned(), input.argument().to_owned()]
}

/// Build a direct AFL++ harness replay command.
#[must_use]
pub fn build_reproduction_args(binary: &str, input: &str) -> Vec<String> {
    build_target_args(binary, AflInput::ConcreteFile(input))
}

/// Construct the `afl-fuzz` argument list for a fuzz run.
///
/// Returns the full command tail: `["afl-fuzz", "-i", corpus, "-o", out, ...]`.
/// The caller (`EngineRunner`) wraps this in a `docker run` invocation.
/// An allocation of one keeps this single-instance argv; an allocation above
/// one returns a `bash -c` multi-instance coordinator command instead.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    if cfg.max_cpus > 1 {
        return build_parallel_run_args(cfg, binary, corpus, out);
    }
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
    // `afl-fuzz -s <seed>` pins the RNG seed (there is no AFL_SEED env var).
    if let Some(seed) = cfg.seed {
        args.push("-s".to_owned());
        args.push(seed.to_string());
    }
    // `cfg.env` is deliberately absent from the argument list: both callers pass
    // the same map through `ResourceLimits.env`, which the sandbox renders onto
    // the container. An `env K=V` wrapper here would be a second home for one
    // meaning and would displace the fuzzer program from argv[0].
    // Extra args (e.g. -dict=...).
    args.extend(cfg.extra_args.iter().cloned());
    // The binary and its AFL-substituted input file. Omitting `@@` selects
    // stdin and would disagree with replay/showmap/minimization.
    args.push("--".to_owned());
    args.extend(build_target_args(binary, AflInput::FuzzerFile));
    args
}

/// Build the multi-instance coordinator command for an allocation above one.
///
/// AFL++ has no single-process multi-core mode: parallelism is N `afl-fuzz`
/// processes sharing one `-o` output tree. The sandbox executes one argv, so
/// the adapter emits a `bash -c` coordinator: the primary runs under `-M
/// main` with the recorded RNG seed, secondaries under `-S sK`, and every
/// instance reads the same staged corpus (each keeps its own queue under
/// the shared output tree; AFL++ syncs discoveries between instances) and
/// carries the time budget and dictionary. The `-i -` resume form is
/// deliberately not used: staging always creates a fresh output tree, and a
/// secondary with `-i -` fails in AFL's output-directory setup because it
/// has no own queue to resume. The TERM/INT trap forwards a cooperative
/// Stop to all instances so AFL can flush `fuzzer_stats`; the coordinator
/// logs every worker's exit status and exits with the primary's status,
/// with the sandbox wall-clock cap as the hard backstop, exactly as for a
/// single instance. This is argv construction, not a new authority: the
/// coordinator runs inside the same sandboxed container with the same
/// resource limits.
fn build_parallel_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    corpus: &str,
    out: &str,
) -> Vec<String> {
    use std::fmt::Write as _;

    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let instance = |line: &mut String, role: &str, seed: Option<u64>| {
        write!(
            line,
            "afl-fuzz -i {} -o {}",
            shell_quote(corpus),
            shell_quote(out)
        )
        .expect("String formatting is infallible");
        if duration > 0 {
            write!(line, " -V {duration}").expect("String formatting is infallible");
        }
        if let Some(seed) = seed {
            write!(line, " -s {seed}").expect("String formatting is infallible");
        }
        write!(line, " {role}").expect("String formatting is infallible");
        for arg in &cfg.extra_args {
            write!(line, " {}", shell_quote(arg)).expect("String formatting is infallible");
        }
        write!(line, " -- {} @@ &", shell_quote(binary)).expect("String formatting is infallible");
    };

    let mut script = String::new();
    instance(&mut script, "-M main", cfg.seed);
    script.push_str("\nprimary=$!\n");
    for worker in 1..cfg.max_cpus {
        instance(&mut script, &format!("-S s{worker}"), None);
        script.push('\n');
    }
    script.push_str("trap 'kill -TERM $(jobs -p) 2>/dev/null' TERM INT\n");
    script.push_str(
        "wait \"$primary\"\nstatus=$?\n\
         for job in $(jobs -p); do\n\
         \x20   wait \"$job\"\n\
         \x20   echo \"afl-worker $job exited $?\"\n\
         done\n\
         exit \"$status\"\n",
    );
    vec!["bash".to_owned(), "-c".to_owned(), script]
}

/// Quote one word for the coordinator script. Container-internal paths and
/// engine flags are plain, but quoting unconditionally keeps a pathological
/// value from becoming shell syntax.
fn shell_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Exact terminal metrics parsed from one AFL++ `fuzzer_stats` snapshot.
///
/// Fields are optional because AFL++ may omit a metric while an instance is
/// starting. `Some(0)` is kept distinct from a missing key.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AflFuzzerStats {
    pub execs_per_sec: Option<f64>,
    pub edges_found: Option<u64>,
    pub total_edges: Option<u64>,
    pub saved_crashes: Option<u64>,
}

/// Failure to read or parse a run-owned AFL++ statistics snapshot.
#[derive(Debug, thiserror::Error)]
pub enum AflStatsError {
    #[error("cannot read AFL++ fuzzer_stats: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsafe AFL++ fuzzer_stats path: {0}")]
    UnsafePath(PathBuf),
    #[error("AFL++ fuzzer_stats exceeds {max} bytes ({actual} bytes)")]
    TooLarge { actual: u64, max: usize },
    #[error("AFL++ fuzzer_stats is not UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("invalid AFL++ fuzzer_stats value for {key}: {value}")]
    InvalidValue { key: &'static str, value: String },
}

/// Parse a bounded AFL++ `fuzzer_stats` snapshot.
///
/// Only exact, documented keys are accepted. Unknown fields are ignored, but
/// a malformed value for a recognized key rejects the snapshot so callers do
/// not mistake corrupt evidence for a real zero.
///
/// # Errors
/// Returns [`AflStatsError`] for oversized, non-UTF-8, or malformed input.
pub fn parse_fuzzer_stats(contents: &[u8]) -> Result<AflFuzzerStats, AflStatsError> {
    if contents.len() > MAX_FUZZER_STATS_BYTES {
        return Err(AflStatsError::TooLarge {
            actual: contents.len() as u64,
            max: MAX_FUZZER_STATS_BYTES,
        });
    }

    let text = std::str::from_utf8(contents)?;
    let mut stats = AflFuzzerStats::default();
    for line in text.lines() {
        let Some((key, raw_value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = raw_value.trim();
        match key {
            "execs_per_sec" => {
                let parsed = value
                    .parse::<f64>()
                    .map_err(|_| invalid_value("execs_per_sec", value))?;
                if !parsed.is_finite() || parsed.is_sign_negative() {
                    return Err(invalid_value("execs_per_sec", value));
                }
                stats.execs_per_sec = Some(parsed);
            }
            "edges_found" => stats.edges_found = Some(parse_u64("edges_found", value)?),
            "total_edges" => stats.total_edges = Some(parse_u64("total_edges", value)?),
            "saved_crashes" => {
                stats.saved_crashes = Some(parse_u64("saved_crashes", value)?);
            }
            _ => {}
        }
    }
    Ok(stats)
}

/// Read the run-wide AFL++ statistics from one run output root.
///
/// Every top-level instance directory (`<run_output>/<instance>/`, e.g.
/// `default` for a single-instance run or `main`/`s1`/... for a multi-worker
/// run) may hold one `fuzzer_stats` snapshot. Snapshots are aggregated
/// run-wide: throughput (`execs_per_sec`) and `saved_crashes` are
/// per-instance execution streams and are summed, while `edges_found` and
/// `total_edges` describe one shared coverage bitmap and are maximized. A
/// field is absent only when no instance reported it; an instance whose
/// snapshot has not flushed yet simply contributes nothing to the sums.
/// Output roots, instance directories, and snapshots must be real
/// directories/files rather than symlinks. A missing snapshot returns
/// `Ok(None)` because AFL++ may not have flushed it yet.
///
/// # Errors
/// Returns [`AflStatsError`] for I/O failures, unsafe paths, or invalid data.
pub fn read_fuzzer_stats(run_output: &Path) -> Result<Option<AflFuzzerStats>, AflStatsError> {
    require_real_directory(run_output)?;

    // Deterministic order so repeated reads of one output tree aggregate
    // identically (floating-point sums are order-sensitive).
    let mut instance_dirs: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(run_output)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            instance_dirs.push(entry.path());
        }
    }
    instance_dirs.sort();

    let mut aggregate: Option<AflFuzzerStats> = None;
    for instance in instance_dirs {
        // A symlinked instance directory is rejected rather than followed,
        // mirroring the snapshot rule below.
        if std::fs::symlink_metadata(&instance)?
            .file_type()
            .is_symlink()
        {
            return Err(AflStatsError::UnsafePath(instance));
        }
        let path = instance.join(AFL_FUZZER_STATS_FILE);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => metadata,
            Ok(_) => return Err(AflStatsError::UnsafePath(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.len() > MAX_FUZZER_STATS_BYTES as u64 {
            return Err(AflStatsError::TooLarge {
                actual: metadata.len(),
                max: MAX_FUZZER_STATS_BYTES,
            });
        }

        let mut contents = Vec::with_capacity(metadata.len() as usize);
        std::fs::File::open(&path)?
            .take((MAX_FUZZER_STATS_BYTES + 1) as u64)
            .read_to_end(&mut contents)?;
        let stats = parse_fuzzer_stats(&contents)?;
        aggregate = match aggregate {
            None => Some(stats),
            Some(current) => Some(current.merged_run_wide(&stats)),
        };
    }
    Ok(aggregate)
}

impl AflFuzzerStats {
    /// Merge one instance snapshot into the run-wide aggregate.
    fn merged_run_wide(&self, next: &Self) -> Self {
        Self {
            execs_per_sec: sum_optional_rate(self.execs_per_sec, next.execs_per_sec),
            saved_crashes: sum_optional_count(self.saved_crashes, next.saved_crashes),
            edges_found: self.edges_found.max(next.edges_found),
            total_edges: self.total_edges.max(next.total_edges),
        }
    }
}

fn sum_optional_rate(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a + b),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    }
}

fn sum_optional_count(current: Option<u64>, next: Option<u64>) -> Option<u64> {
    current.zip(next).map(|(a, b)| a + b).or(current).or(next)
}

fn require_real_directory(path: &Path) -> Result<(), AflStatsError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(AflStatsError::UnsafePath(path.to_path_buf())),
        Err(error) => Err(error.into()),
    }
}

fn parse_u64(key: &'static str, value: &str) -> Result<u64, AflStatsError> {
    value.parse().map_err(|_| invalid_value(key, value))
}

fn invalid_value(key: &'static str, value: &str) -> AflStatsError {
    AflStatsError::InvalidValue {
        key,
        value: value.to_owned(),
    }
}

/// The AFL++ engine adapter. See [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct AflPlusPlus;
