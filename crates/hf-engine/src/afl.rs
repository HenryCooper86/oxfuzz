//! AFL++ engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use std::io::Read;
use std::path::{Path, PathBuf};

use hf_core::engine::FuzzRunConfig;
use hf_core::error::ClassifiedError;

/// Maximum accepted size of one run-owned AFL++ `fuzzer_stats` snapshot.
pub const MAX_FUZZER_STATS_BYTES: usize = 64 * 1024;

const AFL_INPUT_PLACEHOLDER: &str = "@@";
/// The per-instance statistics snapshot filename in an AFL++ output tree; the
/// service's resume-staging donor check keys on it too.
pub const AFL_FUZZER_STATS_FILE: &str = "fuzzer_stats";

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
///
/// Session resume is deliberately not an argv concern: the runner injects
/// `AFL_AUTORESUME=1` when `cfg.resume` is set, and the service stages the
/// continued output tree; the argv stays identical to a cold start. The AFL++
/// in-place resume flag (`-i -`, either token form) is owned by that typed
/// path and is rejected in `cfg.extra_args` in both resume states: without
/// `resume` it would be a hidden second resume source, and with it the flag
/// would duplicate this builder's own `-i`, which afl-fuzz refuses
/// ("Multiple -i options not supported").
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `cfg.extra_args` carries a
/// hand-passed `-i -` / `-i-`.
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    binary: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    reject_hand_passed_resume(&cfg.extra_args)?;
    if cfg.max_cpus > 1 {
        return Ok(build_parallel_run_args(cfg, binary, corpus, out));
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
    // The explicit per-input timeout follows `extra_args` so it wins under
    // afl-fuzz's last-occurrence-wins flag parsing. AFL++ takes exact
    // milliseconds; its auto-calculated default is deliberately not used --
    // practitioners pin the first knob on a new target explicitly.
    if let Some(timeout) = cfg.input_timeout {
        args.push("-t".to_owned());
        args.push(crate::timeout_millis(timeout).to_string());
    }
    // The binary and its AFL-substituted input file. Omitting `@@` selects
    // stdin and would disagree with replay/showmap/minimization.
    args.push("--".to_owned());
    args.extend(build_target_args(binary, AflInput::FuzzerFile));
    Ok(args)
}

/// Reject a hand-passed AFL++ in-place resume (`-i -` or `-i-`) in the escape
/// hatch. `FuzzRunConfig.resume` is the single source of resume truth; this is
/// the enforcement (Engineering Protocol 2.19), applied by every caller because
/// the builder itself refuses.
fn reject_hand_passed_resume(extra_args: &[String]) -> Result<(), ClassifiedError> {
    let mut previous_is_input_flag = false;
    for arg in extra_args {
        let resume = (previous_is_input_flag && arg == "-") || arg == "-i-";
        if resume {
            return Err(ClassifiedError::Validation(
                "extra_args must not carry the AFL++ in-place resume (`-i -`): session \
                 resume is owned by the typed run config (`FuzzRunConfig.resume`, CLI \
                 `--resume`), which stages the continued output tree and sets \
                 AFL_AUTORESUME"
                    .to_owned(),
            ));
        }
        previous_is_input_flag = arg == "-i";
    }
    Ok(())
}

/// Build the multi-instance coordinator command for an allocation above one.
///
/// AFL++ has no single-process multi-core mode: parallelism is N `afl-fuzz`
/// processes sharing one `-o` output tree. The sandbox executes one argv, so
/// the adapter emits a `bash -c` coordinator: the primary runs under `-M
/// main` with the recorded RNG seed, secondaries under `-S sK`, and every
/// instance reads the same staged corpus (each keeps its own queue under
/// the shared output tree; AFL++ syncs discoveries between instances) and
/// carries the time budget and dictionary. Session resume does not change
/// this script: with `FuzzRunConfig.resume` the service copies the most recent
/// compatible output tree into the run's staging and the runner sets
/// `AFL_AUTORESUME=1`, so every instance whose prior directory survived
/// resumes it in place (per `handle_existing_out_dir`, keyed on the instance's
/// `fuzzer_stats`) and any new `--cpus`-grown instance cold-starts from the
/// staged corpus. `-i -` cannot express that mix: it FATALs on an instance
/// whose directory is missing ("Resume attempted but old output directory not
/// found"). The TERM/INT trap forwards a cooperative
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
        // Same per-input timeout as the single-instance argv, per instance and
        // after `extra_args` so the explicit value wins.
        if let Some(timeout) = cfg.input_timeout {
            write!(line, " -t {}", crate::timeout_millis(timeout))
                .expect("String formatting is infallible");
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
/// starting. `Some(0)` is kept distinct from a missing key. Key spellings are
/// the ones `afl-fuzz` writes (`afl-fuzz-stats.c`); the classic-AFL aliases
/// `paths_total` and `unique_hangs` are accepted for the AFL++ keys
/// `corpus_count` and `saved_hangs`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AflFuzzerStats {
    pub execs_per_sec: Option<f64>,
    pub edges_found: Option<u64>,
    pub total_edges: Option<u64>,
    pub saved_crashes: Option<u64>,
    pub execs_done: Option<u64>,
    pub cycles_done: Option<u64>,
    pub corpus_count: Option<u64>,
    /// Bitmap stability percentage, stored without the `%` suffix.
    pub stability_pct: Option<f64>,
    pub saved_hangs: Option<u64>,
    pub start_time_epoch: Option<u64>,
    pub last_update_epoch: Option<u64>,
    /// AFL++ writes `last_find : 0` until the first find; the zero is
    /// normalized to `None` here so "no find yet" cannot masquerade as a
    /// 1970 timestamp.
    pub last_find_epoch: Option<u64>,
    pub run_time_secs: Option<u64>,
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
            "execs_done" => stats.execs_done = Some(parse_u64("execs_done", value)?),
            "cycles_done" => stats.cycles_done = Some(parse_u64("cycles_done", value)?),
            "corpus_count" | "paths_total" => {
                stats.corpus_count = Some(parse_u64("corpus_count", value)?);
            }
            "stability" => stats.stability_pct = Some(parse_pct("stability", value)?),
            "saved_hangs" | "unique_hangs" => {
                stats.saved_hangs = Some(parse_u64("saved_hangs", value)?);
            }
            "start_time" => stats.start_time_epoch = Some(parse_u64("start_time", value)?),
            "last_update" => stats.last_update_epoch = Some(parse_u64("last_update", value)?),
            "last_find" => {
                let epoch = parse_u64("last_find", value)?;
                stats.last_find_epoch = (epoch > 0).then_some(epoch);
            }
            "run_time" => stats.run_time_secs = Some(parse_u64("run_time", value)?),
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
/// run-wide: per-instance execution streams (`execs_per_sec`, `execs_done`,
/// `saved_crashes`, `saved_hangs`, `corpus_count`) are summed; the shared
/// coverage bitmap and progress markers (`edges_found`, `total_edges`,
/// `cycles_done`, `run_time`, `last_update`, `last_find`) take the most
/// advanced value; `stability` takes the least stable instance, which bounds
/// the run's stability claim; `start_time` takes the earliest instance. A
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
            execs_done: sum_optional_count(self.execs_done, next.execs_done),
            saved_hangs: sum_optional_count(self.saved_hangs, next.saved_hangs),
            corpus_count: sum_optional_count(self.corpus_count, next.corpus_count),
            edges_found: self.edges_found.max(next.edges_found),
            total_edges: self.total_edges.max(next.total_edges),
            cycles_done: self.cycles_done.max(next.cycles_done),
            run_time_secs: self.run_time_secs.max(next.run_time_secs),
            last_update_epoch: self.last_update_epoch.max(next.last_update_epoch),
            last_find_epoch: self.last_find_epoch.max(next.last_find_epoch),
            start_time_epoch: self.start_time_epoch.min(next.start_time_epoch),
            stability_pct: min_optional_rate(self.stability_pct, next.stability_pct),
        }
    }

    /// Project the snapshot onto the engine-neutral stats event.
    ///
    /// Derived values use only the snapshot's own timestamps, so the
    /// projection stays deterministic: the find age is `last_update` minus
    /// `last_find` (absent until the first find), and uptime is `run_time`,
    /// falling back to `last_update` minus `start_time` on snapshots flushed
    /// before `run_time` appears.
    #[must_use]
    pub fn to_engine_stats(&self) -> hf_core::engine::EngineStats {
        let elapsed = |later: Option<u64>, earlier: Option<u64>| match (later, earlier) {
            (Some(later), Some(earlier)) => Some(later.saturating_sub(earlier)),
            _ => None,
        };
        hf_core::engine::EngineStats {
            execs_total: self.execs_done,
            execs_per_sec: self.execs_per_sec,
            edges_covered: self.edges_found,
            cycles_done: self.cycles_done,
            corpus_count: self.corpus_count,
            stability_pct: self.stability_pct,
            hangs: self.saved_hangs,
            last_find_age_secs: elapsed(self.last_update_epoch, self.last_find_epoch),
            uptime_secs: self
                .run_time_secs
                .or_else(|| elapsed(self.last_update_epoch, self.start_time_epoch)),
        }
    }
}

fn min_optional_rate(current: Option<f64>, next: Option<f64>) -> Option<f64> {
    match (current, next) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
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

/// Parse an AFL++ percentage value (`96.50%`), stripped of its `%` suffix.
fn parse_pct(key: &'static str, value: &str) -> Result<f64, AflStatsError> {
    let number = value.strip_suffix('%').unwrap_or(value).trim();
    let parsed = number
        .parse::<f64>()
        .map_err(|_| invalid_value(key, value))?;
    if !parsed.is_finite() || parsed.is_sign_negative() {
        return Err(invalid_value(key, value));
    }
    Ok(parsed)
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
