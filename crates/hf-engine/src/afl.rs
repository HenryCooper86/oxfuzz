//! AFL++ engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use std::io::Read;
use std::path::{Path, PathBuf};

use hf_core::engine::FuzzRunConfig;

/// Maximum accepted size of one run-owned AFL++ `fuzzer_stats` snapshot.
pub const MAX_FUZZER_STATS_BYTES: usize = 64 * 1024;

const AFL_INPUT_PLACEHOLDER: &str = "@@";
const AFL_DEFAULT_INSTANCE: &str = "default";
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
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
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
    // Env vars as AFL_ prefixed options are set by the runtime; we pass them
    // as `--env` equivalents via the command environment. Here we emit them
    // as a leading `env` command so the docker exec applies them.
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    // Extra args (e.g. -dict=...).
    args.extend(cfg.extra_args.iter().cloned());
    // The binary and its AFL-substituted input file. Omitting `@@` selects
    // stdin and would disagree with replay/showmap/minimization.
    args.push("--".to_owned());
    args.extend(build_target_args(binary, AflInput::FuzzerFile));
    args
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

/// Read the exact default AFL++ instance statistics from one run output root.
///
/// The only accepted path is `<run_output>/default/fuzzer_stats`. The output
/// root, instance directory, and snapshot must be real directories/files rather
/// than symlinks. A missing snapshot returns `Ok(None)` because AFL++ may not
/// have flushed it yet.
///
/// # Errors
/// Returns [`AflStatsError`] for I/O failures, unsafe paths, or invalid data.
pub fn read_fuzzer_stats(run_output: &Path) -> Result<Option<AflFuzzerStats>, AflStatsError> {
    require_real_directory(run_output)?;
    let instance = run_output.join(AFL_DEFAULT_INSTANCE);
    match std::fs::symlink_metadata(&instance) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err(AflStatsError::UnsafePath(instance)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }

    let path = instance.join(AFL_FUZZER_STATS_FILE);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(AflStatsError::UnsafePath(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
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
    parse_fuzzer_stats(&contents).map(Some)
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
