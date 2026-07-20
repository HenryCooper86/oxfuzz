//! Parsing of CASR `.casrep` crash reports.
//!
//! CASR (`casr-san`/`casr-libfuzzer`/`casr-afl`) emits one JSON `.casrep` per
//! unique crash with an exploitability classification, crash location, and a
//! normalized stack trace. We extract the fields oxfuzz surfaces into
//! [`CasrReport`]; the report contains many more fields we ignore.

use hf_core::crash::{CasrReport, CrashKind, CrashSeverity};
use hf_core::engine::EngineKind;

/// Build the CASR triage command to run inside the sandbox over a crash dir.
///
/// `casr-afl` is used for AFL++ output trees; `casr-libfuzzer` for libFuzzer /
/// honggfuzz and everything else (their harnesses share the libFuzzer file-arg
/// ABI). Both reproduce each crash, classify severity, and cluster/deduplicate,
/// writing `.casrep` reports under `out_dir`. Paths are container paths.
///
/// Note the input expectations differ: `casr-afl` needs the AFL *output tree*
/// (`<instance>/crashes/...`) and reads the target from `--`, so it gets
/// `--ignore-cmdline`; `casr-libfuzzer` takes a flat directory of crash inputs.
#[must_use]
pub fn casr_command(
    engine: EngineKind,
    bin: &str,
    crash_dir: &str,
    out_dir: &str,
    timeout_secs: u64,
) -> Vec<String> {
    match engine {
        EngineKind::AflPlusPlus => vec![
            "casr-afl".to_owned(),
            "--ignore-cmdline".to_owned(),
            "-i".to_owned(),
            crash_dir.to_owned(),
            "-o".to_owned(),
            out_dir.to_owned(),
            "--".to_owned(),
            bin.to_owned(),
            "@@".to_owned(),
        ],
        _ => vec![
            "casr-libfuzzer".to_owned(),
            "-t".to_owned(),
            timeout_secs.to_string(),
            "-i".to_owned(),
            crash_dir.to_owned(),
            "-o".to_owned(),
            out_dir.to_owned(),
            "--".to_owned(),
            bin.to_owned(),
        ],
    }
}

/// Derive a CASR cluster id from a `.casrep` path.
///
/// `casr-libfuzzer`/`casr-afl` group equivalent crashes into `cl<N>`
/// subdirectories. We read the cluster id from any `cl<digits>` path component,
/// so crashes CASR considers the same bug share a cluster id. Returns `None`
/// when the report was not clustered (e.g. a single crash, or CASR ran without
/// clustering) -- callers then fall back to stack-signature dedup.
#[must_use]
pub fn cluster_from_path(path: &std::path::Path) -> Option<u32> {
    path.components().rev().find_map(|c| {
        let name = c.as_os_str().to_str()?;
        let digits = name.strip_prefix("cl")?;
        if digits.is_empty() {
            return None;
        }
        digits.parse::<u32>().ok()
    })
}

/// Infer oxfuzz's [`CrashKind`] from a CASR short description.
#[must_use]
pub fn kind_from_short(short: &str) -> CrashKind {
    let s = short.to_ascii_lowercase();
    if s.contains("overflow")
        || s.contains("use-after")
        || s.contains("asan")
        || s.contains("sanitizer")
    {
        CrashKind::Asan
    } else if s.contains("undefined") || s.contains("ubsan") {
        CrashKind::Ubsan
    } else if s.contains("segv") || s.contains("segmentation") || s.contains("access-violation") {
        CrashKind::Segv
    } else if s.contains("abort") || s.contains("assert") {
        CrashKind::Abort
    } else {
        CrashKind::Other
    }
}

/// The subset of the `.casrep` JSON we consume.
#[derive(serde::Deserialize)]
struct RawCasrep {
    #[serde(rename = "CrashSeverity")]
    crash_severity: Option<RawSeverity>,
    #[serde(rename = "CrashLine")]
    crash_line: Option<String>,
    #[serde(rename = "Stacktrace")]
    stacktrace: Option<Vec<String>>,
}

#[derive(serde::Deserialize)]
struct RawSeverity {
    #[serde(rename = "Type")]
    severity: Option<String>,
    #[serde(rename = "ShortDescription")]
    short_description: Option<String>,
}

/// Map a CASR severity `Type` string to [`CrashSeverity`].
#[must_use]
pub fn severity_from_str(s: &str) -> CrashSeverity {
    match s {
        "EXPLOITABLE" => CrashSeverity::Exploitable,
        "PROBABLY_EXPLOITABLE" => CrashSeverity::ProbablyExploitable,
        "NOT_EXPLOITABLE" => CrashSeverity::NotExploitable,
        _ => CrashSeverity::Undefined,
    }
}

/// Parse a CASR `.casrep` JSON document into a [`CasrReport`].
///
/// Missing fields degrade gracefully (empty strings / `Undefined`); only
/// malformed JSON is an error.
///
/// # Errors
/// Returns the `serde_json` error if `json` is not valid JSON.
pub fn parse_casrep(json: &str) -> Result<CasrReport, serde_json::Error> {
    let raw: RawCasrep = serde_json::from_str(json)?;
    let severity_obj = raw.crash_severity;
    Ok(CasrReport {
        severity: severity_obj
            .as_ref()
            .and_then(|s| s.severity.as_deref())
            .map_or(CrashSeverity::Undefined, severity_from_str),
        severity_short: severity_obj
            .and_then(|s| s.short_description)
            .unwrap_or_default(),
        crashline: raw.crash_line.unwrap_or_default(),
        stack: raw.stacktrace.unwrap_or_default(),
        cluster: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A trimmed but realistic casr-san report for a heap overflow.
    const SAMPLE: &str = r##"{
        "ExecutablePath": "/work/fuzz_copy_chunk",
        "ProcCmdline": "/work/fuzz_copy_chunk crash-abc",
        "CrashSeverity": {
            "Type": "PROBABLY_EXPLOITABLE",
            "ShortDescription": "heap-buffer-overflow(write)",
            "Description": "Heap buffer overflow",
            "Explanation": ""
        },
        "CrashLine": "chunk.c:20:5",
        "Stacktrace": [
            "#0 0x4ff in copy_chunk chunk.c:20:5",
            "#1 0x5aa in LLVMFuzzerTestOneInput harness.c:10:5"
        ],
        "Source": ["  18 |", "  19 |", "  20 |    memcpy(buf, data + 1, n);"]
    }"##;

    #[test]
    fn parses_severity_line_and_stack() {
        let r = parse_casrep(SAMPLE).unwrap();
        assert_eq!(r.severity, CrashSeverity::ProbablyExploitable);
        assert_eq!(r.severity_short, "heap-buffer-overflow(write)");
        assert_eq!(r.crashline, "chunk.c:20:5");
        assert_eq!(r.stack.len(), 2);
        assert!(r.stack[0].contains("copy_chunk"));
    }

    #[test]
    fn missing_fields_degrade_to_undefined() {
        let r = parse_casrep("{}").unwrap();
        assert_eq!(r.severity, CrashSeverity::Undefined);
        assert!(r.severity_short.is_empty());
        assert!(r.stack.is_empty());
    }

    #[test]
    fn libfuzzer_and_afl_commands_differ() {
        let lf = casr_command(
            EngineKind::LibFuzzer,
            "/work/fuzz_t",
            "/work/out",
            "/work/casr",
            30,
        );
        assert_eq!(lf[0], "casr-libfuzzer");
        assert!(lf.contains(&"/work/fuzz_t".to_owned()) && lf.contains(&"30".to_owned()));
        assert!(lf.ends_with(&["--".to_owned(), "/work/fuzz_t".to_owned()]));

        let hf = casr_command(
            EngineKind::Honggfuzz,
            "/work/fuzz_t",
            "/work/out",
            "/work/casr",
            30,
        );
        assert_eq!(hf[0], "casr-libfuzzer");

        let afl = casr_command(
            EngineKind::AflPlusPlus,
            "/work/fuzz_t",
            "/work/out",
            "/work/casr",
            30,
        );
        assert_eq!(afl[0], "casr-afl");
        assert!(afl.contains(&"--ignore-cmdline".to_owned()));
        assert_eq!(afl.last().unwrap(), "@@");
    }

    #[test]
    fn cluster_id_from_casrep_path() {
        use std::path::Path;
        assert_eq!(
            cluster_from_path(Path::new("/work/casr_out/cl3/crash-abc.casrep")),
            Some(3)
        );
        assert_eq!(
            cluster_from_path(Path::new("/work/casr_out/cl12/x.casrep")),
            Some(12)
        );
        // No cluster directory -> None (falls back to signature dedup).
        assert_eq!(
            cluster_from_path(Path::new("/work/casr_out/crash-abc.casrep")),
            None
        );
        // A 'class' dir must not be mistaken for a cluster.
        assert_eq!(cluster_from_path(Path::new("/work/classes/x.casrep")), None);
    }

    #[test]
    fn kind_inference_from_short() {
        assert_eq!(
            kind_from_short("heap-buffer-overflow(write)"),
            CrashKind::Asan
        );
        assert_eq!(kind_from_short("SEGV on unknown address"), CrashKind::Segv);
        assert_eq!(kind_from_short("abort"), CrashKind::Abort);
        assert_eq!(kind_from_short("something else"), CrashKind::Other);
    }

    #[test]
    fn maps_all_severity_strings() {
        assert_eq!(severity_from_str("EXPLOITABLE"), CrashSeverity::Exploitable);
        assert_eq!(
            severity_from_str("NOT_EXPLOITABLE"),
            CrashSeverity::NotExploitable
        );
        assert_eq!(severity_from_str("UNDEFINED"), CrashSeverity::Undefined);
        assert_eq!(severity_from_str("garbage"), CrashSeverity::Undefined);
    }
}
