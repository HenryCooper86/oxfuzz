//! Parsing of CASR `.casrep` crash reports.
//!
//! CASR (`casr-san`/`casr-libfuzzer`/`casr-afl`) emits one JSON `.casrep` per
//! unique crash with an exploitability classification, crash location, and a
//! normalized stack trace. We extract the fields hobot surfaces into
//! [`CasrReport`]; the report contains many more fields we ignore.

use hf_core::crash::{CasrReport, CrashSeverity};

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
