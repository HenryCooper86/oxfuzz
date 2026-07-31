//! Coverage export caching and parsing.
//!
//! Recomputing a coverage export is expensive, so results are cached against a
//! signature of the workspace state that produced them. The parsing helpers
//! turn `llvm-cov export` JSON into the function lists the refine loop uses.

use std::path::Path;

use super::harness_workspace::read_current_harness_source;

/// Cache value: the signature the export was computed for + the raw
/// `llvm-cov export` JSON.
pub(super) type ExportCache = std::sync::Mutex<std::collections::HashMap<String, (u64, String)>>;

/// Process-global cache of raw `llvm-cov export` JSON, keyed by `project::target`
/// and tagged with the corpus+harness signature it was computed for. The
/// covered-set, summary, and frontier accessors all parse from this single
/// cached export, so the expensive (~180s) coverage pipeline runs at most once
/// per signature instead of once per accessor.
pub(super) fn export_cache() -> &'static ExportCache {
    static CACHE: std::sync::OnceLock<ExportCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Build the uncovered-frontier lines for the refine prompt: the target's
/// reachable functions that `llvm-cov` shows as unreached, each annotated with
/// its `file:line:col` location, deduplicated to the first location per
/// function. Falls back to the full frontier when none of the reachable names
/// match the frontier (e.g. llvm-cov name mangling on C++/Rust), so refinement
/// is never left blind while still carrying locations.
pub(super) fn frontier_refine_lines(
    reachable: &[String],
    frontier: &[hf_coverage::UncoveredRegion],
) -> Vec<String> {
    let format_region = |region: &hf_coverage::UncoveredRegion| {
        if region.file.is_empty() {
            region.function.clone()
        } else {
            format!(
                "{} ({}:{}:{})",
                region.function, region.file, region.line, region.col
            )
        }
    };
    let reachable_set: std::collections::HashSet<&str> =
        reachable.iter().map(String::as_str).collect();
    let mut seen = std::collections::HashSet::new();
    let targeted: Vec<String> = frontier
        .iter()
        .filter(|region| reachable_set.contains(region.function.as_str()))
        .filter(|region| seen.insert(region.function.clone()))
        .map(&format_region)
        .collect();
    if !targeted.is_empty() {
        return targeted;
    }
    let mut seen = std::collections::HashSet::new();
    frontier
        .iter()
        .filter(|region| seen.insert(region.function.clone()))
        .map(format_region)
        .collect()
}

/// A cheap fingerprint of the inputs that affect coverage: stable corpus file
/// metadata plus the canonical active harness source. Changes when a run grows
/// the corpus or a successful build commits a new harness, invalidating caches.
pub(super) fn coverage_signature(workspace: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::time::UNIX_EPOCH;

    let modified_nanos = |meta: &std::fs::Metadata| -> u128 {
        meta.modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos())
    };

    let mut corpus_metadata = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace.join("corpus")) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                corpus_metadata.push((entry.file_name(), meta.len(), modified_nanos(&meta)));
            }
        }
    }
    corpus_metadata.sort_by(|a, b| a.0.cmp(&b.0));

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    corpus_metadata.hash(&mut hasher);
    read_current_harness_source(workspace).hash(&mut hasher);
    hasher.finish()
}

/// Parse `llvm-cov export` JSON, returning the names of functions with a
/// non-zero execution count (the covered set).
pub(super) fn parse_covered_functions(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut covered: Vec<String> = value
        .get("data")
        .and_then(|d| d.get(0))
        .and_then(|d| d.get("functions"))
        .and_then(serde_json::Value::as_array)
        .map(|funcs| {
            funcs
                .iter()
                .filter(|f| {
                    f.get("count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                        > 0
                })
                .filter_map(|f| {
                    f.get("name")
                        .and_then(|n| n.as_str())
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    covered.sort();
    covered.dedup();
    covered
}

#[cfg(test)]
mod coverage_tests {
    use super::parse_covered_functions;

    #[test]
    fn parses_covered_functions_from_llvm_cov_json() {
        let json = r#"{"data":[{"functions":[
            {"name":"parse_entry","count":5},
            {"name":"validate","count":2},
            {"name":"never_called","count":0},
            {"name":"decode","count":3}
        ]}]}"#;
        let covered = parse_covered_functions(json);
        assert_eq!(covered, vec!["decode", "parse_entry", "validate"]);
        assert!(!covered.contains(&"never_called".to_owned()));
    }

    #[test]
    fn parse_handles_garbage() {
        assert!(parse_covered_functions("not json").is_empty());
        assert!(parse_covered_functions("{}").is_empty());
    }

    #[test]
    fn coverage_signature_changes_when_corpus_grows() {
        use super::coverage_signature;
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path();
        std::fs::write(ws.join("harness.c"), "x").unwrap();
        std::fs::create_dir_all(ws.join("corpus")).unwrap();
        std::fs::write(ws.join("corpus/a"), "1").unwrap();

        let sig1 = coverage_signature(ws);
        // Same inputs -> same signature (cache hit).
        assert_eq!(sig1, coverage_signature(ws));
        // A new corpus file -> different signature (cache invalidated).
        std::fs::write(ws.join("corpus/b"), "2").unwrap();
        assert_ne!(sig1, coverage_signature(ws));
    }

    fn region(function: &str, file: &str, line: u32) -> hf_coverage::UncoveredRegion {
        hf_coverage::UncoveredRegion {
            function: function.to_owned(),
            file: file.to_owned(),
            line,
            col: 1,
        }
    }

    #[test]
    fn frontier_refine_lines_targets_reachable_functions_with_locations() {
        use super::frontier_refine_lines;
        let reachable = vec!["parse_header".to_owned(), "decode_body".to_owned()];
        let frontier = vec![
            region("parse_header", "parser.c", 42),
            // A second region of the same function collapses to the first line.
            region("parse_header", "parser.c", 51),
            // Not reachable -> excluded when a reachable match exists.
            region("internal_helper", "util.c", 9),
        ];
        let lines = frontier_refine_lines(&reachable, &frontier);
        assert_eq!(lines, vec!["parse_header (parser.c:42:1)".to_owned()]);
    }

    #[test]
    fn frontier_refine_lines_falls_back_to_full_frontier_when_no_reachable_match() {
        use super::frontier_refine_lines;
        // llvm-cov names (mangled) do not intersect the scanner's plain names.
        let reachable = vec!["parse_header".to_owned()];
        let frontier = vec![
            region("_Z6mangledv", "parser.cc", 7),
            region("", "", 0), // empty file -> bare function name
        ];
        let lines = frontier_refine_lines(&reachable, &frontier);
        assert_eq!(
            lines,
            vec!["_Z6mangledv (parser.cc:7:1)".to_owned(), String::new()]
        );
    }
}
