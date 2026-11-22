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

/// The line-by-line coverage of one target, rendered for hand-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageLineReport {
    /// An lcov tracefile with project-relative `SF:` paths.
    pub lcov: String,
    /// One self-contained HTML page: no script, no external resource.
    pub html: String,
    /// Files in the report.
    pub files: usize,
    /// Files left out because they exceeded a report bound.
    pub skipped_files: usize,
    pub lines_hit: usize,
    pub lines_total: usize,
}

/// Where the sandbox mounts the harness workspace; every staged source the
/// coverage build compiles is recorded under it.
const SANDBOX_WORKSPACE_PREFIX: &str = "/work/";

/// Source text shown for one file of a coverage report.
const MAX_REPORT_SOURCE_BYTES: u64 = 4 * 1024 * 1024;

/// The path a coverage report shows for a file `llvm-cov` recorded: relative
/// to the workspace (which mirrors the project layout) when it was staged
/// there, otherwise unchanged (a system header, for example).
pub(super) fn report_display_path(recorded: &str) -> String {
    recorded
        .strip_prefix(SANDBOX_WORKSPACE_PREFIX)
        .unwrap_or(recorded)
        .to_owned()
}

/// The staged text of a file `llvm-cov` recorded, read from the workspace the
/// measurement compiled. `None` when the path is not a workspace path, leaves
/// the workspace (a `..` component or a symlink), is not a regular file, or is
/// larger than the report shows.
pub(super) fn staged_report_source(workspace: &Path, recorded: &str) -> Option<String> {
    let relative = Path::new(recorded.strip_prefix(SANDBOX_WORKSPACE_PREFIX)?);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let path = workspace.join(relative);
    // The export comes from an untrusted binary: resolve the path and require
    // it to stay inside the workspace, so a staged symlink cannot make the
    // report read a host file.
    let resolved = path.canonicalize().ok()?;
    if !resolved.starts_with(workspace.canonicalize().ok()?) {
        return None;
    }
    let metadata = std::fs::metadata(&resolved).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_REPORT_SOURCE_BYTES {
        return None;
    }
    let bytes = std::fs::read(&resolved).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Parse `llvm-cov export` JSON, returning the names of functions with a
/// non-zero execution count (the covered set).
pub(super) fn parse_covered_functions(json: &str) -> Vec<String> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut covered: Vec<String> = value
        .get("data")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("functions").and_then(serde_json::Value::as_array))
        .flatten()
        .filter(|function| {
            function
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|count| count > 0)
        })
        .filter_map(|function| function.get("name").and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    covered.sort();
    covered.dedup();
    covered
}

#[cfg(test)]
mod coverage_tests {
    use super::{parse_covered_functions, report_display_path, staged_report_source};

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
    fn covered_functions_include_all_export_entries() {
        let json = r#"{"data":[
            {"functions":[{"name":"first","count":1}]},
            {"functions":[{"name":"second","count":2},{"name":"first","count":3}]}
        ]}"#;
        assert_eq!(parse_covered_functions(json), vec!["first", "second"]);
    }

    #[test]
    fn report_paths_are_workspace_relative() {
        assert_eq!(report_display_path("/work/src/parse.c"), "src/parse.c");
        assert_eq!(
            report_display_path("/usr/include/stdio.h"),
            "/usr/include/stdio.h"
        );
    }

    #[test]
    fn report_source_is_read_only_from_inside_the_workspace() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("ws");
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/parse.c"), "int x;\n").unwrap();
        std::fs::write(root.path().join("secret.txt"), "host secret").unwrap();

        assert_eq!(
            staged_report_source(&workspace, "/work/src/parse.c").as_deref(),
            Some("int x;\n")
        );
        // Not a workspace path, a parent escape, a directory, a missing file.
        assert_eq!(staged_report_source(&workspace, "/etc/hosts"), None);
        assert_eq!(
            staged_report_source(&workspace, "/work/../secret.txt"),
            None
        );
        assert_eq!(staged_report_source(&workspace, "/work/src"), None);
        assert_eq!(staged_report_source(&workspace, "/work/absent.c"), None);
        assert_eq!(staged_report_source(&workspace, "/work/"), None);
    }

    #[cfg(unix)]
    #[test]
    fn report_source_does_not_follow_a_symlink_out_of_the_workspace() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("ws");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(root.path().join("secret.txt"), "host secret").unwrap();
        std::os::unix::fs::symlink(root.path().join("secret.txt"), workspace.join("link.c"))
            .unwrap();
        assert_eq!(staged_report_source(&workspace, "/work/link.c"), None);
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
