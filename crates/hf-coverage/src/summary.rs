//! Line/region coverage summaries parsed from `llvm-cov export`.
//!
//! Where [`crate::CoverageTracker`] follows aggregate edge deltas over time,
//! this module captures a point-in-time structural picture of how much of the
//! target the corpus exercises: lines, functions, and regions covered out of
//! the total. It parses the `totals` block of an `llvm-cov export` JSON
//! document, which is the same export the function-name coverage overlay
//! already produces.

use serde::Deserialize;

/// Structural coverage totals for a target at a point in time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct CoverageSummary {
    pub lines_covered: u64,
    pub lines_total: u64,
    pub functions_covered: u64,
    pub functions_total: u64,
    pub regions_covered: u64,
    pub regions_total: u64,
}

impl CoverageSummary {
    /// Percentage of lines covered (0.0 when there are no lines).
    #[must_use]
    pub fn line_percent(&self) -> f64 {
        percent(self.lines_covered, self.lines_total)
    }

    /// Percentage of functions covered (0.0 when there are no functions).
    #[must_use]
    pub fn function_percent(&self) -> f64 {
        percent(self.functions_covered, self.functions_total)
    }

    /// Percentage of regions covered (0.0 when there are no regions).
    #[must_use]
    pub fn region_percent(&self) -> f64 {
        percent(self.regions_covered, self.regions_total)
    }
}

fn percent(covered: u64, total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (covered as f64 / total as f64) * 100.0
}

// -- llvm-cov export JSON shape (only the fields we read) --------------------

#[derive(Deserialize)]
struct Export {
    data: Vec<DataEntry>,
}

#[derive(Deserialize)]
struct DataEntry {
    totals: Totals,
}

#[derive(Deserialize)]
struct Totals {
    lines: Metric,
    functions: Metric,
    regions: Metric,
}

#[derive(Deserialize)]
struct Metric {
    count: u64,
    covered: u64,
}

impl Metric {
    fn accumulate(&self, covered: &mut u64, total: &mut u64) -> Option<()> {
        if self.covered > self.count {
            return None;
        }
        *covered = covered.checked_add(self.covered)?;
        *total = total.checked_add(self.count)?;
        Some(())
    }
}

/// Parse and combine the `totals` blocks of an `llvm-cov export` JSON document.
///
/// Returns `None` for malformed input, no data entries, covered counts larger
/// than their totals, or totals that overflow the report's counters.
#[must_use]
pub fn parse_llvm_cov_summary(json: &str) -> Option<CoverageSummary> {
    // Malformed export JSON means that structural coverage is unavailable.
    let export: Export = serde_json::from_str(json).ok()?;
    if export.data.is_empty() {
        return None;
    }
    let mut summary = CoverageSummary::default();
    for entry in export.data {
        entry
            .totals
            .lines
            .accumulate(&mut summary.lines_covered, &mut summary.lines_total)?;
        entry
            .totals
            .functions
            .accumulate(&mut summary.functions_covered, &mut summary.functions_total)?;
        entry
            .totals
            .regions
            .accumulate(&mut summary.regions_covered, &mut summary.regions_total)?;
    }
    Some(summary)
}

// -- Uncovered frontier ------------------------------------------------------

/// A single uncovered code location the corpus has not yet exercised: the
/// "frontier" a refined harness should try to reach. Extracted from the
/// per-function region table of an `llvm-cov export` document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UncoveredRegion {
    /// The function the uncovered region belongs to.
    pub function: String,
    /// Source file (as llvm-cov recorded it) containing the region.
    pub file: String,
    /// 1-based start line of the uncovered region.
    pub line: u32,
    /// 1-based start column of the uncovered region.
    pub col: u32,
}

/// Maximum frontier locations returned, so a large binary cannot flood the
/// refine prompt (and its token budget) with thousands of regions.
const MAX_UNCOVERED_REGIONS: usize = 100;

/// llvm-cov region kind for an ordinary executable code region. Expansion (1),
/// skipped (2), gap (3), and branch (4+) regions are not plain uncovered code
/// and would add noise, so only kind 0 is treated as frontier.
const REGION_KIND_CODE: u64 = 0;

// A function entry carries its own `filenames` table; each region's `file_id`
// indexes into it. Region layout:
// [line_start, col_start, line_end, col_end, exec_count, file_id,
//  expanded_file_id, kind].
#[derive(Deserialize)]
struct ExportFunctions {
    data: Vec<DataEntryFunctions>,
}

#[derive(Deserialize)]
struct DataEntryFunctions {
    #[serde(default)]
    functions: Vec<FunctionEntry>,
}

#[derive(Deserialize)]
struct FunctionEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    filenames: Vec<String>,
    #[serde(default)]
    regions: Vec<Vec<u64>>,
}

/// Extract the uncovered frontier from an `llvm-cov export` JSON document: the
/// code regions (kind 0) with an execution count of zero, each mapped back to
/// its function and source location.
///
/// This is the dynamic dual of [`parse_llvm_cov_summary`]: where that reports
/// aggregate percentages, this points at the concrete `file:line` locations a
/// refined harness should aim to reach. Results are deduplicated to the first
/// location per `(function, file, line)` and capped at `MAX_UNCOVERED_REGIONS`.
/// Invalid source locations are omitted. Returns an empty vector for non-coverage input.
#[must_use]
pub fn parse_llvm_cov_uncovered(json: &str) -> Vec<UncoveredRegion> {
    let Ok(export) = serde_json::from_str::<ExportFunctions>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for func in export.data.into_iter().flat_map(|entry| entry.functions) {
        for region in &func.regions {
            if region.len() < 8 {
                continue;
            }
            let (exec_count, kind) = (region[4], region[7]);
            if exec_count != 0 || kind != REGION_KIND_CODE {
                continue;
            }
            let (Ok(line), Ok(col), Ok(file_id)) = (
                u32::try_from(region[0]),
                u32::try_from(region[1]),
                usize::try_from(region[5]),
            ) else {
                continue;
            };
            let Some(file) = func.filenames.get(file_id) else {
                continue;
            };
            if line == 0 || col == 0 || file.is_empty() {
                continue;
            }
            let file = file.clone();
            if seen.insert((func.name.clone(), file.clone(), line)) {
                out.push(UncoveredRegion {
                    function: func.name.clone(),
                    file,
                    line,
                    col,
                });
                if out.len() >= MAX_UNCOVERED_REGIONS {
                    return out;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPORT: &str = r#"{
      "data": [{
        "totals": {
          "lines": {"count": 10, "covered": 6},
          "functions": {"count": 3, "covered": 2},
          "regions": {"count": 8, "covered": 5}
        },
        "functions": [
          {"name": "covered_fn", "count": 5, "filenames": ["/work/parser.c"],
           "regions": [[10,1,12,2,5,0,0,0]]},
          {"name": "uncovered_fn", "count": 0, "filenames": ["/work/parser.c"],
           "regions": [[20,1,25,2,0,0,0,0]]},
          {"name": "partial_fn", "count": 3, "filenames": ["/work/parser.c"],
           "regions": [[30,1,31,2,3,0,0,0],[32,3,33,4,0,0,0,0]]},
          {"name": "skipped_fn", "count": 0, "filenames": ["/work/parser.c"],
           "regions": [[40,1,45,2,0,0,0,2]]}
        ]
      }],
      "type": "llvm.coverage.json.export",
      "version": "2.0.1"
    }"#;

    #[test]
    fn extracts_uncovered_code_regions_with_locations() {
        let frontier = parse_llvm_cov_uncovered(EXPORT);
        assert_eq!(
            frontier,
            vec![
                UncoveredRegion {
                    function: "uncovered_fn".to_owned(),
                    file: "/work/parser.c".to_owned(),
                    line: 20,
                    col: 1,
                },
                UncoveredRegion {
                    // The unexecuted region of a partially-covered function is
                    // still frontier.
                    function: "partial_fn".to_owned(),
                    file: "/work/parser.c".to_owned(),
                    line: 32,
                    col: 3,
                },
            ],
            "only zero-count code regions are frontier; covered and skipped regions are excluded"
        );
    }

    #[test]
    fn non_coverage_input_yields_empty_frontier() {
        assert!(parse_llvm_cov_uncovered("{}").is_empty());
        assert!(parse_llvm_cov_uncovered("not json").is_empty());
    }

    #[test]
    fn totals_parse_is_unaffected_by_functions() {
        let summary = parse_llvm_cov_summary(EXPORT).expect("totals must still parse");
        assert_eq!(summary.functions_covered, 2);
        assert_eq!(summary.functions_total, 3);
    }
}
