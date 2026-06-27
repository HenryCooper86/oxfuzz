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

/// Parse the `totals` block of an `llvm-cov export` JSON document.
///
/// Returns `None` if the input is not valid llvm-cov export JSON or carries no
/// data entry (e.g. an empty `{}` or a non-coverage document).
#[must_use]
pub fn parse_llvm_cov_summary(json: &str) -> Option<CoverageSummary> {
    let export: Export = serde_json::from_str(json).ok()?;
    let totals = export.data.into_iter().next()?.totals;
    Some(CoverageSummary {
        lines_covered: totals.lines.covered,
        lines_total: totals.lines.count,
        functions_covered: totals.functions.covered,
        functions_total: totals.functions.count,
        regions_covered: totals.regions.covered,
        regions_total: totals.regions.count,
    })
}
