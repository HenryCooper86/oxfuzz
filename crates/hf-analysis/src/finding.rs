//! The output type: one located static-analysis signal.

/// How strongly a rule contributes to a candidate's prioritization boost.
///
/// The weights are the ones the enrichment scoring already uses, so replacing
/// the producer does not change the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational signal.
    Info,
    /// Warning signal.
    Warning,
    /// Error signal.
    Error,
}

impl Severity {
    /// Per-distinct-rule boost contributed by this severity.
    #[must_use]
    pub const fn weight(self) -> f64 {
        match self {
            Self::Info => 0.01,
            Self::Warning => 0.05,
            Self::Error => 0.10,
        }
    }
}

/// A source range. Lines are one-based and columns zero-based, matching the
/// range shape the enrichment join already compares against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceSpan {
    /// One-based starting line.
    pub start_line: u32,
    /// Zero-based starting column.
    pub start_col: u32,
    /// One-based ending line.
    pub end_line: u32,
    /// Zero-based ending column.
    pub end_col: u32,
}

/// One rule match in one translation unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Stable oxfuzz rule identifier. Never an upstream `raptor-*` id: the
    /// rules are re-derived, so no correspondence is claimed.
    pub rule_id: &'static str,
    /// Primary CWE the rule was derived from.
    pub cwe: &'static str,
    /// Contribution weight class.
    pub severity: Severity,
    /// Where the match sits.
    pub span: SourceSpan,
}
