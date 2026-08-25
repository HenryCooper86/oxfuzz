//! Pure domain logic for Change-Aware Pull-Request Fuzzing.
//!
//! Parses a unified diff, maps it to the discovered targets it affects, decides
//! whether two retained runs may be compared at all, classifies findings across
//! them, and computes coverage regression. Everything here is a pure function
//! over retained evidence: no filesystem, no storage, no execution.
//!
//! See `docs/design/change-aware-pr-fuzzing-design.md`.

use std::collections::BTreeSet;
use std::path::Path;

use hf_core::target::TargetCandidate;
use serde::Serialize;
use uuid::Uuid;

/// Largest diff accepted for parsing. A pull request above this size is
/// rejected rather than partially understood.
pub const MAX_DIFF_BYTES: usize = 4 * 1024 * 1024;

/// Exact image identity prefix written by proof-carrying runs. A mutable tag is
/// not proof-bearing and cannot anchor a comparison.
const EXACT_IMAGE_PREFIX: &str = "docker-image-id-sha256:";

/// Retention bound of a target's reachable set, from `hf-discovery`. A set at
/// this size may have been truncated, so absence from it proves nothing.
const REACHABLE_SET_BOUND: usize = 64;

/// An inclusive line span on the new side of a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

/// One file touched by a diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedFile {
    /// Path on the old side, or `None` for an added file.
    pub old_path: Option<String>,
    /// Path on the new side, or `None` for a deleted file.
    pub new_path: Option<String>,
    /// Added-line spans on the new side. Empty for deletions and binaries.
    pub ranges: Vec<LineRange>,
    /// Whether the diff reported this file as binary.
    pub binary: bool,
}

/// A parsed unified diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedDiff {
    pub files: Vec<ChangedFile>,
}

/// Why a diff could not be trusted. A partially understood diff would
/// under-report affected targets, so every failure is explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffRejection {
    /// The input exceeds [`MAX_DIFF_BYTES`].
    TooLarge,
    /// The input contains no unified-diff file or hunk headers.
    NotUnified,
    /// A hunk header did not match the unified-diff grammar.
    MalformedHunkHeader,
    /// A hunk body did not supply the line counts its header promised.
    HunkLengthMismatch,
}

/// How a change affects one discovered target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetImpact {
    /// The target's own definition overlaps a changed line range. Exact.
    Changed,
    /// The target reaches a changed function through the retained call graph.
    /// Approximate.
    ReachesChange,
    /// The evidence needed to decide is missing or bounded. Never a claim that
    /// the target is unaffected.
    Unknown,
}

/// One target classified against a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AffectedTarget {
    pub target_id: Uuid,
    pub symbol: String,
    pub impact: TargetImpact,
    /// Stable reason code for the classification.
    pub reason_code: String,
    /// Whether the classification rests on approximate evidence.
    pub approximate: bool,
}

/// The retained facts a run contributes to a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunComparisonInput {
    pub target_id: Uuid,
    pub engine: String,
    /// Whether the run reached a terminal `Done` campaign state.
    pub terminal: bool,
    pub source_rev: Option<String>,
    pub corpus_rev: Option<String>,
    pub sandbox_rev: Option<String>,
    pub edges: Option<u64>,
}

/// The first condition that made two runs incomparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparabilityRefusal {
    BaseNotTerminal,
    HeadNotTerminal,
    MissingRevision,
    SandboxNotExact,
    DifferentTarget,
    DifferentEngine,
    DifferentCorpus,
    DifferentSandbox,
    /// The source revisions match, so the pair measures no change.
    SameSourceRevision,
}

/// How a finding moved between the base and head runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingChange {
    Introduced,
    CarriedOver,
    Resolved,
    /// The base run retains no crash evidence, so it cannot establish absence.
    Unknown,
}

/// One finding classified across the two runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClassifiedFinding {
    pub stack_signature: String,
    pub change: FindingChange,
}

/// Coverage outcome between two comparable runs.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum CoverageComparison {
    /// One of the runs retains no peak-edge measurement.
    Unavailable,
    Stable {
        delta_pct: f64,
    },
    Regressed {
        delta_pct: f64,
    },
}

/// Parse a unified diff into changed files and new-side line ranges.
///
/// # Errors
/// Returns a [`DiffRejection`] when the input is oversized, is not a unified
/// diff, or contains a hunk that does not match its own header.
pub fn parse_unified_diff(text: &str) -> Result<ParsedDiff, DiffRejection> {
    if text.len() > MAX_DIFF_BYTES {
        return Err(DiffRejection::TooLarge);
    }
    let mut files: Vec<ChangedFile> = Vec::new();
    let mut current: Option<ChangedFile> = None;
    let mut saw_header = false;
    let mut lines = text.lines().peekable();

    while let Some(line) = lines.next() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            saw_header = true;
            if let Some(file) = current.take() {
                files.push(file);
            }
            let (old_path, new_path) = git_header_paths(rest);
            current = Some(ChangedFile {
                old_path,
                new_path,
                ranges: Vec::new(),
                binary: false,
            });
        } else if let Some(rest) = line.strip_prefix("--- ") {
            saw_header = true;
            let file = current.get_or_insert_with(blank_file);
            file.old_path = side_path(rest);
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            saw_header = true;
            let file = current.get_or_insert_with(blank_file);
            file.new_path = side_path(rest);
        } else if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            let file = current.get_or_insert_with(blank_file);
            file.binary = true;
        } else if line.starts_with("@@") {
            saw_header = true;
            let header = parse_hunk_header(line).ok_or(DiffRejection::MalformedHunkHeader)?;
            let file = current.get_or_insert_with(blank_file);
            let mut old_seen = 0u32;
            let mut new_seen = 0u32;
            let mut run: Option<LineRange> = None;
            while old_seen < header.old_count || new_seen < header.new_count {
                let Some(body) = lines.peek() else { break };
                let marker = body.chars().next();
                match marker {
                    Some('+') => {
                        let line_no = header.new_start + new_seen;
                        run = Some(match run {
                            Some(range) if range.end + 1 == line_no => LineRange {
                                start: range.start,
                                end: line_no,
                            },
                            Some(range) => {
                                file.ranges.push(range);
                                LineRange {
                                    start: line_no,
                                    end: line_no,
                                }
                            }
                            None => LineRange {
                                start: line_no,
                                end: line_no,
                            },
                        });
                        new_seen += 1;
                    }
                    Some('-') => old_seen += 1,
                    Some(' ') | None => {
                        old_seen += 1;
                        new_seen += 1;
                    }
                    // "\ No newline at end of file" annotates the previous line.
                    Some('\\') => {}
                    // Anything else ends the hunk body.
                    Some(_) => break,
                }
                lines.next();
            }
            if let Some(range) = run.take() {
                file.ranges.push(range);
            }
            if old_seen != header.old_count || new_seen != header.new_count {
                return Err(DiffRejection::HunkLengthMismatch);
            }
        }
    }
    if let Some(file) = current.take() {
        files.push(file);
    }
    if !saw_header {
        return Err(DiffRejection::NotUnified);
    }
    Ok(ParsedDiff { files })
}

/// Classify every discovered target against a parsed change.
///
/// Targets whose own definition overlaps a changed range are exact; targets
/// that only reach a changed function through the retained call graph are
/// approximate. Nothing is ever reported as unaffected.
#[must_use]
pub fn map_affected_targets(diff: &ParsedDiff, targets: &[TargetCandidate]) -> Vec<AffectedTarget> {
    let changed_symbols: BTreeSet<&str> = targets
        .iter()
        .filter(|target| definition_overlaps(diff, target))
        .map(|target| target.symbol.as_str())
        .collect();

    targets
        .iter()
        .map(|target| {
            if changed_symbols.contains(target.symbol.as_str()) {
                return AffectedTarget {
                    target_id: target.id,
                    symbol: target.symbol.clone(),
                    impact: TargetImpact::Changed,
                    reason_code: "definition_overlaps_change".to_owned(),
                    approximate: false,
                };
            }
            let reaches = target
                .reachable_functions
                .iter()
                .any(|name| changed_symbols.contains(name.as_str()));
            if reaches {
                return AffectedTarget {
                    target_id: target.id,
                    symbol: target.symbol.clone(),
                    impact: TargetImpact::ReachesChange,
                    reason_code: "reaches_changed_function".to_owned(),
                    approximate: true,
                };
            }
            let reason = if target.location.end_line.is_none() {
                "definition_range_unavailable"
            } else if target.reachable_functions.is_empty() {
                "no_retained_reachability"
            } else if target.reachable_functions.len() >= REACHABLE_SET_BOUND {
                "reachable_set_truncated"
            } else {
                "no_retained_path_to_change"
            };
            AffectedTarget {
                target_id: target.id,
                symbol: target.symbol.clone(),
                impact: TargetImpact::Unknown,
                reason_code: reason.to_owned(),
                approximate: true,
            }
        })
        .collect()
}

/// Decide whether two retained runs may anchor a pull-request comparison.
///
/// The coverage-baseline rules elsewhere require whole-context equality, which
/// a pull request breaks by definition. This compares the components instead
/// and requires the source revision to differ.
///
/// # Errors
/// Returns the first condition that failed.
pub fn check_comparability(
    base: &RunComparisonInput,
    head: &RunComparisonInput,
) -> Result<(), ComparabilityRefusal> {
    if !base.terminal {
        return Err(ComparabilityRefusal::BaseNotTerminal);
    }
    if !head.terminal {
        return Err(ComparabilityRefusal::HeadNotTerminal);
    }
    let (Some(base_source), Some(head_source)) = (&base.source_rev, &head.source_rev) else {
        return Err(ComparabilityRefusal::MissingRevision);
    };
    let (Some(base_corpus), Some(head_corpus)) = (&base.corpus_rev, &head.corpus_rev) else {
        return Err(ComparabilityRefusal::MissingRevision);
    };
    let (Some(base_sandbox), Some(head_sandbox)) = (&base.sandbox_rev, &head.sandbox_rev) else {
        return Err(ComparabilityRefusal::MissingRevision);
    };
    if !base_sandbox.starts_with(EXACT_IMAGE_PREFIX)
        || !head_sandbox.starts_with(EXACT_IMAGE_PREFIX)
    {
        return Err(ComparabilityRefusal::SandboxNotExact);
    }
    if base.target_id != head.target_id {
        return Err(ComparabilityRefusal::DifferentTarget);
    }
    if base.engine != head.engine {
        return Err(ComparabilityRefusal::DifferentEngine);
    }
    if base_corpus != head_corpus {
        return Err(ComparabilityRefusal::DifferentCorpus);
    }
    if base_sandbox != head_sandbox {
        return Err(ComparabilityRefusal::DifferentSandbox);
    }
    if base_source == head_source {
        return Err(ComparabilityRefusal::SameSourceRevision);
    }
    Ok(())
}

/// Classify findings across two runs by retained stack signature.
///
/// A base run with no retained crash evidence cannot establish absence, so its
/// head findings are `Unknown` rather than `Introduced`.
#[must_use]
pub fn classify_findings(base: &[String], head: &[String]) -> Vec<ClassifiedFinding> {
    if base.is_empty() {
        return head
            .iter()
            .map(|signature| ClassifiedFinding {
                stack_signature: signature.clone(),
                change: FindingChange::Unknown,
            })
            .collect();
    }
    let base_set: BTreeSet<&str> = base.iter().map(String::as_str).collect();
    let head_set: BTreeSet<&str> = head.iter().map(String::as_str).collect();
    let mut classified: Vec<ClassifiedFinding> = head
        .iter()
        .map(|signature| ClassifiedFinding {
            stack_signature: signature.clone(),
            change: if base_set.contains(signature.as_str()) {
                FindingChange::CarriedOver
            } else {
                FindingChange::Introduced
            },
        })
        .collect();
    classified.extend(
        base.iter()
            .filter(|signature| !head_set.contains(signature.as_str()))
            .map(|signature| ClassifiedFinding {
                stack_signature: signature.clone(),
                change: FindingChange::Resolved,
            }),
    );
    classified
}

/// Compare retained peak edges between two comparable runs.
///
/// Missing evidence is unavailable, never a zero delta.
#[must_use]
pub fn compare_coverage(
    base_edges: Option<u64>,
    head_edges: Option<u64>,
    regression_threshold_pct: f64,
) -> CoverageComparison {
    let (Some(base), Some(head)) = (base_edges, head_edges) else {
        return CoverageComparison::Unavailable;
    };
    if base == 0 {
        // No baseline to take a percentage against.
        return CoverageComparison::Unavailable;
    }
    // Scale before dividing so exact tenths stay exact.
    let delta_pct = ((head as f64 - base as f64) * 100.0) / base as f64;
    if delta_pct <= -regression_threshold_pct {
        CoverageComparison::Regressed { delta_pct }
    } else {
        CoverageComparison::Stable { delta_pct }
    }
}

fn blank_file() -> ChangedFile {
    ChangedFile {
        old_path: None,
        new_path: None,
        ranges: Vec::new(),
        binary: false,
    }
}

/// Split `a/<old> b/<new>` from a `diff --git` header.
fn git_header_paths(rest: &str) -> (Option<String>, Option<String>) {
    let Some(split) = rest.find(" b/") else {
        return (None, None);
    };
    let old = rest[..split].strip_prefix("a/").map(str::to_owned);
    let new = rest[split + " b/".len()..].to_owned();
    (old, Some(new))
}

/// Read one `---`/`+++` side path, dropping any trailing timestamp.
fn side_path(rest: &str) -> Option<String> {
    let path = rest.split('\t').next().unwrap_or(rest).trim_end();
    if path == "/dev/null" {
        return None;
    }
    Some(
        path.strip_prefix("a/")
            .or_else(|| path.strip_prefix("b/"))
            .unwrap_or(path)
            .to_owned(),
    )
}

struct HunkHeader {
    old_count: u32,
    new_start: u32,
    new_count: u32,
}

/// Parse `@@ -old[,count] +new[,count] @@`.
fn parse_hunk_header(line: &str) -> Option<HunkHeader> {
    let body = line.strip_prefix("@@")?;
    let end = body.find("@@")?;
    let mut parts = body[..end].split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    if parts.next().is_some() {
        return None;
    }
    let (_, old_count) = parse_span(old)?;
    let (new_start, new_count) = parse_span(new)?;
    Some(HunkHeader {
        old_count,
        new_start,
        new_count,
    })
}

/// Parse `start[,count]`, where an absent count means one line.
fn parse_span(span: &str) -> Option<(u32, u32)> {
    match span.split_once(',') {
        Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
        None => Some((span.parse().ok()?, 1)),
    }
}

/// Whether a target's persisted definition range overlaps a changed range in
/// the same file.
fn definition_overlaps(diff: &ParsedDiff, target: &TargetCandidate) -> bool {
    let Some(end_line) = target.location.end_line else {
        return false;
    };
    diff.files.iter().any(|file| {
        file.new_path.as_deref().is_some_and(|path| {
            path_matches(&target.location.file, path)
                && file
                    .ranges
                    .iter()
                    .any(|range| range.start <= end_line && target.location.line <= range.end)
        })
    })
}

/// Match a persisted absolute target path against a repository-relative diff
/// path by comparing trailing components.
fn path_matches(target_file: &Path, diff_path: &str) -> bool {
    let mut target_parts: Vec<_> = target_file.components().collect();
    let diff_parts: Vec<_> = Path::new(diff_path).components().collect();
    if diff_parts.is_empty() || diff_parts.len() > target_parts.len() {
        return false;
    }
    target_parts.drain(..target_parts.len() - diff_parts.len());
    target_parts == diff_parts
}
