//! Strict normalization for pinned-version Semgrep CE JSON output.

use std::collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use hf_core::target::{TargetCandidate, TargetInventory, TargetLanguage};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Maximum number of raw findings accepted from one Semgrep analysis.
pub const MAX_FINDINGS: usize = 50_000;
/// Maximum UTF-8 byte length accepted for a Semgrep rule identifier.
pub const MAX_RULE_ID_BYTES: usize = 512;
/// Maximum UTF-8 byte length accepted for a Semgrep finding message.
pub const MAX_MESSAGE_BYTES: usize = 4_096;

const SUPPORTED_VERSION: &str = "1.169.0";

/// Supported Semgrep severity levels in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemgrepSeverity {
    /// Informational static-analysis signal.
    Info,
    /// Warning static-analysis signal.
    Warning,
    /// Error static-analysis signal.
    Error,
}

impl SemgrepSeverity {
    fn parse(value: &str) -> Result<Self, SemgrepValidationError> {
        match value {
            "INFO" => Ok(Self::Info),
            "WARNING" => Ok(Self::Warning),
            "ERROR" => Ok(Self::Error),
            _ => Err(SemgrepValidationError::UnsafeFinding(String::from(
                "unsupported severity",
            ))),
        }
    }

    const fn canonical_name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    const fn nominal_weight(self) -> f64 {
        match self {
            Self::Info => 0.01,
            Self::Warning => 0.05,
            Self::Error => 0.10,
        }
    }

    const fn weight(self) -> f64 {
        self.nominal_weight()
    }
}

/// One positive, ordered Semgrep source range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemgrepRange {
    /// One-based starting line.
    pub start_line: u32,
    /// One-based starting column.
    pub start_col: u32,
    /// One-based ending line.
    pub end_line: u32,
    /// One-based ending column.
    pub end_col: u32,
}

impl SemgrepRange {
    fn from_raw(start: &RawPosition, end: &RawPosition) -> Result<Self, SemgrepValidationError> {
        if start.line == 0 || start.col == 0 || end.line == 0 || end.col == 0 {
            return Err(SemgrepValidationError::UnsafeFinding(String::from(
                "source coordinates must be positive",
            )));
        }
        if (end.line, end.col) < (start.line, start.col) {
            return Err(SemgrepValidationError::UnsafeFinding(String::from(
                "source range end precedes its start",
            )));
        }
        Ok(Self {
            start_line: start.line,
            start_col: start.col,
            end_line: end.line,
            end_col: end.col,
        })
    }
}

/// A bounded finding normalized for later candidate mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepFinding {
    /// Service-owned deterministic fingerprint of normalized content.
    pub fingerprint: String,
    /// Semgrep rule identifier.
    pub rule_id: String,
    /// Supported normalized severity.
    pub severity: SemgrepSeverity,
    /// Human-readable Semgrep rule message.
    pub message: String,
    /// Safe slash-normalized path relative to the staged source root.
    pub relative_path: PathBuf,
    /// Positive, ordered source range.
    pub range: SemgrepRange,
    /// Candidate mapping result, populated by the later mapping phase.
    pub matched_target_id: Option<Uuid>,
    /// Nominal score contribution for this severity.
    pub nominal_weight: f64,
}

/// Immutable-base score overlay derived from matched Semgrep rules.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepTargetScore {
    /// Stable target candidate identifier.
    pub target_id: Uuid,
    /// Candidate fit score observed in the input inventory.
    pub base_score: f64,
    /// Distinct-rule Semgrep boost, capped at `0.20`.
    pub boost: f64,
    /// Base plus boost, capped at `1.0`.
    pub effective_score: f64,
    /// Number of distinct matched rule identifiers.
    pub matched_rule_count: u32,
}

/// Normalized findings plus deterministic score overlays for one inventory.
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepAnalysis {
    /// All normalized findings, including unmatched and ambiguous findings.
    pub findings: Vec<SemgrepFinding>,
    /// One UUID-sorted score row for every candidate.
    pub scores: Vec<SemgrepTargetScore>,
    /// Number of candidates with at least one distinct matched rule.
    pub matched_candidate_count: u32,
}

/// Rejection reasons for incomplete, unsafe, or unsupported Semgrep output.
#[derive(Debug, thiserror::Error)]
pub enum SemgrepValidationError {
    /// The bytes are not the required Semgrep JSON shape.
    #[error("invalid Semgrep JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The output does not use the pinned Semgrep version.
    #[error("unsupported Semgrep output version: {0}")]
    UnsupportedVersion(String),
    /// Semgrep reported errors, skips, or incomplete scan evidence.
    #[error("Semgrep analysis is incomplete: {0}")]
    Incomplete(String),
    /// A bounded result, identifier, or message ceiling was exceeded.
    #[error("Semgrep result limit exceeded: {0}")]
    Limit(String),
    /// A finding contains an unsafe severity, path, or source range.
    #[error("unsafe Semgrep finding: {0}")]
    UnsafeFinding(String),
    /// Distinct normalized findings produced the same fingerprint.
    #[error("Semgrep finding fingerprint collision: {0}")]
    FingerprintCollision(String),
    /// The candidate inventory cannot safely support Semgrep enrichment.
    #[error("invalid Semgrep target inventory: {0}")]
    InvalidInventory(String),
}

#[derive(Deserialize)]
struct RawOutput {
    version: String,
    results: Vec<RawResult>,
    errors: Vec<serde_json::Value>,
    paths: RawPaths,
}

#[derive(Deserialize)]
struct RawResult {
    check_id: String,
    path: String,
    start: RawPosition,
    end: RawPosition,
    extra: RawExtra,
}

#[derive(Deserialize)]
struct RawPosition {
    line: u32,
    col: u32,
}

#[derive(Deserialize)]
struct RawExtra {
    message: String,
    severity: String,
}

#[derive(Deserialize)]
struct RawPaths {
    scanned: Vec<String>,
    skipped: Vec<serde_json::Value>,
}

/// Parses pinned Semgrep CE JSON and returns bounded, normalized findings.
///
/// The staged path manifest must contain safe, already-normalized relative paths.
pub fn parse_findings(
    bytes: &[u8],
    staged_paths: &BTreeSet<PathBuf>,
) -> Result<Vec<SemgrepFinding>, SemgrepValidationError> {
    parse_findings_with_fingerprint(bytes, staged_paths, fingerprint)
}

/// Maps normalized findings to uniquely containing C/C++ candidates and scores them.
pub fn map_and_score(
    inventory: &TargetInventory,
    mut findings: Vec<SemgrepFinding>,
) -> Result<SemgrepAnalysis, SemgrepValidationError> {
    validate_inventory(inventory)?;

    let mut rule_severities = BTreeMap::<(Uuid, String), SemgrepSeverity>::new();
    for finding in &mut findings {
        finding.matched_target_id = uniquely_containing_candidate(inventory, finding);
        if let Some(target_id) = finding.matched_target_id {
            rule_severities
                .entry((target_id, finding.rule_id.clone()))
                .and_modify(|severity| *severity = (*severity).max(finding.severity))
                .or_insert(finding.severity);
        }
    }

    let mut scores = inventory
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id,
                SemgrepTargetScore {
                    target_id: candidate.id,
                    base_score: candidate.fit_score,
                    boost: 0.0,
                    effective_score: candidate.fit_score,
                    matched_rule_count: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for ((target_id, _), severity) in rule_severities {
        let score = scores.get_mut(&target_id).ok_or_else(|| {
            invalid_inventory("mapped target is absent from the validated inventory")
        })?;
        score.boost += severity.weight();
        score.matched_rule_count += 1;
    }

    for score in scores.values_mut() {
        score.boost = ((score.boost.min(0.20) * 100.0).round()) / 100.0;
        score.effective_score = (score.base_score + score.boost).min(1.0);
    }

    let scores = scores.into_values().collect::<Vec<_>>();
    let matched_candidate_count = scores
        .iter()
        .filter(|score| score.matched_rule_count > 0)
        .count()
        .try_into()
        .map_err(|_| invalid_inventory("candidate count exceeds the supported u32 range"))?;

    Ok(SemgrepAnalysis {
        findings,
        scores,
        matched_candidate_count,
    })
}

fn validate_inventory(inventory: &TargetInventory) -> Result<(), SemgrepValidationError> {
    let mut candidate_ids = HashSet::with_capacity(inventory.candidates.len());
    for candidate in &inventory.candidates {
        if candidate.project_root != inventory.project_root {
            return Err(invalid_inventory("candidate project roots do not match"));
        }
        if !matches!(candidate.language, TargetLanguage::C | TargetLanguage::Cpp) {
            return Err(invalid_inventory(
                "only C and C++ candidates can be enriched",
            ));
        }
        if candidate.location.end_line.is_none() || candidate.location.end_col.is_none() {
            return Err(invalid_inventory("candidate source spans must be complete"));
        }
        if !candidate.fit_score.is_finite() || !(0.0..=1.0).contains(&candidate.fit_score) {
            return Err(invalid_inventory(
                "candidate base scores must be finite and between zero and one",
            ));
        }
        if !candidate_ids.insert(candidate.id) {
            return Err(invalid_inventory("candidate identifiers must be unique"));
        }
    }
    Ok(())
}

fn invalid_inventory(reason: &str) -> SemgrepValidationError {
    SemgrepValidationError::InvalidInventory(String::from(reason))
}

fn uniquely_containing_candidate(
    inventory: &TargetInventory,
    finding: &SemgrepFinding,
) -> Option<Uuid> {
    let mut matches = inventory.candidates.iter().filter(|candidate| {
        candidate_relative_path(candidate) == finding.relative_path
            && contains_start(candidate, finding)
    });
    let candidate_id = matches.next()?.id;
    matches.next().is_none().then_some(candidate_id)
}

fn candidate_relative_path(candidate: &TargetCandidate) -> &Path {
    candidate
        .location
        .file
        .strip_prefix(&candidate.project_root)
        .unwrap_or(&candidate.location.file)
}

fn contains_start(candidate: &TargetCandidate, finding: &SemgrepFinding) -> bool {
    let Some(end_line) = candidate.location.end_line else {
        return false;
    };
    let Some(end_col) = candidate.location.end_col else {
        return false;
    };
    let start = (candidate.location.line, candidate.location.col);
    let end = (end_line, end_col);
    let point = (finding.range.start_line, finding.range.start_col);
    start <= point && point <= end
}

fn parse_findings_with_fingerprint<F>(
    bytes: &[u8],
    staged_paths: &BTreeSet<PathBuf>,
    make_fingerprint: F,
) -> Result<Vec<SemgrepFinding>, SemgrepValidationError>
where
    F: Fn(&SemgrepFinding) -> String,
{
    let output: RawOutput = serde_json::from_slice(bytes)?;
    validate_output_header(&output)?;
    validate_scanned_manifest(&output.paths.scanned, staged_paths)?;

    let mut findings_by_fingerprint = HashMap::with_capacity(output.results.len());
    for raw in output.results {
        let finding = normalize_finding(raw, staged_paths, &make_fingerprint)?;
        match findings_by_fingerprint.entry(finding.fingerprint.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(finding);
            }
            Entry::Occupied(entry) if entry.get() == &finding => {}
            Entry::Occupied(entry) => {
                return Err(SemgrepValidationError::FingerprintCollision(
                    entry.key().clone(),
                ));
            }
        }
    }

    let mut findings: Vec<_> = findings_by_fingerprint.into_values().collect();
    findings.sort_by(|left, right| left.fingerprint.cmp(&right.fingerprint));
    Ok(findings)
}

fn validate_output_header(output: &RawOutput) -> Result<(), SemgrepValidationError> {
    if output.version != SUPPORTED_VERSION {
        return Err(SemgrepValidationError::UnsupportedVersion(
            output.version.clone(),
        ));
    }
    if output.results.len() > MAX_FINDINGS {
        return Err(SemgrepValidationError::Limit(format!(
            "{} findings exceeds the {MAX_FINDINGS} finding ceiling",
            output.results.len()
        )));
    }
    if !output.errors.is_empty() {
        return Err(SemgrepValidationError::Incomplete(format!(
            "Semgrep reported {} error entries",
            output.errors.len()
        )));
    }
    if !output.paths.skipped.is_empty() {
        return Err(SemgrepValidationError::Incomplete(format!(
            "Semgrep skipped {} paths",
            output.paths.skipped.len()
        )));
    }
    Ok(())
}

fn validate_scanned_manifest(
    scanned: &[String],
    staged_paths: &BTreeSet<PathBuf>,
) -> Result<(), SemgrepValidationError> {
    let normalized_scanned = scanned
        .iter()
        .map(|path| normalize_path(path))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if normalized_scanned != *staged_paths {
        return Err(SemgrepValidationError::Incomplete(String::from(
            "normalized scanned paths do not exactly match the staged manifest",
        )));
    }
    Ok(())
}

fn normalize_finding<F>(
    raw: RawResult,
    staged_paths: &BTreeSet<PathBuf>,
    make_fingerprint: &F,
) -> Result<SemgrepFinding, SemgrepValidationError>
where
    F: Fn(&SemgrepFinding) -> String,
{
    validate_field_limit("rule identifier", &raw.check_id, MAX_RULE_ID_BYTES)?;
    validate_field_limit("message", &raw.extra.message, MAX_MESSAGE_BYTES)?;

    let severity = SemgrepSeverity::parse(&raw.extra.severity)?;
    let relative_path = normalize_path(&raw.path)?;
    if !staged_paths.contains(&relative_path) {
        return Err(SemgrepValidationError::UnsafeFinding(String::from(
            "finding path is absent from the staged manifest",
        )));
    }
    let range = SemgrepRange::from_raw(&raw.start, &raw.end)?;
    let mut finding = SemgrepFinding {
        fingerprint: String::new(),
        rule_id: raw.check_id,
        severity,
        message: raw.extra.message,
        relative_path,
        range,
        matched_target_id: None,
        nominal_weight: severity.nominal_weight(),
    };
    finding.fingerprint = make_fingerprint(&finding);
    Ok(finding)
}

fn validate_field_limit(
    field: &str,
    value: &str,
    maximum: usize,
) -> Result<(), SemgrepValidationError> {
    if value.len() > maximum {
        return Err(SemgrepValidationError::Limit(format!(
            "{field} is {} bytes; maximum is {maximum}",
            value.len()
        )));
    }
    Ok(())
}

fn normalize_path(raw: &str) -> Result<PathBuf, SemgrepValidationError> {
    if raw.contains('\0') {
        return Err(unsafe_path());
    }

    let slash_normalized = raw.replace('\\', "/");
    let relative = slash_normalized
        .strip_prefix("./")
        .unwrap_or(&slash_normalized);
    let has_windows_prefix = relative.as_bytes().get(1) == Some(&b':')
        && relative
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic);
    if relative.starts_with('/') || has_windows_prefix {
        return Err(unsafe_path());
    }

    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(unsafe_path());
    }

    Ok(PathBuf::from(relative))
}

fn unsafe_path() -> SemgrepValidationError {
    SemgrepValidationError::UnsafeFinding(String::from("unsafe relative path"))
}

fn fingerprint(finding: &SemgrepFinding) -> String {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hash_field(&mut hasher, finding.rule_id.as_bytes());
    hash_field(&mut hasher, finding.severity.canonical_name().as_bytes());
    hash_field(
        &mut hasher,
        finding.relative_path.to_string_lossy().as_bytes(),
    );
    hasher.update(finding.range.start_line.to_be_bytes());
    hasher.update(finding.range.start_col.to_be_bytes());
    hasher.update(finding.range.end_line.to_be_bytes());
    hasher.update(finding.range.end_col.to_be_bytes());
    hash_field(&mut hasher, finding.message.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashMap};
    use std::path::{Path, PathBuf};

    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetInventory, TargetKind,
        TargetLanguage,
    };
    use uuid::Uuid;

    use super::{
        map_and_score, parse_findings, parse_findings_with_fingerprint, SemgrepFinding,
        SemgrepRange, SemgrepSeverity, SemgrepValidationError, MAX_FINDINGS, MAX_MESSAGE_BYTES,
        MAX_RULE_ID_BYTES,
    };

    const VALID: &[u8] = include_bytes!("../tests/fixtures/semgrep/valid.json");
    const UNKNOWN_SEVERITY: &[u8] =
        include_bytes!("../tests/fixtures/semgrep/unknown_severity.json");
    const SKIPPED: &[u8] = include_bytes!("../tests/fixtures/semgrep/skipped.json");
    const ERRORS: &[u8] = include_bytes!("../tests/fixtures/semgrep/errors.json");

    fn manifest(paths: &[&str]) -> BTreeSet<PathBuf> {
        paths.iter().map(PathBuf::from).collect()
    }

    fn one_result(
        check_id: &str,
        path: &str,
        start_line: u32,
        start_col: u32,
        end_line: u32,
        end_col: u32,
        message: &str,
        severity: &str,
        scanned: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "1.169.0",
            "results": [{
                "check_id": check_id,
                "path": path,
                "start": {"line": start_line, "col": start_col},
                "end": {"line": end_line, "col": end_col},
                "extra": {"message": message, "severity": severity}
            }],
            "errors": [],
            "paths": {"scanned": [scanned], "skipped": []}
        }))
        .expect("literal test document should serialize")
    }

    fn candidate(
        id: &str,
        project_root: &str,
        language: TargetLanguage,
        file: &str,
        span: (u32, u32, Option<u32>, Option<u32>),
        fit_score: f64,
    ) -> TargetCandidate {
        TargetCandidate {
            id: Uuid::parse_str(id).expect("literal candidate UUID should parse"),
            project_root: PathBuf::from(project_root),
            language,
            symbol: format!("target_{}", &id[..8]),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from(file),
                line: span.0,
                col: span.1,
                end_line: span.2,
                end_col: span.3,
            },
            signature: Some(String::from("int target(const uint8_t *data, size_t size)")),
            input_surface: InputSurface::Bytes,
            complexity: 4,
            fit_score,
            sanitizers: vec![Sanitizer::Address],
            rationale: String::from("literal test candidate"),
            reachable_functions: Vec::new(),
            accumulated_complexity: 4,
        }
    }

    fn inventory(project_root: &str, candidates: Vec<TargetCandidate>) -> TargetInventory {
        TargetInventory {
            project_root: PathBuf::from(project_root),
            candidates,
            call_graph: HashMap::new(),
        }
    }

    fn finding(
        fingerprint: &str,
        rule_id: &str,
        severity: SemgrepSeverity,
        path: &str,
        start_line: u32,
        start_col: u32,
    ) -> SemgrepFinding {
        let nominal_weight = match severity {
            SemgrepSeverity::Error => 0.10,
            SemgrepSeverity::Warning => 0.05,
            SemgrepSeverity::Info => 0.01,
        };
        SemgrepFinding {
            fingerprint: String::from(fingerprint),
            rule_id: String::from(rule_id),
            severity,
            message: String::from("literal normalized finding"),
            relative_path: PathBuf::from(path),
            range: SemgrepRange {
                start_line,
                start_col,
                end_line: start_line,
                end_col: start_col,
            },
            matched_target_id: None,
            nominal_weight,
        }
    }

    // Production break caught: using non-inclusive or non-unique span containment, or fuzzy paths.
    #[test]
    fn map_findings_requires_exact_path_and_one_inclusive_containing_span() {
        let parse_packet_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000020").expect("UUID should parse");
        let inventory = inventory(
            "/work/project",
            vec![
                candidate(
                    "00000000-0000-0000-0000-000000000020",
                    "/work/project",
                    TargetLanguage::C,
                    "/work/project/src/parser.c",
                    (10, 2, Some(20), Some(30)),
                    0.40,
                ),
                candidate(
                    "00000000-0000-0000-0000-000000000030",
                    "/work/project",
                    TargetLanguage::C,
                    "/work/project/src/parser.c",
                    (15, 1, Some(19), Some(40)),
                    0.30,
                ),
            ],
        );
        let findings = vec![
            finding(
                "unique",
                "rule.unique",
                SemgrepSeverity::Warning,
                "src/parser.c",
                12,
                4,
            ),
            finding(
                "file-level",
                "rule.file",
                SemgrepSeverity::Info,
                "src/parser.c",
                2,
                1,
            ),
            finding(
                "ambiguous",
                "rule.ambiguous",
                SemgrepSeverity::Error,
                "src/parser.c",
                18,
                3,
            ),
            finding(
                "wrong-path",
                "rule.path",
                SemgrepSeverity::Error,
                "src/parser.cc",
                12,
                4,
            ),
            finding(
                "at-start",
                "rule.start",
                SemgrepSeverity::Info,
                "src/parser.c",
                10,
                2,
            ),
            finding(
                "at-end",
                "rule.end",
                SemgrepSeverity::Info,
                "src/parser.c",
                20,
                30,
            ),
        ];

        let analysis =
            map_and_score(&inventory, findings).expect("complete C inventory should map");

        assert_eq!(
            analysis.findings[0].matched_target_id,
            Some(parse_packet_id)
        );
        assert_eq!(analysis.findings[1].matched_target_id, None);
        assert_eq!(analysis.findings[2].matched_target_id, None);
        assert_eq!(analysis.findings[3].matched_target_id, None);
        assert_eq!(
            analysis.findings[4].matched_target_id,
            Some(parse_packet_id)
        );
        assert_eq!(
            analysis.findings[5].matched_target_id,
            Some(parse_packet_id)
        );
        assert_eq!(analysis.matched_candidate_count, 1);
    }

    // Production break caught: allowing a non-C/C++ candidate into Semgrep containment.
    #[test]
    fn map_rejects_non_c_or_cpp_candidates() {
        let rust_candidate = candidate(
            "00000000-0000-0000-0000-000000000001",
            "/work/project",
            TargetLanguage::Rust,
            "/work/project/src/parser.rs",
            (1, 1, Some(5), Some(1)),
            0.50,
        );

        assert!(map_and_score(
            &inventory("/work/project", vec![rust_candidate]),
            Vec::new()
        )
        .is_err());
    }

    // Production break caught: mapping candidates from a root other than the inventory root.
    #[test]
    fn map_rejects_mixed_project_roots() {
        let foreign_candidate = candidate(
            "00000000-0000-0000-0000-000000000001",
            "/other/project",
            TargetLanguage::C,
            "/other/project/src/parser.c",
            (1, 1, Some(5), Some(1)),
            0.50,
        );

        assert!(map_and_score(
            &inventory("/work/project", vec![foreign_candidate]),
            Vec::new()
        )
        .is_err());
    }

    // Production break caught: treating a partly absent candidate end coordinate as complete.
    #[test]
    fn map_rejects_incomplete_candidate_spans() {
        for span in [(1, 1, None, Some(1)), (1, 1, Some(5), None)] {
            let incomplete_candidate = candidate(
                "00000000-0000-0000-0000-000000000001",
                "/work/project",
                TargetLanguage::C,
                "/work/project/src/parser.c",
                span,
                0.50,
            );

            assert!(map_and_score(
                &inventory("/work/project", vec![incomplete_candidate]),
                Vec::new()
            )
            .is_err());
        }
    }

    // Production break caught: collapsing two candidates with one UUID into a single score row.
    #[test]
    fn map_rejects_duplicate_candidate_ids() {
        let candidate = candidate(
            "00000000-0000-0000-0000-000000000001",
            "/work/project",
            TargetLanguage::C,
            "/work/project/src/parser.c",
            (1, 1, Some(5), Some(1)),
            0.50,
        );

        assert!(map_and_score(
            &inventory("/work/project", vec![candidate.clone(), candidate]),
            Vec::new()
        )
        .is_err());
    }

    // Production break caught: accepting NaN, infinity, or a base outside the documented range.
    #[test]
    fn map_rejects_non_finite_or_out_of_range_base_scores() {
        for invalid_score in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.01] {
            let candidate = candidate(
                "00000000-0000-0000-0000-000000000001",
                "/work/project",
                TargetLanguage::Cpp,
                "/work/project/src/parser.cc",
                (1, 1, Some(5), Some(1)),
                invalid_score,
            );
            assert!(
                map_and_score(&inventory("/work/project", vec![candidate]), Vec::new()).is_err(),
                "invalid base score must be rejected"
            );
        }
    }

    // Production break caught: counting locations instead of distinct rules or retaining low severity.
    #[test]
    fn score_deduplicates_rule_locations_and_uses_highest_severity() {
        let target_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("UUID should parse");
        let inventory = inventory(
            "/work/project",
            vec![candidate(
                "00000000-0000-0000-0000-000000000001",
                "/work/project",
                TargetLanguage::C,
                "/work/project/src/parser.c",
                (1, 1, Some(50), Some(1)),
                0.50,
            )],
        );
        let findings = vec![
            finding(
                "error-low",
                "rule.error",
                SemgrepSeverity::Info,
                "src/parser.c",
                2,
                1,
            ),
            finding(
                "error-high",
                "rule.error",
                SemgrepSeverity::Error,
                "src/parser.c",
                3,
                1,
            ),
            finding(
                "error-repeat",
                "rule.error",
                SemgrepSeverity::Warning,
                "src/parser.c",
                4,
                1,
            ),
            finding(
                "warning",
                "rule.warning",
                SemgrepSeverity::Warning,
                "src/parser.c",
                5,
                1,
            ),
            finding(
                "info",
                "rule.info",
                SemgrepSeverity::Info,
                "src/parser.c",
                6,
                1,
            ),
        ];

        let analysis = map_and_score(&inventory, findings).expect("valid findings should score");
        let score = analysis
            .scores
            .iter()
            .find(|score| score.target_id == target_id)
            .expect("candidate score should exist");

        assert_eq!(score.matched_rule_count, 3);
        assert_eq!(score.boost, 0.16);
        assert_eq!(score.effective_score, 0.66);
    }

    // Production break caught: omitting the required zero-overlay row for an unmatched candidate.
    #[test]
    fn score_emits_one_row_for_every_candidate() {
        let matched_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("UUID should parse");
        let zero_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000003").expect("UUID should parse");
        let inventory = inventory(
            "/work/project",
            vec![
                candidate(
                    "00000000-0000-0000-0000-000000000002",
                    "/work/project",
                    TargetLanguage::C,
                    "/work/project/src/parser.c",
                    (1, 1, Some(20), Some(1)),
                    0.50,
                ),
                candidate(
                    "00000000-0000-0000-0000-000000000003",
                    "/work/project",
                    TargetLanguage::Cpp,
                    "/work/project/src/other.cc",
                    (1, 1, Some(20), Some(1)),
                    0.25,
                ),
            ],
        );
        let findings = vec![finding(
            "matched",
            "rule.matched",
            SemgrepSeverity::Info,
            "src/parser.c",
            2,
            1,
        )];

        let analysis = map_and_score(&inventory, findings).expect("valid findings should score");
        let matched = analysis
            .scores
            .iter()
            .find(|score| score.target_id == matched_id)
            .expect("matched candidate score should exist");
        let zero = analysis
            .scores
            .iter()
            .find(|score| score.target_id == zero_id)
            .expect("unmatched candidate score should exist");

        assert_eq!(analysis.scores.len(), 2);
        assert_eq!(matched.boost, 0.01);
        assert_eq!(zero.base_score, 0.25);
        assert_eq!(zero.boost, 0.0);
        assert_eq!(zero.effective_score, 0.25);
        assert_eq!(zero.matched_rule_count, 0);
    }

    // Production break caught: allowing summed boosts or effective scores above their ceilings.
    #[test]
    fn score_caps_boost_and_effective_score() {
        let capped_id =
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("UUID should parse");
        let inventory = inventory(
            "/work/project",
            vec![candidate(
                "00000000-0000-0000-0000-000000000002",
                "/work/project",
                TargetLanguage::C,
                "/work/project/src/parser.c",
                (1, 1, Some(20), Some(1)),
                0.90,
            )],
        );
        let findings = vec![
            finding(
                "first",
                "rule.first",
                SemgrepSeverity::Error,
                "src/parser.c",
                2,
                1,
            ),
            finding(
                "second",
                "rule.second",
                SemgrepSeverity::Error,
                "src/parser.c",
                3,
                1,
            ),
            finding(
                "third",
                "rule.third",
                SemgrepSeverity::Warning,
                "src/parser.c",
                4,
                1,
            ),
        ];

        let analysis = map_and_score(&inventory, findings).expect("valid findings should score");
        let capped = analysis
            .scores
            .iter()
            .find(|score| score.target_id == capped_id)
            .expect("capped candidate score should exist");

        assert_eq!(capped.matched_rule_count, 3);
        assert_eq!(capped.boost, 0.20);
        assert_eq!(capped.effective_score, 1.0);
    }

    // Production break caught: carrying prior overlays into later scoring calls.
    #[test]
    fn score_repeated_calls_recompute_from_immutable_fit_score() {
        let inventory = inventory(
            "/work/project",
            vec![candidate(
                "00000000-0000-0000-0000-000000000001",
                "/work/project",
                TargetLanguage::C,
                "/work/project/src/parser.c",
                (1, 1, Some(20), Some(1)),
                0.50,
            )],
        );
        let findings = vec![finding(
            "repeat",
            "rule.repeat",
            SemgrepSeverity::Error,
            "src/parser.c",
            2,
            1,
        )];

        let first =
            map_and_score(&inventory, findings.clone()).expect("first scoring call should succeed");
        let second =
            map_and_score(&inventory, findings).expect("second scoring call should succeed");

        assert_eq!(inventory.candidates[0].fit_score, 0.50);
        assert_eq!(first.scores[0].base_score, 0.50);
        assert_eq!(first.scores[0].effective_score, 0.60);
        assert_eq!(second.scores[0].base_score, 0.50);
        assert_eq!(second.scores[0].effective_score, 0.60);
    }

    // Production break caught: preserving scanner order instead of persistence-stable UUID order.
    #[test]
    fn score_rows_are_sorted_by_target_uuid() {
        let inventory = inventory(
            "/work/project",
            vec![
                candidate(
                    "00000000-0000-0000-0000-000000000030",
                    "/work/project",
                    TargetLanguage::C,
                    "/work/project/src/third.c",
                    (1, 1, Some(5), Some(1)),
                    0.30,
                ),
                candidate(
                    "00000000-0000-0000-0000-000000000010",
                    "/work/project",
                    TargetLanguage::C,
                    "/work/project/src/first.c",
                    (1, 1, Some(5), Some(1)),
                    0.10,
                ),
                candidate(
                    "00000000-0000-0000-0000-000000000020",
                    "/work/project",
                    TargetLanguage::Cpp,
                    "/work/project/src/second.cc",
                    (1, 1, Some(5), Some(1)),
                    0.20,
                ),
            ],
        );

        let analysis = map_and_score(&inventory, Vec::new()).expect("valid inventory should score");
        let ordered_ids = analysis
            .scores
            .iter()
            .map(|score| score.target_id.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            ordered_ids,
            vec![
                String::from("00000000-0000-0000-0000-000000000010"),
                String::from("00000000-0000-0000-0000-000000000020"),
                String::from("00000000-0000-0000-0000-000000000030"),
            ]
        );
    }

    // Production break caught: dropping severity/path normalization or assigning the wrong weight.
    #[test]
    fn parse_valid_findings_normalizes_error_warning_and_info() {
        let bytes = br#"{
            "version": "1.169.0",
            "results": [
                {
                    "check_id": "rule.error",
                    "path": "src/parser.c",
                    "start": {"line": 8, "col": 5, "offset": 90},
                    "end": {"line": 8, "col": 17, "offset": 102},
                    "extra": {"message": "error match", "severity": "ERROR"}
                },
                {
                    "check_id": "rule.warning",
                    "path": "./include/warn.h",
                    "start": {"line": 3, "col": 2},
                    "end": {"line": 4, "col": 1},
                    "extra": {"message": "warning match", "severity": "WARNING"}
                },
                {
                    "check_id": "rule.info",
                    "path": "lib\\info.cc",
                    "start": {"line": 1, "col": 1},
                    "end": {"line": 1, "col": 2},
                    "extra": {"message": "info match", "severity": "INFO"}
                }
            ],
            "errors": [],
            "paths": {
                "scanned": ["src/parser.c", "./include/warn.h", "lib\\info.cc"],
                "skipped": []
            }
        }"#;
        let findings = parse_findings(
            bytes,
            &manifest(&["include/warn.h", "lib/info.cc", "src/parser.c"]),
        )
        .expect("valid findings should normalize");

        assert_eq!(findings.len(), 3);
        let error = findings
            .iter()
            .find(|finding| finding.rule_id == "rule.error")
            .expect("error finding should exist");
        assert_eq!(error.severity, SemgrepSeverity::Error);
        assert!((error.nominal_weight - 0.10).abs() < f64::EPSILON);
        assert_eq!(error.relative_path, Path::new("src/parser.c"));
        assert_eq!(
            (
                error.range.start_line,
                error.range.start_col,
                error.range.end_line,
                error.range.end_col,
            ),
            (8, 5, 8, 17)
        );
        assert_eq!(error.matched_target_id, None);

        let warning = findings
            .iter()
            .find(|finding| finding.rule_id == "rule.warning")
            .expect("warning finding should exist");
        assert_eq!(warning.severity, SemgrepSeverity::Warning);
        assert!((warning.nominal_weight - 0.05).abs() < f64::EPSILON);
        assert_eq!(warning.relative_path, Path::new("include/warn.h"));

        let info = findings
            .iter()
            .find(|finding| finding.rule_id == "rule.info")
            .expect("info finding should exist");
        assert_eq!(info.severity, SemgrepSeverity::Info);
        assert!((info.nominal_weight - 0.01).abs() < f64::EPSILON);
        assert_eq!(info.relative_path, Path::new("lib/info.cc"));
    }

    // Production break caught: changing canonical fingerprint fields or persisting telemetry.
    #[test]
    fn parse_valid_fixture_accepts_offsets_and_ignores_unknown_fields() {
        let mut document: serde_json::Value =
            serde_json::from_slice(VALID).expect("fixture should be valid JSON");
        document["telemetry"] = serde_json::json!({"opaque": "discard me"});
        document["results"][0]["extra"]["metadata"] =
            serde_json::json!({"source": "upstream only"});
        let bytes = serde_json::to_vec(&document).expect("test document should serialize");

        let findings = parse_findings(&bytes, &manifest(&["src/parser.c"]))
            .expect("supported unknown fields should be ignored");

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            "c.lang.security.audit.dangerous-function-usage"
        );
        assert_eq!(findings[0].message, "dangerous copy");
        assert_eq!(
            findings[0].fingerprint,
            "a2544b9ff9753742963274068b1b66c07f2d39089cb4fc5aad493c67cebf79f7"
        );
    }

    // Production break caught: accepting a malformed document as an empty successful analysis.
    #[test]
    fn parse_malformed_json_is_rejected() {
        let error = parse_findings(br#"{"version":"1.169.0""#, &BTreeSet::new())
            .expect_err("malformed JSON must be rejected");

        assert!(matches!(error, SemgrepValidationError::Json(_)));
    }

    // Production break caught: serde-defaulting an absent results collection.
    #[test]
    fn parse_missing_results_is_rejected() {
        let bytes = br#"{"version":"1.169.0","errors":[],"paths":{"scanned":[],"skipped":[]}}"#;
        let error =
            parse_findings(bytes, &BTreeSet::new()).expect_err("missing results must be rejected");

        assert!(matches!(error, SemgrepValidationError::Json(_)));
    }

    // Production break caught: serde-defaulting an absent errors collection.
    #[test]
    fn parse_missing_errors_is_rejected() {
        let bytes = br#"{"version":"1.169.0","results":[],"paths":{"scanned":[],"skipped":[]}}"#;
        let error =
            parse_findings(bytes, &BTreeSet::new()).expect_err("missing errors must be rejected");

        assert!(matches!(error, SemgrepValidationError::Json(_)));
    }

    // Production break caught: serde-defaulting absent path-completeness evidence.
    #[test]
    fn parse_missing_paths_is_rejected() {
        let bytes = br#"{"version":"1.169.0","results":[],"errors":[]}"#;
        let error =
            parse_findings(bytes, &BTreeSet::new()).expect_err("missing paths must be rejected");

        assert!(matches!(error, SemgrepValidationError::Json(_)));
    }

    // Production break caught: accepting output from an unpinned Semgrep schema version.
    #[test]
    fn parse_unsupported_version_is_rejected() {
        let bytes = br#"{
            "version":"1.170.0",
            "results":[],
            "errors":[],
            "paths":{"scanned":[],"skipped":[]}
        }"#;
        let error = parse_findings(bytes, &BTreeSet::new())
            .expect_err("unrecognized versions must be rejected");

        assert!(matches!(
            error,
            SemgrepValidationError::UnsupportedVersion(version) if version == "1.170.0"
        ));
    }

    // Production break caught: silently mapping an unknown severity to a supported weight.
    #[test]
    fn parse_unknown_severity_is_rejected() {
        let error = parse_findings(UNKNOWN_SEVERITY, &manifest(&["src/parser.c"]))
            .expect_err("unknown severity must be rejected");

        assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        assert!(
            !error.to_string().contains("CRITICAL"),
            "rejected upstream severity text must not be returned"
        );
    }

    // Production break caught: allowing any zero line or column into later span matching.
    #[test]
    fn parse_zero_coordinates_are_rejected() {
        for (start_line, start_col, end_line, end_col) in
            [(0, 1, 1, 2), (1, 0, 1, 2), (1, 1, 0, 2), (1, 1, 1, 0)]
        {
            let bytes = one_result(
                "rule.zero",
                "src/parser.c",
                start_line,
                start_col,
                end_line,
                end_col,
                "zero coordinate",
                "ERROR",
                "src/parser.c",
            );
            let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
                .expect_err("zero coordinates must be rejected");
            assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        }
    }

    // Production break caught: accepting an end coordinate before its start coordinate.
    #[test]
    fn parse_reversed_coordinates_are_rejected() {
        for (start_line, start_col, end_line, end_col) in [(9, 1, 8, 20), (8, 17, 8, 16)] {
            let bytes = one_result(
                "rule.reversed",
                "src/parser.c",
                start_line,
                start_col,
                end_line,
                end_col,
                "reversed range",
                "WARNING",
                "src/parser.c",
            );
            let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
                .expect_err("reversed ranges must be rejected");
            assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        }
    }

    // Production break caught: accepting or echoing absolute, prefixed, or unsafe path components.
    #[test]
    fn parse_unsafe_paths_are_rejected() {
        for path in [
            "/work/source/src/parser.c",
            "C:\\work\\source\\src\\parser.c",
            "\\\\server\\share\\parser.c",
            "../src/parser.c",
            "src/../parser.c",
            "src//parser.c",
            "src/./parser.c",
            "././src/parser.c",
            "src/parser.c/",
            "",
        ] {
            let bytes = one_result(
                "rule.path",
                path,
                1,
                1,
                1,
                2,
                "unsafe path",
                "INFO",
                "src/parser.c",
            );
            let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
                .expect_err("unsafe paths must be rejected");
            assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
            if !path.is_empty() {
                assert!(
                    !error.to_string().contains(path),
                    "rejected raw paths must not be returned"
                );
            }
        }
    }

    // Production break caught: checking drive prefixes before stripping a result path's leading dot.
    #[test]
    fn parse_result_path_rejects_drive_prefix_after_leading_dot_separator() {
        for path in ["./C:/work/source/file.c", ".\\C:\\work\\source\\file.c"] {
            let bytes = one_result(
                "rule.prefixed",
                path,
                1,
                1,
                1,
                2,
                "prefixed path",
                "INFO",
                path,
            );
            let error = parse_findings(&bytes, &manifest(&["C:/work/source/file.c"]))
                .expect_err("result paths must reject a drive prefix after the leading dot");

            assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        }
    }

    // Production break caught: checking drive prefixes before stripping a scanned path's leading dot.
    #[test]
    fn parse_scanned_path_rejects_drive_prefix_after_leading_dot_separator() {
        for path in ["./C:/work/source/file.c", ".\\C:\\work\\source\\file.c"] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "version": "1.169.0",
                "results": [],
                "errors": [],
                "paths": {"scanned": [path], "skipped": []}
            }))
            .expect("literal test document should serialize");
            let error = parse_findings(&bytes, &manifest(&["C:/work/source/file.c"]))
                .expect_err("scanned paths must reject a drive prefix after the leading dot");

            assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        }
    }

    // Production break caught: accepting a result for a file outside the staged manifest.
    #[test]
    fn parse_result_path_absent_from_manifest_is_rejected() {
        let bytes = one_result(
            "rule.unstaged",
            "src/other.c",
            1,
            1,
            1,
            2,
            "unstaged",
            "ERROR",
            "src/parser.c",
        );
        let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
            .expect_err("unstaged result paths must be rejected");

        assert!(matches!(error, SemgrepValidationError::UnsafeFinding(_)));
        assert!(
            !error.to_string().contains("src/other.c"),
            "unstaged upstream paths must not be returned"
        );
    }

    // Production break caught: accepting scanned evidence missing or adding staged files.
    #[test]
    fn parse_scanned_manifest_must_match_exactly() {
        let missing = br#"{
            "version":"1.169.0",
            "results":[],
            "errors":[],
            "paths":{"scanned":["src/parser.c"],"skipped":[]}
        }"#;
        let extra = br#"{
            "version":"1.169.0",
            "results":[],
            "errors":[],
            "paths":{"scanned":["src/parser.c","src/extra.c"],"skipped":[]}
        }"#;

        let missing_error = parse_findings(missing, &manifest(&["src/parser.c", "src/second.c"]))
            .expect_err("scanned paths missing a staged file must be rejected");
        assert!(matches!(
            missing_error,
            SemgrepValidationError::Incomplete(_)
        ));

        let extra_error = parse_findings(extra, &manifest(&["src/parser.c"]))
            .expect_err("scanned paths adding an unstaged file must be rejected");
        assert!(matches!(extra_error, SemgrepValidationError::Incomplete(_)));
    }

    // Production break caught: treating Semgrep analysis errors as complete results.
    #[test]
    fn parse_non_empty_errors_is_rejected() {
        let error = parse_findings(ERRORS, &manifest(&["src/parser.c"]))
            .expect_err("Semgrep errors must reject the whole analysis");

        assert!(matches!(error, SemgrepValidationError::Incomplete(_)));
    }

    // Production break caught: treating skipped source files as a complete analysis.
    #[test]
    fn parse_non_empty_skipped_paths_is_rejected() {
        let error = parse_findings(SKIPPED, &manifest(&["src/parser.c"]))
            .expect_err("skipped paths must reject the whole analysis");

        assert!(matches!(error, SemgrepValidationError::Incomplete(_)));
    }

    // Production break caught: using character counts or an off-by-one rule-id byte ceiling.
    #[test]
    fn parse_rule_id_byte_ceiling_is_exact() {
        let accepted = "r".repeat(MAX_RULE_ID_BYTES);
        let bytes = one_result(
            &accepted,
            "src/parser.c",
            1,
            1,
            1,
            2,
            "message",
            "INFO",
            "src/parser.c",
        );
        assert!(parse_findings(&bytes, &manifest(&["src/parser.c"])).is_ok());

        for rejected in [
            "r".repeat(MAX_RULE_ID_BYTES + 1),
            "é".repeat((MAX_RULE_ID_BYTES / 2) + 1),
        ] {
            let bytes = one_result(
                &rejected,
                "src/parser.c",
                1,
                1,
                1,
                2,
                "message",
                "INFO",
                "src/parser.c",
            );
            let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
                .expect_err("oversized rule ids must be rejected");
            assert!(matches!(error, SemgrepValidationError::Limit(_)));
        }
    }

    // Production break caught: using character counts or an off-by-one message byte ceiling.
    #[test]
    fn parse_message_byte_ceiling_is_exact() {
        let accepted = "m".repeat(MAX_MESSAGE_BYTES);
        let bytes = one_result(
            "rule.message",
            "src/parser.c",
            1,
            1,
            1,
            2,
            &accepted,
            "INFO",
            "src/parser.c",
        );
        assert!(parse_findings(&bytes, &manifest(&["src/parser.c"])).is_ok());

        for rejected in [
            "m".repeat(MAX_MESSAGE_BYTES + 1),
            "é".repeat((MAX_MESSAGE_BYTES / 2) + 1),
        ] {
            let bytes = one_result(
                "rule.message",
                "src/parser.c",
                1,
                1,
                1,
                2,
                &rejected,
                "INFO",
                "src/parser.c",
            );
            let error = parse_findings(&bytes, &manifest(&["src/parser.c"]))
                .expect_err("oversized messages must be rejected");
            assert!(matches!(error, SemgrepValidationError::Limit(_)));
        }
    }

    // Production break caught: processing one result beyond the hard finding-count ceiling.
    #[test]
    fn parse_more_than_max_findings_is_rejected() {
        let result = r#"{
            "check_id":"rule.limit",
            "path":"src/parser.c",
            "start":{"line":1,"col":1},
            "end":{"line":1,"col":2},
            "extra":{"message":"limit","severity":"INFO"}
        }"#;
        let results = std::iter::repeat_n(result, MAX_FINDINGS + 1)
            .collect::<Vec<_>>()
            .join(",");
        let bytes = format!(
            r#"{{"version":"1.169.0","results":[{results}],"errors":[],
                "paths":{{"scanned":["src/parser.c"],"skipped":[]}}}}"#
        );

        let error = parse_findings(bytes.as_bytes(), &manifest(&["src/parser.c"]))
            .expect_err("too many findings must be rejected");

        assert!(matches!(error, SemgrepValidationError::Limit(_)));
    }

    // Production break caught: retaining repeated identical Semgrep results.
    #[test]
    fn parse_identical_fingerprints_are_deduplicated() {
        let bytes = br#"{
            "version":"1.169.0",
            "results":[
                {
                    "check_id":"rule.duplicate",
                    "path":"src/parser.c",
                    "start":{"line":1,"col":1},
                    "end":{"line":1,"col":2},
                    "extra":{"message":"duplicate","severity":"WARNING"}
                },
                {
                    "check_id":"rule.duplicate",
                    "path":"src/parser.c",
                    "start":{"line":1,"col":1},
                    "end":{"line":1,"col":2},
                    "extra":{"message":"duplicate","severity":"WARNING"}
                }
            ],
            "errors":[],
            "paths":{"scanned":["src/parser.c"],"skipped":[]}
        }"#;

        let findings = parse_findings(bytes, &manifest(&["src/parser.c"]))
            .expect("identical duplicates should be accepted once");

        assert_eq!(findings.len(), 1);
    }

    // Production break caught: deduplicating different normalized content on a hash collision.
    #[test]
    fn parse_fingerprint_collision_with_different_content_is_rejected() {
        let bytes = br#"{
            "version":"1.169.0",
            "results":[
                {
                    "check_id":"rule.first",
                    "path":"src/parser.c",
                    "start":{"line":1,"col":1},
                    "end":{"line":1,"col":2},
                    "extra":{"message":"first","severity":"INFO"}
                },
                {
                    "check_id":"rule.second",
                    "path":"src/parser.c",
                    "start":{"line":2,"col":1},
                    "end":{"line":2,"col":2},
                    "extra":{"message":"second","severity":"ERROR"}
                }
            ],
            "errors":[],
            "paths":{"scanned":["src/parser.c"],"skipped":[]}
        }"#;

        let error = parse_findings_with_fingerprint(bytes, &manifest(&["src/parser.c"]), |_| {
            String::from("forced-collision")
        })
        .expect_err("different findings with one fingerprint must be rejected");

        assert!(matches!(
            error,
            SemgrepValidationError::FingerprintCollision(fingerprint)
                if fingerprint == "forced-collision"
        ));
    }
}
