//! Ground-truth annotations in the upstream rule fixtures.
//!
//! Development-only: this reads `third_party/semgrep-rules`, which exists to be
//! measured once for the phase 1c gate and is deleted in phase 1d. Nothing in
//! `src/` may depend on it.

/// What a fixture line asserts about the line that follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// A finding is expected.
    Finding,
    /// No finding is expected.
    Clean,
    /// Semgrep misses this and the fixture author documented why. Not a
    /// requirement: catching one is a genuine improvement, not a regression.
    KnownMiss,
    /// Semgrep false-positives here and the author documented why. Not
    /// reporting it is correct.
    KnownFalsePositive,
}

/// One ground-truth judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    /// One-based line the judgement applies to.
    pub line: u32,
    pub expectation: Expectation,
    /// The upstream rule the annotation names.
    pub upstream_rule: String,
}

/// Parse every annotation in one fixture.
///
/// An annotation applies to the next non-blank, non-comment line, which is the
/// convention the fixtures are written in. Getting that wrong shifts every
/// judgement by one line and makes the whole measurement meaningless.
pub fn parse_annotations(source: &str) -> Vec<Annotation> {
    let lines: Vec<&str> = source.lines().collect();
    let mut annotations = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some((expectation, rule)) = parse_annotation_comment(line) else {
            continue;
        };
        // Scan forward for the line the judgement is about.
        let Some(target) = lines
            .iter()
            .enumerate()
            .skip(index + 1)
            .find(|(_, candidate)| {
                let trimmed = candidate.trim();
                !trimmed.is_empty() && !trimmed.starts_with("//")
            })
            .map(|(target_index, _)| target_index)
        else {
            // A trailing annotation with no following code is dropped rather
            // than pointing past the end of the file and corrupting the count.
            continue;
        };
        annotations.push(Annotation {
            line: u32::try_from(target + 1).unwrap_or(u32::MAX),
            expectation,
            upstream_rule: rule,
        });
    }
    annotations
}

fn parse_annotation_comment(line: &str) -> Option<(Expectation, String)> {
    let comment = line.trim().strip_prefix("//")?.trim_start();
    for (keyword, expectation) in [
        ("todoruleid:", Expectation::KnownMiss),
        ("todook:", Expectation::KnownFalsePositive),
        ("ruleid:", Expectation::Finding),
        ("ok:", Expectation::Clean),
    ] {
        if let Some(rest) = comment.strip_prefix(keyword) {
            let rule = rest.trim().split(',').next().unwrap_or_default().trim();
            if !rule.is_empty() {
                return Some((expectation, rule.to_owned()));
            }
        }
    }
    None
}

/// Upstream rule to the oxfuzz rules covering it, mirroring spec section 18.5.
///
/// An empty slice means uncovered by design, with the reason recorded in spec
/// sections 18.1 through 18.4.
pub const COVERAGE: &[(&str, &[&str])] = &[
    ("argv-envp-access", &["environment-input"]),
    ("command-injection", &["os-command-execution"]),
    ("double-free", &["double-free"]),
    ("format-string-bugs", &["non-literal-format-string"]),
    ("high-entropy-assignment", &[]),
    ("incorrect-order-setuid-setgid", &[]),
    ("incorrect-unsigned-comparison", &[]),
    ("incorrect-use-of-free", &["free-of-non-heap"]),
    ("incorrect-use-of-memset", &["memset-argument-order"]),
    ("incorrect-use-of-sizeof", &[]),
    ("incorrect-use-of-strncat", &["strncat-constant-bound"]),
    ("insecure-api-access-stat", &["toctou-access-check"]),
    ("insecure-api-alloca", &["dangerous-function-alloca"]),
    ("insecure-api-ato", &["unchecked-conversion-ato"]),
    ("insecure-api-gets", &["dangerous-function-gets"]),
    (
        "insecure-api-mktemp-tmpnam-tempnam",
        &["insecure-temporary-file"],
    ),
    ("insecure-api-rand-srand", &["weak-pseudo-random"]),
    (
        "insecure-api-scanf",
        &[
            "unbounded-scanf-conversion",
            "unbounded-string-scan",
            // A non-literal scan format is reported by this rule, and a map
            // that omits it counts a real report as a miss.
            "non-literal-format-string",
        ],
    ),
    ("insecure-api-signal", &["signal-handler-race"]),
    ("insecure-api-sprintf-vsprintf", &["unbounded-format-write"]),
    ("insecure-api-strcpy-strcat", &["unbounded-string-copy"]),
    ("integer-truncation", &[]),
    ("integer-wraparound", &["allocation-size-multiplication"]),
    ("interesting-api-calls", &[]),
    ("memory-address-exposure", &["address-disclosure"]),
    ("mismatched-memory-management", &[]),
    ("mismatched-memory-management-cpp", &[]),
    ("missing-break-in-switch", &[]),
    ("missing-default-in-switch", &[]),
    ("missing-return", &[]),
    (
        "off-by-one",
        &[
            "loop-bound-off-by-one",
            "index-at-buffer-size",
            "allocation-missing-terminator",
            "length-compared-to-size",
            "strncat-constant-bound",
        ],
    ),
    ("overlapping-source-destination", &["overlapping-copy"]),
    ("pointer-subtraction", &["pointer-subtraction-size"]),
    ("putenv-stack-var", &[]),
    ("regex-dos", &["catastrophic-regex"]),
    ("ret-stack-address", &["returned-stack-address"]),
    ("signed-unsigned-conversion", &[]),
    (
        "suspicious-assert",
        &["assignment-in-assertion", "assert-used-as-bound-check"],
    ),
    ("typos", &["assignment-in-condition"]),
    ("unchecked-ret-malloc", &[]),
    ("unchecked-ret-scanf", &["unchecked-return-scanf"]),
    (
        "unchecked-ret-setuid-seteuid",
        &["unchecked-privilege-drop"],
    ),
    (
        "unsafe-ret-snprintf-vsnprintf",
        &["unchecked-truncating-write", "truncating-write-return-used"],
    ),
    (
        "unsafe-ret-strlcpy-strlcat",
        &["unchecked-truncating-write"],
    ),
    ("unsafe-strlen", &["strlen-sum-overflow"]),
    ("unterminated-string-strncpy", &["unterminated-strncpy"]),
    ("use-after-free", &["use-after-free"]),
    (
        "use-of-source-size-in-copy",
        &["source-size-in-copy", "snprintf-size-mismatch"],
    ),
    ("write-into-stack-buffer", &[]),
];
