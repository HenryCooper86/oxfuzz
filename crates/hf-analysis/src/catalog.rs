//! The rule table. Rules are embedded at compile time: there is no runtime rule
//! directory, no user-supplied rules, and no network fetch.

use crate::finding::Severity;

/// How a rule decides whether its captures constitute a finding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleKind {
    /// Every `@hit` capture is a finding.
    Shape,
    /// Two `@site` captures binding the same `@var`, in one block, with no kill
    /// between them. The second site is reported, because that is the defect.
    PairedSites,
    /// The first `@site` following an `@origin` that binds the same `@var`, in
    /// one block, with no kill between them. Used where the two ends are
    /// different events rather than repetitions of one.
    AfterEvent,
}

/// One embedded rule: its identity, how it decides, and the query that finds
/// its participating nodes.
pub(crate) struct Rule {
    pub(crate) id: &'static str,
    pub(crate) cwe: &'static str,
    pub(crate) severity: Severity,
    /// Stated per rule rather than defaulted, so the decision procedure is
    /// visible at the rule rather than inferred from its captures.
    pub(crate) kind: RuleKind,
    pub(crate) query: &'static str,
}

/// Rules matched against C translation units.
/// Rules whose queries compile and match against both grammars.
///
/// tree-sitter-cpp is largely a superset of tree-sitter-c, so a rule about a
/// call shape is identical in both. Sharing them is what gives C++ real
/// coverage; a separate C++ list would have started empty and stayed that way.
pub(crate) const SHARED_RULES: &[Rule] = &[
    Rule {
        id: "dangerous-function-gets",
        cwe: "CWE-242",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/dangerous-function-gets.scm"),
    },
    Rule {
        id: "unchecked-conversion-ato",
        cwe: "CWE-252",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unchecked-conversion-ato.scm"),
    },
    Rule {
        id: "unchecked-return-scanf",
        cwe: "CWE-252",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unchecked-return-scanf.scm"),
    },
    Rule {
        id: "dangerous-function-alloca",
        cwe: "CWE-676",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/dangerous-function-alloca.scm"),
    },
    Rule {
        id: "unbounded-string-copy",
        cwe: "CWE-676",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unbounded-string-copy.scm"),
    },
    Rule {
        id: "unbounded-scanf-conversion",
        cwe: "CWE-676",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unbounded-scanf-conversion.scm"),
    },
    Rule {
        id: "insecure-temporary-file",
        cwe: "CWE-377",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/insecure-temporary-file.scm"),
    },
    Rule {
        id: "weak-pseudo-random",
        cwe: "CWE-338",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/weak-pseudo-random.scm"),
    },
    Rule {
        id: "signal-handler-race",
        cwe: "CWE-364",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/signal-handler-race.scm"),
    },
    Rule {
        id: "toctou-access-check",
        cwe: "CWE-367",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/toctou-access-check.scm"),
    },
    Rule {
        id: "os-command-execution",
        cwe: "CWE-78",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/os-command-execution.scm"),
    },
    Rule {
        id: "strlen-sum-overflow",
        cwe: "CWE-190",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/strlen-sum-overflow.scm"),
    },
    Rule {
        id: "unchecked-privilege-drop",
        cwe: "CWE-252",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unchecked-privilege-drop.scm"),
    },
    Rule {
        id: "unchecked-truncating-write",
        cwe: "CWE-131",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/unchecked-truncating-write.scm"),
    },
    Rule {
        id: "memset-argument-order",
        cwe: "CWE-683",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/memset-argument-order.scm"),
    },
    Rule {
        id: "overlapping-copy",
        cwe: "CWE-1260",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/overlapping-copy.scm"),
    },
    Rule {
        id: "non-literal-format-string",
        cwe: "CWE-134",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/non-literal-format-string.scm"),
    },
    Rule {
        id: "environment-input",
        cwe: "CWE-15",
        severity: Severity::Info,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/environment-input.scm"),
    },
    Rule {
        id: "address-disclosure",
        cwe: "CWE-209",
        severity: Severity::Info,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/address-disclosure.scm"),
    },
    Rule {
        id: "assignment-in-assertion",
        cwe: "CWE-754",
        severity: Severity::Warning,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/assignment-in-assertion.scm"),
    },
    Rule {
        id: "double-free",
        cwe: "CWE-415",
        severity: Severity::Error,
        kind: RuleKind::PairedSites,
        query: include_str!("../rules/c/double-free.scm"),
    },
    Rule {
        id: "use-after-free",
        cwe: "CWE-416",
        severity: Severity::Error,
        kind: RuleKind::AfterEvent,
        query: include_str!("../rules/c/use-after-free.scm"),
    },
    Rule {
        id: "free-of-non-heap",
        cwe: "CWE-590",
        severity: Severity::Error,
        kind: RuleKind::Shape,
        query: include_str!("../rules/c/free-of-non-heap.scm"),
    },
];

/// Rules that only compile against the C grammar.
pub(crate) const C_ONLY_RULES: &[Rule] = &[Rule {
    id: "assignment-in-condition",
    cwe: "CWE-480",
    severity: Severity::Info,
    kind: RuleKind::Shape,
    query: include_str!("../rules/c/assignment-in-condition.scm"),
}];

/// Rules that only compile against the C++ grammar.
pub(crate) const CPP_ONLY_RULES: &[Rule] = &[Rule {
    id: "assignment-in-condition",
    cwe: "CWE-480",
    severity: Severity::Info,
    kind: RuleKind::Shape,
    query: include_str!("../rules/cpp/assignment-in-condition.scm"),
}];
