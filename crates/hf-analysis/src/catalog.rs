//! The rule table. Rules are embedded at compile time: there is no runtime rule
//! directory, no user-supplied rules, and no network fetch.

use crate::finding::Severity;

/// One embedded rule: its identity and the query that matches it.
pub(crate) struct Rule {
    pub(crate) id: &'static str,
    pub(crate) cwe: &'static str,
    pub(crate) severity: Severity,
    pub(crate) query: &'static str,
}

/// Rules matched against C translation units.
pub(crate) const C_RULES: &[Rule] = &[Rule {
    id: "dangerous-function-gets",
    cwe: "CWE-242",
    severity: Severity::Error,
    query: include_str!("../rules/c/dangerous-function-gets.scm"),
}];

/// Rules matched against C++ translation units. C++ gains its own rules once
/// the shape rules that need C++-only grammar nodes are written; until then the
/// set is empty and analysis of a C++ unit yields nothing.
pub(crate) const CPP_RULES: &[Rule] = &[];
