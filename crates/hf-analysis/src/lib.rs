//! hf-analysis: native C/C++ static analysis for fuzz-target prioritization.
//!
//! Findings are advisory signals that improve which functions oxfuzz chooses to
//! fuzz. They are not confirmed vulnerabilities and carry no authority to
//! generate, promote, build, or execute a harness.
//!
//! The crate takes a tree it did not build and returns findings. It performs no
//! I/O, owns no parser, and never learns what a target candidate is; joining
//! findings to candidates and scoring them belongs to `hf-discovery`.
//!
//! See `docs/superpowers/specs/2026-08-21-native-static-analysis-design.md`.

mod catalog;
pub mod finding;
mod query;

use std::sync::OnceLock;

use hf_core::target::TargetLanguage;
use tree_sitter::{Language, Query, Tree};

pub use finding::{Finding, Severity, SourceSpan};

use catalog::{Rule, CPP_RULES, C_RULES};

/// Why an embedded rule could not be compiled into a query.
#[derive(Debug, thiserror::Error)]
#[error("rule '{rule_id}' failed to compile: {source}")]
pub struct RuleCompileError {
    /// The offending rule.
    pub rule_id: &'static str,
    /// The underlying tree-sitter query error.
    #[source]
    pub source: tree_sitter::QueryError,
}

/// The compiled rules for one language.
pub struct RuleSet {
    compiled: Vec<(&'static Rule, Query)>,
}

impl RuleSet {
    /// Number of rules in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    /// Whether this set has no rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// Match every rule against one already-parsed translation unit.
    ///
    /// Pure: performs no I/O, builds no parser, and does not own the tree.
    #[must_use]
    pub fn analyze(&self, tree: &Tree, source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (rule, query) in &self.compiled {
            query::run_rule(rule, query, tree, source, &mut findings);
        }
        query::order_findings(&mut findings);
        findings
    }

    fn compile(language: &Language, rules: &'static [Rule]) -> Result<Self, RuleCompileError> {
        let compiled = rules
            .iter()
            .map(|rule| {
                Query::new(language, rule.query)
                    .map(|query| (rule, query))
                    .map_err(|source| RuleCompileError {
                        rule_id: rule.id,
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { compiled })
    }
}

/// The language grammar and rule table for `lang`, or `None` where oxfuzz has
/// no rules.
///
/// `None` says "unanalyzed", which is honest for a language scanned lexically
/// and therefore carrying no tree to match against. An empty rule set would say
/// "analyzed, nothing found", which is not the same claim.
fn language_rules(lang: TargetLanguage) -> Option<(Language, &'static [Rule])> {
    match lang {
        TargetLanguage::C => Some((tree_sitter_c::LANGUAGE.into(), C_RULES)),
        TargetLanguage::Cpp => Some((tree_sitter_cpp::LANGUAGE.into(), CPP_RULES)),
        TargetLanguage::Rust | TargetLanguage::Go | TargetLanguage::Python => None,
    }
}

/// Compile every embedded rule for `lang`, returning how many compiled.
///
/// Test-facing. Production goes through [`rules_for`], which panics on a
/// failure this function is expected to catch first, in CI.
///
/// # Errors
/// Returns the first rule that does not compile, named.
pub fn compile_all(lang: TargetLanguage) -> Result<usize, RuleCompileError> {
    let Some((language, rules)) = language_rules(lang) else {
        return Ok(0);
    };
    RuleSet::compile(&language, rules).map(|set| set.len())
}

/// The compiled rule set for `lang`, or `None` for a language with no rules.
///
/// Compiled once per language for the process lifetime. Query compilation is
/// not free and there are tens of rules; compiling per file would cost more
/// than matching does.
///
/// # Panics
/// Panics if an embedded rule fails to compile. The rules are compile-time
/// constants and `compile_all` is asserted over all of them in CI, so a
/// panicking build cannot reach a user.
#[must_use]
pub fn rules_for(lang: TargetLanguage) -> Option<&'static RuleSet> {
    static C: OnceLock<RuleSet> = OnceLock::new();
    static CPP: OnceLock<RuleSet> = OnceLock::new();

    let (language, rules) = language_rules(lang)?;
    let cell = match lang {
        TargetLanguage::C => &C,
        TargetLanguage::Cpp => &CPP,
        // `language_rules` already returned None for every other language.
        _ => return None,
    };
    Some(cell.get_or_init(|| {
        RuleSet::compile(&language, rules).expect("embedded rules are verified by compile_all")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_c(source: &str) -> Vec<Finding> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .expect("tree-sitter-c loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        rules_for(TargetLanguage::C)
            .expect("C has rules")
            .analyze(&tree, source)
    }

    #[test]
    fn ordering_sorts_findings_that_arrive_out_of_order() {
        // The integration fixtures above pass incidentally: with three rules
        // whose catalog order already matches their alphabetical order, no
        // source can distinguish a sorted result from an unsorted one. This
        // exercises the ordering directly, so it keeps meaning once Task 8
        // adds rules whose catalog order differs.
        let mut findings = vec![
            finding_at("z-rule", 5, 0),
            finding_at("a-rule", 5, 0),
            finding_at("m-rule", 2, 8),
            finding_at("m-rule", 2, 1),
        ];
        super::query::order_findings(&mut findings);

        let order: Vec<(&str, u32, u32)> = findings
            .iter()
            .map(|f| (f.rule_id, f.span.start_line, f.span.start_col))
            .collect();
        assert_eq!(
            order,
            vec![
                ("m-rule", 2, 1),
                ("m-rule", 2, 8),
                ("a-rule", 5, 0),
                ("z-rule", 5, 0),
            ]
        );
    }

    fn finding_at(rule_id: &'static str, line: u32, col: u32) -> Finding {
        Finding {
            rule_id,
            cwe: "CWE-000",
            severity: Severity::Info,
            span: SourceSpan {
                start_line: line,
                start_col: col,
                end_line: line,
                end_col: col + 1,
            },
        }
    }

    #[test]
    fn findings_are_ordered_by_span_then_rule() {
        let findings = analyze_c("void f(char*b){\n  gets(b);\n  scanf(\"%s\", b);\n}");
        let order: Vec<(u32, &str)> = findings
            .iter()
            .map(|finding| (finding.span.start_line, finding.rule_id))
            .collect();
        assert_eq!(
            order,
            vec![
                (2, "dangerous-function-gets"),
                (3, "unchecked-return-scanf")
            ]
        );
    }

    #[test]
    fn the_same_source_analyzes_identically_twice() {
        // Rule iteration and query-match order must not leak into output: a
        // non-deterministic overlay would make the phase 1c A/B unreadable.
        let source = "void f(char*b){ gets(b); scanf(\"%s\", b); atoi(b); }";
        assert_eq!(analyze_c(source), analyze_c(source));
    }

    #[test]
    fn two_calls_on_one_line_both_report() {
        let findings = analyze_c("void f(char*b){ gets(b); gets(b); }");
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn one_rule_matching_twice_at_one_position_reports_once() {
        // Distinct-rule counting drives the boost, so a rule whose query yields
        // overlapping matches at the same node must not inflate it.
        let findings = analyze_c("void f(char*b){ gets(b); }");
        assert_eq!(findings.len(), 1, "{findings:?}");
    }

    #[test]
    fn flags_the_ato_family_by_pattern() {
        for call in ["atoi(s)", "atol(s)", "atoll(s)"] {
            let findings = analyze_c(&format!("int f(char*s){{ return {call}; }}"));
            assert_eq!(findings.len(), 1, "{call}: {findings:?}");
            assert_eq!(findings[0].rule_id, "unchecked-conversion-ato");
            assert_eq!(findings[0].cwe, "CWE-252");
        }
    }

    #[test]
    fn does_not_flag_a_name_that_only_starts_like_the_family() {
        // #match? must be anchored at both ends or `atomic_load` matches.
        let findings = analyze_c("void f(void){ atomic_load(0); atoi_safe(0); }");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn flags_scanf_whose_result_is_discarded() {
        let findings = analyze_c("void f(char*b){ scanf(\"%s\", b); }");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule_id, "unchecked-return-scanf");
    }

    #[test]
    fn does_not_flag_scanf_whose_result_is_used() {
        // The rule is about the discarded return value, so a checked call is
        // the negative fixture that proves the constraint works.
        let checked = analyze_c("void f(char*b){ if (scanf(\"%s\", b) != 1) return; }");
        assert!(checked.is_empty(), "{checked:?}");
        let assigned = analyze_c("void f(char*b){ int n = scanf(\"%s\", b); (void)n; }");
        assert!(assigned.is_empty(), "{assigned:?}");
    }

    #[test]
    fn flags_a_call_to_gets() {
        let findings = analyze_c("int main(void){ char b[8]; gets(b); return 0; }");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule_id, "dangerous-function-gets");
        assert_eq!(findings[0].cwe, "CWE-242");
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].span.start_line, 1);
    }

    #[test]
    fn does_not_flag_a_name_merely_containing_a_dangerous_one() {
        // The negative fixture is the one that matters: #eq? is exact, so a
        // project's own wrapper must not be reported.
        let findings = analyze_c(
            "int my_gets(char*); int gets_line(char*);\n\
             int main(void){ char b[8]; my_gets(b); gets_line(b); return 0; }",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn reports_the_line_the_call_sits_on() {
        let findings = analyze_c("int main(void){\n  char b[8];\n  gets(b);\n  return 0;\n}");
        assert_eq!(findings[0].span.start_line, 3);
    }

    #[test]
    fn a_source_with_no_match_yields_nothing() {
        assert!(analyze_c("int main(void){ return 0; }").is_empty());
    }

    #[test]
    fn c_and_cpp_have_rule_sets() {
        assert!(rules_for(TargetLanguage::C).is_some());
        assert!(rules_for(TargetLanguage::Cpp).is_some());
    }

    #[test]
    fn languages_without_rules_return_none() {
        // Go and Python are scanned lexically, so there is no tree to match
        // against. None says "unanalyzed", which is honest; an empty set would
        // say "analyzed, nothing found", which is a different claim.
        assert!(rules_for(TargetLanguage::Go).is_none());
        assert!(rules_for(TargetLanguage::Python).is_none());
        assert!(rules_for(TargetLanguage::Rust).is_none());
    }

    #[test]
    fn every_embedded_rule_compiles() {
        // The gate that keeps a malformed .scm out of a user's scan: it fails
        // here, in CI, rather than at analysis time. C++ starts with no rules of
        // its own, so only C is asserted non-empty.
        for lang in [TargetLanguage::C, TargetLanguage::Cpp] {
            compile_all(lang).expect("all embedded rules must compile");
        }
        assert!(
            compile_all(TargetLanguage::C).unwrap() > 0,
            "C has no rules"
        );
    }

    #[test]
    fn severity_weights_match_the_established_boost_model() {
        assert!((Severity::Error.weight() - 0.10).abs() < f64::EPSILON);
        assert!((Severity::Warning.weight() - 0.05).abs() < f64::EPSILON);
        assert!((Severity::Info.weight() - 0.01).abs() < f64::EPSILON);
    }
}
