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
mod sequence;

use std::sync::OnceLock;

use hf_core::target::TargetLanguage;
use tree_sitter::{Language, Query, Tree};

pub use finding::{Finding, Severity, SourceSpan};

use catalog::{Rule, CPP_ONLY_RULES, C_ONLY_RULES, SHARED_RULES};

/// Cap on findings retained from one translation unit.
///
/// A generated or minified source can contain a pathological number of matching
/// sites; retaining them all would cost memory for no ranking value, since the
/// boost saturates at three distinct rules regardless.
pub const MAX_FINDINGS_PER_FILE: usize = 5_000;

/// Cap on findings retained across one analysis session.
///
/// Matches the limit the Semgrep normalization already applied, so behavior at
/// the boundary is unchanged. `hf-analysis` owns the constant rather than
/// borrowing it: the Semgrep one is deleted in phase 1d.
pub const MAX_FINDINGS_TOTAL: usize = 50_000;

/// The result of analyzing one or more translation units.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Analysis {
    /// Findings retained, in deterministic order.
    pub findings: Vec<Finding>,
    /// A cap stopped collection, so this analysis is partial.
    ///
    /// Surfaced rather than silent: a truncated overlay is still usable for
    /// ranking, but a caller comparing two producers needs to know it did not
    /// see everything.
    pub truncated: bool,
}

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

    /// Match every rule against one translation unit, bounded by
    /// [`MAX_FINDINGS_PER_FILE`].
    ///
    /// Truncation keeps the earliest findings in source order rather than an
    /// arbitrary subset, so a partial overlay is still reproducible.
    #[must_use]
    pub fn analyze_bounded(&self, tree: &Tree, source: &str) -> Analysis {
        let mut findings = self.analyze(tree, source);
        let truncated = findings.len() > MAX_FINDINGS_PER_FILE;
        if truncated {
            findings.truncate(MAX_FINDINGS_PER_FILE);
        }
        Analysis {
            findings,
            truncated,
        }
    }

    fn compile(
        language: &Language,
        rule_lists: [&'static [Rule]; 2],
    ) -> Result<Self, RuleCompileError> {
        let compiled = rule_lists
            .into_iter()
            .flatten()
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
fn language_rules(lang: TargetLanguage) -> Option<(Language, [&'static [Rule]; 2])> {
    match lang {
        TargetLanguage::C => Some((tree_sitter_c::LANGUAGE.into(), [SHARED_RULES, C_ONLY_RULES])),
        TargetLanguage::Cpp => Some((
            tree_sitter_cpp::LANGUAGE.into(),
            [SHARED_RULES, CPP_ONLY_RULES],
        )),
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

    /// Every rule ships a positive fixture that must match and a negative one
    /// that must not. The negative is the one that matters: it is where a rule
    /// that over-matches gets caught, and a rule without one is not done.
    const FIXTURES: &[(&str, &str, &str)] = &[
        (
            "returned-stack-address",
            "char* f(void){ char b[8]; return &b; }",
            "char* f(char*heap){ return heap; }",
        ),
        (
            "unterminated-strncpy",
            "void f(char*d, char*s){ strncpy(d, s, sizeof(d)); }",
            "void f(char*d, char*s){ strncpy(d, s, sizeof(d) - 1); }",
        ),
        (
            "environment-from-variable",
            "void f(char*e){ putenv(e); }",
            "void f(void){ putenv(\"A=1\"); }",
        ),
        (
            "catastrophic-regex",
            "void f(void*re){ regcomp(re, \"(a+)+b\", 0); }",
            "void f(void*re){ regcomp(re, \"^[a-z]+$\", 0); }",
        ),
        (
            "pointer-subtraction-size",
            "void f(char*a, char*b, char*d){ memcpy(d, a, a - b); }",
            "void f(char*a, char*d, int n){ memcpy(d, a, n); }",
        ),
        (
            "allocation-size-multiplication",
            "void* f(int a, int b){ return malloc(a * b); }",
            "void* f(int a, int b){ return calloc(a, b); }",
        ),
        (
            "source-size-in-copy",
            "void f(char*d, char*s){ memcpy(d, s, sizeof(s)); }",
            "void f(char*d, char*s){ memcpy(d, s, sizeof(d)); }",
        ),
        (
            "loop-bound-off-by-one",
            "void f(char*s){ for (int i = 0; i <= strlen(s); i++) { g(i); } }",
            "void f(char*s){ for (int i = 0; i < strlen(s); i++) { g(i); } }",
        ),
        (
            "assignment-in-assertion",
            "void f(int a, int b){ assert(a = b); }",
            "void f(int a, int b){ assert(a == b); }",
        ),
        (
            "assignment-in-condition",
            "int f(int a, int b){ if (a = b) { return 1; } return 0; }",
            "int f(int a, int b){ if (a == b) { return 1; } return 0; }",
        ),
        (
            "unchecked-privilege-drop",
            "void f(void){ setuid(1000); }",
            "void f(void){ if (setuid(1000) != 0) return; }",
        ),
        (
            "unchecked-truncating-write",
            "void f(char*b, char*s){ snprintf(b, 8, \"%s\", s); }",
            "void f(char*b, char*s){ int n = snprintf(b, 8, \"%s\", s); (void)n; }",
        ),
        (
            "memset-argument-order",
            "void f(char*b, int n){ memset(b, n, 0); }",
            "void f(char*b, int n){ memset(b, 0, n); }",
        ),
        (
            "overlapping-copy",
            "void f(char*b, int n){ memcpy(b, b, n); }",
            "void f(char*d, char*s, int n){ memcpy(d, s, n); }",
        ),
        (
            "non-literal-format-string",
            "void f(char*fmt){ printf(fmt); }",
            "void f(char*s){ printf(\"%s\", s); }",
        ),
        (
            "environment-input",
            "char* f(void){ return getenv(\"PATH\"); }",
            "char* f(void){ return my_getenv(\"PATH\"); }",
        ),
        (
            "address-disclosure",
            "void f(void*p){ printf(\"ptr %p\", p); }",
            "void f(int n){ printf(\"n %d\", n); }",
        ),
        (
            "dangerous-function-alloca",
            "void f(int n){ char *p = alloca(n); (void)p; }",
            "void f(int n){ char *p = my_alloca(n); int alloca_size = n; (void)p; (void)alloca_size; }",
        ),
        (
            "unbounded-string-copy",
            "void f(char*d, char*s){ strcpy(d, s); }",
            "void f(char*d, char*s){ strncpy(d, s, 8); strlcpy(d, s, 8); }",
        ),
        (
            "unbounded-scanf-conversion",
            "void f(char*b){ scanf(\"%s\", b); }",
            "void f(char*b, int*n){ scanf(\"%10s\", b); scanf(\"%d\", n); }",
        ),
        (
            "insecure-temporary-file",
            "void f(char*t){ mktemp(t); }",
            // mkstemp returns an open descriptor and is the recommended fix.
            "void f(char*t){ mkstemp(t); }",
        ),
        (
            "weak-pseudo-random",
            "int f(void){ return rand(); }",
            "int f(void){ return arc4random(); }",
        ),
        (
            "signal-handler-race",
            "void f(void (*h)(int)){ signal(2, h); }",
            "void f(void *a){ sigaction(2, a, 0); }",
        ),
        (
            "toctou-access-check",
            "int f(char*p){ return access(p, 4); }",
            "int f(int fd, void*st){ return fstat(fd, st); }",
        ),
        (
            "os-command-execution",
            "void f(char*c){ system(c); }",
            "void f(char*c){ my_system(c); }",
        ),
        (
            "strlen-sum-overflow",
            "unsigned long f(char*a, char*b){ return strlen(a) + strlen(b) + 1; }",
            // A single length plus a constant cannot wrap in practice.
            "unsigned long f(char*s){ return strlen(s) + 1; }",
        ),
    ];

    #[test]
    fn the_rule_count_is_asserted_rather_than_drifting() {
        // Written as a literal so adding or dropping a rule is a deliberate
        // edit with a commit message, not a silent change in coverage. The
        // reconciliation table in spec section 18.5 is keyed to these numbers.
        assert_eq!(compile_all(TargetLanguage::C).unwrap(), 32, "C rule count");
        assert_eq!(
            compile_all(TargetLanguage::Cpp).unwrap(),
            32,
            "C++ rule count"
        );
    }

    #[test]
    fn every_rule_carries_a_negative_fixture() {
        // Makes the per-rule discipline enforceable rather than aspirational: a
        // rule added without a fixture that proves it does not over-match fails
        // here instead of shipping unproven.
        const DEDICATED: &[&str] = &[
            "dangerous-function-gets",
            "unchecked-conversion-ato",
            "unchecked-return-scanf",
            // Four negative cases of its own: reassignment between the sites,
            // different variables, different blocks, and a single free.
            "double-free",
            // Three negatives: assignment target, use before the free, and a
            // different variable.
            "use-after-free",
            // Negative: free(*pp), which is ordinary code.
            "free-of-non-heap",
        ];
        let covered: std::collections::HashSet<&str> = FIXTURES
            .iter()
            .map(|(rule_id, _, _)| *rule_id)
            .chain(DEDICATED.iter().copied())
            .collect();
        for rule in catalog::SHARED_RULES
            .iter()
            .chain(catalog::C_ONLY_RULES)
            .chain(catalog::CPP_ONLY_RULES)
        {
            assert!(
                covered.contains(rule.id),
                "rule '{}' has no negative fixture",
                rule.id
            );
        }
    }

    #[test]
    fn every_rule_matches_its_positive_fixture() {
        for (rule_id, positive, _) in FIXTURES {
            let findings = analyze_c(positive);
            assert!(
                findings.iter().any(|finding| finding.rule_id == *rule_id),
                "{rule_id} did not match its positive fixture; got {findings:?}"
            );
        }
    }

    #[test]
    fn no_rule_matches_its_negative_fixture() {
        for (rule_id, _, negative) in FIXTURES {
            let findings = analyze_c(negative);
            assert!(
                !findings.iter().any(|finding| finding.rule_id == *rule_id),
                "{rule_id} over-matched its negative fixture; got {findings:?}"
            );
        }
    }

    #[test]
    fn a_double_free_is_reported_at_the_second_site() {
        let source = "void f(char*p){ free(p); g(); free(p); }";
        let findings = analyze_c(source);
        let hit = findings
            .iter()
            .find(|finding| finding.rule_id == "double-free")
            .expect("double free not reported");
        // The second free is the defect; reporting the first would point a
        // reader at correct code.
        let second_free = source.rfind("free(p)").unwrap();
        assert_eq!(hit.span.start_col as usize, second_free, "{hit:?}");
    }

    #[test]
    fn a_reassignment_between_frees_is_not_a_double_free() {
        let findings = analyze_c("void f(char*p){ free(p); p = 0; free(p); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "double-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn frees_of_different_variables_are_not_a_double_free() {
        let findings = analyze_c("void f(char*p, char*q){ free(p); free(q); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "double-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn frees_in_different_blocks_are_not_a_double_free() {
        // The pass reasons within one block; an if-guarded free followed by an
        // unconditional one is a sequence it cannot judge, so it stays silent.
        let findings = analyze_c("void f(char*p, int c){ if (c) { free(p); } free(p); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "double-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_single_free_is_not_a_double_free() {
        let findings = analyze_c("void f(char*p){ free(p); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "double-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_use_after_free_is_reported() {
        let findings = analyze_c("void f(char*p){ free(p); g(p); }");
        assert!(
            findings.iter().any(|f| f.rule_id == "use-after-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn nulling_the_pointer_after_free_is_not_a_use() {
        // `p = NULL` after a free is the recommended fix, not a use. An
        // assignment target must never count as a site or the rule fires on
        // exactly the code it should be encouraging.
        let findings = analyze_c("void f(char*p){ free(p); p = 0; }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "use-after-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_use_before_the_free_is_not_a_use_after_free() {
        let findings = analyze_c("void f(char*p){ g(p); free(p); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "use-after-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn using_a_different_variable_after_a_free_is_not_a_use_after_free() {
        let findings = analyze_c("void f(char*p, char*q){ free(p); g(q); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "use-after-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn freeing_an_address_of_a_local_is_reported() {
        let findings = analyze_c("void f(void){ int x = 0; free(&x); }");
        assert!(
            findings.iter().any(|f| f.rule_id == "free-of-non-heap"),
            "{findings:?}"
        );
    }

    #[test]
    fn freeing_a_dereferenced_pointer_is_not_a_non_heap_free() {
        // `free(*pp)` frees what the pointer points at, which is ordinary.
        // `&x` and `*x` are the same node kind, so this is the fixture that
        // proves the operator is actually being read.
        let findings = analyze_c("void f(char**pp){ free(*pp); }");
        assert!(
            !findings.iter().any(|f| f.rule_id == "free-of-non-heap"),
            "{findings:?}"
        );
    }

    fn analyze_cpp(source: &str) -> Vec<Finding> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("tree-sitter-cpp loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        rules_for(TargetLanguage::Cpp)
            .expect("C++ has rules")
            .analyze(&tree, source)
    }

    #[test]
    fn cpp_gets_the_shared_rules() {
        // C++ carried no rules at all until the lists were shared, so a C++
        // project got silence rather than analysis. These are the same call
        // shapes in both grammars.
        let findings = analyze_cpp("void f(char*d, char*s){ strcpy(d, s); }");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "unbounded-string-copy"),
            "{findings:?}"
        );
    }

    #[test]
    fn cpp_gets_the_sequence_rules_too() {
        let findings = analyze_cpp("void f(char*p){ free(p); g(); free(p); }");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "double-free"),
            "{findings:?}"
        );
    }

    #[test]
    fn the_condition_rule_works_in_both_grammars() {
        // C wraps a condition in parenthesized_expression and C++ in
        // condition_clause, so this rule needs one form per grammar. Both must
        // report, or C++ silently loses the rule.
        let source = "int f(int a, int b){ if (a = b) { return 1; } return 0; }";
        for findings in [analyze_c(source), analyze_cpp(source)] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == "assignment-in-condition"),
                "{findings:?}"
            );
        }
    }

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

    fn analyze_c_bounded(source: &str) -> Analysis {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c::LANGUAGE.into())
            .expect("tree-sitter-c loads");
        let tree = parser.parse(source, None).expect("fixture parses");
        rules_for(TargetLanguage::C)
            .expect("C has rules")
            .analyze_bounded(&tree, source)
    }

    #[test]
    fn a_pathological_file_is_capped_and_says_so() {
        let mut source = String::from("void f(char*b){\n");
        for _ in 0..(MAX_FINDINGS_PER_FILE + 10) {
            source.push_str("  gets(b);\n");
        }
        source.push('}');

        let analysis = analyze_c_bounded(&source);

        assert_eq!(analysis.findings.len(), MAX_FINDINGS_PER_FILE);
        assert!(analysis.truncated, "truncation must be visible, not silent");
    }

    #[test]
    fn an_ordinary_file_is_not_marked_truncated() {
        let analysis = analyze_c_bounded("void f(char*b){ gets(b); }");
        assert_eq!(analysis.findings.len(), 1);
        assert!(!analysis.truncated);
    }

    #[test]
    fn a_capped_analysis_is_still_ordered() {
        // Truncation must not hand back an arbitrary subset: the retained
        // findings are the first ones in source order, so a partial overlay is
        // still reproducible.
        let mut source = String::from("void f(char*b){\n");
        for _ in 0..(MAX_FINDINGS_PER_FILE + 10) {
            source.push_str("  gets(b);\n");
        }
        source.push('}');

        let analysis = analyze_c_bounded(&source);
        let lines: Vec<u32> = analysis
            .findings
            .iter()
            .map(|finding| finding.span.start_line)
            .collect();
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(lines, sorted);
        assert_eq!(lines[0], 2, "the earliest findings are the ones kept");
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
        // Line 3 carries two rules; within a line the order is by rule id.
        assert_eq!(
            order,
            vec![
                (2, "dangerous-function-gets"),
                (3, "unbounded-scanf-conversion"),
                (3, "unchecked-return-scanf"),
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
        // Two distinct rules fire here and both are true: the return value is
        // discarded, and the %s conversion is unbounded. The assertion names
        // the rule under test rather than the count, so adding a rule that is
        // also correct about this line does not break it.
        let findings = analyze_c("void f(char*b){ scanf(\"%s\", b); }");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "unchecked-return-scanf"),
            "{findings:?}"
        );
    }

    #[test]
    fn does_not_flag_scanf_whose_result_is_used() {
        // The rule is about the discarded return value, so a checked call is
        // the negative fixture that proves the constraint works.
        let checked = analyze_c("void f(char*b){ if (scanf(\"%s\", b) != 1) return; }");
        assert!(
            !checked
                .iter()
                .any(|finding| finding.rule_id == "unchecked-return-scanf"),
            "{checked:?}"
        );
        let assigned = analyze_c("void f(char*b){ int n = scanf(\"%s\", b); (void)n; }");
        assert!(
            !assigned
                .iter()
                .any(|finding| finding.rule_id == "unchecked-return-scanf"),
            "{assigned:?}"
        );
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
