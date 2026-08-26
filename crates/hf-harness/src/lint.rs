//! Static checks on generated harness source.
//!
//! The harness is written by a language model and then executed against
//! untrusted input inside the sandbox. These rules catch, before any container
//! starts, the behaviours that make a harness useless or unsafe: terminating the
//! fuzz process on ordinary malformed input, reaching outside the sandbox,
//! hiding the faults the fuzzer exists to find, and branching on something other
//! than the input bytes.
//!
//! Deterministic and free: no model call, no sandbox, no store. An `Error`
//! finding short-circuits the compile and goes straight to the repair loop,
//! which is cheaper than a container round-trip and catches a class of defect
//! the compiler accepts happily.
//!
//! Matching is lexical, over source lines. A line that is entirely a comment is
//! skipped so a rule name quoted in a comment does not trip its own rule; a
//! rule name inside a string literal or a trailing comment still matches, which
//! is the safe direction for a check whose findings are advisory to a repair
//! prompt.

use std::collections::HashSet;
use std::sync::OnceLock;

use hf_core::target::TargetLanguage;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// How a lint finding affects the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    /// Blocks compilation; the source goes back to the repair loop.
    Error,
    /// Recorded and surfaced; does not block.
    Warning,
}

/// One rule violation in harness source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintFinding {
    /// Whether this blocks the build.
    pub severity: LintSeverity,
    /// Stable kebab-case rule identifier, e.g. `no-process-exit`.
    pub rule: String,
    /// What is wrong and why it matters, written to be read by the repair
    /// prompt as well as by a person.
    pub message: String,
    /// 1-indexed source line.
    pub line: u32,
}

/// One lexical rule.
struct Rule {
    id: &'static str,
    severity: LintSeverity,
    message: &'static str,
    pattern: &'static str,
    /// Only applies to C++ sources.
    cpp_only: bool,
}

/// The harness rules.
///
/// File I/O is deliberately absent: an AFL++ file-mode harness must open
/// `argv[1]`, so a rule against `fopen` would fire on correct code, and a check
/// with false positives on the common case gets ignored.
///
/// Each call pattern requires a non-identifier character before the name and an
/// opening parenthesis after it, so `exit_code` and `parse_time` are not calls
/// to `exit` and `time`.
const RULES: [Rule; 8] = [
    Rule {
        id: "no-process-exit",
        severity: LintSeverity::Error,
        message: "do not terminate the process on malformed input: every such input then \
                  looks like a crash, and the fuzz run ends. Return early instead.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:_exit|exit|abort)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-shell",
        severity: LintSeverity::Error,
        message: "do not spawn a process from a harness: the sandbox is the only execution \
                  authority, and a shell escapes what the fuzzer is measuring.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:system|popen|execlp|execl|execvp|execv)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-sleep",
        severity: LintSeverity::Error,
        message: "do not sleep in the fuzz loop: it destroys throughput and a slow input \
                  is reported as a hang.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:nanosleep|usleep|sleep)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-network",
        severity: LintSeverity::Error,
        message: "do not open a socket from a harness: it reaches outside the sandbox and \
                  makes the result depend on a service the run does not control.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:socket|connect|listen|accept|bind)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-signal-handler",
        severity: LintSeverity::Warning,
        message: "a signal handler can swallow the fault the sanitizer is meant to report, \
                  turning a real crash into a silent pass.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:sigaction|signal)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-nondeterminism",
        severity: LintSeverity::Warning,
        message: "branch only on the input bytes: a clock or RNG makes a crash \
                  irreproducible and breaks corpus minimization.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:srandom|srand|random|rand|clock|time)\s*\(",
        cpp_only: false,
    },
    Rule {
        id: "no-catch-all",
        severity: LintSeverity::Warning,
        message: "a catch-all handler hides target failures the fuzzer exists to observe; \
                  catch only what the API documents as expected.",
        pattern: r"catch\s*\(\s*\.\.\.\s*\)",
        cpp_only: true,
    },
    Rule {
        id: "no-strlen-on-fuzz-data",
        severity: LintSeverity::Warning,
        message: "fuzz input is not NUL-terminated, so treating it as a C string reads past \
                  the buffer inside the harness itself; use the size argument.",
        pattern: r"strlen\s*\(\s*(?:\([^)]*\)\s*)?(?:data|Data|buf)\s*\)",
        cpp_only: false,
    },
];

/// One harness rule, as a reader needs to see it before writing code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessRuleSummary {
    /// Stable rule identifier, matching the finding a violation produces.
    pub id: String,
    /// Whether a violation blocks compilation or only warns.
    pub severity: LintSeverity,
    /// What is wrong and why it matters.
    pub message: String,
    /// Whether the rule applies only to C++ sources.
    pub cpp_only: bool,
}

/// Every harness rule the lint enforces.
///
/// Exposed so an authoring packet can state the constraints up front instead of
/// letting an author discover them as compile failures, and so the packet
/// cannot drift from what the lint actually checks (AGENTS.md 2.18).
#[must_use]
pub fn harness_rules() -> Vec<HarnessRuleSummary> {
    RULES
        .iter()
        .map(|rule| HarnessRuleSummary {
            id: rule.id.to_owned(),
            severity: rule.severity,
            message: rule.message.to_owned(),
            cpp_only: rule.cpp_only,
        })
        .collect()
}

/// The rule patterns, compiled once.
fn compiled_rules() -> &'static Vec<Regex> {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|rule| {
                Regex::new(rule.pattern).expect("lint rule patterns are compile-time constants")
            })
            .collect()
    })
}

/// Whether a line carries nothing but a comment.
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

/// Check generated harness source against the harness rules.
///
/// C and C++ only; other languages return an empty vec until their rule sets
/// exist, so a Rust or Go harness is not silently declared clean by a check that
/// never looked at it.
///
/// At most one finding per rule per line, ordered by line then rule, so the
/// output is stable enough to assert on and to put in a prompt.
#[must_use]
pub fn lint_harness_source(source: &str, language: TargetLanguage) -> Vec<LintFinding> {
    if !matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
        return Vec::new();
    }
    let is_cpp = language == TargetLanguage::Cpp;
    let patterns = compiled_rules();
    let mut seen: HashSet<(u32, &'static str)> = HashSet::new();
    let mut findings = Vec::new();

    for (index, line) in source.lines().enumerate() {
        if is_comment_line(line) {
            continue;
        }
        // `lines()` cannot yield more entries than the source has bytes, and a
        // source that large never reaches here; saturating keeps the cast total.
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        for (rule, pattern) in RULES.iter().zip(patterns) {
            if rule.cpp_only && !is_cpp {
                continue;
            }
            if pattern.is_match(line) && seen.insert((number, rule.id)) {
                findings.push(LintFinding {
                    severity: rule.severity,
                    rule: rule.id.to_owned(),
                    message: rule.message.to_owned(),
                    line: number,
                });
            }
        }
    }
    findings.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.rule.cmp(&b.rule)));
    findings
}

/// Whether any finding blocks the build.
#[must_use]
pub fn has_blocking_finding(findings: &[LintFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == LintSeverity::Error)
}

/// Render findings as diagnostics for the harness repair prompt.
///
/// Returns an empty string for no findings, so a caller can concatenate it with
/// compiler output unconditionally.
#[must_use]
pub fn render_findings(findings: &[LintFinding]) -> String {
    findings
        .iter()
        .map(|finding| {
            let severity = match finding.severity {
                LintSeverity::Error => "error",
                LintSeverity::Warning => "warning",
            };
            format!(
                "{severity}: line {}: {} [{}]",
                finding.line, finding.message, finding.rule
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(source: &str) -> Vec<String> {
        lint_harness_source(source, TargetLanguage::C)
            .into_iter()
            .map(|finding| finding.rule)
            .collect()
    }

    #[test]
    fn flags_process_exit_as_an_error() {
        let findings = lint_harness_source(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { if (n < 4) exit(1); return 0; }",
            TargetLanguage::C,
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule, "no-process-exit");
        assert_eq!(findings[0].severity, LintSeverity::Error);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn flags_shell_and_network_calls() {
        let found = rules("void f(void){ system(\"ls\"); socket(1,2,3); }");
        assert!(found.contains(&"no-shell".to_owned()), "{found:?}");
        assert!(found.contains(&"no-network".to_owned()), "{found:?}");
    }

    #[test]
    fn flags_sleeping_in_the_fuzz_loop() {
        assert!(rules("void f(void){ usleep(1000); }").contains(&"no-sleep".to_owned()));
    }

    #[test]
    fn does_not_flag_an_identifier_that_merely_contains_a_rule_name() {
        // `exit_code` and `parse_time` are ordinary names, not calls.
        let found = rules(
            "int f(void){ int exit_code = 0; long parse_time = 0; return exit_code + parse_time; }",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn does_not_flag_a_rule_name_inside_a_comment() {
        let found = rules("// never call exit() here\nint f(void){ return 0; }");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn flags_strlen_on_the_fuzz_input_as_a_warning() {
        let findings = lint_harness_source(
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t n) { return (int)strlen((const char *)data); }",
            TargetLanguage::C,
        );
        assert_eq!(findings[0].rule, "no-strlen-on-fuzz-data");
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn flags_nondeterminism_as_a_warning() {
        let findings = lint_harness_source("void f(void){ srand(time(0)); }", TargetLanguage::C);
        assert_eq!(findings[0].rule, "no-nondeterminism");
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn catch_all_is_cpp_only() {
        let source = "int f(){ try { g(); } catch (...) { } return 0; }";
        assert!(rules(source).is_empty(), "{:?}", rules(source));
        let cpp: Vec<String> = lint_harness_source(source, TargetLanguage::Cpp)
            .into_iter()
            .map(|finding| finding.rule)
            .collect();
        assert!(cpp.contains(&"no-catch-all".to_owned()), "{cpp:?}");
    }

    #[test]
    fn reports_the_line_a_violation_sits_on() {
        let findings = lint_harness_source(
            "int f(void) {\n    return 0;\n}\nvoid g(void){ abort(); }",
            TargetLanguage::C,
        );
        assert_eq!(findings[0].line, 4);
    }

    #[test]
    fn findings_are_ordered_by_line_then_rule() {
        let findings = lint_harness_source(
            "void a(void){ socket(1,2,3); abort(); }\nvoid b(void){ system(\"x\"); }",
            TargetLanguage::C,
        );
        let ordered: Vec<(u32, &str)> = findings
            .iter()
            .map(|finding| (finding.line, finding.rule.as_str()))
            .collect();
        assert_eq!(
            ordered,
            vec![(1, "no-network"), (1, "no-process-exit"), (2, "no-shell")]
        );
    }

    #[test]
    fn a_clean_harness_produces_no_findings() {
        let found = rules(
            "#include <stdint.h>\n#include <stddef.h>\n\
             int parse(const uint8_t *, size_t);\n\
             int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
             \x20 if (size == 0) return 0;\n\
             \x20 parse(data, size);\n\
             \x20 return 0;\n}",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn blocking_findings_are_errors_only() {
        let warnings = lint_harness_source("void f(void){ srand(1); }", TargetLanguage::C);
        assert!(!has_blocking_finding(&warnings), "{warnings:?}");
        let errors = lint_harness_source("void f(void){ abort(); }", TargetLanguage::C);
        assert!(has_blocking_finding(&errors), "{errors:?}");
    }

    #[test]
    fn rendered_findings_name_the_rule_and_line() {
        let findings = lint_harness_source("void f(void){ abort(); }", TargetLanguage::C);
        let rendered = render_findings(&findings);
        assert!(rendered.contains("no-process-exit"), "{rendered}");
        assert!(rendered.contains("line 1"), "{rendered}");
        assert!(rendered.starts_with("error:"), "{rendered}");
    }

    #[test]
    fn no_findings_render_as_an_empty_string() {
        assert!(render_findings(&[]).is_empty());
    }

    #[test]
    fn non_c_languages_are_not_linted_yet() {
        assert!(lint_harness_source("std::process::exit(1);", TargetLanguage::Rust).is_empty());
    }
}
