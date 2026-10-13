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
#[serde(deny_unknown_fields)]
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

/// Language sets reused across rules, one home per meaning (Engineering Protocol 2.18).
const LANGS_C_CPP: &[TargetLanguage] = &[TargetLanguage::C, TargetLanguage::Cpp];
const LANGS_C_CPP_RUST: &[TargetLanguage] =
    &[TargetLanguage::C, TargetLanguage::Cpp, TargetLanguage::Rust];
const LANGS_C_CPP_PYTHON: &[TargetLanguage] = &[
    TargetLanguage::C,
    TargetLanguage::Cpp,
    TargetLanguage::Python,
];
const LANGS_ALL: &[TargetLanguage] = &[
    TargetLanguage::C,
    TargetLanguage::Cpp,
    TargetLanguage::Rust,
    TargetLanguage::Python,
];
const LANGS_CPP: &[TargetLanguage] = &[TargetLanguage::Cpp];
const LANGS_RUST: &[TargetLanguage] = &[TargetLanguage::Rust];
const LANGS_PYTHON: &[TargetLanguage] = &[TargetLanguage::Python];

/// One lexical rule.
struct Rule {
    id: &'static str,
    severity: LintSeverity,
    message: &'static str,
    pattern: &'static str,
    /// Languages the rule applies to; a rule whose spelling belongs to one
    /// language must not fire on another (`Command::new` in a C file is an
    /// ordinary call).
    languages: &'static [TargetLanguage],
}

/// The harness rules.
///
/// File I/O is deliberately absent: an AFL++ file-mode harness must open
/// `argv[1]`, so a rule against `fopen` would fire on correct code, and a check
/// with false positives on the common case gets ignored.
///
/// Each call pattern requires a non-identifier character before the name and an
/// opening parenthesis after it, so `exit_code` and `parse_time` are not calls
/// to `exit` and `time`. Rust and Python path-qualified calls
/// (`std::process::exit`, `sys.exit`, `time.sleep`) match the same way: the
/// `::`/`.` separator before the name is a non-identifier character.
const RULES: [Rule; 13] = [
    Rule {
        id: "no-process-exit",
        severity: LintSeverity::Error,
        message: "do not terminate the process on malformed input: every such input then \
                  looks like a crash, and the fuzz run ends. Return early instead.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:_exit|exit|abort)\s*\(",
        languages: LANGS_ALL,
    },
    Rule {
        id: "no-shell",
        severity: LintSeverity::Error,
        message: "do not spawn a process from a harness: the sandbox is the only execution \
                  authority, and a shell escapes what the fuzzer is measuring.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:system|popen|execlp|execl|execvp|execv)\s*\(",
        languages: LANGS_C_CPP_PYTHON,
    },
    Rule {
        id: "no-sleep",
        severity: LintSeverity::Error,
        message: "do not sleep in the fuzz loop: it destroys throughput and a slow input \
                  is reported as a hang.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:nanosleep|usleep|sleep)\s*\(",
        languages: LANGS_ALL,
    },
    Rule {
        id: "no-network",
        severity: LintSeverity::Error,
        message: "do not open a socket from a harness: it reaches outside the sandbox and \
                  makes the result depend on a service the run does not control.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:socket|connect|listen|accept|bind)\s*\(",
        languages: LANGS_ALL,
    },
    Rule {
        id: "no-signal-handler",
        severity: LintSeverity::Warning,
        message: "a signal handler can swallow the fault the sanitizer is meant to report, \
                  turning a real crash into a silent pass.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:sigaction|signal)\s*\(",
        languages: LANGS_C_CPP,
    },
    Rule {
        id: "no-nondeterminism",
        severity: LintSeverity::Warning,
        message: "branch only on the input bytes: a clock or RNG makes a crash \
                  irreproducible and breaks corpus minimization.",
        pattern: r"(?:^|[^A-Za-z0-9_])(?:srandom|srand|random|rand|clock|time)\s*\(",
        languages: LANGS_C_CPP_RUST,
    },
    Rule {
        id: "no-catch-all",
        severity: LintSeverity::Warning,
        message: "a catch-all handler hides target failures the fuzzer exists to observe; \
                  catch only what the API documents as expected.",
        pattern: r"catch\s*\(\s*\.\.\.\s*\)",
        languages: LANGS_CPP,
    },
    Rule {
        id: "no-strlen-on-fuzz-data",
        severity: LintSeverity::Warning,
        message: "fuzz input is not NUL-terminated, so treating it as a C string reads past \
                  the buffer inside the harness itself; use the size argument.",
        pattern: r"strlen\s*\(\s*(?:\([^)]*\)\s*)?(?:data|Data|buf)\s*\)",
        languages: LANGS_C_CPP,
    },
    Rule {
        id: "no-process-spawn",
        severity: LintSeverity::Error,
        message: "do not spawn a process from a Rust harness: the sandbox is the only \
                  execution authority, and a child process escapes what the fuzzer is \
                  measuring.",
        pattern: r"(?:^|[^A-Za-z0-9_])Command\s*::\s*new\s*\(",
        languages: LANGS_RUST,
    },
    Rule {
        id: "no-catch-unwind",
        severity: LintSeverity::Warning,
        message: "catch_unwind hides the panic the fuzzing runtime treats as a finding, \
                  turning a real crash into a silent pass; let the panic propagate.",
        pattern: r"(?:^|[^A-Za-z0-9_])catch_unwind\s*\(",
        languages: LANGS_RUST,
    },
    Rule {
        id: "no-subprocess",
        severity: LintSeverity::Error,
        message: "do not run a subprocess from a Python harness: the sandbox is the only \
                  execution authority, and a child process escapes what the fuzzer is \
                  measuring.",
        pattern: r"(?:^|[^A-Za-z0-9_])subprocess\s*\.",
        languages: LANGS_PYTHON,
    },
    Rule {
        id: "no-random-module",
        severity: LintSeverity::Warning,
        message: "branch only on the input bytes: the random module makes a crash \
                  irreproducible and breaks corpus minimization.",
        pattern: r"(?:^|[^A-Za-z0-9_])random\s*\.",
        languages: LANGS_PYTHON,
    },
    Rule {
        id: "no-bare-except",
        severity: LintSeverity::Warning,
        message: "a bare except hides target failures the fuzzer exists to observe; catch \
                  only what the API documents as expected.",
        pattern: r"except\s*:",
        languages: LANGS_PYTHON,
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
    /// Languages the rule applies to, as canonical ids (`TargetLanguage::as_str`).
    pub languages: Vec<&'static str>,
}

/// A whole-source structural rule. The persistent-mode hazards are properties
/// of the harness's overall shape (a missing macro, file-scope mutable state),
/// not one call site, so they cannot live in the per-line `Rule` table. They
/// apply only to a source that carries an AFL++ persistent marker: scoping the
/// heuristic to the shape it describes keeps ordinary driver harnesses free of
/// these findings.
struct StructuralRule {
    id: &'static str,
    message: &'static str,
}

const PERSISTENT_STRUCTURAL_RULES: [StructuralRule; 3] = [
    StructuralRule {
        id: "persistent-loop-without-shm-init",
        message: "the __AFL_LOOP persistent loop reads its input through \
                  __AFL_FUZZ_TESTCASE_BUF/LEN, which only __AFL_FUZZ_INIT() backs; without \
                  it the harness runs empty iterations. Add `__AFL_FUZZ_INIT();` at file scope.",
    },
    StructuralRule {
        id: "persistent-shm-init-without-loop",
        message: "__AFL_FUZZ_INIT() without __AFL_LOOP(N) serves one input per forked child \
                  and re-forks for the next, so the persistent-mode reuse this harness was \
                  built for never happens. Drive the target from `while (__AFL_LOOP(N))`.",
    },
    StructuralRule {
        id: "persistent-mutable-global",
        message: "a persistent harness reuses one process for many inputs: re-initialize \
                  every mutable file-scope variable in the per-iteration reset, or state \
                  leaks between inputs and findings stop reproducing. Make it const, move \
                  it into the call, or reset it.",
    },
];

/// Every harness rule the lint enforces.
///
/// Exposed so an authoring packet can state the constraints up front instead of
/// letting an author discover them as compile failures, and so the packet
/// cannot drift from what the lint actually checks (Engineering Protocol 2.18).
#[must_use]
pub fn harness_rules() -> Vec<HarnessRuleSummary> {
    RULES
        .iter()
        .map(|rule| HarnessRuleSummary {
            id: rule.id.to_owned(),
            severity: rule.severity,
            message: rule.message.to_owned(),
            languages: rule.languages.iter().map(|lang| lang.as_str()).collect(),
        })
        .chain(
            PERSISTENT_STRUCTURAL_RULES
                .iter()
                .map(|rule| HarnessRuleSummary {
                    id: rule.id.to_owned(),
                    severity: LintSeverity::Warning,
                    message: rule.message.to_owned(),
                    languages: vec!["c", "cpp"],
                }),
        )
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
///
/// `#` is a comment opener only for Python: in C it opens a preprocessor
/// directive, which the rules may legitimately need to see.
pub(crate) fn is_comment_line(line: &str, language: TargetLanguage) -> bool {
    let trimmed = line.trim_start();
    if language == TargetLanguage::Python {
        return trimmed.starts_with('#');
    }
    trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
}

/// Check generated harness source against the harness rules.
///
/// Rules are scoped per language: C, C++, Rust (cargo-fuzz/libFuzzer targets),
/// and Python (Atheris) have rule sets; a language without one (Go) returns an
/// empty vec, which means unchecked rather than clean.
///
/// At most one finding per rule per line, ordered by line then rule, so the
/// output is stable enough to assert on and to put in a prompt.
#[must_use]
pub fn lint_harness_source(source: &str, language: TargetLanguage) -> Vec<LintFinding> {
    let patterns = compiled_rules();
    let mut seen: HashSet<(u32, &'static str)> = HashSet::new();
    let mut findings = Vec::new();

    for (index, line) in source.lines().enumerate() {
        if is_comment_line(line, language) {
            continue;
        }
        // `lines()` cannot yield more entries than the source has bytes, and a
        // source that large never reaches here; saturating keeps the cast total.
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        for (rule, pattern) in RULES.iter().zip(patterns) {
            if !rule.languages.contains(&language) {
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
    if matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
        lint_persistent_structure(source, &mut findings);
    }
    findings.sort_by(|a, b| a.line.cmp(&b.line).then_with(|| a.rule.cmp(&b.rule)));
    findings
}

/// The mutable file-scope definition shape: `<type words> <name> = ...` or
/// `<type words> <name>[...] ;`, at column 0. A `(` right after the name marks
/// a function, which the shape never matches.
fn mutable_definition_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(
            r"^[A-Za-z_][A-Za-z0-9_ ]*\*?\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^\]]*\])?\s*(?:=[^=]|;)",
        )
        .expect("the mutable-definition pattern is a compile-time constant")
    })
}

/// Lexical approximation of a mutable file-scope variable definition. Used
/// only to advise (warning tier): `typedef`/`extern` carry no storage here, a
/// `const` token anywhere makes the object read-only, and only column-0 lines
/// are candidates.
fn is_mutable_file_scope_definition(line: &str) -> bool {
    if line.is_empty() || line.starts_with([' ', '\t']) || line.starts_with('#') {
        return false;
    }
    let first = line.split([' ', '\t']).next().unwrap_or_default();
    if first == "typedef" || first == "extern" {
        return false;
    }
    if crate::persistent::line_has_word(line, "const") {
        return false;
    }
    mutable_definition_pattern().is_match(line)
}

/// Structural rules for an AFL++ persistent-mode harness (one carrying a
/// `__AFL_LOOP`/`__AFL_FUZZ_INIT` call): the loop and the shared-memory init
/// need each other, and every mutable file-scope variable is state that must
/// survive the per-iteration reset. All findings are warnings: the
/// compiler/linker hard-fails the structurally broken pairings already
/// (undefined `__afl_fuzz_*` globals), so the lint advises rather than blocks.
fn lint_persistent_structure(source: &str, findings: &mut Vec<LintFinding>) {
    let mut loop_line: Option<u32> = None;
    let mut init_line: Option<u32> = None;
    for (index, line) in source.lines().enumerate() {
        if is_comment_line(line, TargetLanguage::C) {
            continue;
        }
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        if loop_line.is_none() && crate::persistent::line_calls_macro(line, "__AFL_LOOP") {
            loop_line = Some(number);
        }
        if init_line.is_none() && crate::persistent::line_calls_macro(line, "__AFL_FUZZ_INIT") {
            init_line = Some(number);
        }
    }
    match (loop_line, init_line) {
        (None, None) => return,
        (Some(line), None) => findings.push(LintFinding {
            severity: LintSeverity::Warning,
            rule: PERSISTENT_STRUCTURAL_RULES[0].id.to_owned(),
            message: PERSISTENT_STRUCTURAL_RULES[0].message.to_owned(),
            line,
        }),
        (None, Some(line)) => findings.push(LintFinding {
            severity: LintSeverity::Warning,
            rule: PERSISTENT_STRUCTURAL_RULES[1].id.to_owned(),
            message: PERSISTENT_STRUCTURAL_RULES[1].message.to_owned(),
            line,
        }),
        (Some(_), Some(_)) => {}
    }
    for (index, line) in source.lines().enumerate() {
        if is_comment_line(line, TargetLanguage::C) || !is_mutable_file_scope_definition(line) {
            continue;
        }
        findings.push(LintFinding {
            severity: LintSeverity::Warning,
            rule: PERSISTENT_STRUCTURAL_RULES[2].id.to_owned(),
            message: PERSISTENT_STRUCTURAL_RULES[2].message.to_owned(),
            line: u32::try_from(index + 1).unwrap_or(u32::MAX),
        });
    }
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
    fn flags_rust_process_exit_and_process_spawn_as_errors() {
        let source = "fuzz_target!(|data: &[u8]| {\n\
                      \x20   if data.is_empty() { std::process::exit(1); }\n\
                      \x20   let _ = std::process::Command::new(\"sh\").output();\n\
                      });\n";
        let findings = lint_harness_source(source, TargetLanguage::Rust);
        let found: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
        assert!(
            found.contains(&"no-process-exit".to_owned()),
            "{findings:?}"
        );
        assert!(
            found.contains(&"no-process-spawn".to_owned()),
            "{findings:?}"
        );
        assert!(
            findings.iter().all(|f| f.severity == LintSeverity::Error),
            "{findings:?}"
        );
    }

    #[test]
    fn flags_rust_sleep_network_and_catch_unwind() {
        let source = "fn drive(data: &[u8]) {\n\
                      \x20   std::thread::sleep(std::time::Duration::from_secs(1));\n\
                      \x20   let _ = std::net::TcpStream::connect(\"127.0.0.1:80\");\n\
                      \x20   let _ = std::panic::catch_unwind(|| data[0]);\n\
                      }\n";
        let findings = lint_harness_source(source, TargetLanguage::Rust);
        let found: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
        assert!(found.contains(&"no-sleep".to_owned()), "{findings:?}");
        assert!(found.contains(&"no-network".to_owned()), "{findings:?}");
        assert!(
            found.contains(&"no-catch-unwind".to_owned()),
            "{findings:?}"
        );
    }

    #[test]
    fn rust_rules_do_not_apply_to_c_sources() {
        // The Rust-specific rules must stay language-scoped: the same tokens in
        // a C file are not the behaviours the rules name.
        let found = rules("int f(void){ Command_new(); catch_unwind(); return 0; }");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn flags_python_exit_subprocess_and_bare_except() {
        let source = "import subprocess\nimport sys\n\n\
                      def TestOneInput(data):\n\
                      \x20   if len(data) < 1:\n\
                      \x20       sys.exit(1)\n\
                      \x20   try:\n\
                      \x20       subprocess.run([\"ls\"])\n\
                      \x20   except:\n\
                      \x20       pass\n\
                      \x20   return 0\n";
        let findings = lint_harness_source(source, TargetLanguage::Python);
        let found: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
        assert!(
            found.contains(&"no-process-exit".to_owned()),
            "{findings:?}"
        );
        assert!(found.contains(&"no-subprocess".to_owned()), "{findings:?}");
        assert!(found.contains(&"no-bare-except".to_owned()), "{findings:?}");
    }

    #[test]
    fn flags_python_sleep_and_random_module() {
        let source = "import random\nimport time\n\n\
                      def TestOneInput(data):\n\
                      \x20   time.sleep(1)\n\
                      \x20   if random.randint(0, 9) == data[0]:\n\
                      \x20       return -1\n\
                      \x20   return 0\n";
        let findings = lint_harness_source(source, TargetLanguage::Python);
        let found: Vec<String> = findings.iter().map(|f| f.rule.clone()).collect();
        assert!(found.contains(&"no-sleep".to_owned()), "{findings:?}");
        assert!(
            found.contains(&"no-random-module".to_owned()),
            "{findings:?}"
        );
    }

    #[test]
    fn python_comment_lines_are_skipped() {
        let source = "# sys.exit(1) must never run\n# subprocess.run([]) neither\n\
                      def TestOneInput(data): return 0\n";
        assert!(lint_harness_source(source, TargetLanguage::Python).is_empty());
    }

    #[test]
    fn go_harnesses_are_not_linted_yet() {
        // Go has no rule set yet: unchecked rather than clean.
        assert!(
            lint_harness_source("func Fuzz(f *testing.F) { os.Exit(1) }", TargetLanguage::Go)
                .is_empty()
        );
    }

    #[test]
    fn harness_rules_name_their_languages() {
        let all = harness_rules();
        let spawn = all
            .iter()
            .find(|rule| rule.id == "no-process-spawn")
            .expect("no-process-spawn is a rule");
        assert_eq!(spawn.languages, vec!["rust"]);
        let catch_all = all
            .iter()
            .find(|rule| rule.id == "no-catch-all")
            .expect("no-catch-all is a rule");
        assert_eq!(catch_all.languages, vec!["cpp"]);
    }

    // -- AFL++ persistent-mode structural rules -------------------------------

    /// A canonical persistent-mode harness skeleton for these tests.
    fn persistent_source() -> String {
        crate::persistent::render_harness_source(&crate::persistent::PersistentHarnessParts {
            symbol: "parse_entry",
            location: "src/parse.c:42",
            signature: Some("int parse_entry(const uint8_t *data, size_t len)"),
            includes: "",
            forward_decl: "int parse_entry(const uint8_t *data, size_t len);",
            body: "    parse_entry((const uint8_t *)data, size);",
        })
    }

    #[test]
    fn a_loop_without_shm_init_is_a_warning() {
        // The shared-memory input macros have no backing globals without
        // __AFL_FUZZ_INIT(), so this harness reads no fuzzer input.
        let source = "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n\
                      int main(void) {\n\
                      \x20   while (__AFL_LOOP(1000)) { }\n\
                      \x20   return 0;\n\
                      }\n";
        let findings = lint_harness_source(source, TargetLanguage::C);
        let finding = findings
            .iter()
            .find(|f| f.rule == "persistent-loop-without-shm-init")
            .expect("the missing shm init must be named");
        assert_eq!(finding.severity, LintSeverity::Warning);
        assert_eq!(finding.line, 3);
    }

    #[test]
    fn shm_init_without_a_loop_is_a_warning() {
        // One input per forked child: the persistent reuse never happens.
        let source = "__AFL_FUZZ_INIT();\n\
                      int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);\n\
                      int main(void) { return 0; }\n";
        let findings = lint_harness_source(source, TargetLanguage::C);
        let finding = findings
            .iter()
            .find(|f| f.rule == "persistent-shm-init-without-loop")
            .expect("the missing loop must be named");
        assert_eq!(finding.severity, LintSeverity::Warning);
        assert_eq!(finding.line, 1);
    }

    #[test]
    fn a_complete_persistent_structure_draws_no_structural_findings() {
        let findings = lint_harness_source(&persistent_source(), TargetLanguage::C);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn mutable_file_scope_state_in_a_persistent_harness_is_a_warning() {
        let source = format!("static int calls_so_far = 0;\n{}", persistent_source());
        let findings = lint_harness_source(&source, TargetLanguage::C);
        let finding = findings
            .iter()
            .find(|f| f.rule == "persistent-mutable-global")
            .expect("mutable file-scope state must be named");
        assert_eq!(finding.severity, LintSeverity::Warning);
        assert_eq!(finding.line, 1);
        assert!(finding.message.contains("reset"), "{}", finding.message);
    }

    #[test]
    fn mutable_global_variants_match_and_safe_forms_do_not() {
        let persistent = persistent_source();
        let flagged = [
            "int g_state = 0;",
            "static int g_state;",
            "static uint8_t g_buf[4096];",
            "char *g_buf = NULL;",
            "struct ctx g_ctx = {0};",
            "volatile unsigned long g_tick;",
        ];
        for line in flagged {
            let source = format!("{line}\n{persistent}");
            let findings = lint_harness_source(&source, TargetLanguage::C);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule == "persistent-mutable-global"),
                "must flag `{line}`"
            );
        }
        let clean = [
            // Read-only tables are not leakable state.
            "static const int TABLE[4] = {0};",
            "const char *const NAMES[] = {\"a\"};",
            // A typedef introduces no storage; an extern declaration defines none.
            "typedef unsigned int u32;",
            "extern int shared_elsewhere;",
            // Directives and declarations.
            "#define LIMIT 5",
            "int parse_entry(const uint8_t *data, size_t len);",
            // A local variable inside a function body is per-call state.
            "    int counter = 0;",
        ];
        for line in clean {
            let source = format!("{line}\n{persistent}");
            let findings = lint_harness_source(&source, TargetLanguage::C);
            assert!(
                !findings
                    .iter()
                    .any(|f| f.rule == "persistent-mutable-global"),
                "must not flag `{line}`"
            );
        }
    }

    #[test]
    fn the_persistent_rules_do_not_fire_on_driver_style_sources() {
        // Scoping: the same mutable global in a driver-style harness is the
        // driver's loop discipline, outside this rule's scope.
        let source = "static int counter = 0;\n\
                      int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n";
        let findings = lint_harness_source(source, TargetLanguage::C);
        assert!(
            !findings.iter().any(|f| f.rule.starts_with("persistent-")),
            "{findings:?}"
        );
    }

    #[test]
    fn the_persistent_rules_are_c_family_only() {
        let findings = lint_harness_source(&persistent_source(), TargetLanguage::Rust);
        assert!(
            !findings.iter().any(|f| f.rule.starts_with("persistent-")),
            "{findings:?}"
        );
    }

    #[test]
    fn the_persistent_rules_are_listed_for_authors() {
        let all = harness_rules();
        for id in [
            "persistent-loop-without-shm-init",
            "persistent-shm-init-without-loop",
            "persistent-mutable-global",
        ] {
            let rule = all.iter().find(|rule| rule.id == id).expect(id);
            assert_eq!(rule.severity, LintSeverity::Warning);
            assert_eq!(rule.languages, vec!["c", "cpp"]);
        }
    }

    #[test]
    fn comment_only_marker_mentions_do_not_trigger_structural_rules() {
        let source = "// while (__AFL_LOOP(1000)) would go here\n\
                      int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n";
        let findings = lint_harness_source(source, TargetLanguage::C);
        assert!(
            !findings.iter().any(|f| f.rule.starts_with("persistent-")),
            "{findings:?}"
        );
    }
}
