//! hf-harness: Harness generation, compile validation, smoke fuzz.
//!
//! See `docs/design/harness-generation-design.md` and
//! `docs/standards/HARNESS_STANDARD.md`.

pub mod cargo_fuzz;
pub mod generator;
pub mod go_native;
pub mod js_jazzer;
pub mod jvm_jazzer;
pub mod lint;
pub mod persistent;
pub mod project_sources;
pub mod python_atheris;

pub use lint::{
    harness_rules, has_blocking_finding, lint_harness_source, render_findings, HarnessRuleSummary,
    LintFinding, LintSeverity,
};

pub use generator::{
    build_command, build_command_for_source, cmplog_build_command, cmplog_build_command_for_source,
    compile_with_options, draft_analyzed, parse_seed_array, refine, render_finding_repair_request,
    repair, repairable_smoke_failure, repaired_source_from_response,
    smoke_fuzz_in_paths_with_config_and_sandbox_image, source_calls_symbol, source_defines_symbol,
    summarize_diagnostics, try_compile_with_options, try_compile_with_options_streaming,
    CompileFailure, CompileResult, HarnessDraftContext, AFL_LLVM_CMPLOG_ENV,
    MAX_DISTINCT_DIAGNOSTIC_LINES, MAX_REPAIR_DIAGNOSTICS_CHARS, SMOKE_NO_ACTIVITY,
    SMOKE_WALL_CLOCK_EXPIRED,
};

/// Native mutator source composition and sandbox build helpers.
pub mod grammar_mutator;
pub mod managed_mutator;
