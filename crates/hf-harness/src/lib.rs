//! hf-harness: Harness generation, compile validation, smoke fuzz.
//!
//! See `docs/design/harness-generation-design.md` and
//! `docs/standards/HARNESS_STANDARD.md`.

pub mod cargo_fuzz;
pub mod generator;
pub mod lint;
pub mod persistent;

pub use lint::{
    harness_rules, has_blocking_finding, lint_harness_source, render_findings, HarnessRuleSummary,
    LintFinding, LintSeverity,
};

pub use generator::{
    build_command, build_command_for_source, cmplog_build_command, cmplog_build_command_for_source,
    compile, compile_with_options, draft, draft_persistent_with_examples, draft_with_context,
    draft_with_examples, generate_seeds, list_c_files, refine, repair, smoke_fuzz, smoke_fuzz_in,
    smoke_fuzz_in_paths, smoke_fuzz_in_paths_with_config,
    smoke_fuzz_in_paths_with_config_and_sandbox_image, summarize_diagnostics, try_compile,
    try_compile_with_options, CompileFailure, CompileResult, AFL_LLVM_CMPLOG_ENV,
    MAX_DISTINCT_DIAGNOSTIC_LINES, MAX_REPAIR_DIAGNOSTICS_CHARS,
};
