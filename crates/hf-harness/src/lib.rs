//! hf-harness: Harness generation, compile validation, smoke fuzz.
//!
//! See `docs/design/harness-generation-design.md` and
//! `docs/standards/HARNESS_STANDARD.md`.

pub mod cargo_fuzz;
pub mod generator;
pub mod lint;

pub use lint::{
    has_blocking_finding, lint_harness_source, render_findings, LintFinding, LintSeverity,
};

pub use generator::{
    build_command, compile, draft, draft_with_context, generate_seeds, refine, repair, smoke_fuzz,
    smoke_fuzz_in, smoke_fuzz_in_paths, smoke_fuzz_in_paths_with_config,
    smoke_fuzz_in_paths_with_config_and_sandbox_image, try_compile, CompileFailure, CompileResult,
    MAX_REPAIR_DIAGNOSTICS_CHARS,
};
