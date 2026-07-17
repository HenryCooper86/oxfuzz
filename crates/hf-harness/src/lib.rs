//! hf-harness: Harness generation, compile validation, smoke fuzz.
//!
//! See `docs/design/harness-generation-design.md` and
//! `docs/standards/HARNESS_STANDARD.md`.

pub mod cargo_fuzz;
pub mod generator;

pub use generator::{
    build_command, compile, draft, draft_with_context, generate_seeds, refine, repair, smoke_fuzz,
    smoke_fuzz_in, smoke_fuzz_in_paths, smoke_fuzz_in_paths_with_config, try_compile,
    CompileFailure, CompileResult, MAX_REPAIR_DIAGNOSTICS_CHARS,
};
