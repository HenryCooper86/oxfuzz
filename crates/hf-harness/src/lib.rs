//! hf-harness: Harness generation, compile validation, smoke fuzz.
//!
//! See `docs/design/harness-generation-design.md` and
//! `docs/standards/HARNESS_STANDARD.md`.

pub mod cargo_fuzz;
pub mod generator;

pub use generator::{
    build_command, compile, draft, generate_seeds, refine, repair, smoke_fuzz, smoke_fuzz_in,
    try_compile, CompileFailure, CompileResult, MAX_REPAIR_DIAGNOSTICS_CHARS,
};
