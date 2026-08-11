//! hf-engine: Fuzzing engine adapters.
//!
//! Each engine implements the [`EngineAdapter`] trait
//! (argument construction); the [`EngineRunner`](runner::EngineRunner) executes
//! the command via `hf-runtime` and parses progress/coverage uniformly. Covers
//! AFL++, honggfuzz, libFuzzer, and syzkaller. See
//! `docs/design/engine-integration-design.md` and
//! `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

pub mod afl;
pub mod dict;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod progress;
pub mod registry;
pub mod runner;
pub mod seed;
pub mod showmap;
pub mod syzkaller;

pub use registry::{adapter_for, EngineAdapter};
