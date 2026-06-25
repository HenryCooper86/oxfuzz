//! hf-engine: Fuzzing engine adapters.
//!
//! Each engine implements the [`EngineAdapter`](registry::EngineAdapter) trait
//! (argument construction); the [`EngineRunner`](runner::EngineRunner) executes
//! the command via `hf-runtime` and parses progress/coverage uniformly. Covers
//! AFL++, honggfuzz, libFuzzer, `ClusterFuzzLite`, and syzkaller. See
//! `docs/design/engine-integration-design.md` and
//! `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

pub mod afl;
pub mod clusterfuzzlite;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod progress;
pub mod registry;
pub mod runner;
pub mod syzkaller;

pub use registry::{adapter_for, EngineAdapter};
