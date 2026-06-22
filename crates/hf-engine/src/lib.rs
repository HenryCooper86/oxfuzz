//! hf-engine: Fuzzing engine adapters.
//!
//! Implements `FuzzEngine` from `hf-core` for AFL++, honggfuzz, libFuzzer,
//! and `ClusterFuzzLite`. See `docs/design/engine-integration-design.md` and
//! `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

pub mod afl;
pub mod clusterfuzzlite;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod progress;
pub mod registry;
pub mod runner;

pub use registry::EngineRegistry;
