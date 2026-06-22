//! hf-engine: Fuzzing engine adapters.
//!
//! Implements `FuzzEngine` from `hf-core` for AFL++, honggfuzz, libFuzzer,
//! and ClusterFuzzLite. See `docs/design/engine-integration-design.md` and
//! `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

#![allow(dead_code)]

pub mod afl;
pub mod clusterfuzzlite;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod registry;

pub use registry::EngineRegistry;
