//! hf-runtime: Sandboxed runtime for harness builds and fuzz runs.
//!
//! Implements `RuntimeAdapter` from `hf-core`. Two backends are planned:
//! - `DockerRuntime` (default, isolation).
//! - `NativeRuntime` (development only, opt-in, never default).

#![allow(dead_code)]

pub mod adapter;
