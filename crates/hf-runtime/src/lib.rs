//! hf-runtime: Sandboxed runtime for harness builds and fuzz runs.
//!
//! Implements `RuntimeAdapter` from `hf-core`. Two backends:
//! - `DockerRuntime` (default, isolation via bollard).
//! - `StubRuntime` (development only, returns errors).
//!
//! See `docs/design/runtime-design.md` (to be written) and
//! `AGENTS.md` section 2.12 (Fuzzing Safety First).

pub mod adapter;
pub mod config;
pub mod docker;

pub use adapter::StubRuntime;
pub use config::{RuntimeBackend, RuntimeConfig};
