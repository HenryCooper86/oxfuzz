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
pub mod go_native;
pub mod honggfuzz;
pub mod libfuzzer;
pub mod progress;
pub mod registry;
pub mod runner;
pub mod seed;
pub mod showmap;
pub mod syzkaller;

pub use registry::{adapter_for, EngineAdapter};

/// Per-input timeout rendered in whole seconds for engines whose flag takes
/// seconds (libFuzzer `-timeout=`, honggfuzz `--timeout=`). Rounds up so a
/// sub-second budget never becomes 0, which libFuzzer reads as "no timeout".
pub(crate) fn timeout_secs_ceil(timeout: std::time::Duration) -> u64 {
    timeout_millis(timeout).div_ceil(1000).max(1)
}

/// Per-input timeout in exact milliseconds (AFL++ `-t`). The value is
/// range-validated against `fuzzing` policy before it enters a run config;
/// the saturating conversion only guards a hand-built config, which no
/// service path produces.
pub(crate) fn timeout_millis(timeout: std::time::Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}
