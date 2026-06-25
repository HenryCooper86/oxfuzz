//! Engine adapters: map an [`EngineKind`] to its command-construction logic.
//!
//! New engines are added by implementing [`EngineAdapter`] and registering them
//! in [`adapter_for`] (AGENTS.md 2.1: extend via traits, not core changes).

use hf_core::engine::{EngineKind, FuzzRunConfig};

/// An engine adapter builds the sandboxed command line for a fuzz run. The
/// [`EngineRunner`](crate::runner::EngineRunner) parses progress/coverage from
/// the command's output uniformly, so adapters only own argument construction.
pub trait EngineAdapter: Send + Sync {
    /// The engine this adapter drives.
    fn kind(&self) -> EngineKind;

    /// Build the argv for a fuzz run. `binary` (or, for syzkaller, the manager
    /// config), `corpus`, and `out` are container-internal paths.
    fn build_run_args(
        &self,
        cfg: &FuzzRunConfig,
        binary: &str,
        corpus: &str,
        out: &str,
    ) -> Vec<String>;
}

macro_rules! impl_adapter {
    ($ty:path, $kind:expr, $args:path) => {
        impl EngineAdapter for $ty {
            fn kind(&self) -> EngineKind {
                $kind
            }
            fn build_run_args(
                &self,
                cfg: &FuzzRunConfig,
                binary: &str,
                corpus: &str,
                out: &str,
            ) -> Vec<String> {
                $args(cfg, binary, corpus, out)
            }
        }
    };
}

impl_adapter!(
    crate::libfuzzer::LibFuzzer,
    EngineKind::LibFuzzer,
    crate::libfuzzer::build_run_args
);
impl_adapter!(
    crate::afl::AflPlusPlus,
    EngineKind::AflPlusPlus,
    crate::afl::build_run_args
);
impl_adapter!(
    crate::honggfuzz::Honggfuzz,
    EngineKind::Honggfuzz,
    crate::honggfuzz::build_run_args
);
impl_adapter!(
    crate::clusterfuzzlite::ClusterFuzzLite,
    EngineKind::ClusterFuzzLite,
    crate::clusterfuzzlite::build_run_args
);
impl_adapter!(
    crate::syzkaller::Syzkaller,
    EngineKind::Syzkaller,
    crate::syzkaller::build_run_args
);

/// Return the adapter for an engine kind.
#[must_use]
pub fn adapter_for(kind: EngineKind) -> Box<dyn EngineAdapter> {
    match kind {
        EngineKind::LibFuzzer => Box::new(crate::libfuzzer::LibFuzzer),
        EngineKind::AflPlusPlus => Box::new(crate::afl::AflPlusPlus),
        EngineKind::Honggfuzz => Box::new(crate::honggfuzz::Honggfuzz),
        EngineKind::ClusterFuzzLite => Box::new(crate::clusterfuzzlite::ClusterFuzzLite),
        EngineKind::Syzkaller => Box::new(crate::syzkaller::Syzkaller),
    }
}
