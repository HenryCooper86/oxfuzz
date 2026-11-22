//! The terminal figures an engine wrote to its own statistics file.
//!
//! AFL++ keeps `default/fuzzer_stats` and honggfuzz `honggfuzz.stats` in the
//! run output. These are the engine's own counters, so a figure the service
//! did not record live (a smoke run, a run stored before the counters were
//! read) is recovered from them rather than shown as zero.

use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;

/// Counters read from an engine's statistics file; each is absent when the
/// engine did not report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EngineFigures {
    pub edges: Option<u64>,
    pub execs_total: Option<u64>,
    pub saved_crashes: Option<u64>,
}

/// Read the figures `engine` left in `output`. `None` for an engine without a
/// statistics file, and for a missing or unreadable one: either way nothing is
/// recovered and the recorded figures stand.
pub(crate) fn read(engine: EngineKind, output: &Path) -> Option<EngineFigures> {
    match engine {
        // `.ok()`: an unreadable or malformed file recovers nothing, the same
        // outcome as a run that never wrote one.
        EngineKind::AflPlusPlus => hf_engine::afl::read_fuzzer_stats(output)
            .ok()
            .flatten()
            .map(|stats| EngineFigures {
                edges: stats.edges_found,
                execs_total: stats.execs_done,
                saved_crashes: stats.saved_crashes,
            }),
        // `.ok()`: as above.
        EngineKind::Honggfuzz => {
            hf_engine::honggfuzz::read_stats(output)
                .ok()
                .flatten()
                .map(|snapshot| EngineFigures {
                    edges: snapshot.stats.edges_covered,
                    execs_total: snapshot.stats.execs_total,
                    saved_crashes: Some(snapshot.saved_crashes),
                })
        }
        EngineKind::LibFuzzer
        | EngineKind::Syzkaller
        | EngineKind::GoNative
        | EngineKind::Atheris
        | EngineKind::Jazzer
        | EngineKind::JazzerJs => None,
    }
}

/// [`read`] on the blocking pool.
pub(crate) async fn read_async(engine: EngineKind, output: PathBuf) -> Option<EngineFigures> {
    // A failed blocking task recovers nothing, as an unreadable file does.
    tokio::task::spawn_blocking(move || read(engine, &output))
        .await
        .ok()
        .flatten()
}
