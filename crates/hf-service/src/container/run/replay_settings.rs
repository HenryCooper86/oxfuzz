//! Replay settings applied when a run is reserved.
use super::{FuzzRunConfig, ReplayProvenance, Uuid};

/// A replay keeps its original seed and records which run it replays; any
/// other run gets a seed derived from its own id.
pub(super) fn assign_replay_settings(
    run_id: Uuid,
    replay: Option<&ReplayProvenance>,
    config: &mut FuzzRunConfig,
) {
    let Some(provenance) = replay else {
        config
            .seed
            .get_or_insert_with(|| hf_engine::seed::derive_run_seed(run_id));
        return;
    };
    config.seed = Some(provenance.seed);
    config.replay_of = Some(provenance.original_run_id);
}
