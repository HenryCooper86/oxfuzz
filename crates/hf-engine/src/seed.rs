//! Deterministic run seeds.
//!
//! Every persisted run records a seed so the run can be re-executed exactly
//! (`hf-service::ServiceContainer::replay_run`). Only engines with a genuine
//! fixed-seed knob receive it; see `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use uuid::Uuid;

/// Derive the default seed for a run from its id, so every run is
/// reproducible by default even when no seed was explicitly requested.
///
/// The run id is a random UUID v4; folding its two 8-byte halves with XOR
/// spreads that entropy over the whole `u64`. The mapping is part of the
/// replay contract: changing it breaks reproduction of historical runs, so it
/// must stay stable across releases. Zero is remapped to one because
/// libFuzzer treats `-seed=0` as "generate a random seed".
#[must_use]
pub fn derive_run_seed(run_id: Uuid) -> u64 {
    let seed = run_id.as_bytes().chunks_exact(8).fold(0_u64, |acc, chunk| {
        acc ^ u64::from_le_bytes(chunk.try_into().unwrap_or_default())
    });
    if seed == 0 {
        1
    } else {
        seed
    }
}

#[cfg(test)]
mod tests {
    use super::derive_run_seed;
    use uuid::Uuid;

    #[test]
    fn nil_and_max_ids_do_not_panic() {
        assert_eq!(derive_run_seed(Uuid::nil()), 1);
        assert_ne!(derive_run_seed(Uuid::from_bytes([0xff; 16])), 0);
    }
}
