//! Recognition of textual identifiers for engines retired from active use.

/// Canonical wire identifier retained only for migration and targeted errors.
pub const RETIRED_ENGINE_ID: &str = "clusterfuzzlite";

/// Canonical identifier and former aliases retained for persistence boundaries.
pub const RETIRED_ENGINE_IDS: &[&str] = &[RETIRED_ENGINE_ID, "cfl", "cflite"];

/// Whether `value` names the retired engine or one of its former aliases.
#[must_use]
pub fn is_retired_engine_id(value: &str) -> bool {
    let value = value.trim();
    RETIRED_ENGINE_IDS
        .iter()
        .any(|identifier| value.eq_ignore_ascii_case(identifier))
}

#[cfg(test)]
mod tests {
    use super::{is_retired_engine_id, RETIRED_ENGINE_ID, RETIRED_ENGINE_IDS};

    #[test]
    fn exposes_retired_identifiers_for_bound_persistence_queries() {
        assert_eq!(RETIRED_ENGINE_IDS, &[RETIRED_ENGINE_ID, "cfl", "cflite"]);
    }

    #[test]
    fn recognizes_only_retired_engine_identifiers() {
        for value in ["clusterfuzzlite", " ClusterFuzzLite ", "cfl", "CFLITE"] {
            assert!(is_retired_engine_id(value), "{value}");
        }
        for value in ["libfuzzer", "afl++", "honggfuzz", "syzkaller", "cflx"] {
            assert!(!is_retired_engine_id(value), "{value}");
        }
    }
}
