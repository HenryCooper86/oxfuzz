//! Recognition of textual identifiers for engines retired from active use.

/// Canonical wire identifier retained only for migration and targeted errors.
pub const RETIRED_ENGINE_ID: &str = "clusterfuzzlite";

/// Whether `value` names the retired engine or one of its former aliases.
#[must_use]
pub fn is_retired_engine_id(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        RETIRED_ENGINE_ID | "cfl" | "cflite"
    )
}

#[cfg(test)]
mod tests {
    use super::is_retired_engine_id;

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
