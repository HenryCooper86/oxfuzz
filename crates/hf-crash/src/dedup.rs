//! Deduplication of crashes by stack signature.

use hf_core::crash::Crash;

/// Deduplicate crashes by stack signature, keeping one representative per group.
#[must_use]
pub fn dedup(crashes: Vec<Crash>) -> Vec<Crash> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for crash in crashes {
        if crash.stack_signature.is_empty() {
            // No signature (e.g. AFL++ raw crash): keep all.
            result.push(crash);
            continue;
        }
        if seen.insert(crash.stack_signature.clone()) {
            result.push(crash);
        }
    }
    result
}
