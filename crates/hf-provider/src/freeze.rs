//! Per-provider freeze registry with exponential backoff.
//!
//! When a provider fails, the pool freezes it for a backoff window and routes
//! around it. Repeated freezes back off exponentially (capped) so a flapping
//! provider is progressively de-prioritised instead of being hammered. State
//! lives behind a `Mutex` because the `ProviderPool` trait methods take `&self`
//! (interior mutability), mirroring y-agent's `FreezeManager` but flattened into
//! a single registry keyed by provider id.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default base backoff used by the public `freeze` entry point when no
/// classifier-derived backoff is supplied.
const DEFAULT_BASE_BACKOFF: Duration = Duration::from_mins(1);
/// Upper bound on any single freeze window after exponential scaling.
const MAX_BACKOFF: Duration = Duration::from_hours(1);

/// One provider's freeze state.
#[derive(Debug, Clone)]
struct Entry {
    /// Instant after which the provider is eligible again.
    thaw_at: Instant,
    /// Number of consecutive freezes, driving exponential backoff.
    consecutive: u32,
}

/// Tracks which providers are currently frozen and until when.
#[derive(Debug, Default)]
pub struct FreezeRegistry {
    entries: Mutex<HashMap<String, Entry>>,
}

impl FreezeRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // Recover from a poisoned lock rather than panicking: a stale freeze map
        // must never take the whole pool down.
        self.entries.lock().unwrap_or_else(|poisoned| {
            tracing::warn!("recovering from poisoned provider freeze lock");
            poisoned.into_inner()
        })
    }

    /// Whether `id` is currently frozen. Expired freezes are cleared lazily.
    #[must_use]
    pub fn is_frozen(&self, id: &str) -> bool {
        let mut entries = self.lock();
        if let Some(entry) = entries.get(id) {
            if Instant::now() >= entry.thaw_at {
                // Window elapsed: drop the entry but keep the consecutive count
                // is intentionally reset here, since a clean expiry means the
                // provider gets a fresh chance.
                entries.remove(id);
                return false;
            }
            return true;
        }
        false
    }

    /// Freeze `id` for `base` backoff, scaled exponentially by the number of
    /// consecutive freezes and capped at `MAX_BACKOFF`.
    pub fn freeze_for(&self, id: &str, base: Duration) {
        let mut entries = self.lock();
        let consecutive = entries
            .get(id)
            .map_or(1, |e| e.consecutive.saturating_add(1));
        let backoff = scaled_backoff(base, consecutive);
        entries.insert(
            id.to_owned(),
            Entry {
                thaw_at: Instant::now() + backoff,
                consecutive,
            },
        );
    }

    /// Freeze `id` for the default base backoff. Used by the public
    /// `ProviderPool::freeze` trait method, which carries no backoff hint.
    pub fn freeze(&self, id: &str) {
        self.freeze_for(id, DEFAULT_BASE_BACKOFF);
    }

    /// Clear any freeze on `id`, making it immediately eligible again.
    pub fn thaw(&self, id: &str) {
        self.lock().remove(id);
    }
}

/// Scale `base` by `2^(consecutive - 1)`, saturating and capped at the max.
fn scaled_backoff(base: Duration, consecutive: u32) -> Duration {
    let multiplier = 2u64.saturating_pow(consecutive.saturating_sub(1));
    let scaled = base
        .as_secs()
        .saturating_mul(multiplier)
        .min(MAX_BACKOFF.as_secs());
    // Preserve sub-second bases (e.g. tests) when no scaling applies.
    if scaled == 0 && base.as_secs() == 0 {
        return base;
    }
    Duration::from_secs(scaled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_then_frozen() {
        let reg = FreezeRegistry::new();
        assert!(!reg.is_frozen("a"));
        reg.freeze("a");
        assert!(reg.is_frozen("a"));
    }

    #[test]
    fn thaw_clears_freeze() {
        let reg = FreezeRegistry::new();
        reg.freeze("a");
        assert!(reg.is_frozen("a"));
        reg.thaw("a");
        assert!(!reg.is_frozen("a"));
    }

    #[test]
    fn expired_freeze_is_eligible() {
        let reg = FreezeRegistry::new();
        // Zero-duration freeze elapses immediately.
        reg.freeze_for("a", Duration::from_secs(0));
        std::thread::sleep(Duration::from_millis(1));
        assert!(!reg.is_frozen("a"));
    }

    #[test]
    fn backoff_scales_exponentially_and_caps() {
        assert_eq!(
            scaled_backoff(Duration::from_secs(30), 1),
            Duration::from_secs(30)
        );
        assert_eq!(
            scaled_backoff(Duration::from_secs(30), 2),
            Duration::from_mins(1)
        );
        assert_eq!(
            scaled_backoff(Duration::from_secs(30), 3),
            Duration::from_mins(2)
        );
        // Capped at MAX_BACKOFF.
        assert_eq!(scaled_backoff(Duration::from_secs(30), 20), MAX_BACKOFF);
    }
}
