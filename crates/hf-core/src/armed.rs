//! Activation state for work restored after a restart.
//!
//! A crash or a quit leaves durable state behind: an interrupted run, a missed
//! schedule occurrence, a checkpoint. Restoring *what the system was doing* is
//! useful. Resuming it without asking is not: the operator who starts the
//! process again has not thereby consented to a fuzzing campaign picking up
//! where it left off, possibly hours later and against a project that has since
//! changed.
//!
//! [`ArmedState`] separates the two. It carries no data, only permission to
//! act, and it is **never persisted** -- there is deliberately no `Serialize`
//! or `Deserialize` implementation, so no restore path can produce an armed
//! state no matter what a file on disk claims. Every process starts disarmed
//! and stays that way until something explicitly arms it.
//!
//! This composes with, rather than replaces, the revision-bound approval
//! already in the codebase: after a restart a promoted revision's approval is
//! still valid, while the armed state is not.
//!
//! See `docs/design/deepseek-harness-study.md` item 1.5.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Whether this process may act on restored work.
///
/// Cheap to clone; every clone shares one authorization, so arming a session
/// is visible to each subsystem holding a handle and disarming stops all of
/// them.
#[derive(Clone, Debug)]
pub struct ArmedState(Arc<AtomicBool>);

impl ArmedState {
    /// A new, disarmed state. There is no armed constructor: arming is an
    /// action taken at a point in time, never an initial condition.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    /// Authorize this process to act on restored work.
    pub fn arm(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Withdraw authorization.
    pub fn disarm(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    /// Whether acting is currently authorized.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for ArmedState {
    /// Disarmed, so a caller that forgets to choose gets the safe state.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_state_is_disarmed() {
        assert!(!ArmedState::new().is_armed());
    }

    #[test]
    fn the_default_is_disarmed_so_forgetting_to_choose_is_safe() {
        assert!(!ArmedState::default().is_armed());
    }

    #[test]
    fn arming_is_explicit_and_observable() {
        let state = ArmedState::new();
        state.arm();
        assert!(state.is_armed());
    }

    #[test]
    fn disarming_returns_to_the_safe_state() {
        let state = ArmedState::new();
        state.arm();
        state.disarm();
        assert!(!state.is_armed());
    }

    #[test]
    fn clones_share_one_authorization() {
        // Handing the state to a subsystem must not fork it: arming the
        // session has to be visible everywhere the check is made, and
        // disarming has to actually stop everyone.
        let state = ArmedState::new();
        let handed_out = state.clone();
        state.arm();
        assert!(handed_out.is_armed());
        handed_out.disarm();
        assert!(!state.is_armed());
    }
}
