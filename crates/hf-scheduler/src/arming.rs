//! Authorization to act on work restored after a restart.
//!
//! Recovery answers "what was this scheduler doing". Whether to carry on doing
//! it is a separate question, and after a restart the answer is "not until
//! someone says so": a process coming back up hours later, against a project
//! that may have changed underneath it, has no consent to resume a fuzzing
//! campaign on its own.
//!
//! [`ArmSignal`] pairs [`ArmedState`] -- which is never persisted, so no
//! restore path can produce an armed scheduler -- with the wakeup a waiting
//! producer needs. The state lives in `hf-core`, which has no async runtime, so
//! the notification half belongs here rather than there.
//!
//! See `docs/design/deepseek-harness-study.md` item 1.5.

use std::sync::Arc;

use hf_core::armed::ArmedState;
use tokio::sync::Notify;

/// Activation for restored work, with a wakeup for whoever is waiting on it.
///
/// Cheap to clone; every clone shares one authorization and one wakeup.
#[derive(Clone, Default)]
pub struct ArmSignal {
    state: ArmedState,
    changed: Arc<Notify>,
}

impl ArmSignal {
    /// Authorize restored work to proceed, releasing anything held.
    pub fn arm(&self) {
        self.state.arm();
        self.changed.notify_waiters();
    }

    /// Withdraw authorization. Work already submitted is not recalled; this
    /// stops what has not yet been released.
    pub fn disarm(&self) {
        self.state.disarm();
    }

    /// Whether restored work is currently authorized.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.state.is_armed()
    }

    /// Wait until armed.
    ///
    /// The waiter is registered *before* the state is read. Checking first
    /// would leave a window in which [`arm`](Self::arm) fires between the read
    /// and the registration, and the caller would wait for a notification that
    /// has already happened.
    pub async fn wait_until_armed(&self) {
        loop {
            let notified = self.changed.notified();
            if self.is_armed() {
                return;
            }
            notified.await;
        }
    }
}
