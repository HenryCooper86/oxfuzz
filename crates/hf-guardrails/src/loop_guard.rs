//! `LoopGuard`: runaway-loop detection for the agent's reason/act loop.
//!
//! `max_iterations` in the agent is only a hard backstop; it still burns a full
//! budget of (paid) LLM calls on a stuck loop. The `LoopGuard` catches the
//! common runaway shapes early and aborts with a clear reason. It is fed one
//! [`StepRecord`] per agent step and reports the first pattern it sees:
//!
//! - **Repetition**: the same action repeated N times consecutively.
//! - **Oscillation**: a short A, B, A, B cycle.
//! - **`RedundantToolCall`**: the same tool with the same arguments repeated.
//! - **Drift**: no new distinct action over a sliding window.
//!
//! Adapted from y-agent's `loop_guard`, flattened to be dependency-light: the
//! config, pattern enum, and detection result all live here.

use std::collections::VecDeque;

/// Loop pattern kinds the guard can detect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopPattern {
    /// The same action repeated N times consecutively.
    Repetition,
    /// An A, B, A, B oscillation between two actions.
    Oscillation,
    /// The same tool with identical arguments repeated.
    RedundantToolCall,
    /// No new distinct action seen over the recent window.
    Drift,
}

impl LoopPattern {
    /// A short identifier for logging/serialisation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repetition => "repetition",
            Self::Oscillation => "oscillation",
            Self::RedundantToolCall => "redundant_tool_call",
            Self::Drift => "drift",
        }
    }
}

/// Thresholds controlling when each pattern fires.
#[derive(Debug, Clone, Copy)]
pub struct LoopGuardConfig {
    /// Identical consecutive actions before [`LoopPattern::Repetition`] fires.
    pub repetition_threshold: usize,
    /// Cycles (each A, B = one cycle) before [`LoopPattern::Oscillation`] fires.
    pub oscillation_threshold: usize,
    /// Identical tool+args calls before [`LoopPattern::RedundantToolCall`] fires.
    pub redundant_threshold: usize,
    /// Window size with no new distinct action before [`LoopPattern::Drift`] fires.
    pub drift_window: usize,
    /// Whether detection is enabled at all.
    pub enabled: bool,
}

impl Default for LoopGuardConfig {
    fn default() -> Self {
        Self {
            repetition_threshold: 4,
            oscillation_threshold: 3,
            redundant_threshold: 3,
            drift_window: 8,
            enabled: true,
        }
    }
}

/// One recorded agent step: the action taken and an optional argument signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// The action key, typically the tool name (e.g. `"discover"`).
    pub action: String,
    /// A normalized signature of the arguments, for redundant-call detection.
    /// `None` for actions without arguments.
    pub args_signature: Option<String>,
}

impl StepRecord {
    /// A step from a tool call: name plus a normalized argument signature.
    #[must_use]
    pub fn tool(action: impl Into<String>, args_signature: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            args_signature: Some(args_signature.into()),
        }
    }

    /// A step keyed only by an action name (no argument signature).
    #[must_use]
    pub fn action(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            args_signature: None,
        }
    }
}

/// A detected loop, with the pattern and a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopDetection {
    /// Which pattern fired.
    pub pattern: LoopPattern,
    /// A message suitable for surfacing to the user / an event sink.
    pub reason: String,
}

/// Accumulates step history and reports the first loop pattern detected.
#[derive(Debug)]
pub struct LoopGuard {
    config: LoopGuardConfig,
    history: VecDeque<StepRecord>,
}

impl LoopGuard {
    /// Create a guard with the given config.
    #[must_use]
    pub fn new(config: LoopGuardConfig) -> Self {
        Self {
            config,
            history: VecDeque::new(),
        }
    }

    /// Create a guard with default thresholds.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(LoopGuardConfig::default())
    }

    fn max_history(&self) -> usize {
        // Keep enough history to evaluate the widest window.
        self.config
            .repetition_threshold
            .max(self.config.oscillation_threshold * 2)
            .max(self.config.redundant_threshold)
            .max(self.config.drift_window)
            .saturating_mul(2)
            .max(1)
    }

    /// Record one step and return the first loop pattern detected, if any.
    pub fn record(&mut self, step: StepRecord) -> Option<LoopDetection> {
        if !self.config.enabled {
            return None;
        }

        self.history.push_back(step);
        let cap = self.max_history();
        while self.history.len() > cap {
            self.history.pop_front();
        }

        // Most specific first: an identical tool+args call is a stronger signal
        // than a bare repeated action key.
        self.check_redundant_tool()
            .or_else(|| self.check_repetition())
            .or_else(|| self.check_oscillation())
            .or_else(|| self.check_drift())
    }

    /// Reset all accumulated history (e.g. after external progress).
    pub fn reset(&mut self) {
        self.history.clear();
    }

    /// Same `action` repeated `repetition_threshold` times at the tail.
    fn check_repetition(&self) -> Option<LoopDetection> {
        let threshold = self.config.repetition_threshold;
        if threshold == 0 || self.history.len() < threshold {
            return None;
        }
        let last = self.history.back()?;
        let consecutive = self
            .history
            .iter()
            .rev()
            .take_while(|s| s.action == last.action)
            .count();
        if consecutive >= threshold {
            Some(LoopDetection {
                pattern: LoopPattern::Repetition,
                reason: format!(
                    "action '{}' repeated {consecutive} times in a row (threshold {threshold})",
                    last.action
                ),
            })
        } else {
            None
        }
    }

    /// Tail alternates strictly between two distinct actions for N cycles.
    fn check_oscillation(&self) -> Option<LoopDetection> {
        let threshold = self.config.oscillation_threshold;
        let needed = threshold.checked_mul(2)?;
        if needed == 0 || self.history.len() < needed {
            return None;
        }
        let tail: Vec<&StepRecord> = self.history.iter().rev().take(needed).collect();
        // tail[0] is the most recent; alternation means even/odd indices match
        // two distinct action keys.
        let a = &tail[0].action;
        let b = &tail[1].action;
        if a == b {
            return None;
        }
        let alternates = tail.iter().enumerate().all(|(i, step)| {
            if i % 2 == 0 {
                &step.action == a
            } else {
                &step.action == b
            }
        });
        if alternates {
            Some(LoopDetection {
                pattern: LoopPattern::Oscillation,
                reason: format!("oscillation between '{a}' and '{b}' for {threshold} cycles"),
            })
        } else {
            None
        }
    }

    /// Same tool + identical args signature repeated at the tail.
    fn check_redundant_tool(&self) -> Option<LoopDetection> {
        let threshold = self.config.redundant_threshold;
        if threshold == 0 || self.history.len() < threshold {
            return None;
        }
        let last = self.history.back()?;
        let sig = last.args_signature.as_ref()?;
        let consecutive = self
            .history
            .iter()
            .rev()
            .take_while(|s| s.action == last.action && s.args_signature.as_ref() == Some(sig))
            .count();
        if consecutive >= threshold {
            Some(LoopDetection {
                pattern: LoopPattern::RedundantToolCall,
                reason: format!(
                    "tool '{}' called with identical arguments {consecutive} times (threshold {threshold})",
                    last.action
                ),
            })
        } else {
            None
        }
    }

    /// A small set of steps cycling over the last `drift_window` steps -- e.g.
    /// the multi-action cycle `A, B, C, A, B, C` that none of the other
    /// detectors catch (it is neither consecutive repetition nor strict A/B
    /// oscillation).
    fn check_drift(&self) -> Option<LoopDetection> {
        let window = self.config.drift_window;
        // A window of <4 is too short to distinguish a cycle from normal work.
        if window < 4 || self.history.len() < window {
            return None;
        }
        // Key on the full (action, args) signature so genuinely varying
        // arguments -- i.e. real progress through a small toolset -- are not
        // mistaken for a stuck cycle. A repeating cycle reuses the same steps.
        let distinct = self
            .history
            .iter()
            .rev()
            .take(window)
            .map(|s| (s.action.as_str(), s.args_signature.as_deref()))
            .collect::<std::collections::HashSet<_>>()
            .len();
        // `distinct * 2 <= window` means each distinct step recurs at least
        // twice on average -- a cycle, not forward progress. (`distinct == 1`
        // would already be Repetition; this also catches 2..=window/2.)
        if distinct >= 1 && distinct.saturating_mul(2) <= window {
            Some(LoopDetection {
                pattern: LoopPattern::Drift,
                reason: format!(
                    "stuck cycling over {distinct} distinct step(s) across the last {window} steps"
                ),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(guard: &mut LoopGuard, steps: &[StepRecord]) -> Option<LoopDetection> {
        let mut last = None;
        for s in steps {
            last = guard.record(s.clone());
            if last.is_some() {
                return last;
            }
        }
        last
    }

    #[test]
    fn detects_repetition() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default()); // threshold 4
        let steps: Vec<_> = (0..4).map(|_| StepRecord::action("discover")).collect();
        let d = feed(&mut guard, &steps).expect("repetition should fire");
        assert_eq!(d.pattern, LoopPattern::Repetition);
    }

    #[test]
    fn does_not_fire_below_threshold() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        let steps: Vec<_> = (0..3).map(|_| StepRecord::action("discover")).collect();
        assert!(feed(&mut guard, &steps).is_none());
    }

    #[test]
    fn detects_oscillation() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default()); // 3 cycles
        let steps = [
            StepRecord::action("a"),
            StepRecord::action("b"),
            StepRecord::action("a"),
            StepRecord::action("b"),
            StepRecord::action("a"),
            StepRecord::action("b"),
        ];
        let d = feed(&mut guard, &steps).expect("oscillation should fire");
        assert_eq!(d.pattern, LoopPattern::Oscillation);
    }

    #[test]
    fn detects_redundant_tool_call() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default()); // threshold 3
        let steps: Vec<_> = (0..3)
            .map(|_| StepRecord::tool("harness", "target=foo|engine=libfuzzer"))
            .collect();
        let d = feed(&mut guard, &steps).expect("redundant tool call should fire");
        assert_eq!(d.pattern, LoopPattern::RedundantToolCall);
    }

    #[test]
    fn redundant_distinguishes_args() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        // Same tool, different args each time -> no redundant-call detection.
        let steps = [
            StepRecord::tool("harness", "target=a"),
            StepRecord::tool("harness", "target=b"),
            StepRecord::tool("harness", "target=c"),
        ];
        let d = feed(&mut guard, &steps);
        // It may trip Repetition (same action key 3x < threshold 4 -> none).
        assert!(d.is_none(), "distinct args must not be redundant: {d:?}");
    }

    #[test]
    fn detects_drift() {
        // Two actions alternating beyond the window would be oscillation, so use
        // a single action under the repetition threshold by raising it.
        let config = LoopGuardConfig {
            repetition_threshold: 100,
            oscillation_threshold: 100,
            drift_window: 6,
            ..LoopGuardConfig::default()
        };
        let mut guard = LoopGuard::new(config);
        let steps: Vec<_> = (0..6).map(|_| StepRecord::action("spin")).collect();
        let d = feed(&mut guard, &steps).expect("drift should fire");
        assert_eq!(d.pattern, LoopPattern::Drift);
    }

    #[test]
    fn detects_multi_action_cycle() {
        // A, B, C repeating is neither consecutive repetition nor strict A/B
        // oscillation, so only drift can catch it. Default drift_window is 8.
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        let cycle = ["a", "b", "c"];
        let steps: Vec<_> = (0..9).map(|i| StepRecord::action(cycle[i % 3])).collect();
        let d = feed(&mut guard, &steps).expect("multi-action cycle should fire");
        assert_eq!(d.pattern, LoopPattern::Drift);
    }

    #[test]
    fn small_toolset_with_varying_args_does_not_drift() {
        // A small 3-tool set (so not strict A/B oscillation) but each call
        // carries fresh arguments -- real progress, not a cycle. Drift keys on
        // the full (action, args) signature, so this must not fire.
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        let steps: Vec<_> = (0..16)
            .map(|i| StepRecord::tool(format!("tool_{}", i % 3), format!("arg_{i}")))
            .collect();
        assert!(
            feed(&mut guard, &steps).is_none(),
            "varying args over a small toolset must not be drift"
        );
    }

    #[test]
    fn healthy_varied_actions_do_not_fire() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        let steps: Vec<_> = (0..20)
            .map(|i| StepRecord::tool(format!("tool_{}", i % 5), format!("arg_{i}")))
            .collect();
        assert!(
            feed(&mut guard, &steps).is_none(),
            "varied actions must not trigger a false positive"
        );
    }

    #[test]
    fn reset_clears_history() {
        let mut guard = LoopGuard::new(LoopGuardConfig::default());
        let _ = guard.record(StepRecord::action("discover"));
        let _ = guard.record(StepRecord::action("discover"));
        guard.reset();
        // After reset, two more should not be enough to reach threshold 4.
        assert!(guard.record(StepRecord::action("discover")).is_none());
        assert!(guard.record(StepRecord::action("discover")).is_none());
    }

    #[test]
    fn disabled_guard_never_fires() {
        let config = LoopGuardConfig {
            enabled: false,
            ..LoopGuardConfig::default()
        };
        let mut guard = LoopGuard::new(config);
        let steps: Vec<_> = (0..10).map(|_| StepRecord::action("x")).collect();
        assert!(feed(&mut guard, &steps).is_none());
    }
}
