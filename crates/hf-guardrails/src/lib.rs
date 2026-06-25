//! hf-guardrails: the safety layer that gates privileged actions.
//!
//! Fuzzing executes untrusted, possibly malformed code, so no single
//! abstraction may make the system unsafe (AGENTS.md 2.5). Every build and
//! fuzzer invocation is assessed here before it runs (AGENTS.md 2.12): an
//! [`Action`] is scored to a [`RiskTier`], a [`GuardrailPolicy`] turns that into
//! a [`Decision`], and anything requiring human consent is routed to an
//! [`ApprovalGate`].

mod action;
mod hitl;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub use action::{Action, RiskTier};
pub use hitl::{ApprovalGate, AutoApprove, DenyAll, EnvApprovalGate};

/// The outcome of evaluating an action against a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed without human consent.
    Allow,
    /// Allowed only if a human approves; carries the tier and a reason.
    RequireApproval {
        /// The assessed risk tier.
        tier: RiskTier,
        /// Why approval is needed.
        reason: String,
    },
    /// Denied outright by policy, regardless of any approval.
    Deny {
        /// Why the action is denied.
        reason: String,
    },
}

/// A policy mapping risk tiers to allow / approve / deny.
#[derive(Debug, Clone, Copy)]
pub struct GuardrailPolicy {
    /// Actions at or below this tier are allowed without approval.
    pub auto_allow_max: RiskTier,
    /// Actions at or above this tier are denied outright (never prompted).
    /// `None` means nothing is hard-denied.
    pub deny_at: Option<RiskTier>,
}

impl Default for GuardrailPolicy {
    /// Allow low/medium automatically; require approval for high; hard-deny
    /// arbitrary shell execution.
    fn default() -> Self {
        Self {
            auto_allow_max: RiskTier::Medium,
            deny_at: Some(RiskTier::Critical),
        }
    }
}

impl GuardrailPolicy {
    /// A policy that auto-allows everything (no approval, no denial). Use only
    /// in trusted contexts.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            auto_allow_max: RiskTier::Critical,
            deny_at: None,
        }
    }

    /// Evaluate an action.
    #[must_use]
    pub fn evaluate(&self, action: &Action) -> Decision {
        let tier = action.risk();
        if let Some(deny_at) = self.deny_at {
            if tier >= deny_at {
                return Decision::Deny {
                    reason: format!(
                        "{:?}-risk action '{}' is denied by policy",
                        tier,
                        action.label()
                    ),
                };
            }
        }
        if tier <= self.auto_allow_max {
            Decision::Allow
        } else {
            Decision::RequireApproval {
                tier,
                reason: format!(
                    "{:?}-risk action '{}' requires approval",
                    tier,
                    action.label()
                ),
            }
        }
    }
}

/// Raised when an action is not permitted.
#[derive(Debug, Error)]
pub enum GuardrailError {
    /// The action was denied by policy or by the approval gate.
    #[error("guardrail denied: {0}")]
    Denied(String),
}

impl From<GuardrailError> for hf_core::error::ClassifiedError {
    fn from(e: GuardrailError) -> Self {
        hf_core::error::ClassifiedError::Validation(e.to_string())
    }
}

/// The guardrail engine: a policy plus the approval gate used when the policy
/// requires human consent.
#[derive(Clone)]
pub struct Guardrails {
    policy: GuardrailPolicy,
    gate: Arc<dyn ApprovalGate>,
}

impl Guardrails {
    /// Construct guardrails from a policy and an approval gate.
    #[must_use]
    pub fn new(policy: GuardrailPolicy, gate: Arc<dyn ApprovalGate>) -> Self {
        Self { policy, gate }
    }

    /// A permissive engine that auto-approves with audit logging. The default
    /// for trusted local/CLI use; the agent loop replaces the gate with an
    /// interactive one.
    #[must_use]
    pub fn permissive() -> Self {
        Self::new(GuardrailPolicy::permissive(), Arc::new(AutoApprove))
    }

    /// The default policy with an [`EnvApprovalGate`]: high-risk actions are
    /// allowed only when `HF_AUTO_APPROVE` is set, and shell execution is
    /// always denied.
    #[must_use]
    pub fn env_gated() -> Self {
        Self::new(GuardrailPolicy::default(), Arc::new(EnvApprovalGate))
    }

    /// Construct from the environment: `HF_GUARDRAILS=strict` selects the
    /// env-gated policy; anything else (the default) is permissive-with-audit
    /// so existing local workflows are not interrupted.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("HF_GUARDRAILS").as_deref() {
            Ok("strict") => Self::env_gated(),
            _ => Self::permissive(),
        }
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> &GuardrailPolicy {
        &self.policy
    }

    /// Authorize an action, consulting the approval gate when required.
    ///
    /// # Errors
    /// Returns [`GuardrailError::Denied`] if policy denies the action or the
    /// approval gate declines it.
    pub async fn authorize(&self, action: Action) -> Result<(), GuardrailError> {
        match self.policy.evaluate(&action) {
            Decision::Allow => {
                tracing::debug!(action = %action.label(), "guardrail allowed");
                Ok(())
            }
            Decision::Deny { reason } => Err(GuardrailError::Denied(reason)),
            Decision::RequireApproval { reason, .. } => {
                if self.gate.request_approval(&action, &reason).await {
                    Ok(())
                } else {
                    Err(GuardrailError::Denied(format!(
                        "approval declined: {reason}"
                    )))
                }
            }
        }
    }
}

impl Default for Guardrails {
    fn default() -> Self {
        Self::permissive()
    }
}

/// An [`ApprovalGate`] backed by a closure, for wiring GUI / agent approval
/// flows without a dedicated type.
pub struct CallbackGate<F>(pub F);

#[async_trait]
impl<F> ApprovalGate for CallbackGate<F>
where
    F: Fn(&Action, &str) -> bool + Send + Sync,
{
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        (self.0)(action, reason)
    }
}
