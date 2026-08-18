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
mod loop_guard;

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

pub use action::{Action, RiskTier};
pub use hitl::{ApprovalGate, AutoApprove, DenyAll, EnvApprovalGate};
pub use loop_guard::{LoopDetection, LoopGuard, LoopGuardConfig, LoopPattern, StepRecord};

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

/// What an [`Advisor`] may ask for.
///
/// There is deliberately no `Allow` variant. An advisor sits on the extensible
/// half of the pipeline, where registration order is not controlled by the
/// safety layer, so its vocabulary is limited to abstaining or asking for
/// consent. Loosening is not expressible, which means it cannot be reached by
/// accident, by a future extension, or by agent-role text that talks its way
/// into the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advice {
    /// No opinion; defer to the policy.
    Abstain,
    /// Require human consent even where the policy would auto-allow.
    RequireApproval {
        /// Why consent is being asked for.
        reason: String,
    },
}

/// An extension consulted before the policy, able only to tighten.
///
/// Advisors run first and in registration order. The first one to ask for
/// approval wins, and no later advisor can withdraw the request: see [`Advice`]
/// for why the type has no way to say "allow".
pub trait Advisor: Send + Sync {
    /// Advise on `action`.
    fn advise(&self, action: &Action) -> Advice;
}

/// A monotonic, deny-only guard, consulted last.
///
/// This is the non-bypassable half of the pipeline. A guard returns a denial
/// reason or nothing, so no guard, and no ordering of guards, can turn a denial
/// back into permission -- the property is carried by the return type rather
/// than by review discipline. Guards run *after* approval resolution, so an
/// action a human just approved can still be denied here.
///
/// For a system whose central promise is that a generated harness never runs on
/// the host without consent (AGENTS.md 2.5, 2.12), that ordering is the point:
/// consent is a necessary condition for execution, never a sufficient one.
pub trait DenyGuard: Send + Sync {
    /// Return why `action` must not proceed, or `None` to abstain.
    fn deny_reason(&self, action: &Action) -> Option<String>;
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
    advisors: Vec<Arc<dyn Advisor>>,
    guards: Vec<Arc<dyn DenyGuard>>,
}

impl Guardrails {
    /// Construct guardrails from a policy and an approval gate.
    #[must_use]
    pub fn new(policy: GuardrailPolicy, gate: Arc<dyn ApprovalGate>) -> Self {
        Self {
            policy,
            gate,
            advisors: Vec::new(),
            guards: Vec::new(),
        }
    }

    /// Register an [`Advisor`], consulted before the policy. Tighten-only.
    #[must_use]
    pub fn with_advisor(mut self, advisor: Arc<dyn Advisor>) -> Self {
        self.advisors.push(advisor);
        self
    }

    /// Register a [`DenyGuard`], consulted after approval resolution.
    ///
    /// Registration order selects which reason is reported when several guards
    /// would deny; it cannot affect *whether* the action is denied.
    #[must_use]
    pub fn with_guard(mut self, guard: Arc<dyn DenyGuard>) -> Self {
        self.guards.push(guard);
        self
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

    /// Construct from the environment. The default is the safe env-gated policy:
    /// high-risk actions (harness compile/run, fuzzer execution) require explicit
    /// consent via `HF_AUTO_APPROVE=1`. `HF_GUARDRAILS=permissive` opts out into
    /// auto-approve-with-audit for trusted local loops; `strict` is an alias for
    /// the default and remains accepted for compatibility.
    ///
    /// This is the safety boundary for untrusted execution (AGENTS.md 2.5/2.12):
    /// `bootstrap()` constructs guardrails here, so a generated harness never
    /// runs on the host without an explicit opt-in.
    #[must_use]
    pub fn from_env() -> Self {
        match std::env::var("HF_GUARDRAILS").as_deref() {
            Ok("permissive") => Self::permissive(),
            _ => Self::env_gated(),
        }
    }

    /// The active policy.
    #[must_use]
    pub fn policy(&self) -> &GuardrailPolicy {
        &self.policy
    }

    /// Ask the approval gate to consent to `action`, returning whether it was
    /// approved. This is a TIGHTEN-only entry point: it always prompts and never
    /// consults the policy's auto-allow, so a caller can require consent for an
    /// action the policy would otherwise permit (e.g. a manual-autonomy agent
    /// gating every tool). It can only add a prompt; it never loosens anything.
    pub async fn require_approval(&self, action: &Action, reason: &str) -> bool {
        self.gate.request_approval(action, reason).await
    }

    /// Authorize an action, consulting the approval gate when required.
    ///
    /// # Errors
    /// Returns [`GuardrailError::Denied`] if policy denies the action or the
    /// approval gate declines it.
    pub async fn authorize(&self, action: Action) -> Result<(), GuardrailError> {
        // Phase 1: the extensible advisory chain. It may add a prompt; by the
        // shape of `Advice` it cannot remove one.
        let advised = self.first_advice(&action);

        // Phase 2: policy evaluation and approval resolution. `?` here means a
        // denial short-circuits, which is why phase 3 only ever narrows.
        self.resolve_policy(&action, advised).await?;

        // Phase 3: monotonic guards, last and unconditional over everything
        // that survived. Nothing after this point can restore permission.
        if let Some(reason) = self.first_guard_denial(&action) {
            tracing::warn!(action = %action.label(), %reason, "guard denied");
            return Err(GuardrailError::Denied(reason));
        }

        tracing::debug!(action = %action.label(), "guardrail allowed");
        Ok(())
    }

    /// The first advisor asking for consent, if any.
    fn first_advice(&self, action: &Action) -> Option<String> {
        self.advisors
            .iter()
            .find_map(|advisor| match advisor.advise(action) {
                Advice::RequireApproval { reason } => Some(reason),
                Advice::Abstain => None,
            })
    }

    /// The first guard that denies `action`, if any.
    fn first_guard_denial(&self, action: &Action) -> Option<String> {
        self.guards
            .iter()
            .find_map(|guard| guard.deny_reason(action))
    }

    /// Policy evaluation plus approval resolution, honouring an advisor's
    /// request for consent on an otherwise auto-allowed action.
    async fn resolve_policy(
        &self,
        action: &Action,
        advised: Option<String>,
    ) -> Result<(), GuardrailError> {
        let reason = match self.policy.evaluate(action) {
            Decision::Deny { reason } => return Err(GuardrailError::Denied(reason)),
            Decision::RequireApproval { reason, .. } => reason,
            // The policy would auto-allow; an advisor may still have asked.
            Decision::Allow => match advised {
                Some(reason) => reason,
                None => return Ok(()),
            },
        };

        if self.gate.request_approval(action, &reason).await {
            Ok(())
        } else {
            Err(GuardrailError::Denied(format!(
                "approval declined: {reason}"
            )))
        }
    }
}

impl Default for Guardrails {
    /// The safe default: env-gated, matching [`Guardrails::from_env`]'s baseline.
    /// Critical actions (e.g. arbitrary shell execution) are denied and
    /// high-risk actions require explicit consent. A permissive engine must be
    /// requested explicitly via [`Guardrails::permissive`] so trust is never the
    /// silent default.
    fn default() -> Self {
        Self::env_gated()
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
