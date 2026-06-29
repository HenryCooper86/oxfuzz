//! Human-in-the-loop approval gates.

use async_trait::async_trait;

use crate::action::Action;

/// A gate consulted when a policy decision requires human approval.
///
/// Implementations decide how the approval is sourced: an interactive terminal
/// prompt, a GUI permission dialog, an environment flag, or a fixed answer.
#[async_trait]
pub trait ApprovalGate: Send + Sync {
    /// Return `true` to allow the action, `false` to deny it.
    async fn request_approval(&self, action: &Action, reason: &str) -> bool;
}

/// Approves every request, emitting an audit log line. Suitable for trusted,
/// non-interactive contexts (local dev, CI) where execution is expected.
#[derive(Debug, Default, Clone, Copy)]
pub struct AutoApprove;

#[async_trait]
impl ApprovalGate for AutoApprove {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        tracing::warn!(action = %action.label(), reason, "guardrail auto-approved");
        true
    }
}

/// Denies every request. The safe default for fully unattended contexts.
#[derive(Debug, Default, Clone, Copy)]
pub struct DenyAll;

#[async_trait]
impl ApprovalGate for DenyAll {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        tracing::warn!(action = %action.label(), reason, "guardrail denied (DenyAll)");
        false
    }
}

/// Approves only when the `HF_AUTO_APPROVE` environment variable is set to a
/// truthy value (`1`, `true`, `yes`). Denies otherwise. This lets a headless
/// run opt into execution explicitly without a code change.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvApprovalGate;

#[async_trait]
impl ApprovalGate for EnvApprovalGate {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        let approved = std::env::var("HF_AUTO_APPROVE")
            .is_ok_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"));
        if approved {
            tracing::warn!(action = %action.label(), reason, "guardrail approved via HF_AUTO_APPROVE");
        } else {
            tracing::warn!(action = %action.label(), reason, "guardrail denied (set HF_AUTO_APPROVE=1 to allow)");
        }
        approved
    }
}
