//! Approval for a scheduled campaign's own fuzz run.
//!
//! A scheduled campaign runs with nobody at the keyboard, so its run cannot be
//! approved by a click. The operator's standing decision is the scheduler's
//! execution authorization ("Authorize scheduled runs"), which starts withdrawn
//! on every process start and can be withdrawn again at any time. While it is
//! granted, the run of a harness a person already smoke-tested and approved is
//! approved here; a campaign never runs any other harness.
//!
//! Only [`Action::RunFuzzer`] is covered. Every other action, and every action
//! while authorization is withdrawn, is decided by the fallback gate, so the
//! environment opt-in (`HF_AUTO_APPROVE`) keeps working for headless services
//! and a hard policy denial still applies.

use std::sync::Arc;

use async_trait::async_trait;
use hf_guardrails::{Action, ApprovalGate};

/// Reports whether scheduled execution is currently authorized.
pub(super) type ExecutionAuthorization = Arc<dyn Fn() -> bool + Send + Sync>;

pub(super) struct ScheduledRunApproval {
    authorized: ExecutionAuthorization,
    fallback: Arc<dyn ApprovalGate>,
}

impl ScheduledRunApproval {
    pub(super) fn new(authorized: ExecutionAuthorization, fallback: Arc<dyn ApprovalGate>) -> Self {
        Self {
            authorized,
            fallback,
        }
    }
}

#[async_trait]
impl ApprovalGate for ScheduledRunApproval {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        if matches!(action, Action::RunFuzzer { .. }) && (self.authorized)() {
            return true;
        }
        self.fallback.request_approval(action, reason).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use hf_guardrails::{Action, ApprovalGate, GuardrailPolicy, Guardrails, RiskTier};

    use super::ScheduledRunApproval;

    struct Decline;

    #[async_trait::async_trait]
    impl ApprovalGate for Decline {
        async fn request_approval(&self, _: &Action, _: &str) -> bool {
            false
        }
    }

    fn run() -> Action {
        Action::RunFuzzer {
            engine: "AflPlusPlus".to_owned(),
            duration_secs: 60,
        }
    }

    fn guardrails(policy: GuardrailPolicy, authorized: &Arc<AtomicBool>) -> Guardrails {
        let authorized = Arc::clone(authorized);
        Guardrails::new(
            policy,
            Arc::new(ScheduledRunApproval::new(
                Arc::new(move || authorized.load(Ordering::SeqCst)),
                Arc::new(Decline),
            )),
        )
    }

    #[tokio::test]
    async fn an_authorized_scheduler_approves_its_campaign_run_and_nothing_else() {
        let authorized = Arc::new(AtomicBool::new(true));
        let guardrails = guardrails(GuardrailPolicy::default(), &authorized);
        guardrails.authorize(run()).await.unwrap();
        for other in [
            Action::RunHarness,
            Action::PromoteHarness,
            Action::ShellExec {
                command: "make".to_owned(),
            },
        ] {
            assert!(
                guardrails.authorize(other.clone()).await.is_err(),
                "{other:?}"
            );
        }
    }

    #[tokio::test]
    async fn withdrawing_authorization_stops_approving_new_runs() {
        let authorized = Arc::new(AtomicBool::new(true));
        let guardrails = guardrails(GuardrailPolicy::default(), &authorized);
        guardrails.authorize(run()).await.unwrap();
        authorized.store(false, Ordering::SeqCst);
        let error = guardrails.authorize(run()).await.unwrap_err();
        assert!(error.to_string().contains("approval declined"), "{error}");
    }

    #[tokio::test]
    async fn authorization_cannot_override_a_hard_policy_denial() {
        let authorized = Arc::new(AtomicBool::new(true));
        let guardrails = guardrails(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::High),
            },
            &authorized,
        );
        let error = guardrails.authorize(run()).await.unwrap_err();
        assert!(error.to_string().contains("denied by policy"), "{error}");
    }
}
