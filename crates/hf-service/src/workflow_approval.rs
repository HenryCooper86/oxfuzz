//! Approval supplied by an explicit desktop workflow action.

use std::sync::Arc;

use hf_service::{Action, ApprovalGate, ServiceContainer};

#[derive(Clone, Copy)]
pub(crate) enum ExplicitAction {
    RunHarness,
    PromoteHarness,
    RunFuzzer,
    Triage,
    PublishFindings,
    #[cfg(feature = "build-doctor")]
    RunProjectBuild,
    #[cfg(feature = "change-aware")]
    PublishChangeComparison,
    #[cfg(feature = "patch-to-proof")]
    VerifyRemediation,
    #[cfg(feature = "automotive-scapy")]
    AutomotiveVirtualCan,
    #[cfg(feature = "automotive-scapy")]
    AutomotiveReplay,
}

pub(crate) fn with_user_approval(
    container: &ServiceContainer,
    action: ExplicitAction,
) -> ServiceContainer {
    // A workflow click applies only to this command's clone. Keep configured
    // policy and deny guards; unrelated requests never inherit this consent.
    container.clone().with_guardrails(
        container
            .guardrails()
            .clone()
            .with_approval_gate(Arc::new(WorkflowApproval(action))),
    )
}

struct WorkflowApproval(ExplicitAction);

#[async_trait::async_trait]
impl ApprovalGate for WorkflowApproval {
    async fn request_approval(&self, action: &Action, _: &str) -> bool {
        match self.0 {
            ExplicitAction::RunHarness => matches!(action, Action::RunHarness),
            ExplicitAction::PromoteHarness => matches!(action, Action::PromoteHarness),
            ExplicitAction::RunFuzzer => matches!(action, Action::RunFuzzer { .. }),
            ExplicitAction::Triage => matches!(action, Action::Triage),
            ExplicitAction::PublishFindings => matches!(action, Action::PublishFindings { .. }),
            #[cfg(feature = "build-doctor")]
            ExplicitAction::RunProjectBuild => matches!(action, Action::RunProjectBuild { .. }),
            #[cfg(feature = "change-aware")]
            ExplicitAction::PublishChangeComparison => {
                matches!(action, Action::PublishChangeComparison { .. })
            }
            #[cfg(feature = "patch-to-proof")]
            ExplicitAction::VerifyRemediation => matches!(action, Action::VerifyRemediation { .. }),
            #[cfg(feature = "automotive-scapy")]
            ExplicitAction::AutomotiveVirtualCan => {
                matches!(action, Action::AutomotiveVirtualCan { .. })
            }
            #[cfg(feature = "automotive-scapy")]
            ExplicitAction::AutomotiveReplay => matches!(
                action,
                Action::AutomotiveOffline { .. }
                    | Action::AutomotiveVirtualCan { .. }
                    | Action::AutomotivePhysicalBench { .. }
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hf_service::{Action, ApprovalGate, GuardrailPolicy, Guardrails, ServiceContainer};

    use super::{with_user_approval, ExplicitAction};

    struct Decline;

    #[async_trait::async_trait]
    impl ApprovalGate for Decline {
        async fn request_approval(&self, _: &Action, _: &str) -> bool {
            false
        }
    }

    fn service() -> ServiceContainer {
        ServiceContainer::stubbed().with_guardrails(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(Decline),
        ))
    }

    #[tokio::test]
    async fn smoke_click_does_not_approve_promotion_or_change_the_startup_gate() {
        let original = service();
        let clicked = with_user_approval(&original, ExplicitAction::RunHarness);
        clicked
            .guardrails()
            .authorize(Action::RunHarness)
            .await
            .unwrap();
        assert!(clicked
            .guardrails()
            .authorize(Action::PromoteHarness)
            .await
            .is_err());
        assert!(original
            .guardrails()
            .authorize(Action::RunHarness)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn workflow_consent_is_limited_to_the_selected_operation() {
        let cases = [
            (ExplicitAction::RunHarness, Action::RunHarness),
            (ExplicitAction::PromoteHarness, Action::PromoteHarness),
            (
                ExplicitAction::RunFuzzer,
                Action::RunFuzzer {
                    engine: "AFL++ showmap".to_owned(),
                    duration_secs: 10,
                },
            ),
            (
                ExplicitAction::PublishFindings,
                Action::PublishFindings {
                    destination: "issue-tracker".to_owned(),
                },
            ),
            #[cfg(feature = "build-doctor")]
            (
                ExplicitAction::RunProjectBuild,
                Action::RunProjectBuild {
                    build_system: "cmake".to_owned(),
                },
            ),
            #[cfg(feature = "change-aware")]
            (
                ExplicitAction::PublishChangeComparison,
                Action::PublishChangeComparison {
                    destination: "issue-tracker".to_owned(),
                },
            ),
            #[cfg(feature = "patch-to-proof")]
            (
                ExplicitAction::VerifyRemediation,
                Action::VerifyRemediation {
                    engine: "libfuzzer".to_owned(),
                    duration_secs: 10,
                },
            ),
            #[cfg(feature = "automotive-scapy")]
            (
                ExplicitAction::AutomotiveVirtualCan,
                Action::AutomotiveVirtualCan {
                    protocol: "uds".to_owned(),
                    duration_secs: 10,
                },
            ),
        ];
        let original = service();
        for (scope, expected) in &cases {
            let clicked = with_user_approval(&original, *scope);
            for (_, action) in &cases {
                assert_eq!(
                    clicked.guardrails().authorize(action.clone()).await.is_ok(),
                    action == expected,
                    "consent for {expected:?} must not authorize {action:?}",
                );
            }
            assert!(clicked
                .guardrails()
                .authorize(Action::AutomotivePhysicalBench {
                    interface: "can0".to_owned(),
                    protocol: "uds".to_owned(),
                    duration_secs: 10,
                    sidecar_image_sha256: "ab".repeat(32),
                })
                .await
                .is_err());
            assert!(clicked
                .guardrails()
                .authorize(Action::ShellExec {
                    command: "unrelated command".to_owned(),
                })
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn explicit_click_cannot_override_a_hard_policy_denial() {
        let original = service().with_guardrails(Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: hf_service::RiskTier::Low,
                deny_at: Some(hf_service::RiskTier::High),
            },
            Arc::new(Decline),
        ));
        let clicked = with_user_approval(&original, ExplicitAction::RunHarness);
        let error = clicked
            .guardrails()
            .authorize(Action::RunHarness)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("denied by policy"), "{error}");
    }

    #[tokio::test]
    async fn triage_consent_does_not_extend_to_harness_execution() {
        let original = service().with_guardrails(Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: hf_service::RiskTier::Low,
                deny_at: Some(hf_service::RiskTier::Critical),
            },
            Arc::new(Decline),
        ));
        let clicked = with_user_approval(&original, ExplicitAction::Triage);
        clicked
            .guardrails()
            .authorize(Action::Triage)
            .await
            .unwrap();
        assert!(clicked
            .guardrails()
            .authorize(Action::RunHarness)
            .await
            .is_err());
        assert!(original
            .guardrails()
            .authorize(Action::Triage)
            .await
            .is_err());
    }

    #[cfg(feature = "automotive-scapy")]
    #[tokio::test]
    async fn replay_consent_remains_limited_to_automotive_operations() {
        let original = service();
        let clicked = with_user_approval(&original, ExplicitAction::AutomotiveReplay);
        for action in [
            Action::AutomotiveVirtualCan {
                protocol: "uds".to_owned(),
                duration_secs: 10,
            },
            Action::AutomotivePhysicalBench {
                interface: "can0".to_owned(),
                protocol: "uds".to_owned(),
                duration_secs: 10,
                sidecar_image_sha256: "ab".repeat(32),
            },
        ] {
            clicked
                .guardrails()
                .authorize(action.clone())
                .await
                .unwrap();
            assert!(original.guardrails().authorize(action).await.is_err());
        }
        assert!(clicked
            .guardrails()
            .authorize(Action::RunHarness)
            .await
            .is_err());
        assert!(clicked
            .guardrails()
            .authorize(Action::PublishFindings {
                destination: "issue-tracker".to_owned(),
            })
            .await
            .is_err());
    }
}
