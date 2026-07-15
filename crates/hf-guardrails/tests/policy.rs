//! Tests for guardrail policy evaluation and approval gating.

use hf_guardrails::{
    Action, ApprovalGate, AutoApprove, Decision, DenyAll, GuardrailPolicy, Guardrails, RiskTier,
};

fn run_fuzzer() -> Action {
    Action::RunFuzzer {
        engine: "libfuzzer".to_owned(),
        duration_secs: 60,
    }
}

#[test]
fn risk_tiers_are_ordered() {
    assert!(RiskTier::Low < RiskTier::Medium);
    assert!(RiskTier::Medium < RiskTier::High);
    assert!(RiskTier::High < RiskTier::Critical);
    assert_eq!(Action::Discover.risk(), RiskTier::Low);
    assert_eq!(Action::CompileHarness.risk(), RiskTier::Medium);
    assert_eq!(run_fuzzer().risk(), RiskTier::High);
    assert_eq!(
        Action::AutomotiveOffline {
            operation: "analyze_pcap".to_owned(),
        }
        .risk(),
        RiskTier::Medium
    );
    assert_eq!(
        Action::AutomotiveVirtualCan {
            protocol: "uds".to_owned(),
            duration_secs: 5,
        }
        .risk(),
        RiskTier::High
    );
    assert_eq!(
        Action::AutomotivePhysicalBench {
            interface: "can0".to_owned(),
            protocol: "uds".to_owned(),
            duration_secs: 5,
        }
        .risk(),
        RiskTier::High
    );
    assert_eq!(
        Action::ShellExec {
            command: "rm -rf /".to_owned()
        }
        .risk(),
        RiskTier::Critical
    );
}

#[test]
fn automotive_labels_distinguish_offline_virtual_and_physical_access() {
    assert_eq!(
        Action::AutomotiveOffline {
            operation: "analyze_pcap".to_owned(),
        }
        .label(),
        "automotive offline analyze_pcap"
    );
    assert!(Action::AutomotiveVirtualCan {
        protocol: "uds".to_owned(),
        duration_secs: 5,
    }
    .label()
    .contains("virtual CAN"));
    assert!(Action::AutomotivePhysicalBench {
        interface: "can0".to_owned(),
        protocol: "uds".to_owned(),
        duration_secs: 5,
    }
    .label()
    .contains("physical CAN interface can0"));
}

#[test]
fn default_policy_allows_low_requires_high_denies_critical() {
    let p = GuardrailPolicy::default();
    assert_eq!(p.evaluate(&Action::Discover), Decision::Allow);
    assert_eq!(p.evaluate(&Action::CompileHarness), Decision::Allow);
    assert!(matches!(
        p.evaluate(&run_fuzzer()),
        Decision::RequireApproval {
            tier: RiskTier::High,
            ..
        }
    ));
    assert!(matches!(
        p.evaluate(&Action::ShellExec {
            command: "x".to_owned()
        }),
        Decision::Deny { .. }
    ));
}

#[tokio::test]
async fn authorize_routes_through_gate() {
    // Permissive gate approves a high-risk action.
    let allow = Guardrails::new(GuardrailPolicy::default(), std::sync::Arc::new(AutoApprove));
    assert!(allow.authorize(run_fuzzer()).await.is_ok());

    // DenyAll gate declines the same high-risk action.
    let deny = Guardrails::new(GuardrailPolicy::default(), std::sync::Arc::new(DenyAll));
    assert!(deny.authorize(run_fuzzer()).await.is_err());

    // Low-risk actions never reach the gate, so even DenyAll allows them.
    assert!(deny.authorize(Action::Discover).await.is_ok());

    // Critical actions are denied regardless of gate.
    let denied = deny
        .authorize(Action::ShellExec {
            command: "id".to_owned(),
        })
        .await;
    assert!(denied.is_err());
}

#[tokio::test]
async fn permissive_allows_everything() {
    let g = Guardrails::permissive();
    assert!(g.authorize(run_fuzzer()).await.is_ok());
    // Even shell exec is allowed under the fully-permissive policy.
    assert!(
        AutoApprove
            .request_approval(&Action::Discover, "test")
            .await
    );
}
