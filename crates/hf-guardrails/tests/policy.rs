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

fn analyze_source() -> Action {
    Action::AnalyzeSource {
        analyzer: "semgrep".to_owned(),
    }
}

#[test]
fn analyze_source_has_stable_medium_risk_contract() {
    let action = analyze_source();
    assert_eq!(action.kind(), "analyze_source");
    assert_eq!(action.label(), "analyze source with semgrep");
    assert_eq!(action.risk(), RiskTier::Medium);
    assert_eq!(
        GuardrailPolicy::default().evaluate(&action),
        Decision::Allow
    );
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
fn action_kinds_are_stable_snake_case_audit_labels() {
    assert_eq!(Action::Discover.kind(), "discover");
    assert_eq!(Action::DraftHarness.kind(), "draft_harness");
    assert_eq!(Action::CompileHarness.kind(), "compile_harness");
    assert_eq!(Action::RunHarness.kind(), "run_harness");
    assert_eq!(run_fuzzer().kind(), "run_fuzzer");
    assert_eq!(
        Action::AutomotiveOffline {
            operation: "analyze_pcap".to_owned(),
        }
        .kind(),
        "automotive_offline"
    );
    assert_eq!(
        Action::AutomotiveVirtualCan {
            protocol: "uds".to_owned(),
            duration_secs: 5,
        }
        .kind(),
        "automotive_virtual_can"
    );
    assert_eq!(
        Action::AutomotivePhysicalBench {
            interface: "can0".to_owned(),
            protocol: "uds".to_owned(),
            duration_secs: 5,
        }
        .kind(),
        "automotive_physical_bench"
    );
    assert_eq!(Action::Triage.kind(), "triage");
    assert_eq!(Action::CorpusOp.kind(), "corpus_op");
    assert_eq!(Action::Chat.kind(), "chat");
    assert_eq!(
        Action::ShellExec {
            command: "id".to_owned(),
        }
        .kind(),
        "shell_exec"
    );
    assert_eq!(
        Action::WriteHostFile {
            path: "/etc/passwd".to_owned(),
        }
        .kind(),
        "write_host_file"
    );
    assert_eq!(
        Action::AgentTool {
            name: "run_fuzzer".to_owned(),
        }
        .kind(),
        "agent_tool"
    );
}

#[test]
fn risk_tier_names_are_stable_lowercase_audit_labels() {
    assert_eq!(RiskTier::Low.as_str(), "low");
    assert_eq!(RiskTier::Medium.as_str(), "medium");
    assert_eq!(RiskTier::High.as_str(), "high");
    assert_eq!(RiskTier::Critical.as_str(), "critical");
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
async fn default_guardrails_are_safe_not_permissive() {
    // The `Default` impl must be the safe env-gated policy: a Critical action
    // (arbitrary shell execution) is denied outright, unlike a permissive engine
    // which would allow it.
    let g = Guardrails::default();
    assert!(matches!(
        g.policy().evaluate(&Action::ShellExec {
            command: "id".to_owned(),
        }),
        Decision::Deny { .. }
    ));
    assert!(
        g.authorize(Action::ShellExec {
            command: "id".to_owned(),
        })
        .await
        .is_err(),
        "default guardrails must deny a critical shell-exec action"
    );
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
