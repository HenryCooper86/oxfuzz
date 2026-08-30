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

fn run_concolic() -> Action {
    Action::RunConcolic {
        target: "parse_packet".to_owned(),
        duration_secs: 60,
    }
}

fn publish_findings() -> Action {
    Action::PublishFindings {
        destination: "defectdojo".to_owned(),
    }
}

fn verify_remediation() -> Action {
    Action::VerifyRemediation {
        engine: "libfuzzer".to_owned(),
        duration_secs: 60,
    }
}

fn publish_change_comparison() -> Action {
    Action::PublishChangeComparison {
        destination: "issue-tracker".to_owned(),
    }
}

fn run_project_build() -> Action {
    Action::RunProjectBuild {
        build_system: "cmake".to_owned(),
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
fn publishing_a_comparison_has_a_stable_outward_facing_contract() {
    let action = publish_change_comparison();
    assert_eq!(action.kind(), "publish_change_comparison");
    assert_eq!(action.label(), "publish change comparison to issue-tracker");
    // The default policy must not silently allow an outward-facing publish.
    assert_ne!(
        GuardrailPolicy::default().evaluate(&action),
        Decision::Allow
    );
}

#[test]
fn running_a_project_build_has_a_stable_untrusted_execution_contract() {
    let action = run_project_build();
    assert_eq!(action.kind(), "run_project_build");
    assert_eq!(action.label(), "run the project's cmake build");
    // The default policy must not silently run a project's own build system.
    assert_ne!(
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
    assert_eq!(verify_remediation().risk(), RiskTier::High);
    // Publishing leaves the workspace and reaches an external service.
    assert_eq!(publish_change_comparison().risk(), RiskTier::High);
    // Running a project's own build system executes untrusted code.
    assert_eq!(run_project_build().risk(), RiskTier::High);
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
            sidecar_image_sha256: "ab".repeat(32),
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
        sidecar_image_sha256: "ab".repeat(32),
    }
    .label()
    .contains("image sha256:abababababababababababababababababababababababababababababababab"));
}

#[test]
fn action_kinds_are_stable_snake_case_audit_labels() {
    assert_eq!(Action::Discover.kind(), "discover");
    assert_eq!(Action::DraftHarness.kind(), "draft_harness");
    assert_eq!(Action::CompileHarness.kind(), "compile_harness");
    assert_eq!(Action::RunHarness.kind(), "run_harness");
    assert_eq!(run_fuzzer().kind(), "run_fuzzer");
    assert_eq!(run_concolic().kind(), "run_concolic");
    assert_eq!(
        run_concolic().label(),
        "run concolic enrichment for parse_packet for 60s"
    );
    assert_eq!(publish_findings().kind(), "publish_findings");
    assert_eq!(publish_findings().label(), "publish findings to defectdojo");
    assert_eq!(verify_remediation().kind(), "verify_remediation");
    assert_eq!(
        verify_remediation().label(),
        "verify libfuzzer remediation for 60s"
    );
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
            sidecar_image_sha256: "ab".repeat(32),
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
        p.evaluate(&run_concolic()),
        Decision::RequireApproval {
            tier: RiskTier::High,
            ..
        }
    ));
    assert!(matches!(
        p.evaluate(&publish_findings()),
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

// ---------------------------------------------------------------------------
// Monotonic guards (study item 1.4)
//
// The property under test is that no extension point can re-permit what the
// safety layer denied. Every assertion goes through `authorize`, the operation
// that makes the decision -- not through the policy or the gate in isolation,
// because a facade that agrees with the executor proves nothing about callers
// that bypass it.
// ---------------------------------------------------------------------------

struct DenyEverything(&'static str);

impl hf_guardrails::DenyGuard for DenyEverything {
    fn deny_reason(&self, _action: &Action) -> Option<String> {
        Some(self.0.to_owned())
    }
}

struct Abstain;

impl hf_guardrails::DenyGuard for Abstain {
    fn deny_reason(&self, _action: &Action) -> Option<String> {
        None
    }
}

struct AlwaysAsk;

impl hf_guardrails::Advisor for AlwaysAsk {
    fn advise(&self, _action: &Action) -> hf_guardrails::Advice {
        hf_guardrails::Advice::RequireApproval {
            reason: "advisor asked".to_owned(),
        }
    }
}

#[tokio::test]
async fn a_guard_denies_what_the_policy_would_have_allowed() {
    let g = Guardrails::permissive().with_guard(std::sync::Arc::new(DenyEverything("nope")));
    // Discover is low risk and auto-allowed by every policy.
    assert!(
        g.authorize(Action::Discover).await.is_err(),
        "a guard must be able to deny an action the policy allows"
    );
}

#[tokio::test]
async fn a_guard_outranks_an_approval_that_was_granted() {
    // The monotonicity property: the gate said yes, and it does not matter.
    let g = Guardrails::new(GuardrailPolicy::default(), std::sync::Arc::new(AutoApprove))
        .with_guard(std::sync::Arc::new(DenyEverything("denied after approval")));
    let outcome = g.authorize(run_fuzzer()).await;
    assert!(
        outcome.is_err(),
        "an approved action must still be deniable by a guard"
    );
    assert!(outcome
        .unwrap_err()
        .to_string()
        .contains("denied after approval"));
}

#[tokio::test]
async fn guard_registration_order_cannot_turn_a_denial_into_permission() {
    let deny_first = Guardrails::permissive()
        .with_guard(std::sync::Arc::new(DenyEverything("denied")))
        .with_guard(std::sync::Arc::new(Abstain));
    let deny_last = Guardrails::permissive()
        .with_guard(std::sync::Arc::new(Abstain))
        .with_guard(std::sync::Arc::new(DenyEverything("denied")));

    assert!(deny_first.authorize(Action::Discover).await.is_err());
    assert!(
        deny_last.authorize(Action::Discover).await.is_err(),
        "an abstaining guard registered first must not absorb a later denial"
    );
}

#[tokio::test]
async fn an_advisor_can_require_approval_the_policy_would_have_skipped() {
    // Permissive policy auto-allows Discover. An advisor asks for consent, and
    // the gate declines, so the action is denied: the advisor tightened.
    let g = Guardrails::new(GuardrailPolicy::permissive(), std::sync::Arc::new(DenyAll))
        .with_advisor(std::sync::Arc::new(AlwaysAsk));
    assert!(
        g.authorize(Action::Discover).await.is_err(),
        "an advisor must be able to add a prompt the policy would have skipped"
    );
}

#[tokio::test]
async fn an_advisor_cannot_loosen_a_policy_denial() {
    // The advisor's only vocabulary is "abstain" or "ask", so there is no way
    // to express permission; a Critical action stays denied.
    let g = Guardrails::new(GuardrailPolicy::default(), std::sync::Arc::new(AutoApprove))
        .with_advisor(std::sync::Arc::new(AlwaysAsk));
    assert!(
        g.authorize(Action::ShellExec {
            command: "id".to_owned(),
        })
        .await
        .is_err(),
        "no advice may re-permit a policy denial"
    );
}

// ---------------------------------------------------------------------------
// Disarm on recovery (study item 1.5)
// ---------------------------------------------------------------------------

fn armed_guardrails(state: &hf_core::armed::ArmedState) -> Guardrails {
    Guardrails::new(
        GuardrailPolicy::permissive(),
        std::sync::Arc::new(AutoApprove),
    )
    .with_guard(std::sync::Arc::new(hf_guardrails::DisarmedGuard::new(
        state.clone(),
    )))
}

#[tokio::test]
async fn a_disarmed_process_may_not_run_a_fuzzer() {
    let state = hf_core::armed::ArmedState::new();
    let g = armed_guardrails(&state);
    // Permissive policy, auto-approving gate: the only thing standing between
    // a restored campaign and execution is the armed state.
    assert!(
        g.authorize(run_fuzzer()).await.is_err(),
        "a fresh process must not resume a campaign without being armed"
    );
}

#[tokio::test]
async fn a_disarmed_process_may_still_inspect() {
    let state = hf_core::armed::ArmedState::new();
    let g = armed_guardrails(&state);
    // Restoring what the system was doing is the point; only acting is gated.
    assert!(g.authorize(Action::Discover).await.is_ok());
    assert!(g.authorize(Action::Triage).await.is_ok());
}

#[tokio::test]
async fn arming_lets_the_restored_campaign_proceed() {
    let state = hf_core::armed::ArmedState::new();
    let g = armed_guardrails(&state);
    state.arm();
    assert!(g.authorize(run_fuzzer()).await.is_ok());
}

#[tokio::test]
async fn disarming_stops_a_campaign_that_was_previously_authorized() {
    let state = hf_core::armed::ArmedState::new();
    let g = armed_guardrails(&state);
    state.arm();
    assert!(g.authorize(run_fuzzer()).await.is_ok());
    state.disarm();
    assert!(
        g.authorize(run_fuzzer()).await.is_err(),
        "withdrawing authorization must take effect immediately"
    );
}
