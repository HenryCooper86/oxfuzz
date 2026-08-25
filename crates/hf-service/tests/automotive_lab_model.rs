//! Responder model and reset evidence contract.
//!
//! The model is a statement about a reviewed script, never about hardware. An
//! unconfirmed reset is never treated as a successful one.

#![cfg(feature = "automotive-lab")]

use hf_automotive::{AutomotiveMode, AutomotiveProtocol};
use hf_service::automotive_lab::{
    plan_sequence, reset_evidence, simulate_plan, EcuRule, EcuScript, ResetOutcome,
    SequencePlanRequest, StepReachability, MAX_SCRIPT_RULES,
};

fn rule(from: &str, request: &str, response: &str, to: &str) -> EcuRule {
    EcuRule {
        from_state: from.to_owned(),
        request: request.to_owned(),
        response: response.to_owned(),
        to_state: to.to_owned(),
    }
}

fn script() -> EcuScript {
    EcuScript {
        name: "uds-session".to_owned(),
        initial_state: "default".to_owned(),
        rules: vec![
            rule("default", "scan_uds", "positive", "extended"),
            rule("extended", "replay", "positive", "extended"),
        ],
    }
}

fn plan_request() -> SequencePlanRequest {
    SequencePlanRequest {
        protocol: AutomotiveProtocol::Uds,
        mode: AutomotiveMode::VirtualCan,
        operations: vec!["scan_uds".to_owned(), "replay".to_owned()],
        state_model: None,
    }
}

#[test]
fn a_script_must_be_deterministic_and_must_start_somewhere() {
    assert!(script().validate().is_ok());

    // Two rules for the same state and request: the model could not decide.
    let mut ambiguous = script();
    ambiguous
        .rules
        .push(rule("default", "scan_uds", "negative", "default"));
    let error = ambiguous
        .validate()
        .expect_err("a non-deterministic script cannot validate anything");
    assert!(error.to_string().contains("deterministic"));

    // An initial state no rule mentions means the model starts nowhere.
    let mut nowhere = script();
    nowhere.initial_state = "unknown".to_owned();
    assert!(nowhere.validate().is_err());

    let mut empty_name = script();
    empty_name.name = String::new();
    assert!(empty_name.validate().is_err());

    let mut too_many = script();
    too_many.rules = (0..=MAX_SCRIPT_RULES)
        .map(|index| rule("default", &format!("op{index}"), "positive", "default"))
        .collect();
    assert!(too_many.validate().is_err());
}

#[test]
fn simulation_reports_reachability_under_the_script_and_never_reorders_the_plan() {
    let plan = plan_sequence(&plan_request(), &[]);
    let simulation = simulate_plan(&script(), &plan).expect("a valid script simulates");

    assert_eq!(simulation.script_name, "uds-session");
    assert_eq!(
        simulation.steps.len(),
        plan.steps.len(),
        "every planned step is reported"
    );
    // The plan's own order is preserved: the model reports, it does not plan.
    for (index, step) in simulation.steps.iter().enumerate() {
        assert_eq!(step.index, plan.steps[index].index);
        assert_eq!(step.operation, plan.steps[index].operation);
    }
    assert_eq!(
        simulation.steps[0].reachability,
        StepReachability::Reachable
    );
    assert_eq!(simulation.steps[0].state_before, "default");
}

#[test]
fn an_unreachable_step_is_reported_rather_than_failing_the_plan() {
    // A script that only knows the first operation.
    let narrow = EcuScript {
        name: "narrow".to_owned(),
        initial_state: "default".to_owned(),
        rules: vec![rule("default", "scan_uds", "positive", "extended")],
    };
    let mut request = plan_request();
    request.operations = vec!["scan_uds".to_owned(), "replay".to_owned()];
    let plan = plan_sequence(&request, &[]);
    let simulation = simulate_plan(&narrow, &plan).expect("simulates");

    assert!(
        simulation
            .steps
            .iter()
            .any(|step| step.reachability == StepReachability::UnreachableUnderScript),
        "an incomplete script shows as unreachable steps"
    );
    // An incomplete script is the common case, not a refusal.
    assert!(!simulation.steps.is_empty());
}

#[test]
fn an_invalid_script_refuses_to_simulate() {
    let mut ambiguous = script();
    ambiguous
        .rules
        .push(rule("default", "scan_uds", "negative", "default"));
    let plan = plan_sequence(&plan_request(), &[]);
    assert!(simulate_plan(&ambiguous, &plan).is_err());
}

#[test]
fn reset_is_confirmed_only_when_both_digests_are_present_and_equal() {
    let baseline = "a".repeat(64);
    let confirmed = reset_evidence(Some(&baseline), Some(&baseline));
    assert_eq!(confirmed.outcome, ResetOutcome::Confirmed);
    assert!(confirmed.attributable);

    let other = "b".repeat(64);
    let mismatched = reset_evidence(Some(&baseline), Some(&other));
    assert_eq!(mismatched.outcome, ResetOutcome::Mismatched);
    assert!(
        !mismatched.attributable,
        "a reset that did not restore the baseline leaves the start state unknown"
    );
}

#[test]
fn a_missing_digest_is_unconfirmed_and_never_silently_successful() {
    let baseline = "a".repeat(64);
    for evidence in [
        reset_evidence(Some(&baseline), None),
        reset_evidence(None, Some(&baseline)),
        reset_evidence(None, None),
    ] {
        assert_eq!(evidence.outcome, ResetOutcome::Unconfirmed);
        assert!(
            !evidence.attributable,
            "findings after an unconfirmed reset are not attributable"
        );
        assert!(!evidence.reason_code.is_empty());
    }
}
