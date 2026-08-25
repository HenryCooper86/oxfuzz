//! Stateful Automotive Lab planning and coverage contract.
//!
//! The physical bench gains no sequence path, and coverage never invents a
//! denominator it has no evidence for.

#![cfg(feature = "automotive-lab")]

use std::collections::BTreeMap;

use chrono::{TimeZone, Utc};
use hf_automotive::{AutomotiveMode, AutomotiveProtocol, StateSignature};
use hf_service::automotive_lab::{
    plan_sequence, protocol_state_coverage, ObservedStateEvidence, PlanRefusal, SequencePlanRequest,
};
use uuid::Uuid;

fn state(protocol: AutomotiveProtocol, key: &str, value: &str) -> StateSignature {
    let mut observations = BTreeMap::new();
    observations.insert(key.to_owned(), value.to_owned());
    StateSignature::from_observations(protocol, observations).expect("a valid signature")
}

fn evidence(signature: StateSignature, seconds: i64) -> ObservedStateEvidence {
    ObservedStateEvidence {
        signature,
        source_operation_id: Uuid::nil(),
        observed_at: Utc.timestamp_opt(seconds, 0).unwrap(),
    }
}

fn request(mode: AutomotiveMode) -> SequencePlanRequest {
    SequencePlanRequest {
        protocol: AutomotiveProtocol::Uds,
        mode,
        operations: vec!["scan_uds".to_owned(), "replay".to_owned()],
        state_model: None,
    }
}

#[test]
fn a_plan_naming_the_physical_bench_is_refused_and_says_why() {
    let plan = plan_sequence(&request(AutomotiveMode::PhysicalBench), &[]);
    assert_eq!(
        plan.refusal,
        Some(PlanRefusal::PhysicalBenchNotSequenceable)
    );
    assert!(
        plan.steps.is_empty(),
        "a refused plan carries no steps to run"
    );
}

#[test]
fn virtual_and_offline_modes_plan_normally() {
    for mode in [AutomotiveMode::VirtualCan, AutomotiveMode::OfflinePcap] {
        let observed = vec![evidence(
            state(AutomotiveProtocol::Uds, "session", "default"),
            10,
        )];
        let plan = plan_sequence(&request(mode), &observed);
        assert_eq!(plan.refusal, None, "{mode:?} is sequenceable");
        assert!(!plan.steps.is_empty());
        assert_eq!(plan.mode, mode);
    }
}

#[test]
fn coverage_reports_observed_states_from_retained_evidence() {
    let default_session = state(AutomotiveProtocol::Uds, "session", "default");
    let extended = state(AutomotiveProtocol::Uds, "session", "extended");
    let observed = vec![
        evidence(default_session.clone(), 10),
        // The same state seen twice is one state.
        evidence(default_session.clone(), 20),
        evidence(extended.clone(), 30),
    ];

    let coverage = protocol_state_coverage(AutomotiveProtocol::Uds, &observed, None);
    assert_eq!(coverage.observed.len(), 2);
    assert!(coverage
        .observed
        .iter()
        .any(|entry| entry.digest == default_session.digest.as_str()));
}

#[test]
fn without_a_state_model_there_is_no_denominator_and_no_unreached_list() {
    let observed = vec![evidence(
        state(AutomotiveProtocol::Uds, "session", "default"),
        10,
    )];
    let coverage = protocol_state_coverage(AutomotiveProtocol::Uds, &observed, None);

    assert_eq!(
        coverage.expected_total, None,
        "retained evidence cannot establish how many states exist"
    );
    assert!(
        coverage.unreached.is_empty(),
        "nothing can be called unreached without a model of what exists"
    );
    assert_eq!(coverage.model_name, None);
}

#[test]
fn a_reviewed_model_supplies_the_denominator_and_is_named() {
    let default_session = state(AutomotiveProtocol::Uds, "session", "default");
    let observed = vec![evidence(default_session.clone(), 10)];
    let model = hf_service::automotive_lab::StateModel {
        name: "uds-session-model".to_owned(),
        states: vec![
            default_session.digest.as_str().to_owned(),
            "a".repeat(64),
            "b".repeat(64),
        ],
    };

    let coverage = protocol_state_coverage(AutomotiveProtocol::Uds, &observed, Some(&model));
    assert_eq!(coverage.expected_total, Some(3));
    assert_eq!(coverage.model_name.as_deref(), Some("uds-session-model"));
    assert_eq!(coverage.unreached.len(), 2);
    assert!(coverage.unreached.contains(&"a".repeat(64)));
}

#[test]
fn a_state_observed_but_absent_from_the_model_is_not_silently_dropped() {
    let observed = vec![evidence(
        state(AutomotiveProtocol::Uds, "session", "extended"),
        10,
    )];
    let model = hf_service::automotive_lab::StateModel {
        name: "narrow-model".to_owned(),
        states: vec!["a".repeat(64)],
    };
    let coverage = protocol_state_coverage(AutomotiveProtocol::Uds, &observed, Some(&model));

    // The evidence still reports what it saw, even though the model did not
    // anticipate it; a model that is wrong should be visibly wrong.
    assert_eq!(coverage.observed.len(), 1);
    assert_eq!(coverage.expected_total, Some(1));
    assert_eq!(coverage.unreached.len(), 1);
}

#[test]
fn planning_is_deterministic_and_prefers_unreached_states_then_least_recently_seen() {
    let old_state = state(AutomotiveProtocol::Uds, "session", "default");
    let recent = state(AutomotiveProtocol::Uds, "session", "extended");
    let observed = vec![
        evidence(old_state.clone(), 10),
        evidence(recent.clone(), 900),
    ];

    let model = hf_service::automotive_lab::StateModel {
        name: "model".to_owned(),
        states: vec![
            old_state.digest.as_str().to_owned(),
            recent.digest.as_str().to_owned(),
            "c".repeat(64),
        ],
    };
    let mut req = request(AutomotiveMode::VirtualCan);
    req.state_model = Some(model);

    let first = plan_sequence(&req, &observed);
    let second = plan_sequence(&req, &observed);
    assert_eq!(first.steps, second.steps, "planning is deterministic");

    // The unreached state leads; then the least recently observed one.
    assert_eq!(first.steps[0].reason_code, "unreached_state");
    assert_eq!(
        first.steps[0].expected_start_state.as_deref(),
        Some("c".repeat(64).as_str())
    );
    assert_eq!(first.steps[1].reason_code, "least_recently_observed");
    assert_eq!(
        first.steps[1].expected_start_state.as_deref(),
        Some(old_state.digest.as_str().to_owned().as_str())
    );
}

#[test]
fn a_plan_with_no_operations_is_empty_rather_than_invented() {
    let mut req = request(AutomotiveMode::VirtualCan);
    req.operations.clear();
    let plan = plan_sequence(&req, &[]);
    assert!(plan.steps.is_empty());
    assert_eq!(plan.refusal, Some(PlanRefusal::NoOperations));
}
