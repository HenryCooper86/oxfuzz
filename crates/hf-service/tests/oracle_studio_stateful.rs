//! Metamorphic, stateful, and resource oracle contract.
//!
//! These three carry evidence the stateless kinds do not: a relation, a step
//! index, an observed growth. Bounds exist so a specification cannot ask for a
//! sequence that never terminates.

#![cfg(feature = "oracle-studio")]

use hf_core::target::TargetLanguage;
use hf_service::oracle_studio::{
    classify_oracle_violation, render_oracle_harness, validate_spec, MetamorphicRelation,
    OracleKind, OracleProperty, OracleSpec, MAX_RESOURCE_GROWTH, MAX_STATEFUL_STEPS,
    ORACLE_VIOLATION_MARKER,
};
use uuid::Uuid;

fn spec(property: OracleProperty) -> OracleSpec {
    OracleSpec {
        id: Uuid::nil(),
        target_symbol: "parse_packet".to_owned(),
        property,
        description: "the property under test".to_owned(),
    }
}

fn metamorphic(relation: MetamorphicRelation) -> OracleSpec {
    spec(OracleProperty::Metamorphic {
        transform: "append_padding".to_owned(),
        relation,
    })
}

fn stateful(max_steps: u32) -> OracleSpec {
    spec(OracleProperty::Stateful {
        apply: "apply_operation".to_owned(),
        check: "session_is_consistent".to_owned(),
        max_steps,
    })
}

fn resource(max_growth: u64) -> OracleSpec {
    spec(OracleProperty::Resource {
        measure: "bytes_allocated".to_owned(),
        max_growth,
    })
}

#[test]
fn each_new_kind_reports_its_own_kind() {
    assert_eq!(
        metamorphic(MetamorphicRelation::Equal).kind(),
        OracleKind::Metamorphic
    );
    assert_eq!(stateful(16).kind(), OracleKind::Stateful);
    assert_eq!(resource(4096).kind(), OracleKind::Resource);
}

#[test]
fn a_metamorphic_relation_comes_from_a_closed_vocabulary_and_renders_its_comparison() {
    for (relation, comparison) in [
        (MetamorphicRelation::Equal, "!="),
        (MetamorphicRelation::NotLess, "<"),
        (MetamorphicRelation::NotGreater, ">"),
    ] {
        let source = render_oracle_harness(&metamorphic(relation)).expect("renders");
        assert!(source.contains("append_padding"), "it calls the transform");
        assert!(source.contains("parse_packet"), "it calls the target twice");
        assert!(
            source.contains(comparison),
            "the {relation:?} relation renders its comparison"
        );
    }
}

#[test]
fn a_stateful_scaffold_bounds_its_sequence_and_reports_the_failing_step() {
    let source = render_oracle_harness(&stateful(16)).expect("renders");
    assert!(source.contains("apply_operation"));
    assert!(source.contains("session_is_consistent"));
    assert!(
        source.contains("16"),
        "the reviewed step ceiling is in the source"
    );
    assert!(
        source.contains("step="),
        "a stateful violation names the step it failed at"
    );
}

#[test]
fn a_resource_scaffold_compares_a_reported_measurement_across_the_call() {
    let source = render_oracle_harness(&resource(4096)).expect("renders");
    assert!(source.contains("bytes_allocated"));
    assert!(source.contains("parse_packet"));
    assert!(
        source.contains("4096"),
        "the reviewed allowance is in the source"
    );
    assert!(
        source.contains("growth="),
        "a resource violation names how much it grew"
    );
}

#[test]
fn a_step_ceiling_or_growth_allowance_outside_its_range_is_refused() {
    for steps in [0, MAX_STATEFUL_STEPS + 1] {
        assert!(
            validate_spec(&stateful(steps)).is_err(),
            "{steps} steps is out of range"
        );
    }
    assert!(
        validate_spec(&resource(MAX_RESOURCE_GROWTH + 1)).is_err(),
        "an unbounded growth allowance proves nothing"
    );
    // The bounds themselves are accepted.
    assert!(validate_spec(&stateful(MAX_STATEFUL_STEPS)).is_ok());
    assert!(validate_spec(&resource(MAX_RESOURCE_GROWTH)).is_ok());
}

#[test]
fn hostile_symbols_are_refused_in_the_new_kinds_too() {
    let hostile = "evil(); system(\"id\"); //".to_owned();
    for property in [
        OracleProperty::Metamorphic {
            transform: hostile.clone(),
            relation: MetamorphicRelation::Equal,
        },
        OracleProperty::Stateful {
            apply: hostile.clone(),
            check: "ok".to_owned(),
            max_steps: 4,
        },
        OracleProperty::Stateful {
            apply: "ok".to_owned(),
            check: hostile.clone(),
            max_steps: 4,
        },
        OracleProperty::Resource {
            measure: hostile.clone(),
            max_growth: 16,
        },
    ] {
        let candidate = spec(property);
        assert!(validate_spec(&candidate).is_err());
        assert!(render_oracle_harness(&candidate).is_err());
    }
}

#[test]
fn every_new_scaffold_survives_the_harness_lint() {
    for candidate in [
        metamorphic(MetamorphicRelation::Equal),
        metamorphic(MetamorphicRelation::NotLess),
        stateful(8),
        resource(1024),
    ] {
        let source = render_oracle_harness(&candidate).unwrap();
        let findings = hf_harness::lint_harness_source(&source, TargetLanguage::C);
        assert!(
            !hf_harness::has_blocking_finding(&findings),
            "an oracle scaffold must build: {}",
            hf_harness::render_findings(&findings)
        );
    }
}

#[test]
fn violation_detail_is_classified_and_its_absence_does_not_stop_classification() {
    let id = Uuid::new_v4();

    let with_step = format!("{ORACLE_VIOLATION_MARKER} {id} stateful step=3\n");
    let violation = classify_oracle_violation(&with_step).expect("classifies");
    assert_eq!(violation.kind, OracleKind::Stateful);
    assert_eq!(violation.detail.as_deref(), Some("step=3"));

    let with_growth = format!("{ORACLE_VIOLATION_MARKER} {id} resource growth=8192\n");
    let violation = classify_oracle_violation(&with_growth).expect("classifies");
    assert_eq!(violation.detail.as_deref(), Some("growth=8192"));

    // The oracle and kind are what make a line a violation.
    let bare = format!("{ORACLE_VIOLATION_MARKER} {id} metamorphic\n");
    let violation = classify_oracle_violation(&bare).expect("classifies without detail");
    assert_eq!(violation.kind, OracleKind::Metamorphic);
    assert_eq!(violation.detail, None);
}
