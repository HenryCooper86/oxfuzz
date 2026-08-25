//! Oracle Studio specification and scaffold contract.
//!
//! Symbols reach generated C source, so validation is the injection boundary
//! and fails closed. Every rendered scaffold must survive the harness lint the
//! rest of the pipeline enforces.

#![cfg(feature = "oracle-studio")]

use hf_core::target::TargetLanguage;
use hf_service::oracle_studio::{
    classify_oracle_violation, render_oracle_harness, validate_spec, OracleKind, OracleProperty,
    OracleSpec, ORACLE_VIOLATION_MARKER,
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

fn differential() -> OracleSpec {
    spec(OracleProperty::Differential {
        reference: "parse_packet_reference".to_owned(),
    })
}

fn round_trip() -> OracleSpec {
    spec(OracleProperty::RoundTrip {
        encode: "encode_packet".to_owned(),
        decode: "decode_packet".to_owned(),
    })
}

fn invariant() -> OracleSpec {
    spec(OracleProperty::Invariant {
        predicate: "arena_is_balanced".to_owned(),
    })
}

#[test]
fn a_symbol_that_is_not_a_plain_identifier_never_reaches_generated_source() {
    // Each of these would break out of the call site it is interpolated into.
    for hostile in [
        "parse(); system(\"id\"); //",
        "parse_packet, evil()",
        "parse_packet\n#include <stdlib.h>",
        "parse packet",
        "1_leading_digit",
        "",
        "*deref",
        "parse_packet /* comment */",
    ] {
        let candidate = spec(OracleProperty::Differential {
            reference: hostile.to_owned(),
        });
        let error = validate_spec(&candidate)
            .expect_err("a non-identifier symbol is refused before rendering");
        assert!(
            error.to_string().contains("identifier"),
            "the refusal explains what was wrong: {error}"
        );
        assert!(
            render_oracle_harness(&candidate).is_err(),
            "rendering refuses the same specification"
        );
    }
}

#[test]
fn an_over_long_symbol_is_bounded() {
    let candidate = spec(OracleProperty::Differential {
        reference: "a".repeat(4096),
    });
    assert!(validate_spec(&candidate).is_err());
}

#[test]
fn every_kind_renders_a_scaffold_that_names_its_property_and_traps() {
    for (candidate, expected_kind, symbols) in [
        (
            differential(),
            OracleKind::Differential,
            vec!["parse_packet_reference"],
        ),
        (
            round_trip(),
            OracleKind::RoundTrip,
            vec!["encode_packet", "decode_packet"],
        ),
        (
            invariant(),
            OracleKind::Invariant,
            vec!["arena_is_balanced"],
        ),
    ] {
        assert_eq!(candidate.kind(), expected_kind);
        let source = render_oracle_harness(&candidate).expect("a valid spec renders");

        assert!(source.contains("LLVMFuzzerTestOneInput"), "it is a harness");
        assert!(
            source.contains("// Discovered target: parse_packet"),
            "every scaffold records which target the oracle belongs to"
        );
        for symbol in symbols {
            assert!(source.contains(symbol), "it calls {symbol}");
        }
        assert!(
            source.contains(ORACLE_VIOLATION_MARKER),
            "a violation is recorded as retained evidence"
        );
        assert!(
            source.contains("__builtin_trap()"),
            "the failure path is unconditional, unlike assert under NDEBUG"
        );
        assert!(
            source.contains("the property under test"),
            "the reviewed property statement travels with the harness"
        );
    }
}

#[test]
fn the_target_is_called_by_the_kinds_whose_subject_it_is() {
    // Differential and invariant test the target itself.
    for candidate in [differential(), invariant()] {
        let source = render_oracle_harness(&candidate).unwrap();
        assert!(
            source.contains("parse_packet(data, size)"),
            "it calls the target"
        );
    }
    // Round-trip's subject is the encode/decode pair, so it does not.
    let source = render_oracle_harness(&round_trip()).unwrap();
    assert!(!source.contains("parse_packet(data, size)"));
}

#[test]
fn every_rendered_scaffold_survives_the_harness_lint() {
    for candidate in [differential(), round_trip(), invariant()] {
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
fn rendering_is_deterministic_so_a_reviewed_scaffold_is_what_gets_built() {
    let candidate = round_trip();
    assert_eq!(
        render_oracle_harness(&candidate).unwrap(),
        render_oracle_harness(&candidate).unwrap()
    );
}

#[test]
fn the_marker_classifies_a_violation_and_names_the_oracle() {
    let id = Uuid::new_v4();
    let output =
        format!("some fuzzer chatter\n{ORACLE_VIOLATION_MARKER} {id} round_trip\nmore output\n");
    let violation = classify_oracle_violation(&output).expect("the marker classifies");
    assert_eq!(violation.oracle_id, id);
    assert_eq!(violation.kind, OracleKind::RoundTrip);
}

#[test]
fn a_memory_safety_crash_in_an_oracle_harness_is_not_an_oracle_violation() {
    // A real ASan report from a harness that also carries an oracle.
    let output = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n\
                  READ of size 1 at 0x602 thread T0\n";
    assert!(
        classify_oracle_violation(output).is_none(),
        "only the marker makes a finding an oracle violation"
    );
}

#[test]
fn absence_of_a_marker_is_not_evidence_that_the_property_holds() {
    assert!(classify_oracle_violation("").is_none());
    // A malformed marker line is not a violation either.
    assert!(classify_oracle_violation(&format!("{ORACLE_VIOLATION_MARKER} not-a-uuid")).is_none());
}
