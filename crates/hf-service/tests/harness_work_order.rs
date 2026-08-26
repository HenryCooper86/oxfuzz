//! Harness Work Order domain contract.
//!
//! The packet is the provider-free authoring path: deterministic, secret-free,
//! and carrying the compile reality the harness will actually be built against.

#![cfg(feature = "harness-work-order")]

use std::path::PathBuf;

use hf_core::build::BuildContext;
use hf_service::harness_work_order::{build_work_order, render_work_order, WorkOrderInputs};

fn inputs() -> WorkOrderInputs {
    WorkOrderInputs {
        target_symbol: "parse_packet".to_owned(),
        signature: Some("int parse_packet(const uint8_t*, size_t)".to_owned()),
        location: "src/parser.c:42".to_owned(),
        rationale: "untrusted packet parser reached from the network path".to_owned(),
        language: "c".to_owned(),
        source_excerpt: "int parse_packet(const uint8_t *data, size_t len) {\n    return 0;\n}"
            .to_owned(),
        build_context: BuildContext {
            include_dirs: vec![PathBuf::from("/proj/include")],
            defines: vec!["-DHAVE_CONFIG_H=1".to_owned()],
            std_flag: Some("-std=c11".to_owned()),
            extra_flags: vec!["-fno-omit-frame-pointer".to_owned()],
            entry_count: 12,
            dropped: Vec::new(),
        },
        seed_suggestions: vec!["tests/fixtures/packet.bin".to_owned()],
        project_display: "/proj".to_owned(),
    }
}

#[test]
fn the_packet_carries_the_compile_reality_the_harness_will_be_built_against() {
    let rendered = render_work_order(&build_work_order(&inputs()));

    assert!(rendered.contains("/proj/include"), "include directories");
    assert!(rendered.contains("-DHAVE_CONFIG_H=1"), "defines");
    assert!(rendered.contains("-std=c11"), "language standard");
}

#[test]
fn the_packet_names_the_candidate_and_shows_its_source() {
    let rendered = render_work_order(&build_work_order(&inputs()));

    assert!(rendered.contains("parse_packet"));
    assert!(rendered.contains("src/parser.c:42"));
    assert!(rendered.contains("int parse_packet(const uint8_t *data, size_t len)"));
}

#[test]
fn the_packet_states_the_rules_the_lint_will_enforce() {
    let order = build_work_order(&inputs());
    let rendered = render_work_order(&order);

    assert!(
        !order.harness_rules.is_empty(),
        "an author must see the constraints before writing, not as compile failures after"
    );
    // The rules come from the lint itself, so the packet cannot drift from it.
    for rule in &order.harness_rules {
        assert!(
            rendered.contains(&rule.id),
            "rule {} must be rendered",
            rule.id
        );
    }
    let ids: Vec<&str> = order.harness_rules.iter().map(|r| r.id.as_str()).collect();
    assert!(ids.contains(&"no-process-exit"));
    assert!(ids.contains(&"no-shell"));
}

#[test]
fn the_packet_tells_the_author_how_to_validate_the_result() {
    let order = build_work_order(&inputs());

    assert!(
        !order.validation_commands.is_empty(),
        "a packet that cannot be checked is a suggestion, not a work order"
    );
    let rendered = render_work_order(&order);
    assert!(rendered.contains("oxfuzz"));
}

#[test]
fn the_same_retained_state_renders_byte_identical_packets() {
    let first = render_work_order(&build_work_order(&inputs()));
    let second = render_work_order(&build_work_order(&inputs()));

    assert_eq!(first, second, "two exports must be diffable");
}

#[test]
fn nothing_from_the_environment_reaches_the_packet() {
    // A regression guard: if someone later interpolates configuration into the
    // packet, a credential must not be what arrives.
    let rendered = render_work_order(&build_work_order(&inputs()));

    for marker in [
        "HF_PROVIDER_API_KEY",
        "API_KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "Bearer ",
    ] {
        assert!(!rendered.contains(marker), "packet must not carry {marker}");
    }
}

#[test]
fn a_candidate_with_no_recorded_signature_still_produces_a_packet() {
    let mut inputs = inputs();
    inputs.signature = None;

    let rendered = render_work_order(&build_work_order(&inputs));

    assert!(rendered.contains("parse_packet"));
}

#[test]
fn an_empty_compile_context_is_stated_rather_than_left_blank() {
    let mut inputs = inputs();
    inputs.build_context = BuildContext {
        include_dirs: Vec::new(),
        defines: Vec::new(),
        std_flag: None,
        extra_flags: Vec::new(),
        entry_count: 0,
        dropped: Vec::new(),
    };

    let rendered = render_work_order(&build_work_order(&inputs));

    assert!(
        rendered.to_lowercase().contains("no compile database"),
        "an author must know the flags are guesses, not the project's own"
    );
}

#[test]
fn a_packet_with_no_seed_suggestion_says_so() {
    let mut inputs = inputs();
    inputs.seed_suggestions = Vec::new();

    let rendered = render_work_order(&build_work_order(&inputs));

    assert!(rendered.to_lowercase().contains("no seed"));
}

#[test]
fn a_candidate_with_no_recorded_rationale_does_not_render_a_dangling_label() {
    let mut inputs = inputs();
    inputs.rationale = String::new();

    let rendered = render_work_order(&build_work_order(&inputs));

    assert!(
        !rendered.contains("Why it was ranked: \n"),
        "an empty rationale must be stated, not left as an empty field"
    );
    assert!(rendered.contains("Why it was ranked: not recorded"));
}
