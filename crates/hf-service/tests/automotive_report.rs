#![cfg(feature = "automotive-scapy")]

use std::collections::BTreeMap;

use chrono::{TimeZone as _, Utc};
use hf_automotive::{AutomotiveProtocol, StateSignature};
use hf_service::automotive::AutomotiveStateCorpusEntry;
use hf_service::automotive_report::{
    append_ai_interpretation, automotive_report_system_prompt, automotive_report_user_prompt,
    render_automotive_report, validate_ai_interpretation, AutomotiveDangerousServicesPosture,
    AutomotivePhysicalBenchPosture, AutomotivePolicyPosture, AutomotiveReportData,
    AutomotiveReportOperation, AutomotiveReportSafetyPosture,
};
use hf_storage::AutomotiveOperationStatus;
use uuid::Uuid;

const OPERATION_ID: Uuid = Uuid::from_u128(0x11111111_2222_3333_4444_555555555555);
const FAILED_OPERATION_ID: Uuid = Uuid::from_u128(0xaaaaaaaa_bbbb_cccc_dddd_eeeeeeeeeeee);
const STATE_DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const REQUEST_DIGEST: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
const TRANSCRIPT_DIGEST: &str = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef";

fn report_data() -> AutomotiveReportData {
    let state_signature = StateSignature::from_observations(
        AutomotiveProtocol::Uds,
        BTreeMap::from([("session".to_owned(), "extended".to_owned())]),
    )
    .unwrap();
    let started_at = Utc.with_ymd_and_hms(2026, 7, 16, 8, 0, 0).unwrap();
    AutomotiveReportData {
        generated_at: "2026-07-16T09:00:00Z".to_owned(),
        project_name: "vehicle-gateway".to_owned(),
        tool_version: "0.1.0".to_owned(),
        safety: AutomotiveReportSafetyPosture {
            runtime_policy: AutomotivePolicyPosture::Enabled,
            allowed_protocols: vec!["can".to_owned(), "uds".to_owned()],
            allowed_modes: vec!["offline_pcap".to_owned(), "virtual_can".to_owned()],
            virtual_interface_count: 1,
            physical_bench: AutomotivePhysicalBenchPosture::Disabled,
            physical_interface_count: 0,
            dangerous_services: AutomotiveDangerousServicesPosture::Denied,
            max_packets: 10_000,
            max_duration_secs: 300,
            max_rate_per_second: 100,
        },
        operations: vec![
            AutomotiveReportOperation {
                id: OPERATION_ID,
                operation: "analyze_capture".to_owned(),
                mode: "offline_pcap".to_owned(),
                protocol: Some("uds".to_owned()),
                status: AutomotiveOperationStatus::Done,
                started_at,
                ended_at: Some(started_at + chrono::Duration::seconds(2)),
                request_sha256: REQUEST_DIGEST.to_owned(),
                transcript_sha256: Some(TRANSCRIPT_DIGEST.to_owned()),
                artifact_dir: ".service/automotive/operation-one".to_owned(),
                error: None,
                state_signatures: vec![state_signature],
                result_summary: Some("42 decoded events; 1 protocol state".to_owned()),
                result_complete: Some(true),
            },
            AutomotiveReportOperation {
                id: FAILED_OPERATION_ID,
                operation: "execute_replay".to_owned(),
                mode: "virtual_can".to_owned(),
                protocol: Some("uds".to_owned()),
                status: AutomotiveOperationStatus::Failed,
                started_at: started_at + chrono::Duration::minutes(5),
                ended_at: Some(started_at + chrono::Duration::minutes(5)),
                request_sha256: "1212".repeat(16),
                transcript_sha256: None,
                artifact_dir: ".service/automotive/operation-two".to_owned(),
                error: Some(
                    "sidecar response failed validation at path=/Users/alice/vehicle/capture.pcap \
                     and \"C:\\private\\frame.bin\""
                        .to_owned(),
                ),
                state_signatures: Vec::new(),
                result_summary: None,
                result_complete: None,
            },
        ],
        state_corpus: vec![AutomotiveStateCorpusEntry {
            project_root: "/private/host/path/vehicle-gateway".to_owned(),
            protocol: AutomotiveProtocol::Uds,
            state_digest: STATE_DIGEST.to_owned(),
            artifact_sha256: "3434".repeat(16),
            source_operation_id: OPERATION_ID,
            artifact_path: "project/.service/automotive/state-corpus/uds/evidence".to_owned(),
            created_at: started_at + chrono::Duration::minutes(3),
        }],
    }
}

#[test]
fn deterministic_report_is_a_complete_traceable_campaign_record() {
    let report = render_automotive_report(&report_data());

    assert!(report.starts_with("# Automotive Fuzzing Campaign Report"));
    for section in [
        "## Executive Summary",
        "## Scope and Safety Posture",
        "## Campaign Workflow",
        "## Protocol-State Exploration",
        "## Findings",
        "## Evidence Manifest",
        "## Limitations",
        "## Recommendations",
    ] {
        assert!(report.contains(section), "missing {section}");
    }
    assert!(report.contains(&format!("[OP:{OPERATION_ID}]")));
    assert!(report.contains(&format!("[STATE:{STATE_DIGEST}]")));
    assert!(report.contains(&format!("[TRANSCRIPT:{TRANSCRIPT_DIGEST}]")));
    assert!(report.contains("sidecar response failed validation"));
    assert!(!report.contains("/Users/alice"));
    assert!(!report.contains("C:\\private"));
    assert!(report.contains("42 decoded events"));
    assert!(report.contains("1 completed"));
    assert!(report.contains("1 failed"));
    assert!(!report.contains("/private/host/path"));
}

#[test]
fn a_done_but_incomplete_operation_is_reported_as_partial_not_completed() {
    // A Done operation whose result was not complete must be counted as
    // "partial" in the Executive Summary, matching the Campaign Workflow table
    // (which treats it as "Attention") and the Findings section -- not double-
    // counted as "completed".
    let mut data = report_data();
    if let Some(op) = data.operations.first_mut() {
        op.result_complete = Some(false);
    }
    let report = render_automotive_report(&data);
    assert!(
        report.contains("0 completed"),
        "an incomplete Done op must not be counted as completed"
    );
    assert!(
        report.contains("1 partial"),
        "an incomplete Done op must be counted as partial"
    );
}

#[test]
fn report_does_not_overstate_protocol_state_evidence() {
    let report = render_automotive_report(&report_data()).to_ascii_lowercase();

    assert!(report.contains("protocol-state"));
    assert!(report.contains("not source coverage"));
    assert!(report.contains("does not by itself prove a vulnerability"));
    assert!(!report.contains("confirmed vulnerability"));
}

#[test]
fn ai_prompt_is_grounded_and_only_known_evidence_citations_are_accepted() {
    let data = report_data();
    let facts = render_automotive_report(&data);
    let prompt = automotive_report_user_prompt(&facts, &data);

    assert!(automotive_report_system_prompt().contains("NEVER invent"));
    assert!(prompt.contains(&facts));
    assert!(prompt.contains("[OP:<uuid>]"));
    assert!(prompt.contains("Hypotheses"));
    assert!(prompt.contains("cannot authorize"));

    let valid = format!(
        "### Evidence-backed interpretation\nThe failed virtual replay needs review \
         [OP:{FAILED_OPERATION_ID}].\n\n### Hypotheses\nNone.\n\n### Missing evidence\n\
         No successful virtual replay is retained.\n\n### Recommended next actions\nReview the \
         retained failure before another supervised virtual run [OP:{FAILED_OPERATION_ID}]."
    );
    assert!(validate_ai_interpretation(&valid, &data).is_ok());

    let unknown = valid.replace(
        &FAILED_OPERATION_ID.to_string(),
        "00000000-0000-0000-0000-000000000001",
    );
    assert!(validate_ai_interpretation(&unknown, &data)
        .unwrap_err()
        .contains("unknown operation"));

    let uncited = "### Evidence-backed interpretation\nLooks good.\n\n### Hypotheses\nNone.\n\n\
        ### Missing evidence\nNone.\n\n### Recommended next actions\nContinue.";
    assert!(validate_ai_interpretation(uncited, &data)
        .unwrap_err()
        .contains("citation"));
}

#[test]
fn ai_interpretation_is_advisory_and_cannot_replace_the_fact_sheet() {
    let data = report_data();
    let facts = render_automotive_report(&data);
    let interpretation = format!(
        "### Evidence-backed interpretation\nReview the retained failure [OP:{FAILED_OPERATION_ID}].\n\n\
         ### Hypotheses\nNone.\n\n### Missing evidence\nA completed virtual replay.\n\n\
         ### Recommended next actions\nRepeat only after operator review [OP:{FAILED_OPERATION_ID}]."
    );
    let composed = append_ai_interpretation(&facts, &interpretation, "test-model");

    assert!(composed.starts_with(&facts));
    assert!(composed.contains("## AI-Assisted Interpretation"));
    assert!(composed.contains("advisory"));
    assert!(composed.contains("test-model"));
}
