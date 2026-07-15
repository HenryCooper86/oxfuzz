#![cfg(feature = "automotive-scapy")]

use std::collections::{BTreeMap, BTreeSet};

use hf_automotive::{
    canonical_transcript_hash, AnalyzeCaptureRequest, ArtifactRef, AutomotiveCapability,
    AutomotiveError, AutomotiveErrorCode, AutomotiveMode, AutomotiveProtocol, AutomotiveRequest,
    AutomotiveResult, CapabilityReport, CapabilityRequest, ContractError, MessageDirection,
    ModeConfig, MutationRequest, MutationResult, OperationLimits, ProtocolMessage, ReplayAction,
    ReplayPlan, ReplayPlanRequest, ReplayRequest, ReplayResult, ReplayStep, ResponseEnvelope,
    SchemaEnvelope, StateSignature, TranscriptEvent, Validate, AUTOMOTIVE_SCHEMA_VERSION,
};

fn limits() -> OperationLimits {
    OperationLimits {
        max_events: 64,
        max_payload_bytes: 4_096,
        max_duration_ms: 10_000,
        max_rate_per_second: 100,
    }
}

fn artifact(id: &str) -> ArtifactRef {
    ArtifactRef {
        artifact_id: id.to_owned(),
        sha256: "ab".repeat(32),
        media_type: "application/vnd.tcpdump.pcap".to_owned(),
        size_bytes: 128,
    }
}

fn message(protocol: AutomotiveProtocol, payload_hex: &str) -> ProtocolMessage {
    ProtocolMessage {
        protocol,
        payload_hex: payload_hex.to_owned(),
        fields: BTreeMap::from([
            ("service".to_owned(), "diagnostic".to_owned()),
            ("source".to_owned(), "fixture".to_owned()),
        ]),
    }
}

fn replay_plan(protocol: AutomotiveProtocol) -> ReplayPlan {
    ReplayPlan {
        protocol,
        mode: AutomotiveMode::VirtualCan,
        deterministic_seed: 7,
        steps: vec![ReplayStep {
            sequence: 0,
            delay_micros: 100,
            action: ReplayAction::Send,
            message: message(protocol, "010203"),
        }],
    }
}

fn event(
    sequence: u64,
    protocol: AutomotiveProtocol,
    payload_hex: &str,
    metadata: BTreeMap<String, String>,
) -> TranscriptEvent {
    TranscriptEvent {
        sequence,
        protocol,
        direction: MessageDirection::Transmit,
        offset_micros: sequence * 100,
        payload_hex: payload_hex.to_owned(),
        metadata,
    }
}

#[test]
fn every_supported_protocol_has_a_stable_serialized_name() {
    let expected = [
        "can",
        "can_fd",
        "iso_tp",
        "uds",
        "gmlan",
        "some_ip",
        "some_ip_sd",
        "do_ip",
        "obd",
        "ccp",
        "xcp",
        "bmw_hsfz",
        "sec_oc",
    ];

    assert_eq!(AutomotiveProtocol::ALL.len(), expected.len());
    for (protocol, name) in AutomotiveProtocol::ALL.into_iter().zip(expected) {
        let encoded = serde_json::to_string(&protocol).unwrap();
        assert_eq!(encoded, format!("\"{name}\""));
        assert_eq!(
            serde_json::from_str::<AutomotiveProtocol>(&encoded).unwrap(),
            protocol
        );
    }
}

#[test]
fn mode_configuration_requires_a_safe_interface_and_physical_approval() {
    assert!(ModeConfig::OfflinePcap.validate().is_ok());
    assert!(ModeConfig::VirtualCan {
        interface: "vcan0".to_owned(),
    }
    .validate()
    .is_ok());
    assert!(ModeConfig::VirtualCan {
        interface: "../can0".to_owned(),
    }
    .validate()
    .is_err());
    assert!(ModeConfig::VirtualCan {
        interface: "can0".to_owned(),
    }
    .validate()
    .is_err());
    assert!(ModeConfig::PhysicalBench {
        interface: "can:0".to_owned(),
        approval_id: "approval-1".to_owned(),
    }
    .validate()
    .is_ok());
    assert!(ModeConfig::PhysicalBench {
        interface: "can0".to_owned(),
        approval_id: String::new(),
    }
    .validate()
    .is_err());
}

#[test]
fn capabilities_must_declare_a_complete_nonempty_surface() {
    let report = CapabilityReport {
        adapter_name: "scapy-sidecar".to_owned(),
        adapter_version: "2.7.0".to_owned(),
        schema_versions: BTreeSet::from([AUTOMOTIVE_SCHEMA_VERSION]),
        protocols: AutomotiveProtocol::ALL.into_iter().collect(),
        modes: AutomotiveMode::ALL.into_iter().collect(),
        capabilities: BTreeSet::from([
            AutomotiveCapability::DecodeCapture,
            AutomotiveCapability::GenerateMutations,
            AutomotiveCapability::BuildReplayPlan,
            AutomotiveCapability::StateFeedback,
        ]),
        limits: limits(),
    };
    assert!(report.validate().is_ok());

    let mut invalid = report;
    invalid.schema_versions.clear();
    assert!(invalid.validate().is_err());

    invalid.schema_versions.insert(AUTOMOTIVE_SCHEMA_VERSION);
    invalid.modes.remove(&AutomotiveMode::PhysicalBench);
    invalid
        .capabilities
        .insert(AutomotiveCapability::ExecutePhysical);
    assert!(matches!(
        invalid.validate(),
        Err(ContractError::InconsistentField {
            field: "capabilities.execute_physical",
            ..
        })
    ));
}

#[test]
fn artifact_references_reject_path_like_ids_and_invalid_media_types() {
    let mut reference = artifact("capture-1");
    assert!(reference.validate().is_ok());

    reference.artifact_id = "../capture.pcap".to_owned();
    assert!(matches!(
        reference.validate(),
        Err(ContractError::InvalidField {
            field: "artifact.artifact_id",
            ..
        })
    ));

    reference.artifact_id = "capture.pcap".to_owned();
    reference.media_type = "application /pcap".to_owned();
    assert!(matches!(
        reference.validate(),
        Err(ContractError::InvalidField {
            field: "artifact.media_type",
            ..
        })
    ));

    reference.media_type = "application/pcap".to_owned();
    reference.size_bytes = 0;
    assert!(matches!(
        reference.validate(),
        Err(ContractError::InvalidField {
            field: "artifact.size_bytes",
            ..
        })
    ));
}

#[test]
fn request_variants_validate_artifacts_limits_and_replay_mode() {
    let analysis = AutomotiveRequest::AnalyzeCapture(AnalyzeCaptureRequest {
        protocol: AutomotiveProtocol::DoIp,
        capture: artifact("capture-1"),
        limits: limits(),
    });
    assert!(analysis.validate().is_ok());

    let mutation = AutomotiveRequest::GenerateMutations(MutationRequest {
        protocol: AutomotiveProtocol::Uds,
        source: artifact("seed-capture"),
        deterministic_seed: 42,
        mutation_count: 65,
        limits: limits(),
    });
    assert!(matches!(
        mutation.validate(),
        Err(ContractError::LimitExceeded { .. })
    ));

    let replay = AutomotiveRequest::ExecuteReplay(ReplayRequest {
        mode: ModeConfig::PhysicalBench {
            interface: "can0".to_owned(),
            approval_id: "approval-123".to_owned(),
        },
        plan: replay_plan(AutomotiveProtocol::CanFd),
        limits: limits(),
    });
    assert!(matches!(
        replay.validate(),
        Err(ContractError::InconsistentField { .. })
    ));
}

#[test]
fn replay_plan_rejects_duplicate_sequences_and_mixed_protocols() {
    let mut plan = replay_plan(AutomotiveProtocol::IsoTp);
    plan.steps.push(ReplayStep {
        sequence: 0,
        delay_micros: 200,
        action: ReplayAction::ExpectResponse,
        message: message(AutomotiveProtocol::Uds, "7e00"),
    });

    assert!(matches!(
        plan.validate(),
        Err(ContractError::DuplicateSequence { sequence: 0 })
    ));

    plan.steps[1].sequence = 1;
    assert!(matches!(
        plan.validate(),
        Err(ContractError::InconsistentField { .. })
    ));

    plan.steps[1].message = message(AutomotiveProtocol::IsoTp, "7e00");
    plan.steps[1].sequence = 3;
    assert!(matches!(
        plan.validate(),
        Err(ContractError::InconsistentField { .. })
    ));
}

#[test]
fn replay_request_enforces_aggregate_payload_and_schedule_limits() {
    let mut plan = replay_plan(AutomotiveProtocol::Uds);
    plan.steps.push(ReplayStep {
        sequence: 1,
        delay_micros: 200,
        action: ReplayAction::ExpectResponse,
        message: message(AutomotiveProtocol::Uds, "040506"),
    });
    let mut request = ReplayRequest {
        mode: ModeConfig::VirtualCan {
            interface: "vcan0".to_owned(),
        },
        plan,
        limits: OperationLimits {
            max_payload_bytes: 4,
            ..limits()
        },
    };

    assert!(matches!(
        request.validate(),
        Err(ContractError::LimitExceeded {
            field: "replay.payload",
            ..
        })
    ));

    request.limits.max_payload_bytes = limits().max_payload_bytes;
    request.plan.steps[1].delay_micros = request.limits.max_duration_ms * 1_000 + 1;
    assert!(matches!(
        request.validate(),
        Err(ContractError::LimitExceeded {
            field: "replay.duration_micros",
            ..
        })
    ));

    request.plan.steps[0].delay_micros = 0;
    request.plan.steps[1].delay_micros = 500_000;
    request.limits.max_rate_per_second = 1;
    assert!(matches!(
        request.validate(),
        Err(ContractError::LimitExceeded {
            field: "replay.rate",
            ..
        })
    ));
}

#[test]
fn replay_plan_generation_has_typed_request_and_result_variants() {
    let request = AutomotiveRequest::BuildReplayPlan(ReplayPlanRequest {
        protocol: AutomotiveProtocol::BmwHsfz,
        source: artifact("decoded-session"),
        target_mode: AutomotiveMode::VirtualCan,
        deterministic_seed: 99,
        limits: limits(),
    });
    assert!(request.validate().is_ok());

    let result = AutomotiveResult::ReplayPlan(replay_plan(AutomotiveProtocol::BmwHsfz));
    assert!(result.validate().is_ok());
}

#[test]
fn transcript_hash_is_canonical_over_event_and_metadata_order() {
    let metadata_a = BTreeMap::from([
        ("zeta".to_owned(), "last".to_owned()),
        ("alpha".to_owned(), "first".to_owned()),
    ]);
    let mut metadata_b = BTreeMap::new();
    metadata_b.insert("alpha".to_owned(), "first".to_owned());
    metadata_b.insert("zeta".to_owned(), "last".to_owned());
    let first = event(0, AutomotiveProtocol::Can, "0102", metadata_a);
    let second = event(1, AutomotiveProtocol::Can, "0304", BTreeMap::new());
    let reordered_first = event(0, AutomotiveProtocol::Can, "0102", metadata_b);

    let ordered = canonical_transcript_hash(&[first.clone(), second.clone()]).unwrap();
    let reordered = canonical_transcript_hash(&[second, reordered_first]).unwrap();
    assert_eq!(ordered, reordered);
    assert_eq!(ordered.as_str().len(), 64);

    let changed =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Can, "0103", first.metadata)])
            .unwrap();
    assert_ne!(ordered, changed);
}

#[test]
fn state_signature_is_deterministic_and_protocol_scoped() {
    let observations_a = BTreeMap::from([
        ("session".to_owned(), "extended".to_owned()),
        ("security".to_owned(), "locked".to_owned()),
    ]);
    let mut observations_b = BTreeMap::new();
    observations_b.insert("security".to_owned(), "locked".to_owned());
    observations_b.insert("session".to_owned(), "extended".to_owned());

    let uds = StateSignature::from_observations(AutomotiveProtocol::Uds, observations_a).unwrap();
    let same =
        StateSignature::from_observations(AutomotiveProtocol::Uds, observations_b.clone()).unwrap();
    let gmlan =
        StateSignature::from_observations(AutomotiveProtocol::Gmlan, observations_b).unwrap();

    assert_eq!(uds.digest, same.digest);
    assert_ne!(uds.digest, gmlan.digest);
    assert!(uds.validate().is_ok());
}

#[test]
fn result_rejects_duplicate_state_signatures() {
    let signature = StateSignature::from_observations(
        AutomotiveProtocol::Uds,
        BTreeMap::from([("session".to_owned(), "extended".to_owned())]),
    )
    .unwrap();
    let transcript_hash =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Uds, "5003", BTreeMap::new())])
            .unwrap();
    let result = AutomotiveResult::CaptureAnalysis(hf_automotive::CaptureAnalysisResult {
        protocol: AutomotiveProtocol::Uds,
        event_count: 1,
        transcript: ArtifactRef {
            artifact_id: "transcript.json".to_owned(),
            sha256: transcript_hash.as_str().to_owned(),
            media_type: "application/vnd.hobot-fuzz.automotive-transcript+json".to_owned(),
            size_bytes: 128,
        },
        transcript_hash,
        state_signatures: vec![signature.clone(), signature],
    });

    assert!(matches!(
        result.validate(),
        Err(ContractError::InconsistentField {
            field: "result.state_signatures",
            ..
        })
    ));
}

#[test]
fn capture_analysis_requires_a_matching_canonical_transcript_artifact() {
    let transcript_hash =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Uds, "5003", BTreeMap::new())])
            .unwrap();
    let mut result = hf_automotive::CaptureAnalysisResult {
        protocol: AutomotiveProtocol::Uds,
        event_count: 1,
        transcript: ArtifactRef {
            artifact_id: "transcript.json".to_owned(),
            sha256: "cd".repeat(32),
            media_type: "application/vnd.hobot-fuzz.automotive-transcript+json".to_owned(),
            size_bytes: 128,
        },
        transcript_hash,
        state_signatures: Vec::new(),
    };

    assert!(matches!(
        result.validate(),
        Err(ContractError::InconsistentField {
            field: "analysis.transcript.sha256",
            ..
        })
    ));

    result.transcript.sha256 = result.transcript_hash.as_str().to_owned();
    assert!(result.validate().is_ok());

    result.transcript.media_type = "application/json".to_owned();
    assert!(matches!(
        result.validate(),
        Err(ContractError::InvalidField {
            field: "analysis.transcript.media_type",
            ..
        })
    ));
}

#[test]
fn schema_envelopes_are_versioned_and_validate_their_payload() {
    let capability_value = serde_json::to_value(SchemaEnvelope::new(
        "capabilities-1",
        AutomotiveRequest::Capabilities(CapabilityRequest {}),
    ))
    .unwrap();
    assert_eq!(capability_value["operation"], "capabilities");
    assert_eq!(capability_value["payload"], serde_json::json!({}));

    let request = AutomotiveRequest::AnalyzeCapture(AnalyzeCaptureRequest {
        protocol: AutomotiveProtocol::SomeIpSd,
        capture: artifact("capture-sd"),
        limits: limits(),
    });
    let envelope = SchemaEnvelope::new("request-1", request);
    assert_eq!(envelope.schema_version, AUTOMOTIVE_SCHEMA_VERSION);
    assert!(envelope.validate().is_ok());

    let encoded = serde_json::to_string(&envelope).unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 4);
    assert_eq!(object["request_id"], "request-1");
    assert_eq!(object["operation"], "analyze_capture");
    assert!(object["payload"].is_object());
    let mut decoded: SchemaEnvelope<AutomotiveRequest> = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, envelope);
    decoded.schema_version += 1;
    assert!(matches!(
        decoded.validate(),
        Err(ContractError::UnsupportedSchema { .. })
    ));
}

#[test]
fn results_and_structured_errors_round_trip_and_fail_closed() {
    let transcript_hash =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Xcp, "ff00", BTreeMap::new())])
            .unwrap();
    let result = AutomotiveResult::Replay(ReplayResult {
        protocol: AutomotiveProtocol::Xcp,
        mode: AutomotiveMode::VirtualCan,
        planned_events: 1,
        executed_events: 1,
        transcript_hash,
        state_signatures: Vec::new(),
        completed: true,
    });
    assert!(result.validate().is_ok());

    let invalid = AutomotiveResult::Mutations(MutationResult {
        protocol: AutomotiveProtocol::Ccp,
        generated: 0,
        transcript_hash: None,
        artifacts: Vec::new(),
    });
    assert!(invalid.validate().is_err());

    let error = AutomotiveError {
        code: AutomotiveErrorCode::ApprovalRequired,
        message: "physical bench approval is required".to_owned(),
        field: Some("mode.approval_id".to_owned()),
        retryable: false,
        details: BTreeMap::from([("mode".to_owned(), "physical_bench".to_owned())]),
    };
    assert!(error.validate().is_ok());
    let response = ResponseEnvelope::failure("error-1", error.clone(), None);
    assert!(response.validate().is_ok());
    let encoded = serde_json::to_string(&response).unwrap();
    let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 6);
    assert_eq!(object["schema_version"], AUTOMOTIVE_SCHEMA_VERSION);
    assert_eq!(object["request_id"], "error-1");
    assert_eq!(object["ok"], false);
    assert!(object["result"].is_null());
    let decoded: ResponseEnvelope = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded.error, Some(error));
}

#[test]
fn response_transcript_hash_must_match_the_typed_result() {
    let result_hash =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Can, "0102", BTreeMap::new())])
            .unwrap();
    let conflicting_hash =
        canonical_transcript_hash(&[event(0, AutomotiveProtocol::Can, "0103", BTreeMap::new())])
            .unwrap();
    let response = ResponseEnvelope::success(
        "result-1",
        AutomotiveResult::Replay(ReplayResult {
            protocol: AutomotiveProtocol::Can,
            mode: AutomotiveMode::VirtualCan,
            planned_events: 1,
            executed_events: 1,
            transcript_hash: result_hash,
            state_signatures: Vec::new(),
            completed: true,
        }),
        Some(conflicting_hash),
    );

    assert!(matches!(
        response.validate(),
        Err(ContractError::InconsistentField {
            field: "response.transcript_sha256",
            ..
        })
    ));
}
