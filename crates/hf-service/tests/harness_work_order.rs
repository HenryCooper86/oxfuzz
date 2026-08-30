//! Pure-model tests for the deterministic Harness Work Order v2 packet.

#![cfg(feature = "harness-work-order")]

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use hf_service::harness_work_order::{
    build_work_order, quote_posix_arg, render_work_order, verify_work_order, work_order_commands,
    HarnessWorkOrderErrorCode, HarnessWorkOrderPayload, WorkOrderArg, WorkOrderCompileContext,
    WorkOrderPlaceholder, WorkOrderRule, WorkOrderSeedReference, WorkOrderSourceEvidence,
    WorkOrderStep, WorkOrderTargetEvidence, HARNESS_WORK_ORDER_SCHEMA_VERSION,
    MAX_WORK_ORDER_PACKET_BYTES,
};
use hf_service::ServiceContainer;

fn payload() -> HarnessWorkOrderPayload {
    HarnessWorkOrderPayload {
        target: WorkOrderTargetEvidence {
            symbol: "parse_packet".to_owned(),
            signature: Some("int parse_packet(const uint8_t*, size_t)".to_owned()),
            language: TargetLanguage::C,
            relative_source: "src/parser.c".to_owned(),
            line: 42,
            rationale: "reachable from an untrusted network packet".to_owned(),
        },
        engine: EngineKind::LibFuzzer,
        source: WorkOrderSourceEvidence {
            excerpt: "int parse_packet(const uint8_t *data, size_t len) { return 0; }".to_owned(),
            excerpt_truncated: false,
            sha256: "a".repeat(64),
        },
        compile_context: WorkOrderCompileContext {
            include_dirs: vec!["include".to_owned()],
            defines: vec!["HAVE_CONFIG_H=1".to_owned()],
            std_flag: Some("-std=c11".to_owned()),
            extra_flags: vec!["-fno-omit-frame-pointer".to_owned()],
            compile_units: 12,
            dropped_flags: vec!["-Winvalid-pch".to_owned()],
        },
        compile_context_sha256: String::new(),
        harness_rules: vec![WorkOrderRule {
            id: "no-shell".to_owned(),
            blocking: true,
            message: "Harnesses must not invoke a shell.".to_owned(),
        }],
        seeds: vec![WorkOrderSeedReference {
            sha256: "b".repeat(64),
            size: 16,
        }],
        validation_steps: vec![
            WorkOrderStep::Import,
            WorkOrderStep::Qualify,
            WorkOrderStep::Rank,
            WorkOrderStep::Promote,
            WorkOrderStep::RunCampaign { duration_secs: 300 },
            WorkOrderStep::Coverage,
        ],
    }
}

#[test]
fn unchanged_evidence_produces_byte_identical_packets() {
    let first = build_work_order(payload()).expect("build first packet");
    let second = build_work_order(payload()).expect("build second packet");

    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).expect("serialize first packet"),
        serde_json::to_vec(&second).expect("serialize second packet")
    );
    assert_eq!(first.schema_version, HARNESS_WORK_ORDER_SCHEMA_VERSION);
}

#[test]
fn each_evidence_class_changes_the_packet_identifier() {
    let original = build_work_order(payload()).expect("build packet");
    let mut variants = Vec::new();

    let mut changed_target = payload();
    changed_target.target.language = TargetLanguage::Cpp;
    variants.push(changed_target);

    let mut changed_engine = payload();
    changed_engine.engine = EngineKind::Honggfuzz;
    variants.push(changed_engine);

    let mut changed_source = payload();
    changed_source.source.excerpt.push_str(" // changed");
    variants.push(changed_source);

    let mut changed_source_digest = payload();
    changed_source_digest.source.sha256 = "e".repeat(64);
    variants.push(changed_source_digest);

    let mut changed_context = payload();
    changed_context
        .compile_context
        .defines
        .push("TRACE=1".to_owned());
    variants.push(changed_context);

    let mut changed_rules = payload();
    changed_rules.harness_rules[0].message.push_str(" Always.");
    variants.push(changed_rules);

    let mut changed_seed = payload();
    changed_seed.seeds[0].size = 17;
    variants.push(changed_seed);

    let mut changed_steps = payload();
    changed_steps.validation_steps = vec![WorkOrderStep::Import, WorkOrderStep::Qualify];
    variants.push(changed_steps);

    for changed in variants {
        let packet = build_work_order(changed).expect("build changed packet");
        assert_ne!(packet.id, original.id);
    }
}

#[test]
fn construction_normalizes_set_like_evidence_before_hashing() {
    let mut unordered = payload();
    unordered.compile_context.include_dirs =
        vec!["zinc".to_owned(), "include".to_owned(), "zinc".to_owned()];
    unordered.compile_context.defines = vec!["Z=1".to_owned(), "A=1".to_owned(), "Z=1".to_owned()];
    unordered.compile_context.extra_flags = vec!["-z".to_owned(), "-a".to_owned(), "-z".to_owned()];
    unordered.compile_context.dropped_flags = vec![
        "-drop-z".to_owned(),
        "-drop-a".to_owned(),
        "-drop-z".to_owned(),
    ];
    unordered.harness_rules = vec![
        WorkOrderRule {
            id: "z-rule".to_owned(),
            blocking: false,
            message: "Z".to_owned(),
        },
        WorkOrderRule {
            id: "a-rule".to_owned(),
            blocking: true,
            message: "A".to_owned(),
        },
        WorkOrderRule {
            id: "z-rule".to_owned(),
            blocking: false,
            message: "Z".to_owned(),
        },
    ];
    unordered.seeds = vec![
        WorkOrderSeedReference {
            sha256: "d".repeat(64),
            size: 2,
        },
        WorkOrderSeedReference {
            sha256: "c".repeat(64),
            size: 1,
        },
        WorkOrderSeedReference {
            sha256: "d".repeat(64),
            size: 2,
        },
    ];

    let mut ordered = unordered.clone();
    ordered.compile_context.include_dirs = vec!["include".to_owned(), "zinc".to_owned()];
    ordered.compile_context.defines = vec!["A=1".to_owned(), "Z=1".to_owned()];
    ordered.compile_context.extra_flags = vec!["-a".to_owned(), "-z".to_owned()];
    ordered.compile_context.dropped_flags = vec!["-drop-a".to_owned(), "-drop-z".to_owned()];
    ordered.harness_rules = vec![
        WorkOrderRule {
            id: "a-rule".to_owned(),
            blocking: true,
            message: "A".to_owned(),
        },
        WorkOrderRule {
            id: "z-rule".to_owned(),
            blocking: false,
            message: "Z".to_owned(),
        },
    ];
    ordered.seeds = vec![
        WorkOrderSeedReference {
            sha256: "c".repeat(64),
            size: 1,
        },
        WorkOrderSeedReference {
            sha256: "d".repeat(64),
            size: 2,
        },
    ];

    let normalized = build_work_order(unordered).expect("normalize unordered evidence");
    let canonical = build_work_order(ordered).expect("build ordered evidence");

    assert_eq!(normalized, canonical);
    assert_eq!(normalized.payload.compile_context_sha256.len(), 64);
}

#[test]
fn verification_rejects_v1_packets_and_tampered_digests() {
    let packet = build_work_order(payload()).expect("build packet");

    let mut v1 = packet.clone();
    v1.schema_version = 1;
    assert_eq!(
        verify_work_order(&v1)
            .expect_err("v1 must be rejected")
            .code,
        HarnessWorkOrderErrorCode::UnsupportedWorkOrderSchema
    );

    let mut packet_digest = packet.clone();
    packet_digest.id = "0".repeat(64);
    assert_eq!(
        verify_work_order(&packet_digest)
            .expect_err("packet digest tampering must be rejected")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );

    let mut context_digest = packet;
    context_digest.payload.compile_context_sha256 = "0".repeat(64);
    assert_eq!(
        verify_work_order(&context_digest)
            .expect_err("compile-context digest tampering must be rejected")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
}

#[test]
fn construction_rejects_absolute_host_paths_from_packet_json() {
    let mut candidate = payload();
    candidate.target.relative_source = "/Users/operator/project/src/parser.c".to_owned();

    let error = build_work_order(candidate).expect_err("absolute paths must be rejected");
    assert_eq!(error.code, HarnessWorkOrderErrorCode::InvalidProjectPath);
}

#[test]
fn construction_rejects_invalid_digests_and_more_than_twenty_seeds() {
    let mut invalid_source = payload();
    invalid_source.source.sha256 = "A".repeat(64);
    assert_eq!(
        build_work_order(invalid_source)
            .expect_err("source digest must be lowercase SHA-256")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );

    let mut invalid_seed = payload();
    invalid_seed.seeds[0].sha256 = "invalid".to_owned();
    assert_eq!(
        build_work_order(invalid_seed)
            .expect_err("seed digest must be lowercase SHA-256")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );

    let mut too_many_seeds = payload();
    too_many_seeds.seeds = (0_u8..21)
        .map(|index| WorkOrderSeedReference {
            sha256: format!("{index:02x}").repeat(32),
            size: u64::from(index),
        })
        .collect();
    assert_eq!(
        build_work_order(too_many_seeds)
            .expect_err("twenty-first seed must be rejected")
            .code,
        HarnessWorkOrderErrorCode::SeedLimitExceeded
    );
}

#[test]
fn construction_rejects_packets_larger_than_the_storage_limit() {
    let mut oversized = payload();
    oversized.target.rationale = "x".repeat(MAX_WORK_ORDER_PACKET_BYTES);

    assert_eq!(
        build_work_order(oversized)
            .expect_err("oversized packet must be rejected")
            .code,
        HarnessWorkOrderErrorCode::WorkOrderTooLarge
    );
}

#[test]
fn verification_rejects_a_noncanonical_retained_payload() {
    let mut packet = build_work_order(payload()).expect("build packet");
    packet.payload.compile_context.include_dirs = vec!["zinc".to_owned(), "include".to_owned()];

    assert_eq!(
        verify_work_order(&packet)
            .expect_err("stored payload must remain canonical")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
}

#[test]
fn commands_use_typed_placeholders_and_approval_requirements() {
    let commands = work_order_commands(&build_work_order(payload()).expect("build packet"));

    assert_eq!(commands[0].step, WorkOrderStep::Import);
    assert!(commands[0]
        .argv
        .contains(&WorkOrderArg::Placeholder(WorkOrderPlaceholder::SourceFile)));
    assert_eq!(commands[1].step, WorkOrderStep::Qualify);
    assert!(commands[1].approval_required);
    assert!(commands[1].argv.contains(&WorkOrderArg::Placeholder(
        WorkOrderPlaceholder::SubmissionId
    )));
    assert_eq!(commands[2].step, WorkOrderStep::Rank);
    assert!(commands[2]
        .argv
        .contains(&WorkOrderArg::Placeholder(WorkOrderPlaceholder::AttemptIds)));
    assert_eq!(commands[3].step, WorkOrderStep::Promote);
    assert!(commands[3].approval_required);
    assert!(commands[3]
        .argv
        .contains(&WorkOrderArg::Placeholder(WorkOrderPlaceholder::AttemptId)));
    assert_eq!(
        commands[4].step,
        WorkOrderStep::RunCampaign { duration_secs: 300 }
    );
    assert!(commands[4].approval_required);

    let rendered = render_work_order(&build_work_order(payload()).expect("build packet"));
    assert!(rendered.contains("Approval required"));
}

#[test]
fn posix_quoting_preserves_literal_arguments() {
    assert_eq!(quote_posix_arg("plain"), "plain");
    assert_eq!(quote_posix_arg("two words"), "'two words'");
    assert_eq!(quote_posix_arg("a'b"), "'a'\"'\"'b'");
    assert_eq!(quote_posix_arg("$(touch nope)"), "'$(touch nope)'");
}

#[tokio::test]
async fn work_order_export_propagates_a_malformed_compile_database() {
    let project = tempfile::tempdir().expect("create project");
    std::fs::write(
        project.path().join("parser.c"),
        "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t len) { return len > 0 && data[0]; }\n",
    )
    .expect("write source");
    std::fs::write(project.path().join("compile_commands.json"), "{not json")
        .expect("write malformed compile database");
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let error = container
        .harness_work_order(
            project.path(),
            "parse_packet",
            TargetLanguage::C,
            EngineKind::LibFuzzer,
        )
        .await
        .expect_err("malformed compile database must stop export");

    assert!(matches!(error, ClassifiedError::Validation(_)));
    assert!(error.to_string().contains("compile"), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn work_order_export_through_a_symlinked_root_uses_relative_compile_evidence() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    let alias = workspace.path().join("project-alias");
    std::fs::create_dir_all(project.join("include")).expect("create include directory");
    std::fs::write(
        project.join("parser.c"),
        "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t len) { return len > 0 && data[0]; }\n",
    )
    .expect("write source");
    let compile_database = serde_json::json!([{
        "directory": project,
        "file": project.join("parser.c"),
        "arguments": [
            "cc",
            format!("-I{}", project.join("include").display()),
            "-c",
            "parser.c",
        ],
    }]);
    std::fs::write(
        project.join("compile_commands.json"),
        serde_json::to_vec(&compile_database).expect("serialize compile database"),
    )
    .expect("write compile database");
    std::os::unix::fs::symlink(&project, &alias).expect("create project alias");

    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);

    let order = container
        .harness_work_order(
            &alias,
            "parse_packet",
            TargetLanguage::C,
            EngineKind::LibFuzzer,
        )
        .await
        .expect("export work order through project alias");
    let packet_json = serde_json::to_string(&order).expect("serialize packet");

    assert_eq!(order.payload.compile_context.include_dirs, vec!["include"]);
    assert!(!packet_json.contains(&alias.display().to_string()));
    assert!(!packet_json.contains(&project.display().to_string()));
}
