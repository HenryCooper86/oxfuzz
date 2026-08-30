//! Pure-model tests for the deterministic Harness Work Order v2 packet.

#![cfg(feature = "harness-work-order")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hf_core::corpus::{CorpusEntry, CorpusSource};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::{
    InputSurface, SourceLocation, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
};
use hf_service::harness_work_order::{
    build_work_order, quote_posix_arg, render_work_order, verify_work_order, work_order_commands,
    HarnessWorkOrderErrorCode, HarnessWorkOrderPayload, WorkOrderArg, WorkOrderCompileContext,
    WorkOrderPlaceholder, WorkOrderRule, WorkOrderSeedReference, WorkOrderSourceEvidence,
    WorkOrderStep, WorkOrderTargetEvidence, HARNESS_WORK_ORDER_SCHEMA_VERSION,
    MAX_WORK_ORDER_PACKET_BYTES,
};
use hf_service::{HarnessWorkOrderExportRequest, ServiceContainer};

#[derive(Default)]
struct CountingRuntime {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RuntimeAdapter for CountingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        _cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(ClassifiedError::Sandbox(
            "work order export must not start a runtime command".to_owned(),
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Err(ClassifiedError::Sandbox(
            "work order export must not write through the runtime".to_owned(),
        ))
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Err(ClassifiedError::Sandbox(
            "work order export must not read through the runtime".to_owned(),
        ))
    }
}

fn retained_target(project: &Path, source: PathBuf, language: TargetLanguage) -> TargetCandidate {
    TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: std::fs::canonicalize(project).expect("canonicalize project"),
        language,
        symbol: "parse_packet".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: source,
            line: 2,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("int parse_packet(const unsigned char *, size_t)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 4,
        fit_score: 0.8,
        sanitizers: Vec::new(),
        rationale: "parses attacker controlled packet bytes".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 4,
    }
}

async fn persist_target(store: &hf_storage::Store, candidate: TargetCandidate) -> TargetCandidate {
    store
        .save_inventory(
            &TargetInventory {
                project_root: candidate.project_root.clone(),
                candidates: vec![candidate.clone()],
                call_graph: std::collections::HashMap::default(),
            },
            Utc::now(),
        )
        .await
        .expect("persist retained target");
    candidate
}

fn export_request(project: &Path) -> HarnessWorkOrderExportRequest {
    HarnessWorkOrderExportRequest {
        project: project.to_path_buf(),
        target: "parse_packet".to_owned(),
        language: TargetLanguage::C,
        engine: EngineKind::LibFuzzer,
    }
}

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
fn construction_and_verification_reject_noncanonical_fixed_sandbox_include_paths() {
    for path in [
        "/work/../etc",
        "/work/./include",
        "/work//include",
        "/work/include/",
        "/work\\include",
    ] {
        let mut invalid = payload();
        invalid.compile_context.include_dirs = vec![path.to_owned()];
        assert_eq!(
            build_work_order(invalid)
                .expect_err("noncanonical sandbox path must be rejected")
                .code,
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "{path}"
        );

        let mut stored = build_work_order(payload()).expect("build valid packet");
        stored.payload.compile_context.include_dirs = vec![path.to_owned()];
        assert_eq!(
            verify_work_order(&stored)
                .expect_err("stored noncanonical sandbox path must be rejected")
                .code,
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "{path}"
        );
    }
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
async fn service_export_persists_identical_packet_before_return_without_runtime_or_provider() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(project.join("include")).expect("create include directory");
    std::fs::write(
        project.join("parser.c"),
        "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t len) { return len > 0 && data[0]; }\n",
    )
    .expect("write source");
    let compile_database = serde_json::json!([{
        "directory": project,
        "file": project.join("parser.c"),
        "arguments": ["cc", "-Iinclude", "-I/work/system", "-c", "parser.c"],
    }]);
    std::fs::write(
        project.join("compile_commands.json"),
        serde_json::to_vec(&compile_database).expect("serialize compile database"),
    )
    .expect("write compile database");

    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let target = persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    for index in 0_u8..21 {
        store
            .upsert_corpus_entry(
                target.id,
                &CorpusEntry {
                    path: PathBuf::from("must-not-leak"),
                    sha256: format!("{index:02x}").repeat(32),
                    size: u64::from(index),
                    source: CorpusSource::Seed,
                    coverage_hash: None,
                },
            )
            .await
            .expect("persist retained corpus entry");
    }
    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());

    let first = container
        .export_harness_work_order(export_request(&project))
        .await
        .expect("export retained evidence");
    let persisted = store
        .harness_work_order(&first.id)
        .await
        .expect("load persisted work order")
        .expect("export must be durable before returning");
    let second = container
        .export_harness_work_order(export_request(&project))
        .await
        .expect("retry retained export");

    assert_eq!(first, second);
    assert_eq!(
        persisted.packet_json,
        serde_json::to_string(&first).expect("serialize returned packet")
    );
    assert_eq!(
        first.payload.compile_context.include_dirs,
        vec!["/work/system", "include"]
    );
    assert_eq!(
        first
            .payload
            .seeds
            .iter()
            .map(|seed| seed.sha256.clone())
            .collect::<Vec<_>>(),
        (0_u8..20)
            .map(|index| format!("{index:02x}").repeat(32))
            .collect::<Vec<_>>()
    );
    let packet_json = serde_json::to_string(&first).expect("serialize packet");
    assert!(!packet_json.contains("must-not-leak"));
    assert!(!packet_json.contains(&project.display().to_string()));
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn service_work_order_reads_and_lists_only_verified_durable_packets() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        project.join("parser.c"),
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write source");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store);
    let exported = container
        .export_harness_work_order(export_request(&project))
        .await
        .expect("export work order");

    assert_eq!(
        container
            .harness_work_order_by_id(&exported.id)
            .await
            .expect("load durable work order"),
        exported
    );
    assert_eq!(
        container
            .list_harness_work_orders(Some(&project))
            .await
            .expect("list project work orders"),
        vec![exported]
    );
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn service_export_representes_project_root_include_as_dot() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        project.join("parser.c"),
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write source");
    let compile_database = serde_json::json!([{
        "directory": project,
        "file": project.join("parser.c"),
        "arguments": ["cc", "-I.", "-c", "parser.c"],
    }]);
    std::fs::write(
        project.join("compile_commands.json"),
        serde_json::to_vec(&compile_database).expect("serialize compile database"),
    )
    .expect("write compile database");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);

    let exported = container
        .export_harness_work_order(export_request(&project))
        .await
        .expect("project-root include must export");

    assert_eq!(exported.payload.compile_context.include_dirs, vec!["."]);
}

#[tokio::test]
async fn service_work_order_reads_reject_malformed_and_digest_invalid_durable_packets() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let malformed_id = "c".repeat(64);
    store
        .insert_harness_work_order(&hf_storage::HarnessWorkOrderRecord {
            id: malformed_id.clone(),
            target_id: uuid::Uuid::new_v4(),
            project_root: "/retained/project".to_owned(),
            schema_version: 2,
            packet_json: "{}".to_owned(),
            created_at: Utc::now(),
        })
        .await
        .expect("insert malformed durable row");
    let packet = build_work_order(payload()).expect("build packet");
    let invalid_id = "d".repeat(64);
    let mut invalid_packet = packet.clone();
    invalid_packet.id = invalid_id.clone();
    store
        .insert_harness_work_order(&hf_storage::HarnessWorkOrderRecord {
            id: invalid_id.clone(),
            target_id: uuid::Uuid::new_v4(),
            project_root: "/retained/other".to_owned(),
            schema_version: packet.schema_version,
            packet_json: serde_json::to_string(&invalid_packet).expect("serialize invalid packet"),
            created_at: Utc::now(),
        })
        .await
        .expect("insert digest-invalid durable row");
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);

    assert_eq!(
        container
            .harness_work_order_by_id(&malformed_id)
            .await
            .expect_err("malformed durable packet must fail")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(
        container
            .harness_work_order_by_id(&invalid_id)
            .await
            .expect_err("digest-invalid durable packet must fail directly")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(
        container
            .list_harness_work_orders(None)
            .await
            .expect_err("list must reject an invalid durable packet")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
}

#[tokio::test]
async fn concurrent_identical_exports_return_one_durable_packet() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        project.join("parser.c"),
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write source");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store.clone());
    let request = export_request(&project);
    let (first, second) = tokio::join!(
        container.export_harness_work_order(request.clone()),
        container.export_harness_work_order(request)
    );
    let first = first.expect("first concurrent export");
    let second = second.expect("second concurrent export");

    assert_eq!(first, second);
    assert_eq!(
        store
            .list_harness_work_orders(None)
            .await
            .expect("list durable rows")
            .len(),
        1
    );
}

#[tokio::test]
async fn same_packet_id_with_different_project_lookup_evidence_is_rejected() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let first_project = workspace.path().join("first");
    let second_project = workspace.path().join("second");
    for project in [&first_project, &second_project] {
        std::fs::create_dir_all(project).expect("create project");
        std::fs::write(
            project.join("parser.c"),
            "// heading\nint parse_packet(void) { return 0; }\n",
        )
        .expect("write source");
    }
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    for project in [&first_project, &second_project] {
        persist_target(
            &store,
            retained_target(project, PathBuf::from("parser.c"), TargetLanguage::C),
        )
        .await;
    }
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);
    let first = container
        .export_harness_work_order(export_request(&first_project))
        .await
        .expect("export first project");

    assert_eq!(
        container
            .export_harness_work_order(export_request(&second_project))
            .await
            .expect_err("project lookup mismatch must not reuse a packet")
            .code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(
        container
            .harness_work_order_by_id(&first.id)
            .await
            .expect("first durable packet remains readable"),
        first
    );
}

#[tokio::test]
async fn service_export_rejects_an_unsupported_engine_language_pair() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        project.join("parser.py"),
        "def parse_packet(data):\n    return data\n",
    )
    .expect("write source");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.py"), TargetLanguage::Python),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);

    let error = container
        .export_harness_work_order(HarnessWorkOrderExportRequest {
            project,
            target: "parse_packet".to_owned(),
            language: TargetLanguage::Python,
            engine: EngineKind::LibFuzzer,
        })
        .await
        .expect_err("libFuzzer does not support Python targets");
    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
}

#[tokio::test]
async fn service_export_requires_storage_and_a_matching_retained_target() {
    let project = tempfile::tempdir().expect("create project");
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_packet(void) { return 0; }",
    )
    .expect("write source");
    let container = ServiceContainer::new(Arc::new(CountingRuntime::default()), None);

    assert_eq!(
        container
            .export_harness_work_order(export_request(project.path()))
            .await
            .expect_err("storage is mandatory")
            .code,
        HarnessWorkOrderErrorCode::StorageRequired
    );
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);
    assert_eq!(
        container
            .export_harness_work_order(export_request(project.path()))
            .await
            .expect_err("discovery must not run for an unknown target")
            .code,
        HarnessWorkOrderErrorCode::WorkOrderNotFound
    );
}

#[tokio::test]
async fn service_work_order_reads_return_stable_not_found_codes() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);

    assert_eq!(
        container
            .harness_work_order_by_id("missing")
            .await
            .expect_err("missing work order must be visible")
            .code,
        HarnessWorkOrderErrorCode::WorkOrderNotFound
    );
}

#[tokio::test]
async fn service_export_rejects_malformed_compile_database_before_persistence() {
    let project = tempfile::tempdir().expect("create project");
    std::fs::write(
        project.path().join("parser.c"),
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write source");
    std::fs::write(project.path().join("compile_commands.json"), "{not json")
        .expect("write malformed compile database");
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(project.path(), PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store.clone());

    let error = container
        .export_harness_work_order(export_request(project.path()))
        .await
        .expect_err("malformed compile database must stop export");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert!(!error
        .message
        .contains(&project.path().display().to_string()));
    assert!(store
        .list_harness_work_orders(None)
        .await
        .expect("list rows")
        .is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn service_export_rejects_symlinked_or_escaping_retained_sources() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    let outside = workspace.path().join("outside.c");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        &outside,
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write outside source");
    std::os::unix::fs::symlink(&outside, project.join("parser.c")).expect("link source");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);
    assert_eq!(
        container
            .export_harness_work_order(export_request(&project))
            .await
            .expect_err("symlink source must fail closed")
            .code,
        HarnessWorkOrderErrorCode::InvalidProjectPath
    );
}

#[tokio::test]
async fn service_export_rejects_retained_source_paths_that_escape_the_project() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let project = workspace.path().join("project");
    std::fs::create_dir_all(&project).expect("create project");
    std::fs::write(
        workspace.path().join("outside.c"),
        "// heading\nint parse_packet(void) { return 0; }\n",
    )
    .expect("write outside source");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(&project, PathBuf::from("../outside.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);

    assert_eq!(
        container
            .export_harness_work_order(export_request(&project))
            .await
            .expect_err("escaping retained source must fail")
            .code,
        HarnessWorkOrderErrorCode::InvalidProjectPath
    );
}

#[tokio::test]
async fn service_export_rejects_oversized_retained_source() {
    let project = tempfile::tempdir().expect("create project");
    std::fs::write(
        project.path().join("parser.c"),
        vec![b'x'; 4 * 1024 * 1024 + 1],
    )
    .expect("write oversized source");
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    persist_target(
        &store,
        retained_target(project.path(), PathBuf::from("parser.c"), TargetLanguage::C),
    )
    .await;
    let container =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);
    assert_eq!(
        container
            .export_harness_work_order(export_request(project.path()))
            .await
            .expect_err("oversized retained source must fail")
            .code,
        HarnessWorkOrderErrorCode::SourceTooLarge
    );
}
