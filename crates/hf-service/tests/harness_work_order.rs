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
    HarnessWorkOrderErrorCode, HarnessWorkOrderErrorKind, HarnessWorkOrderPayload,
    ImportHarnessWorkOrderSubmissionRequest, WorkOrderArg, WorkOrderCompileContext,
    WorkOrderPlaceholder, WorkOrderRule, WorkOrderSeedReference, WorkOrderSourceEvidence,
    WorkOrderStep, WorkOrderSubmissionOrigin, WorkOrderTargetEvidence,
    HARNESS_WORK_ORDER_SCHEMA_VERSION, MAX_WORK_ORDER_PACKET_BYTES,
    MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES,
};
use hf_service::{HarnessWorkOrderExportRequest, ServiceContainer};
use sha2::{Digest, Sha256};

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

async fn persist_work_order(store: &hf_storage::Store, packet: hf_service::HarnessWorkOrder) {
    store
        .insert_harness_work_order(&hf_storage::HarnessWorkOrderRecord {
            id: packet.id.clone(),
            target_id: uuid::Uuid::new_v4(),
            project_root: "/retained/project".to_owned(),
            schema_version: packet.schema_version,
            packet_json: serde_json::to_string(&packet).expect("serialize work order packet"),
            created_at: Utc::now(),
        })
        .await
        .expect("persist work order");
}

fn submission_request(
    work_order_id: String,
    source: impl Into<String>,
    origin: WorkOrderSubmissionOrigin,
    parent_submission_id: Option<uuid::Uuid>,
) -> ImportHarnessWorkOrderSubmissionRequest {
    ImportHarnessWorkOrderSubmissionRequest {
        work_order_id,
        source: source.into(),
        origin,
        parent_submission_id,
    }
}

fn human_origin() -> WorkOrderSubmissionOrigin {
    WorkOrderSubmissionOrigin::Human
}

fn external_origin() -> WorkOrderSubmissionOrigin {
    WorkOrderSubmissionOrigin::ExternalTool {
        tool: "  external author  ".to_owned(),
        model: Some("  model-v1  ".to_owned()),
        response_id: Some("  response-1  ".to_owned()),
    }
}

async fn insert_raw_submission(
    store: &hf_storage::Store,
    work_order_id: &str,
    source: &str,
    origin_json: &str,
    lint_json: &str,
    submitted_at: &str,
) -> uuid::Uuid {
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
         (id, work_order_id, source, source_sha256, origin_json, parent_submission_id, lint_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
    )
    .bind(id.to_string())
    .bind(work_order_id)
    .bind(source)
    .bind(hex::encode(Sha256::digest(source.as_bytes())))
    .bind(origin_json)
    .bind(lint_json)
    .bind(submitted_at)
    .execute(store.pool())
    .await
    .expect("insert raw submission");
    id
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
        "//work/include",
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

#[tokio::test]
async fn submission_import_preserves_source_and_persists_lint_without_dispatch() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let packet = build_work_order(payload()).expect("build work order");
    persist_work_order(&store, packet.clone()).await;
    let runtime = Arc::new(CountingRuntime::default());
    let service = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let source = "\nvoid LLVMFuzzerTestOneInput(void) { abort(); }\n";

    let human = service
        .import_harness_work_order_submission(submission_request(
            packet.id.clone(),
            source,
            human_origin(),
            None,
        ))
        .await
        .expect("import human submission");
    let external = service
        .import_harness_work_order_submission(submission_request(
            packet.id.clone(),
            source,
            external_origin(),
            None,
        ))
        .await
        .expect("import external submission");
    let retry = service
        .import_harness_work_order_submission(submission_request(
            packet.id.clone(),
            source,
            WorkOrderSubmissionOrigin::ExternalTool {
                tool: "external author".to_owned(),
                model: Some("model-v1".to_owned()),
                response_id: Some("response-1".to_owned()),
            },
            None,
        ))
        .await
        .expect("retry exact external submission");
    let repair = service
        .import_harness_work_order_submission(submission_request(
            packet.id.clone(),
            source,
            external_origin(),
            Some(external.id),
        ))
        .await
        .expect("import repair submission");

    assert_eq!(human.source, source);
    assert!(hf_harness::has_blocking_finding(&human.lint));
    assert_eq!(retry, external);
    assert_ne!(human.id, external.id);
    assert_ne!(external.id, repair.id);
    assert_eq!(repair.parent_submission_id, Some(external.id));
    assert_eq!(
        external.origin,
        WorkOrderSubmissionOrigin::ExternalTool {
            tool: "external author".to_owned(),
            model: Some("model-v1".to_owned()),
            response_id: Some("response-1".to_owned()),
        }
    );
    assert_eq!(
        service
            .harness_work_order_submission(human.id)
            .await
            .expect("retrieve submission"),
        human
    );
    assert_eq!(
        service
            .list_harness_work_order_submissions(&packet.id)
            .await
            .expect("list submissions")
            .len(),
        3
    );
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn submission_import_rejects_invalid_input_parent_and_limit() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let first_packet = build_work_order(payload()).expect("build first work order");
    let mut second_payload = payload();
    second_payload.target.symbol = "parse_other_packet".to_owned();
    let second_packet = build_work_order(second_payload).expect("build second work order");
    persist_work_order(&store, first_packet.clone()).await;
    persist_work_order(&store, second_packet.clone()).await;
    let runtime = Arc::new(CountingRuntime::default());
    let service = ServiceContainer::new(runtime.clone(), None).with_store(store);

    let oversized_source = "x".repeat(65_537);
    for (source, origin) in [
        ("", human_origin()),
        (oversized_source.as_str(), human_origin()),
    ] {
        let error = service
            .import_harness_work_order_submission(submission_request(
                first_packet.id.clone(),
                source,
                origin,
                None,
            ))
            .await
            .expect_err("invalid source must fail");
        assert!(matches!(
            error.code,
            HarnessWorkOrderErrorCode::SourceEmpty | HarnessWorkOrderErrorCode::SourceTooLarge
        ));
        assert_eq!(error.kind, HarnessWorkOrderErrorKind::Validation);
    }
    for origin in [
        WorkOrderSubmissionOrigin::ExternalTool {
            tool: "\n".to_owned(),
            model: None,
            response_id: None,
        },
        WorkOrderSubmissionOrigin::ExternalTool {
            tool: "tool".to_owned(),
            model: Some(format!("{}\u{7f}", "a".repeat(127))),
            response_id: Some("response".to_owned()),
        },
        WorkOrderSubmissionOrigin::ExternalTool {
            tool: "tool".to_owned(),
            model: None,
            response_id: Some("r".repeat(257)),
        },
    ] {
        let error = service
            .import_harness_work_order_submission(submission_request(
                first_packet.id.clone(),
                "void f(void) {}",
                origin,
                None,
            ))
            .await
            .expect_err("invalid provenance must fail");
        assert_eq!(error.code, HarnessWorkOrderErrorCode::InvalidProvenance);
        assert_eq!(error.kind, HarnessWorkOrderErrorKind::Validation);
    }

    let root = service
        .import_harness_work_order_submission(submission_request(
            first_packet.id.clone(),
            "void root(void) {}",
            human_origin(),
            None,
        ))
        .await
        .expect("import root submission");
    let missing_parent = service
        .import_harness_work_order_submission(submission_request(
            first_packet.id.clone(),
            "void missing_parent(void) {}",
            human_origin(),
            Some(uuid::Uuid::new_v4()),
        ))
        .await
        .expect_err("missing parent must fail");
    assert_eq!(
        missing_parent.code,
        HarnessWorkOrderErrorCode::ParentNotFound
    );
    let cross_work_order = service
        .import_harness_work_order_submission(submission_request(
            second_packet.id.clone(),
            "void cross_work_order(void) {}",
            human_origin(),
            Some(root.id),
        ))
        .await
        .expect_err("cross-work-order parent must fail");
    assert_eq!(
        cross_work_order.code,
        HarnessWorkOrderErrorCode::ParentWorkOrderMismatch
    );

    for index in 1..20 {
        service
            .import_harness_work_order_submission(submission_request(
                first_packet.id.clone(),
                format!("void submission_{index}(void) {{}}"),
                human_origin(),
                None,
            ))
            .await
            .expect("import within submission limit");
    }
    let limit = service
        .import_harness_work_order_submission(submission_request(
            first_packet.id.clone(),
            "void twenty_first(void) {}",
            human_origin(),
            None,
        ))
        .await
        .expect_err("twenty-first distinct submission must fail");
    assert_eq!(
        limit.code,
        HarnessWorkOrderErrorCode::SubmissionLimitReached
    );
    assert_eq!(limit.kind, HarnessWorkOrderErrorKind::Validation);
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn submission_import_accepts_exact_source_and_provenance_limits() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let packet = build_work_order(payload()).expect("build work order");
    persist_work_order(&store, packet.clone()).await;
    let service =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store);
    let source = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);

    let submission = service
        .import_harness_work_order_submission(submission_request(
            packet.id,
            source.clone(),
            WorkOrderSubmissionOrigin::ExternalTool {
                tool: "t".repeat(128),
                model: Some("m".repeat(128)),
                response_id: Some("r".repeat(256)),
            },
            None,
        ))
        .await
        .expect("exact configured limits must be accepted");

    assert_eq!(submission.source, source);
    assert_eq!(
        submission.origin,
        WorkOrderSubmissionOrigin::ExternalTool {
            tool: "t".repeat(128),
            model: Some("m".repeat(128)),
            response_id: Some("r".repeat(256)),
        }
    );
}

#[tokio::test]
async fn submission_operations_require_durable_storage() {
    let service = ServiceContainer::new(Arc::new(CountingRuntime::default()), None);
    let work_order_id = "a".repeat(64);

    let import_error = service
        .import_harness_work_order_submission(submission_request(
            work_order_id.clone(),
            "void f(void) {}",
            human_origin(),
            None,
        ))
        .await
        .expect_err("import requires durable storage");
    assert_eq!(
        import_error.code,
        HarnessWorkOrderErrorCode::StorageRequired
    );
    assert_eq!(import_error.kind, HarnessWorkOrderErrorKind::Storage);
    let get_error = service
        .harness_work_order_submission(uuid::Uuid::new_v4())
        .await
        .expect_err("get requires durable storage");
    assert_eq!(get_error.code, HarnessWorkOrderErrorCode::StorageRequired);
    assert_eq!(get_error.kind, HarnessWorkOrderErrorKind::Storage);
    let list_error = service
        .list_harness_work_order_submissions(&work_order_id)
        .await
        .expect_err("list requires durable storage");
    assert_eq!(list_error.code, HarnessWorkOrderErrorCode::StorageRequired);
    assert_eq!(list_error.kind, HarnessWorkOrderErrorKind::Storage);
}

#[tokio::test]
async fn submission_reads_reject_tampered_packets_and_malformed_durable_data() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let valid_packet = build_work_order(payload()).expect("build valid work order");
    persist_work_order(&store, valid_packet.clone()).await;
    let malformed_packet_id = "e".repeat(64);
    store
        .insert_harness_work_order(&hf_storage::HarnessWorkOrderRecord {
            id: malformed_packet_id.clone(),
            target_id: uuid::Uuid::new_v4(),
            project_root: "/retained/malformed".to_owned(),
            schema_version: HARNESS_WORK_ORDER_SCHEMA_VERSION,
            packet_json: "{}".to_owned(),
            created_at: Utc::now(),
        })
        .await
        .expect("persist malformed packet row");
    let runtime = Arc::new(CountingRuntime::default());
    let service = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());

    let packet_error = service
        .import_harness_work_order_submission(submission_request(
            malformed_packet_id,
            "void f(void) {}",
            human_origin(),
            None,
        ))
        .await
        .expect_err("tampered packet must block import");
    assert_eq!(
        packet_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(packet_error.kind, HarnessWorkOrderErrorKind::Validation);

    let malformed_origin_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
         (id, work_order_id, source, source_sha256, origin_json, parent_submission_id, lint_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
    )
    .bind(malformed_origin_id.to_string())
    .bind(&valid_packet.id)
    .bind("void malformed_origin(void) {}")
    .bind(hex::encode(Sha256::digest(b"void malformed_origin(void) {}")))
    .bind("{\"unknown\":true}")
    .bind("[]")
    .bind("2026-08-30T00:00:00Z")
    .execute(store.pool())
    .await
    .expect("insert malformed origin row");
    let origin_error = service
        .harness_work_order_submission(malformed_origin_id)
        .await
        .expect_err("malformed origin JSON must fail retrieval");
    assert_eq!(
        origin_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(origin_error.kind, HarnessWorkOrderErrorKind::Validation);

    let malformed_lint_packet = build_work_order(HarnessWorkOrderPayload {
        target: WorkOrderTargetEvidence {
            symbol: "parse_lint_packet".to_owned(),
            ..payload().target
        },
        ..payload()
    })
    .expect("build lint work order");
    persist_work_order(&store, malformed_lint_packet.clone()).await;
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
         (id, work_order_id, source, source_sha256, origin_json, parent_submission_id, lint_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&malformed_lint_packet.id)
    .bind("void malformed_lint(void) {}")
    .bind(hex::encode(Sha256::digest(b"void malformed_lint(void) {}")))
    .bind("\"human\"")
    .bind("{\"not\":\"a lint list\"}")
    .bind("2026-08-30T00:00:01Z")
    .execute(store.pool())
    .await
    .expect("insert malformed lint row");
    let lint_error = service
        .list_harness_work_order_submissions(&malformed_lint_packet.id)
        .await
        .expect_err("malformed lint JSON must fail listing");
    assert_eq!(
        lint_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(lint_error.kind, HarnessWorkOrderErrorKind::Validation);

    sqlx::query("DROP TRIGGER harness_work_order_submissions_validate_submitted_at")
        .execute(store.pool())
        .await
        .expect("remove temporary timestamp guard");
    let malformed_timestamp_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
         (id, work_order_id, source, source_sha256, origin_json, parent_submission_id, lint_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)",
    )
    .bind(malformed_timestamp_id.to_string())
    .bind(&valid_packet.id)
    .bind("void malformed_timestamp(void) {}")
    .bind(hex::encode(Sha256::digest(b"void malformed_timestamp(void) {}")))
    .bind("\"human\"")
    .bind("[]")
    .bind("not-a-timestamp")
    .execute(store.pool())
    .await
    .expect("insert malformed timestamp row");
    let timestamp_error = service
        .harness_work_order_submission(malformed_timestamp_id)
        .await
        .expect_err("malformed timestamp must fail retrieval");
    assert_eq!(
        timestamp_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    assert_eq!(timestamp_error.kind, HarnessWorkOrderErrorKind::Validation);
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn submission_reads_reject_invalid_or_noncanonical_durable_provenance() {
    let workspace = tempfile::tempdir().expect("create workspace");
    let store = Arc::new(
        hf_storage::Store::connect(workspace.path().join("work-order.db"))
            .await
            .expect("create store"),
    );
    let service =
        ServiceContainer::new(Arc::new(CountingRuntime::default()), None).with_store(store.clone());
    let origins = vec![
        r#"{"external_tool":{"tool":"","model":null,"response_id":null}}"#.to_owned(),
        r#"{"external_tool":{"tool":"tool\u0001","model":null,"response_id":null}}"#.to_owned(),
        format!(
            r#"{{"external_tool":{{"tool":"{}","model":null,"response_id":null}}}}"#,
            "t".repeat(129)
        ),
        r#"{"external_tool":{"tool":"tool","model":null,"response_id":null,"extra":true}}"#
            .to_owned(),
        r#"{"external_tool": { "tool": "tool", "model": null, "response_id": null }}"#.to_owned(),
        r#"{"external_tool":{"response_id":null,"tool":"tool","model":null}}"#.to_owned(),
    ];

    for (index, origin_json) in origins.into_iter().enumerate() {
        let mut malformed_payload = payload();
        malformed_payload.target.symbol = format!("parse_provenance_{index}");
        let packet = build_work_order(malformed_payload).expect("build work order");
        persist_work_order(&store, packet.clone()).await;
        let source = format!("void malformed_provenance_{index}(void) {{}}");
        let id = insert_raw_submission(
            &store,
            &packet.id,
            &source,
            &origin_json,
            "[]",
            "2026-08-30T00:00:00Z",
        )
        .await;

        for result in [
            service.harness_work_order_submission(id).await.map(|_| ()),
            service
                .list_harness_work_order_submissions(&packet.id)
                .await
                .map(|_| ()),
        ] {
            let error = result.expect_err("invalid durable provenance must fail");
            assert_eq!(
                error.code,
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
            );
            assert_eq!(error.kind, HarnessWorkOrderErrorKind::Validation);
        }
    }
}
