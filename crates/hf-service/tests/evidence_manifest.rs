#![cfg(feature = "proof-carrying")]

use std::collections::BTreeMap;

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_crash::remediation::RemediationStatus;
use hf_service::evidence::{
    CampaignEvidencePricing, EvidenceApproval, EvidenceCost, EvidenceCoverage, EvidenceError,
    EvidenceFinding, EvidenceManifest, EvidenceManifestBody, EvidenceRunConfig, EvidenceRunStatus,
};
use hf_service::ServiceContainer;
use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus, Store};
use uuid::Uuid;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn body() -> EvidenceManifestBody {
    EvidenceManifestBody {
        schema_version: 1,
        manifest_id: Uuid::from_u128(1),
        generated_at: "2026-07-22T00:00:00Z".to_owned(),
        project: "parser".to_owned(),
        target: "parse_header".to_owned(),
        run_id: Uuid::from_u128(2),
        status: EvidenceRunStatus::Done,
        engine: EngineKind::LibFuzzer,
        run_config: EvidenceRunConfig {
            duration_secs: 60,
            max_mem_mb: 1024,
            max_cpus: 1,
            sanitizer: "address".to_owned(),
            seed: Some(7),
            environment: BTreeMap::from([
                ("ASAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned()),
                ("TZ".to_owned(), "UTC".to_owned()),
            ]),
            extra_args: vec!["-max_len=4096".to_owned()],
        },
        source_revision: digest('a'),
        harness_sha256: digest('b'),
        binary_sha256: digest('c'),
        comparison_context_sha256: digest('d'),
        corpus_sha256: digest('e'),
        sandbox_image: "oxfuzz/fuzz-sandbox:0.1.0".to_owned(),
        sandbox_image_sha256: digest('f'),
        approval: EvidenceApproval {
            approval_id: Uuid::from_u128(3),
            harness_id: Uuid::from_u128(4),
            source_sha256: digest('b'),
            binary_sha256: digest('c'),
            kind: "clean_smoke".to_owned(),
            approved_at: "2026-07-21T23:00:00Z".to_owned(),
        },
        coverage: EvidenceCoverage {
            edges: 100,
            delta_edges: 10,
        },
        findings: vec![EvidenceFinding {
            crash_id: Uuid::from_u128(5),
            stack_signature: digest('1'),
            reproducer_sha256: digest('2'),
            minimized: true,
        }],
        cost: EvidenceCost {
            compute_cost_usd: 1.25,
            model_cost_usd: 0.05,
        },
    }
}

#[test]
fn manifest_digest_is_canonical_and_detects_mutation() {
    let first = EvidenceManifest::new(body()).expect("valid manifest");
    let mut reordered = body();
    reordered.run_config.environment = BTreeMap::new();
    reordered
        .run_config
        .environment
        .insert("TZ".to_owned(), "UTC".to_owned());
    reordered
        .run_config
        .environment
        .insert("ASAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned());
    let second = EvidenceManifest::new(reordered).expect("equivalent manifest");
    assert_eq!(first.manifest_sha256, second.manifest_sha256);
    first.verify().expect("unchanged manifest verifies");

    let mut tampered = first;
    tampered.body.coverage.edges += 1;
    assert_eq!(tampered.verify(), Err(EvidenceError::DigestMismatch));
}

#[test]
fn approval_must_match_the_exact_harness_and_binary() {
    let mut mismatched = body();
    mismatched.approval.binary_sha256 = digest('9');
    assert_eq!(
        EvidenceManifest::new(mismatched),
        Err(EvidenceError::ApprovalMismatch)
    );
}

#[test]
fn non_finite_cost_and_nonterminal_runs_fail_closed() {
    let mut non_finite = body();
    non_finite.cost.compute_cost_usd = f64::NAN;
    assert_eq!(
        EvidenceManifest::new(non_finite),
        Err(EvidenceError::InvalidCost)
    );

    let mut running = body();
    running.status = EvidenceRunStatus::Running;
    assert_eq!(
        EvidenceManifest::new(running),
        Err(EvidenceError::NonTerminalRun)
    );
}

#[tokio::test]
async fn service_assembles_a_manifest_from_durable_run_and_approval_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("evidence.db"))
        .await
        .unwrap();
    let target_id = Uuid::from_u128(10);
    let target = TargetCandidate {
        id: target_id,
        project_root: directory.path().to_path_buf(),
        symbol: "parse_header".to_owned(),
        language: TargetLanguage::C,
        kind: TargetKind::Function,
        location: SourceLocation {
            file: directory.path().join("parser.c"),
            line: 1,
            col: 1,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        accumulated_complexity: 1,
        reachable_functions: Vec::new(),
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "fixture".to_owned(),
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();

    let harness_id = Uuid::from_u128(11);
    let harness = Harness {
        id: harness_id,
        target_id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_bin"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    let harness_sha256 = digest('b');
    let binary_sha256 = digest('c');
    store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &harness_sha256,
            &binary_sha256,
            Utc::now(),
        )
        .await
        .unwrap();

    let now = Utc::now();
    let mut run = RunRecord::new(
        directory.path().to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(60)),
            max_mem_mb: 1024,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: Some(9),
            replay_of: None,
        }),
        now,
    );
    run.status = RunStatus::Done;
    run.ended_at = Some(now + chrono::Duration::seconds(60));
    run.edges = Some(42);
    run.harness_rev = Some(harness_sha256.clone());
    run.binary_rev = Some(binary_sha256.clone());
    run.context_rev = Some(digest('d'));
    run.source_rev = Some(digest('a'));
    run.corpus_rev = Some(digest('e'));
    run.sandbox_rev = Some(digest('f'));
    store.insert_run(&run).await.unwrap();

    let crash_input = directory.path().join("crash-input");
    std::fs::write(&crash_input, b"crash").unwrap();
    let crash = Crash {
        id: Uuid::from_u128(12),
        run_id: run.id,
        target_id,
        input_path: crash_input,
        stack_signature: digest('1'),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
    };
    store.upsert_crash(&crash).await.unwrap();

    let container = ServiceContainer::stubbed().with_store(Arc::new(store));
    let manifest = container
        .campaign_evidence_manifest(
            run.id,
            CampaignEvidencePricing {
                compute_usd_per_hour: 3.0,
                model_cost_usd: 0.25,
            },
        )
        .await
        .expect("complete durable evidence");

    manifest.verify().unwrap();
    assert_eq!(manifest.body.target, "parse_header");
    assert_eq!(manifest.body.approval.harness_id, harness_id);
    assert_eq!(manifest.body.findings.len(), 1);
    assert_eq!(manifest.body.cost.compute_cost_usd, 0.05);

    let patch = "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-old\n+fixed\n";
    let bundle = directory.path().join("remediation-bundle");
    let handoff = container
        .export_remediation_draft(
            run.id,
            crash.id,
            patch,
            &bundle,
            CampaignEvidencePricing {
                compute_usd_per_hour: 3.0,
                model_cost_usd: 0.25,
            },
        )
        .await
        .expect("atomic draft handoff");
    assert_eq!(handoff.status, RemediationStatus::Draft);
    assert_eq!(
        handoff.binding.evidence_manifest_sha256,
        manifest.manifest_sha256
    );
    assert!(bundle.join("remediation.json").is_file());
    assert!(bundle.join("PATCH.diff").is_file());
    assert_eq!(std::fs::read(bundle.join("reproducer")).unwrap(), b"crash");
    assert!(bundle.join("REMEDIATION.md").is_file());
}
