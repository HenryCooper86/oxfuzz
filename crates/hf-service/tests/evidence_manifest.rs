#![cfg(feature = "proof-carrying")]

use std::collections::BTreeMap;

use hf_core::engine::EngineKind;
use hf_service::evidence::{
    EvidenceApproval, EvidenceCost, EvidenceCoverage, EvidenceError, EvidenceFinding,
    EvidenceManifest, EvidenceManifestBody, EvidenceRunConfig, EvidenceRunStatus,
    EVIDENCE_SCHEMA_VERSION,
};
use uuid::Uuid;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn body() -> EvidenceManifestBody {
    EvidenceManifestBody {
        schema_version: EVIDENCE_SCHEMA_VERSION,
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
    assert_eq!(EVIDENCE_SCHEMA_VERSION, 2);
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
fn legacy_v1_evidence_is_not_accepted_as_exact_image_provenance() {
    let mut legacy = body();
    legacy.schema_version = 1;

    assert_eq!(
        EvidenceManifest::new(legacy),
        Err(EvidenceError::UnsupportedSchema)
    );
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

// Proof-carrying evidence reads walk the run root with descriptor-relative,
// symlink-refusing opens (rustix openat) and fail closed as Sandbox off unix,
// so the full-assembly path this test drives is a unix-only capability. Its
// imports live in the function so non-unix builds see no unused-import noise.
#[cfg(unix)]
#[tokio::test]
async fn service_assembles_a_manifest_from_durable_run_and_approval_evidence() {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use chrono::Utc;
    use hf_core::crash::{Crash, CrashKind};
    use hf_core::engine::FuzzRunConfig;
    use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use hf_crash::remediation::RemediationStatus;
    use hf_service::evidence::CampaignEvidencePricing;
    use hf_service::ServiceContainer;
    use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus, Store};

    /// Tolerance for comparing a computed `f64` cost against its exact expected value.
    const EPS: f64 = 1e-9;

    fn isolate_workspace() -> &'static Path {
        static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        ROOT.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "oxfuzz_evidence_it_{}_{}",
                std::process::id(),
                Uuid::new_v4()
            ));
            std::env::set_var("HF_WORKSPACE_DIR", &root);
            hf_service::initialize_workspace_root().expect("initialize evidence-test workspace");
            root
        })
    }

    let workspace_root = isolate_workspace().to_path_buf();
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
            end_line: None,
            end_col: None,
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
            extra_flags: Vec::new(),
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
    let mut crash = Crash {
        id: Uuid::from_u128(12),
        run_id: run.id,
        target_id,
        input_path: crash_input,
        stack_signature: digest('1'),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: hf_core::crash::CrashOrigin::Unknown,
    };
    let store = Arc::new(store);
    store.upsert_crash(&crash).await.unwrap();

    let container = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let error = container
        .campaign_evidence_manifest(
            run.id,
            CampaignEvidencePricing {
                compute_usd_per_hour: 3.0,
                model_cost_usd: 0.25,
            },
        )
        .await
        .expect_err("legacy tag-derived sandbox provenance must fail closed");
    assert!(error.to_string().contains("exact sandbox image"));
    sqlx::query("UPDATE runs SET sandbox_rev = ?2 WHERE id = ?1")
        .bind(run.id.to_string())
        .bind(format!("docker-image-id-sha256:{}", digest('f')))
        .execute(store.pool())
        .await
        .unwrap();

    let run_output = hf_service::workspace_dir(directory.path(), "parse_header")
        .join("runs")
        .join(run.id.to_string())
        .join("out");
    std::fs::create_dir_all(&run_output).unwrap();
    let error = container
        .campaign_evidence_manifest(
            run.id,
            CampaignEvidencePricing {
                compute_usd_per_hour: 3.0,
                model_cost_usd: 0.25,
            },
        )
        .await
        .expect_err("evidence must not read a crash outside its approved run root");
    assert!(error.to_string().contains("approved run root"));

    crash.input_path = run_output.join("crash-input");
    std::fs::write(&crash.input_path, b"crash").unwrap();
    store.upsert_crash(&crash).await.unwrap();

    let patch = "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-old\n+fixed\n";
    let error = container
        .remediation_draft(
            run.id,
            crash.id,
            patch,
            CampaignEvidencePricing {
                compute_usd_per_hour: 3.0,
                model_cost_usd: 0.25,
            },
        )
        .await
        .expect_err("non-minimized reproducers must not create remediation drafts");
    assert!(error.to_string().contains("minimized"));

    crash.minimized = true;
    store.upsert_crash(&crash).await.unwrap();
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
    assert!((manifest.body.cost.compute_cost_usd - 0.05).abs() < EPS);
    assert_eq!(manifest.body.sandbox_image_sha256, digest('f'));

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
    assert_eq!(
        handoff.binding.sandbox_image_sha256,
        manifest.body.sandbox_image_sha256
    );
    assert!(bundle.join("remediation.json").is_file());
    assert!(bundle.join("PATCH.diff").is_file());
    assert_eq!(std::fs::read(bundle.join("reproducer")).unwrap(), b"crash");
    assert!(bundle.join("REMEDIATION.md").is_file());

    drop(container);
    drop(store);
    std::fs::remove_dir_all(workspace_root).expect("remove evidence-test workspace");
}
