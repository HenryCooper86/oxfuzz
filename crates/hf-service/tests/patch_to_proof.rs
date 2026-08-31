#![cfg(feature = "patch-to-proof")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus, SmokeRunSummary};
use hf_core::runtime::{
    CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::evidence::CampaignEvidencePricing;
use hf_service::{RemediationDraftRequest, ServiceContainer};
#[cfg(unix)]
use hf_service::{RemediationOperationStatus, RemediationStartRequest};
use hf_storage::{HarnessApprovalKind, RunRecord, RunStatus, Store};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

#[derive(Default)]
struct VerificationRuntime {
    calls: Mutex<Vec<Vec<String>>>,
}

impl VerificationRuntime {
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl RuntimeAdapter for VerificationRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        ImmutableImageReference::from_sha256_id(format!("sha256:{}", "f".repeat(64))).map(Some)
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls.lock().unwrap().push(cmd.to_vec());
        if cmd.first().is_some_and(|program| program == "bash") {
            std::fs::write(cwd.join("fuzz_parse_packet"), b"patched-binary").unwrap();
        }
        let original_replay = cmd
            .first()
            .is_some_and(|program| program.contains("/runs/") && program.ends_with("/harness"));
        Ok(CommandResult {
            exit_code: if original_replay { 77 } else { 0 },
            stdout: if cmd.iter().any(|arg| arg.starts_with("-max_total_time=")) {
                "DONE".to_owned()
            } else {
                String::new()
            },
            stderr: if original_replay {
                "ERROR: AddressSanitizer: heap-buffer-overflow".to_owned()
            } else {
                String::new()
            },
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        std::fs::read_to_string(path).map_err(|error| ClassifiedError::Sandbox(error.to_string()))
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn component_digest(prefix: &[u8], entries: &[(&str, &[u8])]) -> String {
    let mut digest = Sha256::new();
    digest.update(prefix);
    for (path, bytes) in entries {
        digest.update(path.as_bytes());
        digest.update(b"\0");
        digest.update(bytes);
        digest.update(b"\0");
    }
    hex::encode(digest.finalize())
}

fn workspace_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_patch_to_proof_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().unwrap();
        root
    })
}

async fn fixture() -> (
    ServiceContainer,
    Arc<VerificationRuntime>,
    tempfile::TempDir,
    Uuid,
    Uuid,
) {
    let _ = workspace_root();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("parser.c"), b"unsafe();\n").unwrap();
    let store = Arc::new(
        Store::connect(project.path().join("oxfuzz.db"))
            .await
            .unwrap(),
    );
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.path().to_path_buf(),
        symbol: "parse_packet".to_owned(),
        language: TargetLanguage::C,
        kind: TargetKind::Function,
        location: SourceLocation {
            file: project.path().join("parser.c"),
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

    let harness_source =
        "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return n>0?d[0]:0;}";
    let original_binary = b"original-binary";
    let harness_sha256 = sha256(harness_source.as_bytes());
    let original_binary_sha256 = sha256(original_binary);
    let mut harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: harness_source.to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_packet"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::SmokePassed,
        smoke_run: Some(SmokeRunSummary {
            duration_secs: 60,
            execs_per_sec: 1.0,
            crashes: 0,
            passed: true,
            source_sha256: Some(harness_sha256.clone()),
            binary_sha256: Some(original_binary_sha256.clone()),
            run_id: Some(Uuid::new_v4()),
        }),
    };
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;
    store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &harness_sha256,
            &original_binary_sha256,
            Utc::now(),
        )
        .await
        .unwrap();

    let mut run = RunRecord::new(
        project.path().to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(60)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: Some(7),
            replay_of: None,
        }),
        Utc::now(),
    );
    run.status = RunStatus::Done;
    run.ended_at = Some(Utc::now());
    run.harness_rev = Some(harness_sha256);
    run.binary_rev = Some(original_binary_sha256);
    run.context_rev = Some("4".repeat(64));
    run.source_rev = Some(component_digest(
        b"oxfuzz-run-source-v1\0",
        &[("parser.c", b"unsafe();\n")],
    ));
    run.corpus_rev = Some(component_digest(
        b"oxfuzz-run-corpus-v1\0",
        &[("corpus/seed", b"seed")],
    ));
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "f".repeat(64)));
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    store.insert_run(&run).await.unwrap();
    store
        .set_run_harness_source(run.id, harness_source)
        .await
        .unwrap();

    let target_workspace = hf_service::workspace_dir(project.path(), "parse_packet");
    let run_root = target_workspace.join("runs").join(run.id.to_string());
    std::fs::create_dir_all(run_root.join("input")).unwrap();
    std::fs::create_dir_all(run_root.join("corpus")).unwrap();
    std::fs::create_dir_all(run_root.join("out")).unwrap();
    std::fs::write(run_root.join("input/harness"), original_binary).unwrap();
    std::fs::write(run_root.join("input/harness.source"), harness_source).unwrap();
    std::fs::write(run_root.join("corpus/seed"), b"seed").unwrap();
    let crash_path = run_root.join("out/crash-proof");
    std::fs::write(&crash_path, b"crash").unwrap();
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: crash_path,
        stack_signature: "1".repeat(64),
        kind: CrashKind::Asan,
        summary: "overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
        origin: CrashOrigin::Target,
    };
    store.upsert_crash(&crash).await.unwrap();

    let runtime = Arc::new(VerificationRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store);
    (container, runtime, project, run.id, crash.id)
}

#[cfg(unix)]
#[tokio::test]
async fn approved_patch_runs_all_required_stages_and_persists_verified_evidence() {
    let (container, runtime, _project, run_id, finding_id) = fixture().await;
    let draft = container
        .create_remediation_operation(RemediationDraftRequest {
            run_id,
            finding_id,
            patch: "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned(),
            follow_up_fuzz_seconds: 1,
            pricing: CampaignEvidencePricing {
                compute_usd_per_hour: 0.0,
                model_cost_usd: 0.0,
            },
        })
        .await
        .unwrap();
    assert_eq!(draft.status, RemediationOperationStatus::Draft);
    assert!(
        runtime.calls().is_empty(),
        "draft creation must not execute code"
    );

    let approved = container
        .approve_remediation_operation(draft.operation_id, "local-operator")
        .await
        .unwrap();
    assert_eq!(approved.status, RemediationOperationStatus::Approved);
    assert!(
        runtime.calls().is_empty(),
        "approval alone must not execute code"
    );

    container
        .start_remediation_verification(RemediationStartRequest {
            operation_id: draft.operation_id,
        })
        .await
        .unwrap();
    let terminal = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let view = container
                .remediation_operation(draft.operation_id)
                .await
                .unwrap();
            if view.status == RemediationOperationStatus::Verified {
                break view;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("verification should finish");

    let evidence = terminal.verification.expect("terminal sandbox evidence");
    assert_eq!(evidence.original_replay.detail_code, "original_reproduced");
    assert_eq!(evidence.patch_build.detail_code, "patch_built");
    assert_eq!(evidence.patched_replay.detail_code, "patched_replay_clean");
    assert_eq!(evidence.regression.cases, 1);
    assert_eq!(evidence.follow_up_fuzz.detail_code, "follow_up_clean");
    assert_ne!(
        evidence.patched_binary_sha256.as_deref(),
        Some(terminal.binding.original_binary_sha256.as_str())
    );

    let calls = runtime.calls();
    assert!(calls
        .iter()
        .any(|command| command.first().is_some_and(|value| value == "patch")));
    assert!(calls
        .iter()
        .any(|command| command.first().is_some_and(|value| value == "bash")));
    assert!(calls.iter().any(|command| command
        .iter()
        .any(|value| value.starts_with("-max_total_time="))));
}

#[cfg(unix)]
#[tokio::test]
async fn unapproved_operation_cannot_start_or_claim_verified_status() {
    let (container, runtime, _project, run_id, finding_id) = fixture().await;
    let draft = container
        .create_remediation_operation(RemediationDraftRequest {
            run_id,
            finding_id,
            patch: "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned(),
            follow_up_fuzz_seconds: 1,
            pricing: CampaignEvidencePricing {
                compute_usd_per_hour: 0.0,
                model_cost_usd: 0.0,
            },
        })
        .await
        .unwrap();

    let error = container
        .start_remediation_verification(RemediationStartRequest {
            operation_id: draft.operation_id,
        })
        .await
        .expect_err("draft execution must fail");
    assert!(error.to_string().contains("approved"));
    assert!(runtime.calls().is_empty());
}

/// The design requires guardrail authorization before the first sandbox
/// command. A denial must refuse the start and leave the approved operation
/// exactly as it was, rather than claiming it and stranding it in `running`.
#[cfg(unix)]
#[tokio::test]
async fn verification_does_not_start_without_guardrail_authorization() {
    use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};

    let (container, runtime, _project, run_id, finding_id) = fixture().await;
    let draft = container
        .create_remediation_operation(RemediationDraftRequest {
            run_id,
            finding_id,
            patch: "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned(),
            follow_up_fuzz_seconds: 1,
            pricing: CampaignEvidencePricing {
                compute_usd_per_hour: 0.0,
                model_cost_usd: 0.0,
            },
        })
        .await
        .unwrap();
    container
        .approve_remediation_operation(draft.operation_id, "local-operator")
        .await
        .unwrap();

    // The same durable store, under a policy that denies every high-risk action.
    let denied = ServiceContainer::new(runtime.clone(), None)
        .with_store(Arc::clone(container.store().expect("fixture store")))
        .with_guardrails(Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::Low),
            },
            Arc::new(DenyAll),
        ));
    let error = denied
        .start_remediation_verification(RemediationStartRequest {
            operation_id: draft.operation_id,
        })
        .await
        .expect_err("a denied action never starts sandbox verification");
    assert!(
        error.to_string().contains("guardrail"),
        "the refusal names the guardrail: {error}"
    );

    let view = container
        .remediation_operation(draft.operation_id)
        .await
        .unwrap();
    assert_eq!(
        view.status,
        RemediationOperationStatus::Approved,
        "a denied start leaves the operation approved, never claimed"
    );
    assert!(
        runtime.calls().is_empty(),
        "a denied start executes nothing"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn windows_refuses_patch_to_proof_without_secure_evidence_reads() {
    let (container, runtime, _project, run_id, finding_id) = fixture().await;

    let error = container
        .create_remediation_operation(RemediationDraftRequest {
            run_id,
            finding_id,
            patch: "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned(),
            follow_up_fuzz_seconds: 1,
            pricing: CampaignEvidencePricing {
                compute_usd_per_hour: 0.0,
                model_cost_usd: 0.0,
            },
        })
        .await
        .expect_err("Windows must refuse an evidence read without handle-relative traversal");

    assert!(
        error.to_string().contains(
            "proof-carrying evidence reads require descriptor-relative filesystem access"
        ),
        "the refusal names the unavailable secure read: {error}"
    );
    assert!(
        runtime.calls().is_empty(),
        "an unavailable evidence read executes nothing"
    );
}
