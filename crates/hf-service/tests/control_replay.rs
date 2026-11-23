//! Control-input replay: a fault that survives benign inputs does not establish
//! valid API usage, and no other outcome changes what triage claims.

#![cfg(feature = "control-replay")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::crash::{Crash, CrashControlKind, CrashOrigin};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxNetworkMode,
    SandboxOptions,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::finding_proof::{
    finding_proof_card, finding_usage_review_state, FindingProofStatus, FindingUsageReviewState,
    InputDependenceDetermination,
};
use hf_service::triage_disposition::{
    triage_disposition, ClaimCeiling, Disposition, DispositionAction,
};
use hf_service::ServiceContainer;
use sha2::{Digest, Sha256};

const TARGET_FAULT: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118\n    #0 0x4f1a2b in parse_input /work/parse.c:7:3\n    #1 0x51b3c4 in LLVMFuzzerTestOneInput /work/harness.c:4:5\n";
const OTHER_FAULT: &str = "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000118\n    #0 0x4f1a2b in other_function /work/other.c:9:3\n    #1 0x51b3c4 in LLVMFuzzerTestOneInput /work/harness.c:4:5\n";
const HARNESS_FAULT: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000118\n    #0 0x51b3c4 in LLVMFuzzerTestOneInput /work/harness.c:4:5\n";

#[derive(Clone, Copy)]
enum Controls {
    Reproduce,
    Clean,
    SameLengthOnly,
    TimedOut,
    DifferentFailure,
}

struct ControlRuntime {
    controls: Controls,
    candidate: &'static [u8],
    fault: &'static str,
    baseline_clean: bool,
    candidate_replays: Mutex<usize>,
    observed: Mutex<Vec<(Vec<u8>, SandboxOptions)>>,
}

impl ControlRuntime {
    fn new(controls: Controls) -> Self {
        Self {
            controls,
            candidate: b"xyz",
            fault: TARGET_FAULT,
            baseline_clean: false,
            candidate_replays: Mutex::new(0),
            observed: Mutex::new(Vec::new()),
        }
    }

    fn result(cwd: &Path, exit_code: i32, stderr: &str, end: CommandTermination) -> CommandResult {
        CommandResult {
            exit_code,
            stdout: String::new(),
            stderr: stderr.to_owned(),
            workspace: cwd.to_path_buf(),
            termination: end,
        }
    }
}

#[async_trait]
impl RuntimeAdapter for ControlRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        options: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        if cmd.first().is_some_and(|part| part.starts_with("casr-")) {
            return Err(ClassifiedError::Sandbox("CASR unavailable".to_owned()));
        }
        if let Some(output) = cmd
            .iter()
            .find_map(|part| part.strip_prefix("-exact_artifact_path="))
        {
            let mount = options
                .extra_mounts
                .iter()
                .find(|mount| output.starts_with(&mount.container_path))
                .expect("minimizer output mount");
            let relative = output
                .strip_prefix(&mount.container_path)
                .unwrap()
                .trim_start_matches('/');
            std::fs::write(mount.host_path.join(relative), self.candidate).unwrap();
            return Ok(Self::result(cwd, 0, "", CommandTermination::Completed));
        }
        if let Some(input) = cmd.iter().find(|part| part.contains("/triage/controls/")) {
            let host = cwd.join(input.strip_prefix("/work/").expect("workspace path"));
            let bytes = std::fs::read(host).expect("control input exists during replay");
            let same_length = bytes.len() == self.candidate.len();
            self.observed.lock().unwrap().push((bytes, options.clone()));
            let done = CommandTermination::Completed;
            return Ok(match self.controls {
                Controls::Reproduce => Self::result(cwd, 1, self.fault, done),
                Controls::SameLengthOnly if same_length => Self::result(cwd, 1, self.fault, done),
                Controls::Clean | Controls::SameLengthOnly => Self::result(cwd, 0, "", done),
                Controls::TimedOut => Self::result(cwd, 124, "", CommandTermination::TimedOut),
                Controls::DifferentFailure => Self::result(cwd, 1, OTHER_FAULT, done),
            });
        }
        let replays_candidate = cmd.iter().any(|part| {
            Path::new(part)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("min"))
        });
        if self.baseline_clean && replays_candidate {
            // Confirmation takes three replays; the control baseline follows.
            let mut replays = self.candidate_replays.lock().unwrap();
            *replays += 1;
            if *replays > 3 {
                return Ok(Self::result(cwd, 0, "", CommandTermination::Completed));
            }
        }
        Ok(Self::result(
            cwd,
            1,
            self.fault,
            CommandTermination::Completed,
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    project: PathBuf,
    target: TargetCandidate,
    run: hf_storage::RunRecord,
    store: Arc<hf_storage::Store>,
}

impl Fixture {
    fn run_root(&self) -> PathBuf {
        hf_service::workspace_dir(&self.project, &self.target.symbol)
            .join("runs")
            .join(self.run.id.to_string())
    }

    async fn triage(&self, runtime: Arc<ControlRuntime>) -> Crash {
        let service = ServiceContainer::new(runtime, None).with_store(Arc::clone(&self.store));
        service
            .triage_run(
                &self.project,
                &self.target.symbol,
                self.run.id,
                hf_service::AiPolicy::Off,
            )
            .await
            .unwrap();
        let mut persisted = self.store.list_crashes_by_run(self.run.id).await.unwrap();
        assert_eq!(persisted.len(), 1);
        persisted.remove(0)
    }
}

async fn fixture(name: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    common::install_managed_workspace("oxfuzz_control_replay_tests");
    let project = root.path().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    let target = TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: project.clone(),
        language: TargetLanguage::C,
        symbol: "parse_input".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("parse.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "test".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    };
    let harness = hf_core::harness::Harness {
        id: uuid::Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: hf_core::harness::BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_input"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: hf_core::harness::HarnessStatus::Promoted,
        smoke_run: None,
        custom_mutator: None,
        cmplog: None,
    };
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(1)),
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
            input_timeout: None,
            resume: false,
            cmplog: false,
        }),
        chrono::Utc::now(),
    );
    run.status = hf_storage::RunStatus::Done;
    run.ended_at = Some(chrono::Utc::now());
    run.evidence_dir = Some(format!("runs/{}/out", run.id));
    let run_root = hf_service::workspace_dir(&project, &target.symbol)
        .join("runs")
        .join(run.id.to_string());
    std::fs::create_dir_all(run_root.join("input")).unwrap();
    std::fs::create_dir_all(run_root.join("out")).unwrap();
    std::fs::write(run_root.join("input/harness"), b"immutable run binary").unwrap();
    std::fs::write(
        run_root.join("out/crash-original"),
        b"crashing input that should become smaller",
    )
    .unwrap();
    run.binary_rev = Some(format!("{:x}", Sha256::digest(b"immutable run binary")));
    run.sandbox_rev = Some(format!(
        "docker-image-id-sha256:{}",
        hf_test_utils::immutable_test_image().unwrap().sha256()
    ));
    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("service.db"))
            .await
            .unwrap(),
    );
    store
        .upsert_target(&target, chrono::Utc::now())
        .await
        .unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();
    Fixture {
        _root: root,
        project,
        target,
        run,
        store,
    }
}

#[tokio::test]
async fn a_fault_that_survives_every_control_needs_a_usage_review() {
    let fixture = fixture("control-all").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Reproduce));

    let crash = fixture.triage(runtime.clone()).await;

    assert!(crash.minimized);
    assert_eq!(
        crash.origin,
        CrashOrigin::Target,
        "origin is never rewritten"
    );
    let controls = crash
        .control_replay
        .as_ref()
        .expect("control evidence retained");
    assert_eq!(
        controls
            .observations
            .iter()
            .map(|control| control.kind)
            .collect::<Vec<_>>(),
        CrashControlKind::ALL
    );
    let card = finding_proof_card(&crash);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::InputIndependent
    );
    assert_eq!(card.input_dependence.status, FindingProofStatus::Supported);
    let view = triage_disposition(&crash, &card);
    assert_eq!(view.disposition, Disposition::InputIndependentFault);
    assert_eq!(view.action, DispositionAction::ReviewHarnessUsage);
    assert_eq!(view.claim_ceiling, ClaimCeiling::TargetFramesFault);
}

#[tokio::test]
async fn controls_are_the_specified_bytes_in_an_isolated_read_only_sandbox() {
    let fixture = fixture("control-sandbox").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Clean));

    fixture.triage(runtime.clone()).await;

    let observed = runtime.observed.lock().unwrap();
    let inputs: Vec<&[u8]> = observed.iter().map(|(bytes, _)| bytes.as_slice()).collect();
    assert_eq!(inputs, [&[0u8, 0, 0][..], b"AAA", &[1u8][..]]);
    let image = hf_test_utils::immutable_test_image().unwrap();
    for (_, options) in observed.iter() {
        assert!(options.workspace_read_only);
        assert_eq!(options.network_mode, SandboxNetworkMode::None);
        assert!(options.extra_mounts.is_empty());
        assert_eq!(options.image.as_deref(), Some(image.reference()));
    }
    drop(observed);
    let controls = fixture.run_root().join("triage/controls");
    assert!(
        std::fs::read_dir(controls).unwrap().next().is_none(),
        "derivable control inputs are not retained"
    );
}

#[tokio::test]
async fn only_a_fault_surviving_every_control_changes_the_disposition() {
    for (controls, determination, status) in [
        (
            Controls::Clean,
            InputDependenceDetermination::InputDependent,
            FindingProofStatus::Supported,
        ),
        (
            Controls::SameLengthOnly,
            InputDependenceDetermination::SizeOrContentSensitive,
            FindingProofStatus::Supported,
        ),
        (
            Controls::TimedOut,
            InputDependenceDetermination::Inconclusive,
            FindingProofStatus::NotVerified,
        ),
        (
            Controls::DifferentFailure,
            InputDependenceDetermination::Inconclusive,
            FindingProofStatus::NotVerified,
        ),
    ] {
        let fixture = fixture("control-outcomes").await;
        let crash = fixture
            .triage(Arc::new(ControlRuntime::new(controls)))
            .await;
        let card = finding_proof_card(&crash);
        assert_eq!(card.input_dependence.determination, determination);
        assert_eq!(card.input_dependence.status, status);
        assert_eq!(
            triage_disposition(&crash, &card).disposition,
            Disposition::ReachabilityUnproven
        );
    }
}

#[tokio::test]
async fn a_control_identical_to_the_candidate_proves_nothing() {
    let fixture = fixture("control-identical").await;
    let mut runtime = ControlRuntime::new(Controls::Reproduce);
    runtime.candidate = b"AAA";

    let crash = fixture.triage(Arc::new(runtime)).await;

    let card = finding_proof_card(&crash);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::Inconclusive
    );
    assert_eq!(
        triage_disposition(&crash, &card).disposition,
        Disposition::ReachabilityUnproven
    );
}

#[tokio::test]
async fn a_fault_that_minimizes_to_nothing_is_still_tested_on_its_original_input() {
    let fixture = fixture("control-empty-min").await;
    let mut runtime = ControlRuntime::new(Controls::Reproduce);
    runtime.candidate = b"";
    let runtime = Arc::new(runtime);

    let crash = fixture.triage(runtime.clone()).await;

    assert!(!crash.minimized, "an empty minimizer output is rejected");
    assert_eq!(runtime.observed.lock().unwrap().len(), 3);
    let card = finding_proof_card(&crash);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::InputIndependent
    );
    assert_eq!(
        triage_disposition(&crash, &card).disposition,
        Disposition::InputIndependentFault
    );
}

#[tokio::test]
async fn a_crash_that_stops_reproducing_runs_no_controls() {
    let fixture = fixture("control-flaky").await;
    let mut runtime = ControlRuntime::new(Controls::Reproduce);
    runtime.baseline_clean = true;
    let runtime = Arc::new(runtime);

    let crash = fixture.triage(runtime.clone()).await;

    assert!(crash.minimized);
    assert!(runtime.observed.lock().unwrap().is_empty());
    let card = finding_proof_card(&crash);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::Inconclusive
    );
    assert_eq!(
        triage_disposition(&crash, &card).disposition,
        Disposition::ReachabilityUnproven
    );
}

#[tokio::test]
async fn retained_control_evidence_is_recomputed_not_trusted() {
    let fixture = fixture("control-tamper").await;
    let crash = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::Reproduce)))
        .await;

    let mut forged_log = crash.clone();
    let controls = forged_log.control_replay.as_mut().unwrap();
    controls.observations[0].observation.log = String::new();

    let mut forged_digest = crash.clone();
    let controls = forged_digest.control_replay.as_mut().unwrap();
    controls.observations[1].input_sha256 = "0".repeat(64);

    let mut forged_baseline = crash.clone();
    forged_baseline.control_replay.as_mut().unwrap().baseline[1].log = String::new();

    let mut missing = crash;
    let controls = missing.control_replay.as_mut().unwrap();
    controls.observations.pop();

    for forged in [forged_log, forged_digest, forged_baseline, missing] {
        let card = finding_proof_card(&forged);
        assert_eq!(
            card.input_dependence.determination,
            InputDependenceDetermination::Inconclusive
        );
        assert_eq!(
            triage_disposition(&forged, &card).disposition,
            Disposition::ReachabilityUnproven
        );
    }
}

#[tokio::test]
async fn a_harness_fault_runs_no_controls() {
    let fixture = fixture("control-harness").await;
    let mut runtime = ControlRuntime::new(Controls::Reproduce);
    runtime.fault = HARNESS_FAULT;
    let runtime = Arc::new(runtime);

    let crash = fixture.triage(runtime.clone()).await;

    assert_eq!(crash.origin, CrashOrigin::Harness);
    assert!(runtime.observed.lock().unwrap().is_empty());
    assert!(crash.control_replay.is_none());
}

#[tokio::test]
async fn control_staging_failure_keeps_the_minimized_crash() {
    let fixture = fixture("control-staging").await;
    let triage = fixture.run_root().join("triage");
    std::fs::create_dir_all(&triage).unwrap();
    std::fs::write(triage.join("controls"), b"not a directory").unwrap();
    let runtime = Arc::new(ControlRuntime::new(Controls::Reproduce));

    let crash = fixture.triage(runtime.clone()).await;

    assert!(crash.minimized);
    assert!(runtime.observed.lock().unwrap().is_empty());
    let card = finding_proof_card(&crash);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::NotVerified
    );
    assert_eq!(
        triage_disposition(&crash, &card).disposition,
        Disposition::ReachabilityUnproven
    );
}

#[tokio::test]
async fn evidence_persisted_before_controls_existed_still_decodes() {
    let fixture = fixture("control-legacy").await;
    let crash = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::Reproduce)))
        .await;
    let mut json = serde_json::to_value(&crash).unwrap();
    json.as_object_mut().unwrap().remove("control_replay");

    let legacy: Crash = serde_json::from_value(json).unwrap();

    let card = finding_proof_card(&legacy);
    assert_eq!(
        card.input_dependence.determination,
        InputDependenceDetermination::NotVerified
    );
    assert_eq!(
        triage_disposition(&legacy, &card).disposition,
        Disposition::ReachabilityUnproven
    );
}

#[tokio::test]
async fn an_input_independent_fault_sorts_after_findings_and_before_unattributed_faults() {
    assert!(Disposition::MinimizationPending < Disposition::InputIndependentFault);
    assert!(Disposition::InputIndependentFault < Disposition::SymbolizationPending);
    assert!(ClaimCeiling::FaultObserved < ClaimCeiling::TargetFramesFault);
    assert!(ClaimCeiling::TargetFramesFault < ClaimCeiling::TargetFaultObserved);
}

fn exported_counts(crash: &Crash, project: &Path) -> (usize, usize) {
    let sarif = hf_service::sarif::crashes_to_sarif(std::slice::from_ref(crash), "test", project);
    let generic = hf_service::defectdojo::crashes_to_generic(std::slice::from_ref(crash));
    (
        sarif["runs"][0]["results"].as_array().unwrap().len(),
        generic["findings"].as_array().unwrap().len(),
    )
}

async fn stored(fixture: &Fixture) -> Crash {
    fixture
        .store
        .list_crashes_by_run(fixture.run.id)
        .await
        .unwrap()
        .remove(0)
}

#[tokio::test]
async fn a_held_fault_reaches_exports_only_after_a_recorded_review() {
    let fixture = fixture("hold-release").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Reproduce));
    let crash = fixture.triage(runtime.clone()).await;
    assert_eq!(
        finding_usage_review_state(&crash),
        FindingUsageReviewState::Held
    );
    assert_eq!(exported_counts(&crash, &fixture.project), (0, 0));
    let sarif =
        hf_service::sarif::crashes_to_sarif(std::slice::from_ref(&crash), "test", &fixture.project);
    assert_eq!(sarif["runs"][0]["properties"]["heldForUsageReview"], 1);

    let service = ServiceContainer::new(runtime, None).with_store(Arc::clone(&fixture.store));
    let released = service
        .finding_usage_review(&fixture.project, crash.id, true)
        .await
        .unwrap();

    assert_eq!(released.usage_review, FindingUsageReviewState::Released);
    assert_eq!(
        released.disposition.disposition,
        Disposition::ReachabilityUnproven
    );
    let persisted = stored(&fixture).await;
    assert_eq!(exported_counts(&persisted, &fixture.project), (1, 1));

    let held = service
        .finding_usage_review(&fixture.project, crash.id, false)
        .await
        .unwrap();
    assert_eq!(held.usage_review, FindingUsageReviewState::Held);
    assert_eq!(
        held.disposition.disposition,
        Disposition::InputIndependentFault
    );
    assert_eq!(
        exported_counts(&stored(&fixture).await, &fixture.project),
        (0, 0)
    );
}

#[tokio::test]
async fn a_recorded_review_survives_retriage_of_the_same_evidence() {
    let fixture = fixture("hold-retriage").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Reproduce));
    let crash = fixture.triage(runtime.clone()).await;
    let service =
        ServiceContainer::new(runtime.clone(), None).with_store(Arc::clone(&fixture.store));
    service
        .finding_usage_review(&fixture.project, crash.id, true)
        .await
        .unwrap();

    let retriaged = fixture.triage(runtime).await;

    assert_eq!(retriaged.id, crash.id);
    assert_eq!(
        finding_usage_review_state(&retriaged),
        FindingUsageReviewState::Released
    );
}

#[tokio::test]
async fn a_review_of_other_evidence_does_not_release_a_fault() {
    let fixture = fixture("hold-other-evidence").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Reproduce));
    let crash = fixture.triage(runtime.clone()).await;
    let service = ServiceContainer::new(runtime, None).with_store(Arc::clone(&fixture.store));
    service
        .finding_usage_review(&fixture.project, crash.id, true)
        .await
        .unwrap();
    let mut changed = stored(&fixture).await;
    let review = changed
        .control_replay
        .as_mut()
        .and_then(|controls| controls.usage_review.as_mut())
        .unwrap();
    review.input_sha256 = "f".repeat(64);

    assert_eq!(
        finding_usage_review_state(&changed),
        FindingUsageReviewState::Held
    );
    assert_eq!(exported_counts(&changed, &fixture.project), (0, 0));
}

#[tokio::test]
async fn a_retriage_that_cannot_repeat_the_experiment_keeps_the_hold() {
    let fixture = fixture("hold-flaky-retriage").await;
    let crash = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::Reproduce)))
        .await;
    assert_eq!(
        finding_usage_review_state(&crash),
        FindingUsageReviewState::Held
    );

    let retriaged = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::TimedOut)))
        .await;

    assert_eq!(
        finding_usage_review_state(&retriaged),
        FindingUsageReviewState::Held
    );
    assert_eq!(exported_counts(&retriaged, &fixture.project), (0, 0));
}

#[tokio::test]
async fn a_changed_input_path_does_not_release_a_held_fault() {
    let fixture = fixture("hold-input-path").await;
    let crash = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::Reproduce)))
        .await;
    let mut moved = crash;
    moved.input_path = PathBuf::from("/elsewhere/other-input");

    assert_eq!(
        finding_proof_card(&moved).input_dependence.determination,
        InputDependenceDetermination::Inconclusive
    );
    assert_eq!(
        finding_usage_review_state(&moved),
        FindingUsageReviewState::Held
    );
    assert_eq!(exported_counts(&moved, &fixture.project), (0, 0));
}

#[tokio::test]
async fn a_finding_that_is_not_held_cannot_be_reviewed() {
    let fixture = fixture("hold-not-held").await;
    let runtime = Arc::new(ControlRuntime::new(Controls::Clean));
    let crash = fixture.triage(runtime.clone()).await;
    assert_eq!(exported_counts(&crash, &fixture.project), (1, 1));
    let service = ServiceContainer::new(runtime, None).with_store(Arc::clone(&fixture.store));

    let error = service
        .finding_usage_review(&fixture.project, crash.id, true)
        .await
        .unwrap_err();

    assert!(matches!(error, ClassifiedError::Validation(_)));
}

#[tokio::test]
async fn a_push_of_only_held_findings_is_refused_with_the_reason() {
    let fixture = fixture("hold-push").await;
    let held = fixture
        .triage(Arc::new(ControlRuntime::new(Controls::Reproduce)))
        .await;
    let error = hf_service::defectdojo::findings_held(std::slice::from_ref(&held)).unwrap_err();
    assert!(error.to_string().contains("usage review"));

    let mut publishable = held.clone();
    publishable.control_replay = None;
    assert_eq!(
        hf_service::defectdojo::findings_held(&[held, publishable]).unwrap(),
        1
    );
    assert_eq!(hf_service::defectdojo::findings_held(&[]).unwrap(), 0);
}
