//! Independent, bounded replay evidence for native minimizer output.

use std::io::Read;
use std::path::Path;

use hf_core::crash::{Crash, CrashKind, CrashOrigin, CrashReplayObservation, CrashReproduction};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandTermination, ResourceLimits, SandboxOptions};
use sha2::{Digest, Sha256};

use super::harness_workspace::container_input_path;
use super::ServiceContainer;

const MAX_REPLAY_LOG_BYTES: usize = 32 * 1024;
/// Replays of the crash input that must agree before controls are meaningful.
const CONTROL_BASELINE_RUNS: usize = 2;

#[derive(PartialEq, Eq)]
struct FailureIdentity {
    kind: CrashKind,
    signature: String,
    origin: CrashOrigin,
    class: String,
}

fn semantic_class(kind: CrashKind, log: &str) -> Option<String> {
    let lower = log.to_ascii_lowercase();
    match kind {
        CrashKind::Asan => {
            let detail = lower.lines().find_map(|line| {
                line.split_once("addresssanitizer:")
                    .map(|(_, detail)| detail)
            })?;
            let class = detail.split_whitespace().next()?;
            [
                "heap-buffer-overflow",
                "stack-buffer-overflow",
                "global-buffer-overflow",
                "heap-use-after-free",
                "stack-use-after-return",
                "stack-use-after-scope",
                "double-free",
                "alloc-dealloc-mismatch",
                "new-delete-type-mismatch",
                "use-after-poison",
                "container-overflow",
                "stack-overflow",
                "segv",
                "deadlysignal",
                "negative-size-param",
                "memcpy-param-overlap",
            ]
            .contains(&class)
            .then(|| class.to_owned())
        }
        CrashKind::Leak if lower.contains("leaksanitizer: detected memory leak") => {
            Some("memory-leak".to_owned())
        }
        CrashKind::Ubsan => {
            let detail = lower.lines().find_map(|line| {
                line.split_once("runtime error:")
                    .map(|(_, detail)| detail.trim_start())
            })?;
            [
                "signed integer overflow",
                "unsigned integer overflow",
                "load of misaligned address",
                "store to misaligned address",
                "member access within misaligned address",
                "reference binding to misaligned address",
                "load of null pointer",
                "store to null pointer",
                "member access within null pointer",
                "reference binding to null pointer",
                "division by zero",
                "shift exponent",
                "left shift of negative value",
                "execution reached an unreachable program point",
            ]
            .into_iter()
            .find(|category| {
                detail
                    .strip_prefix(category)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with([' ', ':']))
            })
            .map(str::to_owned)
        }
        CrashKind::Msan if lower.contains("memorysanitizer: use-of-uninitialized-value") => {
            Some("use-of-uninitialized-value".to_owned())
        }
        CrashKind::Tsan if lower.contains("threadsanitizer: data race") => {
            Some("data-race".to_owned())
        }
        CrashKind::Segv if lower.contains("sigsegv") || lower.contains("segv on") => {
            Some("segv".to_owned())
        }
        CrashKind::Abort if lower.contains("sigabrt") => Some("sigabrt".to_owned()),
        _ => None,
    }
}

fn log_identity(log: &str) -> Option<FailureIdentity> {
    if log.len() > MAX_REPLAY_LOG_BYTES || !hf_crash::looks_like_crash(log) {
        return None;
    }
    let (kind, signature, _) = hf_crash::classify(log);
    if signature.is_empty() {
        return None;
    }
    Some(FailureIdentity {
        kind,
        signature,
        origin: hf_crash::crash_origin(log),
        class: semantic_class(kind, log)?,
    })
}

fn failure_identity(observation: &CrashReplayObservation) -> Option<FailureIdentity> {
    if observation.termination != Some(CommandTermination::Completed)
        || observation.exit_code.is_none_or(|code| code == 0)
        || observation.error.is_some()
    {
        return None;
    }
    log_identity(&observation.log)
}

/// Whether `log` is the sanitizer output behind a CASR classification: CASR
/// names the class as `heap-buffer-overflow(read)` and the faulting source
/// position as its crash line, and both must be what the log reports.
fn describes_casr_classification(
    casr: &hf_core::crash::CasrReport,
    identity: &FailureIdentity,
    log: &str,
) -> bool {
    !casr.crashline.is_empty()
        && log.contains(&casr.crashline)
        && casr.severity_short.split('(').next() == Some(identity.class.as_str())
}

/// The failure a finding's replays must reproduce: the identity of its
/// retained classification log, provided that log agrees with the persisted
/// classification. A CASR finding is classified by CASR's own description
/// rather than by a signature of the log, so it is compared on that
/// description.
fn reference_identity(crash: &Crash, evidence: &CrashReproduction) -> Option<FailureIdentity> {
    let log = evidence.reference_log.as_deref()?;
    let identity = log_identity(log)?;
    let classified_alike = match &crash.casr {
        Some(casr) => describes_casr_classification(casr, &identity, log),
        None => {
            identity.signature == crash.stack_signature
                && semantic_class(crash.kind, &crash.summary).as_ref() == Some(&identity.class)
        }
    };
    if !classified_alike
        || identity.kind != crash.kind
        || (crash.origin != CrashOrigin::Unknown && identity.origin != crash.origin)
    {
        return None;
    }
    Some(identity)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_artifact_paths(crash: &Crash, evidence: &CrashReproduction) -> bool {
    let Some(minimized) = evidence.candidate_input.parent() else {
        return false;
    };
    let Some(triage) = minimized.parent() else {
        return false;
    };
    let Some(run) = triage.parent() else {
        return false;
    };
    let expected_run = crash.run_id.to_string();
    let paths = [&evidence.original_input, &evidence.candidate_input];
    paths.iter().all(|path| {
        path.is_absolute()
            && !path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    }) && minimized
        .file_name()
        .is_some_and(|name| name == "minimized")
        && triage.file_name().is_some_and(|name| name == "triage")
        && run
            .file_name()
            .is_some_and(|name| name == expected_run.as_str())
        && run
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "runs")
        && evidence.original_input.starts_with(run.join("out"))
        && evidence.original_input != run.join("out")
        && evidence
            .candidate_input
            .file_name()
            .is_some_and(|name| name == format!("{}.min", crash.id).as_str())
        && crash.input_path
            == if crash.minimized {
                &evidence.candidate_input
            } else {
                &evidence.original_input
            }
            .as_path()
}

/// Recomputed support for retained observations; saved flags never establish a match.
pub(crate) struct ReproductionAssessment {
    pub(crate) original_matches: usize,
    pub(crate) candidate_matches: usize,
    pub(crate) confirmed: bool,
    pub(crate) reason: &'static str,
}

pub(crate) fn assess_reproduction(
    crash: &Crash,
    evidence: &CrashReproduction,
) -> ReproductionAssessment {
    let reference = reference_identity(crash, evidence);
    let matches = |observation: &CrashReplayObservation| {
        reference.is_some() && failure_identity(observation) == reference
    };
    let original_matches = evidence
        .original
        .iter()
        .filter(|observation| matches(observation))
        .count();
    let candidate_matches = evidence
        .candidate
        .iter()
        .filter(|observation| matches(observation))
        .count();
    let provenance = evidence.version == 1
        && evidence.run_id == crash.run_id
        && evidence.crash_id == crash.id
        && valid_artifact_paths(crash, evidence)
        && [
            &evidence.original_sha256,
            &evidence.candidate_sha256,
            &evidence.binary_sha256,
        ]
        .into_iter()
        .all(|digest| valid_digest(digest))
        && hf_core::runtime::ImmutableImageReference::from_sha256_id(&evidence.image).is_ok();
    let count = evidence.requested_runs as usize;
    let complete = (2..=10).contains(&evidence.requested_runs)
        && evidence.original.len() == count
        && evidence.candidate.len() == count;
    let consistent_flags = evidence
        .original
        .iter()
        .chain(&evidence.candidate)
        .all(|observation| observation.matches_reference == matches(observation));
    let reason = if !provenance {
        "Replay artifact attribution is invalid or incomplete."
    } else if reference.is_none() {
        "No comparable retained classification log binds these replays to this finding."
    } else if !complete {
        "The requested replay observations are incomplete."
    } else if !consistent_flags {
        "Saved matching flags contradict the actual replay outcomes."
    } else if original_matches != count || candidate_matches != count {
        "At least one replay did not reproduce the classified reference failure."
    } else if !evidence.confirmed {
        "The retained operation did not confirm these observations."
    } else {
        "All requested replays reproduced the classified reference failure."
    };
    ReproductionAssessment {
        original_matches,
        candidate_matches,
        confirmed: provenance
            && reference.is_some()
            && complete
            && consistent_flags
            && evidence.confirmed
            && original_matches == count
            && candidate_matches == count,
        reason,
    }
}

/// What control-input replay showed about a confirmed failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlOutcome {
    /// Every control reproduced the failure.
    InputIndependent,
    /// Some controls reproduced it and the others exited cleanly.
    SizeOrContentSensitive,
    /// Every control exited cleanly.
    InputDependent,
    /// The retained evidence cannot support a determination.
    Inconclusive,
}

/// Recomputed support for retained control observations.
pub(crate) struct ControlAssessment {
    pub(crate) outcome: ControlOutcome,
    pub(crate) reason: &'static str,
}

impl ControlAssessment {
    const fn inconclusive(reason: &'static str) -> Self {
        Self {
            outcome: ControlOutcome::Inconclusive,
            reason,
        }
    }
}

fn exited_cleanly(observation: &CrashReplayObservation) -> bool {
    observation.termination == Some(CommandTermination::Completed)
        && observation.exit_code == Some(0)
        && observation.error.is_none()
        && !hf_crash::looks_like_crash(&observation.log)
}

/// The one failure every baseline replay produced, if they agree.
fn consistent_baseline(baseline: &[CrashReplayObservation]) -> Option<FailureIdentity> {
    if baseline.len() != CONTROL_BASELINE_RUNS {
        return None;
    }
    let first = failure_identity(baseline.first()?)?;
    baseline[1..]
        .iter()
        .all(|observation| failure_identity(observation).as_ref() == Some(&first))
        .then_some(first)
}

/// Assess retained control replay; `None` when no control evidence is retained.
///
/// Every match is recomputed from the retained logs and every digest from the
/// control's kind and length, so a saved flag or digest cannot establish a
/// result.
pub(crate) fn assess_controls(crash: &Crash) -> Option<ControlAssessment> {
    let controls = crash.control_replay.as_ref()?;
    if controls.input_path != crash.input_path {
        return Some(ControlAssessment::inconclusive(
            "The retained control evidence does not describe this crash's input.",
        ));
    }
    Some(assess_control_evidence(crash, controls))
}

/// Assess one control record on its own terms. A hold reads this rather than
/// [`assess_controls`], so an interrupted re-triage that changes which input
/// the crash names cannot release a fault the evidence still shows as
/// input-independent.
pub(crate) fn assess_control_evidence(
    crash: &Crash,
    controls: &hf_core::crash::CrashControlReplay,
) -> ControlAssessment {
    if controls.version != 1
        || crash.origin != CrashOrigin::Target
        || !valid_digest(&controls.input_sha256)
        || !valid_digest(&controls.binary_sha256)
        || hf_core::runtime::ImmutableImageReference::from_sha256_id(&controls.image).is_err()
    {
        return ControlAssessment::inconclusive(
            "The retained control evidence does not describe this crash's input.",
        );
    }
    let Some(reference) = consistent_baseline(&controls.baseline)
        .filter(|identity| identity.origin == CrashOrigin::Target)
    else {
        return ControlAssessment::inconclusive(
            "The crash did not reproduce one consistent target failure before the controls.",
        );
    };
    if !controls
        .baseline
        .iter()
        .all(|observation| observation.matches_reference)
    {
        return ControlAssessment::inconclusive(
            "A saved matching flag contradicts the retained baseline.",
        );
    }
    let limit = hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes;
    let Some(input_len) = usize::try_from(controls.input_len)
        .ok()
        .filter(|len| *len > 0 && controls.input_len <= limit)
    else {
        return ControlAssessment::inconclusive("The retained input length is invalid.");
    };
    if !controls
        .observations
        .iter()
        .map(|control| control.kind)
        .eq(hf_core::crash::CrashControlKind::ALL)
    {
        return ControlAssessment::inconclusive(
            "The retained control observations are incomplete.",
        );
    }
    let mut reproduced = 0;
    for control in &controls.observations {
        let digest = format!("{:x}", Sha256::digest(control.kind.input(input_len)));
        if control.input_sha256 != digest {
            return ControlAssessment::inconclusive(
                "A retained control digest does not match its specified bytes.",
            );
        }
        if digest == controls.input_sha256 {
            return ControlAssessment::inconclusive(
                "A control is identical to the crashing input.",
            );
        }
        let matches = failure_identity(&control.observation).as_ref() == Some(&reference);
        if control.observation.matches_reference != matches {
            return ControlAssessment::inconclusive(
                "A saved matching flag contradicts the retained control outcome.",
            );
        }
        if matches {
            reproduced += 1;
        } else if !exited_cleanly(&control.observation) {
            return ControlAssessment::inconclusive(
                "A control timed out, failed to run, or produced a different failure.",
            );
        }
    }
    if reproduced == controls.observations.len() {
        ControlAssessment {
            outcome: ControlOutcome::InputIndependent,
            reason: "Every benign control input reproduced the same failure.",
        }
    } else if reproduced == 0 {
        ControlAssessment {
            outcome: ControlOutcome::InputDependent,
            reason: "No benign control input reproduced the failure.",
        }
    } else {
        ControlAssessment {
            outcome: ControlOutcome::SizeOrContentSensitive,
            reason: "Some benign control inputs reproduced the failure; the others exited cleanly.",
        }
    }
}

fn read_bounded_input(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    let limit = hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes;
    let file = std::fs::File::open(path).map_err(|e| ClassifiedError::Storage(e.to_string()))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        return Err(ClassifiedError::Validation(
            "crash confirmation input is empty or oversized".to_owned(),
        ));
    }
    Ok(bytes)
}

fn input_digest(path: &Path) -> Result<String, ClassifiedError> {
    Ok(format!("{:x}", Sha256::digest(read_bounded_input(path)?)))
}

fn bounded_log(stdout: &str, stderr: &str) -> String {
    let mut log = String::new();
    for part in [stderr, "\n", stdout] {
        let mut end = part.len().min(MAX_REPLAY_LOG_BYTES - log.len());
        while !part.is_char_boundary(end) {
            end -= 1;
        }
        log.push_str(&part[..end]);
    }
    log
}

fn replay_limits(policy: &crate::config::TriageSettings) -> ResourceLimits {
    ResourceLimits {
        max_mem_mb: 2048,
        max_cpus: 1,
        max_duration_secs: policy.replay_timeout_secs,
        env: std::collections::HashMap::new(),
        ptrace: false,
    }
}

fn replay_sandbox(image: &hf_core::runtime::ImmutableImageReference) -> SandboxOptions {
    SandboxOptions {
        workspace_read_only: true,
        image: Some(image.reference().to_owned()),
        ..SandboxOptions::default()
    }
}

impl ServiceContainer {
    async fn replay_observation(
        &self,
        command: &[String],
        workspace: &Path,
        limits: &ResourceLimits,
        sandbox: &SandboxOptions,
    ) -> CrashReplayObservation {
        match self
            .runtime
            .run_command_opts(command, workspace, limits, sandbox)
            .await
        {
            Ok(result) => CrashReplayObservation {
                exit_code: Some(result.exit_code),
                termination: Some(result.termination),
                log: bounded_log(&result.stdout, &result.stderr),
                matches_reference: false,
                error: None,
            },
            Err(error) => CrashReplayObservation {
                exit_code: None,
                termination: None,
                log: String::new(),
                matches_reference: false,
                error: Some(bounded_log("", &error.to_string())),
            },
        }
    }

    /// Replay controls for each target-origin crash, whether or not it was
    /// minimized: an input-independent fault can minimize to an empty input,
    /// which the minimization path rejects. A failure to stage leaves the crash
    /// without control evidence, because this experiment is optional.
    #[cfg(feature = "control-replay")]
    pub(super) async fn replay_triaged_controls(
        &self,
        workspace: &Path,
        run: &hf_storage::RunRecord,
        engine: hf_core::engine::EngineKind,
        binary: &Path,
        image: &hf_core::runtime::ImmutableImageReference,
        policy: &crate::config::TriageSettings,
        crashes: &mut [Crash],
    ) -> Result<(), ClassifiedError> {
        use hf_core::engine::EngineKind;

        if !matches!(engine, EngineKind::LibFuzzer | EngineKind::AflPlusPlus) {
            return Ok(());
        }
        for crash in crashes
            .iter_mut()
            .take(crate::crash_minimization::MAX_CRASH_MINIMIZATIONS)
            .filter(|crash| crash.origin == CrashOrigin::Target)
        {
            match self
                .replay_crash_controls(workspace, run, binary, image, policy, crash)
                .await
            {
                Ok(mut controls) => {
                    // An experiment that could not finish says nothing new, so
                    // it must not replace evidence that is holding this crash.
                    let inconclusive = assess_control_evidence(crash, &controls).outcome
                        == ControlOutcome::Inconclusive;
                    if inconclusive && crash.control_replay.is_some() {
                        tracing::warn!(
                            crash_id = %crash.id,
                            "crash control replay was inconclusive; keeping retained evidence"
                        );
                        continue;
                    }
                    controls.usage_review = crash
                        .control_replay
                        .as_ref()
                        .and_then(|retained| retained.usage_review.clone());
                    crash.control_replay = Some(controls);
                }
                Err(error) => {
                    tracing::warn!(
                        crash_id = %crash.id,
                        "crash control replay could not be staged: {error}"
                    );
                    continue;
                }
            }
            if let Some(store) = &self.store {
                store
                    .upsert_crash(crash)
                    .await
                    .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
            }
        }
        Ok(())
    }

    /// Replay the crash input, then each control when the baseline agrees.
    ///
    /// # Errors
    /// Returns an error when the input changes or controls cannot be staged.
    /// A replay that fails to run is retained as an observation instead.
    #[cfg(feature = "control-replay")]
    async fn replay_crash_controls(
        &self,
        workspace: &Path,
        run: &hf_storage::RunRecord,
        binary: &Path,
        image: &hf_core::runtime::ImmutableImageReference,
        policy: &crate::config::TriageSettings,
        crash: &Crash,
    ) -> Result<hf_core::crash::CrashControlReplay, ClassifiedError> {
        let input = read_bounded_input(&crash.input_path)?;
        let input_sha256 = format!("{:x}", Sha256::digest(&input));
        let limits = replay_limits(policy);
        let sandbox = replay_sandbox(image);
        let binary_path = container_input_path(workspace, binary);
        let command = vec![
            binary_path.clone(),
            container_input_path(workspace, &crash.input_path),
        ];
        let mut baseline = Vec::with_capacity(CONTROL_BASELINE_RUNS);
        for _ in 0..CONTROL_BASELINE_RUNS {
            baseline.push(
                self.replay_observation(&command, workspace, &limits, &sandbox)
                    .await,
            );
        }
        if input_digest(&crash.input_path)? != input_sha256 {
            return Err(ClassifiedError::Validation(
                "crash control input changed during replay".to_owned(),
            ));
        }
        let reference = consistent_baseline(&baseline);
        for observation in &mut baseline {
            observation.matches_reference = reference.is_some();
        }
        let mut replay = hf_core::crash::CrashControlReplay {
            version: 1,
            input_path: crash.input_path.clone(),
            input_sha256,
            input_len: input.len() as u64,
            binary_sha256: run.binary_rev.clone().ok_or_else(|| {
                ClassifiedError::Validation("missing retained binary identity".to_owned())
            })?,
            image: image.reference().to_owned(),
            baseline,
            observations: Vec::new(),
            usage_review: None,
        };
        let Some(reference) = reference else {
            return Ok(replay);
        };
        let staged =
            crate::crash_minimization::stage_controls(workspace, run.id, crash.id, input.len())?;
        for control in staged.inputs() {
            let command = vec![binary_path.clone(), control.container_path.clone()];
            let mut observation = self
                .replay_observation(&command, workspace, &limits, &sandbox)
                .await;
            observation.matches_reference =
                failure_identity(&observation).as_ref() == Some(&reference);
            replay
                .observations
                .push(hf_core::crash::CrashControlObservation {
                    kind: control.kind,
                    input_sha256: control.sha256.clone(),
                    observation,
                });
        }
        super::staging::run_binary_path(workspace, run, "")?;
        Ok(replay)
    }

    pub(super) async fn confirm_minimized_crash(
        &self,
        workspace: &Path,
        run: &hf_storage::RunRecord,
        binary: &Path,
        inputs: (&Path, &Path),
        image: &hf_core::runtime::ImmutableImageReference,
        policy: &crate::config::TriageSettings,
        crash: &Crash,
        reference_log: Option<&str>,
    ) -> Result<CrashReproduction, ClassifiedError> {
        let retained_binary = super::staging::run_binary_path(workspace, run, "")?;
        if retained_binary != binary {
            return Err(ClassifiedError::Validation(
                "crash confirmation requires the retained run binary".to_owned(),
            ));
        }
        let mut evidence = CrashReproduction {
            version: 1,
            run_id: run.id,
            crash_id: crash.id,
            requested_runs: policy.confirmation_runs,
            reference_log: reference_log.map(|log| bounded_log("", log)),
            original_input: inputs.0.to_path_buf(),
            original_sha256: input_digest(inputs.0)?,
            candidate_input: inputs.1.to_path_buf(),
            candidate_sha256: input_digest(inputs.1)?,
            binary_sha256: run.binary_rev.clone().ok_or_else(|| {
                ClassifiedError::Validation("missing retained binary identity".to_owned())
            })?,
            image: image.reference().to_owned(),
            original: Vec::new(),
            candidate: Vec::new(),
            confirmed: false,
        };
        let limits = replay_limits(policy);
        let sandbox = replay_sandbox(image);
        for (input, observations) in [
            (inputs.0, &mut evidence.original),
            (inputs.1, &mut evidence.candidate),
        ] {
            let command = vec![
                container_input_path(workspace, binary),
                container_input_path(workspace, input),
            ];
            for _ in 0..policy.confirmation_runs {
                observations.push(
                    self.replay_observation(&command, workspace, &limits, &sandbox)
                        .await,
                );
            }
        }
        if input_digest(inputs.0)? != evidence.original_sha256
            || input_digest(inputs.1)? != evidence.candidate_sha256
        {
            return Err(ClassifiedError::Validation(
                "crash confirmation input changed during replay".to_owned(),
            ));
        }
        let reference = reference_identity(crash, &evidence);
        for observation in evidence.original.iter_mut().chain(&mut evidence.candidate) {
            observation.matches_reference =
                reference.is_some() && failure_identity(observation) == reference;
        }
        // Seed the operation flag from the saved observations before the
        // authoritative assessment: assess_reproduction reads
        // `evidence.confirmed` as the retained operation's own verdict, so
        // this store is load-bearing, not dead.
        evidence.confirmed = evidence
            .original
            .iter()
            .chain(&evidence.candidate)
            .all(|observation| observation.matches_reference);
        evidence.confirmed = assess_reproduction(crash, &evidence).confirmed;
        super::staging::run_binary_path(workspace, run, "")?;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_categories_cannot_establish_failure_identity() {
        for log in [
            "ERROR: AddressSanitizer: unknown-class\n#0 parse_input",
            "parser.c:1:1: runtime error: unknown category\n#0 parse_input",
            "parser.c:1:1: runtime error: signed integer overflowing\n#0 parse_input",
        ] {
            let observation = CrashReplayObservation {
                exit_code: Some(1),
                termination: Some(CommandTermination::Completed),
                log: log.to_owned(),
                matches_reference: true,
                error: None,
            };
            assert!(failure_identity(&observation).is_none());
        }
    }

    const CASR_LOG: &str = "==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000033\nREAD of size 1\n    #0 0xaaaa in decode_utf8 /work/utf8.c:31:27\n    #1 0xbbbb in LLVMFuzzerTestOneInput /work/harness.c:7:11";

    /// A finding classified by CASR, with replays of the original and the
    /// minimized candidate that all print `replay_log`.
    fn casr_finding(reference_log: Option<&str>, replay_log: &str) -> Crash {
        let run_id = uuid::Uuid::new_v4();
        let id = uuid::Uuid::new_v4();
        let run = std::env::temp_dir().join("runs").join(run_id.to_string());
        let original = run.join("out/crash-original");
        let observation = CrashReplayObservation {
            exit_code: Some(1),
            termination: Some(CommandTermination::Completed),
            log: replay_log.to_owned(),
            matches_reference: true,
            error: None,
        };
        Crash {
            control_replay: None,
            reproduction: Some(CrashReproduction {
                version: 1,
                run_id,
                crash_id: id,
                requested_runs: 2,
                reference_log: reference_log.map(str::to_owned),
                original_input: original.clone(),
                original_sha256: "a".repeat(64),
                candidate_input: run.join("triage/minimized").join(format!("{id}.min")),
                candidate_sha256: "b".repeat(64),
                binary_sha256: "c".repeat(64),
                image: format!("sha256:{}", "d".repeat(64)),
                original: vec![observation.clone(), observation.clone()],
                candidate: vec![observation.clone(), observation],
                confirmed: true,
            }),
            id,
            run_id,
            target_id: uuid::Uuid::new_v4(),
            input_path: original,
            stack_signature: "/work/utf8.c:31:27".to_owned(),
            kind: CrashKind::Asan,
            summary: "heap-buffer-overflow(read) at /work/utf8.c:31:27".to_owned(),
            minimized: false,
            bug_report: None,
            origin: CrashOrigin::Target,
            casr: Some(hf_core::crash::CasrReport {
                severity: hf_core::crash::CrashSeverity::NotExploitable,
                severity_short: "heap-buffer-overflow(read)".to_owned(),
                crashline: "/work/utf8.c:31:27".to_owned(),
                stack: vec!["#0 0xaaaa in decode_utf8 /work/utf8.c:31:27".to_owned()],
                cluster: None,
            }),
        }
    }

    fn assessed(crash: &Crash) -> ReproductionAssessment {
        assess_reproduction(crash, crash.reproduction.as_ref().unwrap())
    }

    #[test]
    fn a_casr_finding_is_confirmed_against_the_sanitizer_log_of_its_report() {
        let replay = format!("INFO: Seed: 1\n{CASR_LOG}");
        let assessment = assessed(&casr_finding(Some(CASR_LOG), &replay));
        assert!(assessment.confirmed, "{}", assessment.reason);
        assert_eq!(assessment.candidate_matches, 2);
    }

    #[test]
    fn a_casr_finding_without_a_sanitizer_log_stays_unconfirmed() {
        let assessment = assessed(&casr_finding(None, CASR_LOG));
        assert!(!assessment.confirmed);
        assert!(assessment.reason.contains("No comparable retained"));
    }

    #[test]
    fn a_log_that_does_not_describe_the_casr_classification_cannot_confirm_it() {
        // The same failure everywhere, but at another line than CASR reported.
        let elsewhere = CASR_LOG.replace("utf8.c:31:27", "utf8.c:12:3");
        assert!(!assessed(&casr_finding(Some(&elsewhere), &elsewhere)).confirmed);
        // Another class of fault than CASR reported.
        let other = CASR_LOG.replace("heap-buffer-overflow", "heap-use-after-free");
        assert!(!assessed(&casr_finding(Some(&other), &other)).confirmed);
        // Replays that fail differently from the report's own log.
        let moved = CASR_LOG.replace("decode_utf8", "another_function");
        assert!(!assessed(&casr_finding(Some(CASR_LOG), &moved)).confirmed);
    }

    #[test]
    fn msan_and_tsan_reports_have_a_semantic_class() {
        assert_eq!(
            semantic_class(
                CrashKind::Msan,
                "==14==WARNING: MemorySanitizer: use-of-uninitialized-value"
            )
            .as_deref(),
            Some("use-of-uninitialized-value")
        );
        assert_eq!(
            semantic_class(
                CrashKind::Tsan,
                "WARNING: ThreadSanitizer: data race (pid=45)"
            )
            .as_deref(),
            Some("data-race")
        );
        // A kind without its own report text has no class to compare.
        assert_eq!(semantic_class(CrashKind::Msan, "SIGABRT"), None);
    }
}
