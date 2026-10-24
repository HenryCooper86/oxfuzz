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

fn reference_identity(crash: &Crash, evidence: &CrashReproduction) -> Option<FailureIdentity> {
    let identity = log_identity(evidence.reference_log.as_deref()?)?;
    if crash.casr.is_some()
        || identity.kind != crash.kind
        || identity.signature != crash.stack_signature
        || semantic_class(crash.kind, &crash.summary).as_ref() != Some(&identity.class)
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

fn input_digest(path: &Path) -> Result<String, ClassifiedError> {
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
    Ok(format!("{:x}", Sha256::digest(&bytes)))
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

impl ServiceContainer {
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
        let limits = ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: policy.replay_timeout_secs,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = SandboxOptions {
            workspace_read_only: true,
            image: Some(image.reference().to_owned()),
            ..SandboxOptions::default()
        };
        for (input, observations) in [
            (inputs.0, &mut evidence.original),
            (inputs.1, &mut evidence.candidate),
        ] {
            let command = vec![
                container_input_path(workspace, binary),
                container_input_path(workspace, input),
            ];
            for _ in 0..policy.confirmation_runs {
                let observation = match self
                    .runtime
                    .run_command_opts(&command, workspace, &limits, &sandbox)
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
                };
                observations.push(observation);
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
}
