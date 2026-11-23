//! Harness repair proposals requested from a retained finding.
//!
//! The repair prompt is retained before dispatch and its response after
//! (Engineering Protocol 2.13). The result compiles in the proposal workspace,
//! so it replaces nothing, executes nothing, and carries no approval.

use std::path::Path;
use std::sync::Arc;

use hf_core::crash::Crash;
use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, LlmProvider as _};
use hf_core::types::Message;
use hf_guardrails::Action;
use hf_prompt::{FindingRepairEvidence, FindingRepairReason};
use hf_storage::{
    FindingHarnessRepairCompletion, FindingHarnessRepairOutcome, FindingHarnessRepairRecord, Store,
    MAX_FINDING_HARNESS_REPAIR_BYTES,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::harness::HarnessBuildObserver;
use super::project_identity::select_target_candidate;
use super::target_source::{read_crash_site, read_target_definition};
use super::{require_fuzzing_harness_engine, AiPolicy, LlmProviderBridge, ServiceContainer};
use crate::finding_repair::FindingHarnessRepair;
use crate::triage_disposition::Disposition;

/// The evidence reason for a disposition that may lead to a harness repair.
/// Every other disposition either is a target finding or has no harness claim.
const fn repair_reason(disposition: Disposition) -> Option<FindingRepairReason> {
    match disposition {
        Disposition::HarnessDefect => Some(FindingRepairReason::HarnessFault),
        Disposition::InputIndependentFault => Some(FindingRepairReason::InputIndependent),
        _ => None,
    }
}

/// The most direct retained sanitizer output for this crash.
fn retained_log(crash: &Crash) -> String {
    let controls = crash
        .control_replay
        .as_ref()
        .and_then(|controls| controls.baseline.first())
        .map(|observation| observation.log.as_str());
    let reproduction = crash.reproduction.as_ref().and_then(|evidence| {
        evidence
            .candidate
            .first()
            .map(|observation| observation.log.as_str())
            .filter(|log| !log.trim().is_empty())
            .or(evidence.reference_log.as_deref())
    });
    controls
        .filter(|log| !log.trim().is_empty())
        .or(reproduction)
        .map(str::to_owned)
        .or_else(|| {
            crash
                .casr
                .as_ref()
                .filter(|casr| !casr.stack.is_empty())
                .map(|casr| casr.stack.join("\n"))
        })
        .unwrap_or_else(|| crash.summary.clone())
}

fn bounded_detail(detail: &str) -> &str {
    let mut end = detail
        .len()
        .min(hf_storage::MAX_FINDING_HARNESS_REPAIR_DETAIL_BYTES);
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    &detail[..end]
}

/// Record how a repair finished. The source of truth for a compiled proposal
/// is its harness revision, so a failed audit write is reported, not fatal.
async fn finish(store: &Store, id: Uuid, completion: FindingHarnessRepairCompletion<'_>) {
    let completion = FindingHarnessRepairCompletion {
        detail: bounded_detail(completion.detail),
        ..completion
    };
    if let Err(error) = store
        .complete_finding_harness_repair(id, &completion, chrono::Utc::now())
        .await
    {
        tracing::warn!(repair = %id, %error, "finding repair outcome not retained");
    }
}

impl ServiceContainer {
    /// Ask the model to repair the harness behind one finding, and compile a
    /// changed result as an unpromoted proposal revision.
    ///
    /// Only a harness defect or an input-independent fault qualifies: changing
    /// the harness in response to a target finding would hide that finding.
    ///
    /// # Errors
    /// Returns a validation error for `AiPolicy::Off`, a non-qualifying finding,
    /// or a harness that changed since the finding's run; a provider error when
    /// no model is available; and a harness error when the answer has no
    /// source or does not compile.
    pub async fn finding_harness_repair(
        &self,
        project: &Path,
        crash_id: Uuid,
        max_repairs: usize,
        policy: AiPolicy,
    ) -> Result<FindingHarnessRepair, ClassifiedError> {
        if policy == AiPolicy::Off {
            return Err(ClassifiedError::Validation(
                "a harness repair from a finding is model-only, so an ai policy of `off` cannot \
                 run it"
                    .to_owned(),
            ));
        }
        let store = self.compilation_store()?;
        let item = self.finding_review_for_project(project, crash_id).await?;
        let reason = repair_reason(item.disposition.disposition).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "finding {crash_id} does not point at the harness; changing the harness would \
                 hide it"
            ))
        })?;
        let owner = self.crash_owner_for_project(project, crash_id).await?;
        let (engine, lang) = (item.engine, item.target_language);
        let target = item.target_selector.as_str();
        require_fuzzing_harness_engine(engine, lang)?;
        self.admit_harness_build(project, lang).await?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(
            Action::CompileHarness,
            "finding_harness_repair",
            Some(project),
        )
        .await?;
        let inventory = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inventory.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();
        let _target_revision = self
            .acquire_target_revision(&candidate.project_root, target)
            .await?;
        let active = self.active_harness_locked(project, target, engine).await?;
        let base_source_sha256 = format!("{:x}", Sha256::digest(active.source.as_bytes()));
        if owner.run.harness_rev.as_deref() != Some(base_source_sha256.as_str()) {
            return Err(ClassifiedError::Validation(format!(
                "the harness that produced finding {crash_id} is no longer active"
            )));
        }
        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for harness repair".to_owned())
        })?;

        let log = retained_log(&owner.crash);
        let root = std::fs::canonicalize(&candidate.project_root)
            .map_err(|error| ClassifiedError::Validation(format!("resolve project: {error}")))?;
        let target_definition = read_target_definition(&root, &candidate).map(|definition| {
            hf_prompt::render_target_source_section(
                &definition.relative_file,
                candidate.location.line,
                &definition.excerpt,
            )
        });
        let crash_site = hf_crash::fault_location(&log, owner.crash.casr.as_ref())
            .and_then(|(file, line)| read_crash_site(&root, &file, line))
            .map(|site| {
                hf_prompt::render_crash_site_section(
                    &site.relative_file,
                    site.first_line,
                    site.crash_line,
                    &site.excerpt,
                )
            });
        let kind = format!("{:?}", owner.crash.kind);
        let prompt = hf_harness::render_finding_repair_request(
            &candidate,
            engine,
            &active.source,
            &FindingRepairEvidence {
                reason,
                kind: &kind,
                summary: &owner.crash.summary,
                log: &log,
                target_definition: target_definition.as_deref(),
                crash_site: crash_site.as_deref(),
            },
        );
        if prompt.len() > MAX_FINDING_HARNESS_REPAIR_BYTES {
            return Err(ClassifiedError::Validation(format!(
                "the harness repair prompt is too large to retain ({} bytes)",
                prompt.len()
            )));
        }
        let record = FindingHarnessRepairRecord {
            id: Uuid::new_v4(),
            crash_id,
            run_id: owner.crash.run_id,
            project_root: root.to_string_lossy().into_owned(),
            prompt_version: hf_prompt::FINDING_REPAIR_PROMPT_VERSION,
            base_source_sha256,
            prompt,
            response: None,
            outcome: None,
            detail: None,
            harness_id: None,
            created_at: chrono::Utc::now(),
            completed_at: None,
        };
        store.begin_finding_harness_repair(&record).await?;

        let result = |outcome, detail: &str, harness_id, repairs_used| FindingHarnessRepair {
            repair_id: record.id,
            outcome,
            detail: detail.to_owned(),
            harness_id,
            target: target.to_owned(),
            engine: engine.as_str().to_owned(),
            lang: lang.as_str().to_owned(),
            repairs_used,
        };
        let bridge = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
        let request = ChatRequest::from_messages(vec![Message::user(record.prompt.clone())]);
        let response = match bridge.chat_completion(&request).await {
            Ok(response) => response,
            Err(error) => {
                let detail = format!("the repair call failed: {error}");
                finish(
                    store,
                    record.id,
                    FindingHarnessRepairCompletion {
                        response: None,
                        outcome: FindingHarnessRepairOutcome::Failed,
                        detail: &detail,
                        harness_id: None,
                    },
                )
                .await;
                return Err(ClassifiedError::Provider(detail));
            }
        };
        let text = response.text();
        // An answer too large to retain cannot be used: the source it would
        // produce could not be reconstructed from retained evidence.
        if text.len() > MAX_FINDING_HARNESS_REPAIR_BYTES {
            let detail = "the repair response is too large to retain";
            finish(
                store,
                record.id,
                FindingHarnessRepairCompletion {
                    response: None,
                    outcome: FindingHarnessRepairOutcome::Failed,
                    detail,
                    harness_id: None,
                },
            )
            .await;
            return Err(ClassifiedError::Harness(detail.to_owned()));
        }
        let Some(source) = hf_harness::repaired_source_from_response(text) else {
            let detail = "the repair response contained no fenced code block";
            finish(
                store,
                record.id,
                FindingHarnessRepairCompletion {
                    response: Some(text),
                    outcome: FindingHarnessRepairOutcome::Failed,
                    detail,
                    harness_id: None,
                },
            )
            .await;
            return Err(ClassifiedError::Harness(detail.to_owned()));
        };
        if source.trim() == active.source.trim() {
            let detail = "the model returned the harness unchanged; it found no API misuse to \
                          correct";
            finish(
                store,
                record.id,
                FindingHarnessRepairCompletion {
                    response: Some(text),
                    outcome: FindingHarnessRepairOutcome::Unchanged,
                    detail,
                    harness_id: None,
                },
            )
            .await;
            return Ok(result(
                FindingHarnessRepairOutcome::Unchanged,
                detail,
                None,
                0,
            ));
        }
        let symbol = &candidate.symbol;
        let rejection = if hf_harness::source_defines_symbol(&source, symbol)
            && !hf_harness::source_defines_symbol(&active.source, symbol)
        {
            Some(format!(
                "the repair defines its own copy of the target `{symbol}`, so it would not test \
                 the project's code; it was not compiled"
            ))
        } else if hf_harness::source_calls_symbol(&active.source, symbol)
            && !hf_harness::source_calls_symbol(&source, symbol)
        {
            Some(format!(
                "the repair no longer calls the target `{symbol}`, so it was not compiled"
            ))
        } else {
            None
        };
        if let Some(detail) = rejection {
            finish(
                store,
                record.id,
                FindingHarnessRepairCompletion {
                    response: Some(text),
                    outcome: FindingHarnessRepairOutcome::Rejected,
                    detail: &detail,
                    harness_id: None,
                },
            )
            .await;
            return Ok(result(
                FindingHarnessRepairOutcome::Rejected,
                &detail,
                None,
                0,
            ));
        }
        let compiled = match self
            .prepare_proposal_workspace_locked(project, target)
            .await
        {
            Ok(workspace) => {
                self.compile_source_with_repair_locked(
                    &candidate,
                    target,
                    engine,
                    lang,
                    &workspace,
                    source,
                    max_repairs,
                    active.sanitizer,
                    active.cmplog.is_some(),
                    policy,
                    HarnessBuildObserver::SILENT,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match compiled {
            Ok(outcome) => {
                let detail = "the repair compiled as a proposal; adopt it to review and qualify it";
                finish(
                    store,
                    record.id,
                    FindingHarnessRepairCompletion {
                        response: Some(text),
                        outcome: FindingHarnessRepairOutcome::Proposed,
                        detail,
                        harness_id: Some(outcome.harness_id),
                    },
                )
                .await;
                Ok(result(
                    FindingHarnessRepairOutcome::Proposed,
                    detail,
                    Some(outcome.harness_id),
                    outcome.repairs_used,
                ))
            }
            Err(error) => {
                finish(
                    store,
                    record.id,
                    FindingHarnessRepairCompletion {
                        response: Some(text),
                        outcome: FindingHarnessRepairOutcome::Failed,
                        detail: &format!("the repair did not compile: {error}"),
                        harness_id: None,
                    },
                )
                .await;
                Err(error)
            }
        }
    }
}
