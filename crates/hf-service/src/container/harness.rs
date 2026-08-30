//! Harness authoring, sandbox qualification, and promotion.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::build::BuildContext;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus};
use hf_core::provider::{ChatRequest, ChatResponse, FinishReason, LlmProvider as _};
use hf_core::target::{Sanitizer, TargetCandidate, TargetLanguage};
use hf_core::types::Message;
use hf_guardrails::Action;
use hf_storage::{HarnessAiReviewRecord, RunKind, RunRecord, RunStatus, Store};
use uuid::Uuid;

use super::coverage_cache::frontier_refine_lines;
use super::crash_inputs::is_regular_file;
use super::guards::{ensure_run_journal_durable, PersistedRunGuard};
use super::harness_workspace::{
    copy_project_sources, generate_target_seeds, harness_binary_name, read_current_harness_source,
    write_current_harness_id, write_current_harness_source,
};
use super::output_budget::{
    output_budget_status, OutputBudget, MAX_RUN_OUTPUT_BYTES, MAX_RUN_OUTPUT_ENTRIES,
};
use super::project_identity::{
    canonical_project_root, select_target_candidate, stored_project_matches,
};
use super::staging::{
    qualification_evidence, resolve_run_sandbox_image, retain_run_context, run_context_digests,
    sha256_file, stage_run_artifacts, verify_run_artifacts,
};
use super::workspace::{
    prepare_configured_workspace_root, workspace_dir, workspace_relative_record,
};
use super::{
    heuristic_draft, require_fuzzing_harness_engine, resolve_internal_run, AiPolicy,
    CompileOutcome, HarnessGenOutcome, LlmProviderBridge, SeedEntry, ServiceContainer,
    SMOKE_FUZZ_SECS,
};

/// Maximum complete source revision accepted by the mandatory model review.
const MAX_HARNESS_REVIEW_SOURCE_BYTES: usize = 64 * 1024;
/// Maximum normalized provider response retained as review evidence.
const MAX_HARNESS_REVIEW_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HARNESS_REVIEW_REASONS: usize = 32;
const MAX_HARNESS_REVIEW_REASON_BYTES: usize = 1024;
const HARNESS_AI_REVIEW_SCHEMA_VERSION: u32 = 1;
const HARNESS_AI_REVIEW_PROMPT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessPreExecutionOpinion {
    exercises_target: bool,
    safe_to_execute: bool,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessAiReviewEvidence {
    schema_version: u32,
    prompt_version: u32,
    target: String,
    opinion: HarnessPreExecutionOpinion,
    response: ChatResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HarnessReviewOutcome {
    pub harness_id: Uuid,
    pub source_sha256: String,
    pub binary_sha256: String,
}

#[derive(Debug, Clone, Copy)]
struct ExactPromotion<'a> {
    harness_id: Uuid,
    source_sha256: &'a str,
    binary_sha256: &'a str,
}

fn validate_harness_review_opinion(
    opinion: &HarnessPreExecutionOpinion,
) -> Result<(), ClassifiedError> {
    if opinion.reasons.is_empty()
        || opinion.reasons.len() > MAX_HARNESS_REVIEW_REASONS
        || opinion.reasons.iter().any(|reason| {
            reason.trim().is_empty() || reason.len() > MAX_HARNESS_REVIEW_REASON_BYTES
        })
    {
        return Err(ClassifiedError::Provider(
            "LLM harness review returned invalid or unbounded reasons".to_owned(),
        ));
    }
    Ok(())
}

fn enforce_positive_harness_review(
    opinion: &HarnessPreExecutionOpinion,
) -> Result<(), ClassifiedError> {
    validate_harness_review_opinion(opinion)?;
    if opinion.exercises_target && opinion.safe_to_execute {
        return Ok(());
    }
    Err(ClassifiedError::Harness(format!(
        "LLM review refused harness execution: {}",
        opinion.reasons.join("; ")
    )))
}

fn require_expected_harness_id(
    harness: &Harness,
    expected_harness_id: Option<Uuid>,
) -> Result<(), ClassifiedError> {
    if expected_harness_id.is_some_and(|expected| expected != harness.id) {
        return Err(ClassifiedError::Validation(
            "active harness revision does not match the requested harness id".to_owned(),
        ));
    }
    Ok(())
}

fn require_expected_promotion(
    harness: &Harness,
    expected: Option<ExactPromotion<'_>>,
) -> Result<(), ClassifiedError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    require_expected_harness_id(harness, Some(expected.harness_id))?;
    let (_, source_sha256, binary_sha256) = qualification_evidence(harness)?;
    if source_sha256 != expected.source_sha256 || binary_sha256 != expected.binary_sha256 {
        return Err(ClassifiedError::Validation(
            "active smoke qualification does not match the requested source and binary digests"
                .to_owned(),
        ));
    }
    Ok(())
}

/// The project's compile context for prompt rendering, or `None` when it ships
/// no database or the database cannot be read.
///
/// Drafting is best-effort and never fails, so an unreadable database degrades
/// to a prompt without build context. `project_compile_flags` still fails the
/// build for that same project, which is where an operator needs to see it.
#[cfg(feature = "build-context")]
fn project_build_context(container: &ServiceContainer, project: &Path) -> Option<BuildContext> {
    match container.resolve_build_context(project) {
        Ok(context) => context,
        Err(error) => {
            tracing::warn!(
                "compile database for {} is unusable ({error}); drafting without build context",
                project.display()
            );
            None
        }
    }
}

/// Compile-database support is not built in, so prompts carry no build context.
#[cfg(not(feature = "build-context"))]
fn project_build_context(_container: &ServiceContainer, _project: &Path) -> Option<BuildContext> {
    None
}

/// The container path the sandbox stages the project at. Compile-database
/// include directories are rewritten against it.
#[cfg(feature = "build-context")]
const CONTAINER_WORKSPACE: &str = "/work";

/// Project-derived compile flags for a harness build, empty when the project
/// ships no compile database.
///
/// A broken database propagates rather than degrading to no flags: a project
/// that has one and cannot parse it is misconfigured, and building without the
/// flags would fail later with a confusing missing-header error instead.
#[cfg(feature = "build-context")]
fn project_compile_flags(
    container: &ServiceContainer,
    project: &Path,
) -> Result<Vec<String>, ClassifiedError> {
    Ok(container
        .resolve_build_context(project)?
        .map(|context| {
            hf_discovery::build_context::staged_compile_flags(
                &context,
                project,
                CONTAINER_WORKSPACE,
            )
        })
        .unwrap_or_default())
}

/// Compile-database support is not built in, so a harness compiles with the
/// engine arguments alone.
#[cfg(not(feature = "build-context"))]
fn project_compile_flags(_container: &ServiceContainer, _project: &Path) -> Vec<String> {
    Vec::new()
}

impl ServiceContainer {
    async fn harness_review_locked(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        language: TargetLanguage,
        expected_harness_id: Option<Uuid>,
    ) -> Result<(Harness, HarnessReviewOutcome), ClassifiedError> {
        let harness = self.active_harness_locked(project, target, engine).await?;
        require_expected_harness_id(&harness, expected_harness_id)?;
        if harness.language != language {
            return Err(ClassifiedError::Validation(format!(
                "active harness language is {:?}, not {language:?}",
                harness.language
            )));
        }
        if !matches!(
            harness.status,
            HarnessStatus::Compiled | HarnessStatus::SmokePassed | HarnessStatus::Promoted
        ) {
            return Err(ClassifiedError::Validation(format!(
                "only a compiled harness can be reviewed; active status is {:?}",
                harness.status
            )));
        }
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let binary_name = harness_binary_name(target);
        let binary = workspace_dir(project, target).join(&binary_name);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }
        let binary_sha256 = sha256_file(&binary)?;
        self.require_harness_ai_review(store, &harness, target, &binary_sha256)
            .await?;
        Ok((
            harness.clone(),
            HarnessReviewOutcome {
                harness_id: harness.id,
                source_sha256: sha256_hex(harness.source.as_bytes()),
                binary_sha256,
            },
        ))
    }

    pub(crate) async fn harness_review_exact(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        language: TargetLanguage,
        expected_harness_id: Uuid,
    ) -> Result<HarnessReviewOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let _target_revision = self
            .acquire_target_revision(project_root.as_path(), target)
            .await?;
        let (_, review) = self
            .harness_review_locked(
                project_root.as_path(),
                target,
                engine,
                language,
                Some(expected_harness_id),
            )
            .await?;
        Ok(review)
    }

    async fn require_harness_ai_review(
        &self,
        store: &Store,
        harness: &Harness,
        target: &str,
        binary_sha256: &str,
    ) -> Result<(), ClassifiedError> {
        let source_sha256 = sha256_hex(harness.source.as_bytes());
        if let Some(record) = store.harness_ai_review(harness.id).await? {
            if record.source_sha256 != source_sha256 {
                return Err(ClassifiedError::Storage(format!(
                    "stored LLM review for harness {} belongs to a different source digest",
                    harness.id
                )));
            }
            if record.binary_sha256 != binary_sha256 {
                return Err(ClassifiedError::Validation(format!(
                    "compiled binary digest no longer matches the LLM review for harness {}",
                    harness.id
                )));
            }
            let evidence: HarnessAiReviewEvidence = serde_json::from_str(&record.review_json)
                .map_err(|error| {
                    ClassifiedError::Storage(format!(
                        "stored LLM review for harness {} is malformed: {error}",
                        harness.id
                    ))
                })?;
            if evidence.schema_version != HARNESS_AI_REVIEW_SCHEMA_VERSION
                || evidence.prompt_version != HARNESS_AI_REVIEW_PROMPT_VERSION
                || evidence.target != target
                || evidence.response.finish_reason != FinishReason::Stop
            {
                return Err(ClassifiedError::Storage(format!(
                    "stored LLM review for harness {} has invalid provenance",
                    harness.id
                )));
            }
            let response_opinion: HarnessPreExecutionOpinion =
                serde_json::from_str(evidence.response.text().trim()).map_err(|error| {
                    ClassifiedError::Storage(format!(
                        "stored LLM review response for harness {} is malformed: {error}",
                        harness.id
                    ))
                })?;
            if response_opinion != evidence.opinion {
                return Err(ClassifiedError::Storage(format!(
                    "stored LLM review for harness {} has inconsistent evidence",
                    harness.id
                )));
            }
            return enforce_positive_harness_review(&evidence.opinion);
        }

        if harness.source.len() > MAX_HARNESS_REVIEW_SOURCE_BYTES {
            return Err(ClassifiedError::Validation(format!(
                "harness source is {} bytes; the exact-source LLM review limit is {} bytes",
                harness.source.len(),
                MAX_HARNESS_REVIEW_SOURCE_BYTES
            )));
        }
        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider(
                "harness execution requires an independent LLM review, but no LLM provider is configured"
                    .to_owned(),
            )
        })?;
        let prompt = hf_prompt::render_harness_pre_execution_review_prompt(target, &harness.source);
        let provider = LlmProviderBridge::new(pool).with_diagnostics(
            Arc::clone(&self.diagnostics),
            "harness_pre_execution_review",
        );
        let request = ChatRequest::from_messages(vec![Message::user(prompt)]);
        let response = provider.chat_completion(&request).await.map_err(|error| {
            ClassifiedError::Provider(format!("LLM harness review failed: {error}"))
        })?;
        if response.finish_reason != FinishReason::Stop {
            return Err(ClassifiedError::Provider(format!(
                "LLM harness review did not complete normally: {:?}",
                response.finish_reason
            )));
        }
        let serialized_response = serde_json::to_vec(&response)
            .map_err(|error| ClassifiedError::Provider(error.to_string()))?;
        if serialized_response.len() > MAX_HARNESS_REVIEW_RESPONSE_BYTES {
            return Err(ClassifiedError::Provider(format!(
                "LLM harness review response exceeded {MAX_HARNESS_REVIEW_RESPONSE_BYTES} bytes"
            )));
        }
        let opinion: HarnessPreExecutionOpinion = serde_json::from_str(response.text().trim())
            .map_err(|error| {
                ClassifiedError::Provider(format!(
                    "LLM harness review returned malformed JSON: {error}"
                ))
            })?;
        validate_harness_review_opinion(&opinion)?;
        let evidence = HarnessAiReviewEvidence {
            schema_version: HARNESS_AI_REVIEW_SCHEMA_VERSION,
            prompt_version: HARNESS_AI_REVIEW_PROMPT_VERSION,
            target: target.to_owned(),
            opinion: opinion.clone(),
            response,
        };
        let review = HarnessAiReviewRecord {
            harness_id: harness.id,
            source_sha256,
            binary_sha256: binary_sha256.to_owned(),
            review_json: serde_json::to_string(&evidence)
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?,
            reviewed_at: Utc::now(),
        };
        store.record_harness_ai_review(&review).await?;
        enforce_positive_harness_review(&opinion)
    }

    /// Resolve a target symbol to its discovered candidate id.
    ///
    /// Unknown symbols are rejected rather than being attached to the nil UUID.
    /// Shared by harness compilation and triage so persisted records key off the
    /// same canonical project and target identity.
    async fn resolve_target_id(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            let project_targets: Vec<TargetCandidate> = targets
                .into_iter()
                .filter(|candidate| {
                    stored_project_matches(&candidate.project_root, &project)
                        && candidate.language == lang
                })
                .collect();
            if let Some(candidate) = select_target_candidate(&project_targets, target)? {
                return Ok(candidate.id);
            }
        }
        let inventory = self.discover(&project, lang).await?;
        select_target_candidate(&inventory.candidates, target)?
            .map(|c| c.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    /// Draft the harness source for a candidate: LLM-authored when a provider is
    /// configured, otherwise the heuristic template. Never fails -- an LLM error
    /// degrades to the heuristic draft so generation can proceed.
    async fn draft_harness_source(
        &self,
        project: &Path,
        candidate: &TargetCandidate,
        engine: EngineKind,
    ) -> String {
        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            let related = crate::knowledge::harness_related_context(project, candidate);
            let build = project_build_context(self, project);
            match hf_harness::draft_with_context(
                candidate,
                engine,
                &related,
                build.as_ref(),
                Box::new(provider),
            )
            .await
            {
                Ok(draft) => return draft.source,
                Err(e) => tracing::warn!(
                    "LLM harness draft for '{}' failed ({e}); using heuristic draft",
                    candidate.symbol
                ),
            }
        }
        heuristic_draft(candidate, engine).source
    }

    /// Compile `initial_source` in the sandbox, and on a compile failure feed the
    /// diagnostics back to the LLM for up to `max_repairs` corrective passes.
    /// Shared by harness generation and coverage-guided refinement.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Harness` if the harness still fails to build
    /// after `max_repairs` attempts, or an infrastructure error from the sandbox.
    /// One LLM repair pass over failing harness source.
    ///
    /// `None` when there is no provider configured to repair with, or the
    /// repair call itself failed; either makes the current failure terminal.
    /// Shared by the lint gate and the compiler-failure path so both feed the
    /// model the same way.
    async fn repair_harness_source(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        source: &str,
        diagnostics: &str,
    ) -> Option<String> {
        let pool = self.provider_pool()?;
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
        match hf_harness::repair(candidate, engine, source, diagnostics, Box::new(provider)).await {
            Ok(draft) => Some(draft.source),
            Err(error) => {
                tracing::warn!("harness repair for '{}' failed: {error}", candidate.symbol);
                None
            }
        }
    }

    async fn compile_source_with_repair(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let target = &candidate.symbol;
        let _target_revision = self
            .acquire_target_revision(&candidate.project_root, target)
            .await?;
        self.compile_source_with_repair_locked(
            candidate,
            engine,
            lang,
            workspace,
            initial_source,
            max_repairs,
        )
        .await
    }

    /// Compile a replacement while the caller holds workspace-operation followed
    /// by target-revision leases for the complete read/replace sequence.
    async fn compile_source_with_repair_locked(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let target = &candidate.symbol;
        let mut source = initial_source;
        let mut repairs_used = 0usize;
        let mut last_diagnostics = String::new();

        loop {
            let lint = hf_harness::lint_harness_source(&source, lang);
            if hf_harness::has_blocking_finding(&lint) {
                // A lint error is a build failure the compiler would have
                // accepted. Route it into the same repair path, skipping the
                // container round-trip that would have produced a clean build
                // of an unusable harness.
                last_diagnostics = hf_harness::render_findings(&lint);
                match self
                    .repair_harness_source(candidate, engine, &source, &last_diagnostics)
                    .await
                {
                    Some(repaired) if repairs_used < max_repairs => {
                        source = repaired;
                        repairs_used += 1;
                        continue;
                    }
                    _ => break,
                }
            }
            let mut build_cmd =
                hf_harness::build_command(engine, lang, &harness_binary_name(target));
            build_cmd.output = PathBuf::from(harness_binary_name(target));
            #[cfg(feature = "build-context")]
            {
                build_cmd.extra_flags = project_compile_flags(self, &candidate.project_root)?;
            }
            #[cfg(not(feature = "build-context"))]
            {
                build_cmd.extra_flags = project_compile_flags(self, &candidate.project_root);
            }
            let harness = Harness {
                id: Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: source.clone(),
                language: lang,
                build_cmd,
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            match hf_harness::try_compile(harness, self.runtime.as_ref(), workspace).await? {
                hf_harness::CompileResult::Ok(compiled) => {
                    if let Some(store) = &self.store {
                        store
                            .upsert_harness(&compiled)
                            .await
                            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
                    }
                    write_current_harness_source(workspace, &compiled.source)?;
                    // Point `harness.active` at the freshly-compiled harness, as
                    // `harness_compile` does. Without this, a repair/refine that
                    // rewrites the source leaves the marker on the previous id, so
                    // `active_harness` later reads a stale id whose source no
                    // longer matches and hard-errors ("compile it again") even
                    // though the refined harness built cleanly.
                    write_current_harness_id(workspace, compiled.id)?;
                    let binary_name = compiled
                        .build_cmd
                        .output
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(target)
                        .to_string();
                    return Ok(HarnessGenOutcome {
                        status: compiled.status,
                        binary_name,
                        workspace: workspace.to_path_buf(),
                        repairs_used,
                        lint,
                    });
                }
                hf_harness::CompileResult::Failed(failure) => {
                    last_diagnostics = failure.diagnostics();
                    if repairs_used >= max_repairs {
                        break;
                    }
                    match self
                        .repair_harness_source(candidate, engine, &source, &last_diagnostics)
                        .await
                    {
                        Some(repaired) => {
                            source = repaired;
                            repairs_used += 1;
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }

        let diag: String = last_diagnostics.chars().take(600).collect();
        Err(ClassifiedError::Harness(format!(
            "harness for '{target}' failed to build after {repairs_used} repair attempt(s): {diag}"
        )))
    }

    /// Generated harnesses that need human review or promotion.
    pub async fn harness_review_queue(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Result<Vec<crate::workbench::HarnessReviewItem>, ClassifiedError> {
        crate::workbench::harness_review_queue(self.store.as_deref(), project, target).await
    }

    /// Draft a harness for a target using the LLM provider pool.
    ///
    /// Falls back to a heuristic template when no provider is configured so
    /// the GUI still produces a draft without an API key.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the LLM call fails or the target is not
    /// found.
    pub async fn harness_draft(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<HarnessDraft, ClassifiedError> {
        self.harness_draft_with_policy(project, target, engine, lang, AiPolicy::Auto)
            .await
    }

    /// Draft a harness under an explicit [`AiPolicy`].
    ///
    /// The generator is an operator decision, not an accident of whether a key
    /// happens to be exported: the model and the template produce materially
    /// different harnesses, so a caller can demand one, refuse the other, or
    /// accept either. The draft records which one answered
    /// ([`HarnessDraft::generator`]).
    ///
    /// # Errors
    /// Returns a validation error for an engine/language that cannot carry a
    /// generated harness, and -- under [`AiPolicy::Require`] -- a provider error
    /// when no provider is configured or the model call fails, rather than
    /// substituting a template harness the caller said it did not want.
    pub async fn harness_draft_with_policy(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        policy: AiPolicy,
    ) -> Result<HarnessDraft, ClassifiedError> {
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::DraftHarness, "harness_draft", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        if policy == AiPolicy::Off {
            return Ok(heuristic_draft(&candidate, engine));
        }
        let Some(pool) = self.provider_pool() else {
            if policy == AiPolicy::Require {
                return Err(ClassifiedError::Provider(
                    "an AI harness was required but no LLM provider is configured; \
                     set HF_PROVIDER_API_KEY, or pass the heuristic generator instead"
                        .to_owned(),
                ));
            }
            // No LLM configured: generate a heuristic draft so the GUI still
            // produces something useful.
            return Ok(heuristic_draft(&candidate, engine));
        };
        {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            // Augment the prompt with related project context when this
            // project has been indexed; empty on any failure, which renders
            // the un-augmented prompt.
            let related = crate::knowledge::harness_related_context(project, &candidate);
            let build = project_build_context(self, project);
            match hf_harness::draft_with_context(
                &candidate,
                engine,
                &related,
                build.as_ref(),
                Box::new(provider),
            )
            .await
            {
                Ok(draft) => Ok(draft),
                // The LLM is configured but the call failed (provider down,
                // auth, bad model, network). Under `Auto` degrade to the
                // heuristic draft so the pipeline still produces a usable
                // harness; under `Require` the caller said a template is not an
                // acceptable substitute, so the failure surfaces instead of
                // being quietly answered by a different generator.
                Err(e) if policy == AiPolicy::Require => Err(ClassifiedError::Provider(format!(
                    "an AI harness was required but the model call failed: {e}"
                ))),
                Err(e) => {
                    tracing::warn!(
                        "LLM harness draft for '{target}' failed ({e}); \
                         falling back to heuristic draft"
                    );
                    Ok(heuristic_draft(&candidate, engine))
                }
            }
        }
    }

    /// Compile a harness in the sandbox via `hf-runtime`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the build command fails.
    pub async fn harness_compile(
        &self,
        source: String,
        project: &Path,
        engine: EngineKind,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let _target_revision = self.acquire_target_revision(project, target).await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_compile", Some(project))
            .await?;
        // Cheapest check first: a harness that terminates the process, spawns a
        // shell, or opens a socket is rejected before a container starts.
        let lint = hf_harness::lint_harness_source(&source, lang);
        if hf_harness::has_blocking_finding(&lint) {
            return Err(ClassifiedError::Harness(format!(
                "harness lint failed:\n{}",
                hf_harness::render_findings(&lint)
            )));
        }
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let mut build_cmd = hf_harness::build_command(engine, lang, &harness_binary_name(target));
        #[cfg(feature = "build-context")]
        {
            build_cmd.extra_flags = project_compile_flags(self, project)?;
        }
        #[cfg(not(feature = "build-context"))]
        {
            build_cmd.extra_flags = project_compile_flags(self, project);
        }
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: self.resolve_target_id(project, target, lang).await?,
            engine,
            source,
            language: lang,
            build_cmd,
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Draft,
            smoke_run: None,
        };
        let compiled = hf_harness::compile(harness, self.runtime.as_ref(), &workspace).await?;
        // Persist the compiled harness so it survives restarts and the
        // Harness/list views can show it before pointing the active marker at
        // the record. Qualification is safety-critical, so a configured store
        // must durably accept the record.
        if let Some(store) = &self.store {
            store
                .upsert_harness(&compiled)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        }
        write_current_harness_source(&workspace, &compiled.source)?;
        write_current_harness_id(&workspace, compiled.id)?;
        Ok(CompileOutcome {
            harness_id: compiled.id,
            status: compiled.status,
            binary_name: compiled
                .build_cmd
                .output
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(target)
                .to_string(),
            workspace,
            lint,
        })
    }

    /// Generate a harness end to end with automatic repair: draft -> compile,
    /// and on a compile failure feed the diagnostics back to the LLM for up to
    /// `max_repairs` corrective passes before giving up.
    ///
    /// This is the recommended entry point over calling `harness_draft` +
    /// `harness_compile` separately: a large fraction of first-draft harnesses
    /// fail to compile, and abandoning the target on the first failure wastes a
    /// discovered, potentially high-value target. Repair recovers many of them.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown,
    /// `ClassifiedError::Harness` if the harness still fails to build after
    /// `max_repairs` attempts, or an infrastructure error from the sandbox.
    pub async fn harness_generate(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_generate", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();
        let _target_revision = self
            .acquire_target_revision(&candidate.project_root, target)
            .await?;

        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let source = self.draft_harness_source(project, &candidate, engine).await;
        self.compile_source_with_repair_locked(
            &candidate,
            engine,
            lang,
            &workspace,
            source,
            max_repairs,
        )
        .await
    }

    /// Coverage-guided harness refinement: when coverage has stagnated, ask the
    /// LLM to reshape the current harness so the fuzzer reaches the target's
    /// still-uncovered reachable functions, then compile the result (with the
    /// same auto-repair loop as generation).
    ///
    /// Recomputes coverage to determine which reachable functions are still
    /// uncovered, so the model gets a concrete goal rather than "improve this".
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown or has no
    /// current harness, `ClassifiedError::Provider` if no LLM is configured, or
    /// an error from the refine/compile steps.
    pub async fn harness_refine(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_refine", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();
        let _target_revision = self
            .acquire_target_revision(&candidate.project_root, target)
            .await?;

        let workspace = workspace_dir(project, target);
        let current_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no current harness for '{target}' to refine; generate one first"
            ))
        })?;

        // Prefer the dynamic llvm-cov frontier (uncovered code with file:line
        // locations) so the refine prompt points the LLM at concrete gaps. Fall
        // back to the static reachable-minus-covered names when no source
        // coverage frontier is available (non-C targets, tooling missing) --
        // both accessors early-return without running the pipeline for a
        // non-C target, so the fallback costs nothing extra.
        let frontier = self.coverage_uncovered_locked(project, target).await;
        let uncovered: Vec<String> = if frontier.is_empty() {
            let covered: std::collections::HashSet<String> = self
                .coverage_functions_locked(project, target)
                .await
                .into_iter()
                .collect();
            candidate
                .reachable_functions
                .iter()
                .filter(|f| !covered.contains(*f))
                .cloned()
                .collect()
        } else {
            frontier_refine_lines(&candidate.reachable_functions, &frontier)
        };

        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for refinement".to_owned())
        })?;
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_refine");
        let refined = hf_harness::refine(
            &candidate,
            engine,
            &current_source,
            &uncovered,
            Box::new(provider),
        )
        .await?;

        self.compile_source_with_repair_locked(
            &candidate,
            engine,
            lang,
            &workspace,
            refined.source,
            max_repairs,
        )
        .await
    }

    /// Run a short smoke fuzz (60 seconds, clamped to the configured campaign
    /// ceiling) on the active, persisted harness revision and durably record
    /// its qualification evidence.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the binary is missing or the smoke run
    /// finds zero execs/sec.
    pub async fn harness_smoke(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<crate::verification::SmokeOutcome, ClassifiedError> {
        let harness = self.active_harness(project, target, engine).await?;
        self.harness_smoke_exact(project, target, engine, lang, harness.id)
            .await
    }

    pub(crate) async fn harness_smoke_exact(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        expected_harness_id: Uuid,
    ) -> Result<crate::verification::SmokeOutcome, ClassifiedError> {
        let review = self
            .harness_review_exact(project, target, engine, lang, expected_harness_id)
            .await?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let _target_revision = self
            .acquire_target_revision(project_root.as_path(), target)
            .await?;
        self.harness_smoke_locked(
            project_root.as_path(),
            target,
            engine,
            lang,
            expected_harness_id,
            review,
        )
        .await
    }

    async fn harness_smoke_locked(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        expected_harness_id: Uuid,
        review: HarnessReviewOutcome,
    ) -> Result<crate::verification::SmokeOutcome, ClassifiedError> {
        let resolved = resolve_internal_run(engine, SMOKE_FUZZ_SECS)?;
        if !engine.supports_language(lang) {
            return Err(ClassifiedError::Validation(format!(
                "fuzzing engine '{}' does not support {lang:?} harnesses",
                engine.as_str()
            )));
        }
        let workspace = workspace_dir(project, target);
        let harness = self.active_harness_locked(project, target, engine).await?;
        require_expected_harness_id(&harness, Some(expected_harness_id))?;
        if harness.language != lang {
            return Err(ClassifiedError::Validation(format!(
                "active harness language is {:?}, not {lang:?}",
                harness.language
            )));
        }
        if !matches!(
            harness.status,
            HarnessStatus::Compiled | HarnessStatus::SmokePassed | HarnessStatus::Promoted
        ) {
            return Err(ClassifiedError::Validation(format!(
                "only a compiled harness can be smoke-qualified; active status is {:?}",
                harness.status
            )));
        }
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let binary_name = harness_binary_name(target);
        let binary = workspace.join(&binary_name);
        let source_path = workspace.join("harness.source");
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }
        let reviewed_binary_sha256 = review.binary_sha256.clone();
        if review.harness_id != harness.id
            || review.source_sha256 != sha256_hex(harness.source.as_bytes())
            || !is_regular_file(&source_path)
            || sha256_file(&source_path)? != review.source_sha256
            || sha256_file(&binary)? != reviewed_binary_sha256
        {
            return Err(ClassifiedError::Validation(
                "compiled binary digest changed after LLM review; compile and review the harness again"
                    .to_owned(),
            ));
        }
        self.authorize_recorded(Action::RunHarness, "harness_smoke", Some(project))
            .await?;

        // Allocate the run identity before execution so its immutable inputs and
        // every finding are owned by one durable evidence directory.
        let mut smoke_config = FuzzRunConfig {
            harness_id: harness.id,
            engine: resolved.engine,
            duration: Some(std::time::Duration::from_secs(resolved.duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(workspace.join("corpus")),
            sanitizer: harness.sanitizer,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        };
        let mut smoke_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            None,
            Utc::now(),
        );
        // Persist the deterministic seed with the run config so the smoke run
        // is reproducible, exactly like a campaign run.
        smoke_config.seed = Some(hf_engine::seed::derive_run_seed(smoke_record.id));
        smoke_record.config = Some(smoke_config.clone());
        smoke_record.kind = RunKind::Smoke;
        let sandbox_image = resolve_run_sandbox_image(self.runtime.as_ref()).await?;
        let context = run_context_digests(&workspace, sandbox_image.sha256())?;
        retain_run_context(&mut smoke_record, context);
        let artifacts = stage_run_artifacts(&workspace, smoke_record.id, &harness.source, &binary)?;
        if artifacts.binary_sha256 != reviewed_binary_sha256 {
            if let Some(run_root) = artifacts.output_host.parent() {
                // Best-effort cleanup only; no run record references this
                // pre-execution staging directory.
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Validation(
                "compiled binary digest changed after LLM review; compile and review the harness again"
                    .to_owned(),
            ));
        }
        smoke_record.status = RunStatus::Running;
        smoke_record.harness_rev = Some(artifacts.source_sha256.clone());
        smoke_record.binary_rev = Some(artifacts.binary_sha256.clone());
        smoke_record.evidence_dir = Some(workspace_relative_record(&artifacts.output_relative));
        if let Err(error) = store.insert_run(&smoke_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        // Journal the smoke run like a campaign run. Without this, a process
        // kill/crash during the ~60s smoke window leaves a permanent `Running`
        // row: clear_all_runs and delete_run both reject a run with no crash
        // evidence, so that orphan makes clear_all_runs fail forever and cannot
        // be removed via the service API. Journaling lets bootstrap reconcile it
        // to Failed on the next launch, exactly like a full run.
        self.run_journal
            .open_run(smoke_record.id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            smoke_record.id,
        );
        if let Err(error) = store
            .set_run_harness_source(smoke_record.id, &harness.source)
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        if let Err(error) = verify_run_artifacts(&artifacts) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let active = self.active_harness_locked(project, target, engine).await?;
        require_expected_harness_id(&active, Some(expected_harness_id))?;
        if sha256_file(&source_path)? != review.source_sha256
            || sha256_file(&binary)? != review.binary_sha256
        {
            return Err(ClassifiedError::Validation(
                "active harness artifacts changed after LLM review; compile and review the harness again"
                    .to_owned(),
            ));
        }
        let mut staged_harness = harness;
        staged_harness.build_cmd.output = artifacts.binary_host.clone();
        let mut smoked = match hf_harness::smoke_fuzz_in_paths_with_config_and_sandbox_image(
            staged_harness,
            self.runtime.as_ref(),
            &workspace,
            &artifacts.corpus_relative,
            &artifacts.output_relative,
            &smoke_config,
            Some(sandbox_image.reference().to_owned()),
        )
        .await
        {
            Ok(smoked) => smoked,
            Err(error) => {
                let _ = store
                    .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                return Err(error);
            }
        };
        // The runtime needs the staged artifact path, but that path is run
        // specific rather than part of the compiled harness revision. Persist
        // the original build identity when smoke advances its status.
        smoked.build_cmd = active.build_cmd;
        // Fail smoke only on a definite overflow; a transient scan race must not
        // fail a valid smoke run (mirrors the campaign monitor).
        if output_budget_status(
            &artifacts.output_host,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            64 * 1024 * 1024,
        ) == OutputBudget::Exceeded
            || output_budget_status(
                &artifacts.corpus_host,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            ) == OutputBudget::Exceeded
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Sandbox(
                "smoke corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let Some(summary) = smoked.smoke_run.as_mut() else {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Harness(
                "smoke run produced no summary".to_owned(),
            ));
        };
        summary.source_sha256 = Some(artifacts.source_sha256.clone());
        summary.binary_sha256 = Some(artifacts.binary_sha256.clone());
        summary.run_id = Some(smoke_record.id);
        let summary = summary.clone();
        if let Err(error) = store
            .set_run_stats(
                smoke_record.id,
                0,
                summary.execs_per_sec,
                u64::from(summary.crashes),
            )
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        store
            .set_run_status(smoke_record.id, RunStatus::Done, Some(Utc::now()))
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        store
            .upsert_harness(&smoked)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        // Close the journal entry on success before disarming the guard, so a
        // cleanly-completed smoke run is not reconciled to Failed on restart.
        self.run_journal.close_run(smoke_record.id);
        persisted_run.disarm();
        // Deterministic self-verification (grok-build lesson L2): pair the summary
        // with a verdict so every presentation layer surfaces a hollow pass -- a
        // harness that compiled and "passed" yet never drove the target -- instead
        // of re-deriving that judgment. Observation only; it changes no control flow.
        let verdict = crate::verification::assess_harness_smoke(&summary, smoked.status);
        Ok(crate::verification::SmokeOutcome { summary, verdict })
    }

    /// Promote the active harness after a clean persisted smoke run. Calling
    /// this method is the explicit human approval boundary used by every
    /// presentation layer; agents and schedulers never call it implicitly.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the active revision has not completed a
    /// crash-free smoke run or its qualification record cannot be persisted.
    pub async fn harness_promote(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let harness = self.active_harness(project, target, engine).await?;
        let (_, source_sha256, binary_sha256) = qualification_evidence(&harness)?;
        self.harness_promote_exact(
            project,
            target,
            engine,
            harness.id,
            source_sha256,
            binary_sha256,
        )
        .await
    }

    pub(crate) async fn harness_promote_exact(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        expected_harness_id: Uuid,
        expected_source_sha256: &str,
        expected_binary_sha256: &str,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let _target_revision = self
            .acquire_target_revision(project_root.as_path(), target)
            .await?;
        self.harness_promote_locked(
            project_root.as_path(),
            target,
            engine,
            Some(ExactPromotion {
                harness_id: expected_harness_id,
                source_sha256: expected_source_sha256,
                binary_sha256: expected_binary_sha256,
            }),
        )
        .await
    }

    async fn harness_promote_locked(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        expected: Option<ExactPromotion<'_>>,
    ) -> Result<Harness, ClassifiedError> {
        let harness = self.active_harness_locked(project, target, engine).await?;
        require_expected_promotion(&harness, expected)?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness '{target}' has no persisted smoke evidence; run smoke qualification first"
            ))
        })?;
        if harness.status != HarnessStatus::SmokePassed || !smoke.passed {
            return Err(ClassifiedError::Validation(format!(
                "harness '{target}' cannot be promoted until a crash-free smoke run passes"
            )));
        }
        self.verify_harness_qualification_locked(project, target, &harness)
            .await?;
        // Reload immediately before the persistence mutation so a direct caller
        // cannot promote a revision replaced while qualification was checked.
        let mut harness = self.active_harness_locked(project, target, engine).await?;
        require_expected_promotion(&harness, expected)?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness '{target}' has no persisted smoke evidence; run smoke qualification first"
            ))
        })?;
        if harness.status != HarnessStatus::SmokePassed || !smoke.passed {
            return Err(ClassifiedError::Validation(format!(
                "harness '{target}' cannot be promoted until a crash-free smoke run passes"
            )));
        }
        let (_, source_sha256, binary_sha256) = qualification_evidence(&harness)?;
        let source_sha256 = source_sha256.to_owned();
        let binary_sha256 = binary_sha256.to_owned();
        harness.status = HarnessStatus::Promoted;
        self.persist_clean_harness_promotion(&harness, &source_sha256, &binary_sha256)
            .await?;
        Ok(harness)
    }

    async fn persist_clean_harness_promotion(
        &self,
        harness: &Harness,
        source_sha256: &str,
        binary_sha256: &str,
    ) -> Result<(), ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".to_owned(),
            )
        })?;
        store
            .promote_harness_with_approval(
                harness,
                hf_storage::HarnessApprovalKind::CleanSmoke,
                source_sha256,
                binary_sha256,
                Utc::now(),
            )
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Promote a harness with documented smoke findings. This is intentionally
    /// separate from clean promotion so callers cannot accidentally treat a
    /// crash-bearing revision as crash-free.
    pub async fn harness_promote_with_findings(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let _target_revision = self.acquire_target_revision(project, target).await?;
        let mut harness = self.active_harness_locked(project, target, engine).await?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run smoke qualification before approving findings".into())
        })?;
        if smoke.crashes == 0 {
            return Err(ClassifiedError::Validation(
                "known-findings approval requires at least one smoke crash".into(),
            ));
        }
        self.verify_harness_qualification_locked(project, target, &harness)
            .await?;
        let (_, source_sha256, binary_sha256) = qualification_evidence(&harness)?;
        let source_sha256 = source_sha256.to_owned();
        let binary_sha256 = binary_sha256.to_owned();
        harness.status = HarnessStatus::Promoted;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".into(),
            )
        })?;
        store
            .promote_harness_with_approval(
                &harness,
                hf_storage::HarnessApprovalKind::KnownFindings,
                &source_sha256,
                &binary_sha256,
                Utc::now(),
            )
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(harness)
    }

    /// Generate seed corpus inputs for a target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn generate_seeds(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let seeds = generate_target_seeds(target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &hf_corpus::list(&corpus_dir)?)
            .await?;
        corpus
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ClassifiedError::Internal(
                            "generated seed path has no UTF-8 filename".to_owned(),
                        )
                    })?
                    .to_owned();
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect()
    }

    /// Generate a seed corpus for a target using the LLM (structural, format-
    /// aware seeds), falling back to the heuristic seeds when no provider is
    /// configured or the model returns nothing usable. Seeds are written into
    /// the target's corpus directory and deduplicated by content hash.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory or a seed file cannot
    /// be written.
    pub async fn generate_seeds_llm(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
        count: usize,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // Clamp the requested count to a sane range so no presentation layer can
        // ask the LLM for zero or an absurd number of seeds. Owning the bound
        // here keeps CLI, REST, and Tauri consistent (the clamp previously lived
        // only in the web handler).
        let count = count.clamp(1, 64);
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // LLM seeds when a provider and the target candidate are available.
        let mut datas: Vec<Vec<u8>> = Vec::new();
        if let Some(pool) = self.provider_pool() {
            if let Ok(inv) = self.discover(project, lang).await {
                if let Ok(Some(candidate)) = select_target_candidate(&inv.candidates, target) {
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "seed_gen");
                    match hf_harness::generate_seeds(candidate, count, Box::new(provider)).await {
                        Ok(seeds) => datas = seeds,
                        Err(e) => tracing::warn!("LLM seed generation for '{target}' failed: {e}"),
                    }
                }
            }
        }
        // Fall back to the heuristic seeds so a corpus is always produced.
        if datas.is_empty() {
            datas = generate_target_seeds(target)
                .into_iter()
                .map(|(data, _)| data)
                .collect();
        }

        let mut named_seeds = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, data) in datas.into_iter().enumerate() {
            use sha2::{Digest as _, Sha256};
            let sha = format!("{:x}", Sha256::digest(&data));
            if !seen.insert(sha.clone()) {
                continue;
            }
            let name = format!("llmseed_{i}");
            named_seeds.push((data, name));
        }

        // Make the AI seeds first-class, tracked corpus entries (parity with
        // corpus_seed/corpus_grow), so they show in the browse-all corpus view
        // and survive as persisted rows -- previously LLM seeds only landed on
        // disk. Listing the dir also folds in any pre-existing entries; the
        // exact target reconciliation stays idempotent.
        let target_id = self.resolve_target_id(project, target, lang).await?;
        let generated = hf_corpus::seed(target_id, &corpus_dir, named_seeds).await?;
        let entries = generated
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let corpus = hf_corpus::list(&corpus_dir)?;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(entries)
    }
}

#[cfg(all(test, feature = "build-context"))]
mod build_context_wiring_tests {
    use std::sync::Arc;

    use super::{project_compile_flags, ServiceContainer};

    #[test]
    fn a_compile_database_reaches_the_harness_build_command() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(project.path().join("include")).unwrap();
        // Built with serde_json rather than string interpolation: a Windows
        // temporary directory is `C:\Users\...`, and those separators are
        // invalid JSON escapes when pasted into a string literal.
        let document = serde_json::json!([{
            "directory": project.path(),
            "file": project.path().join("a.c"),
            "arguments": [
                "cc".to_owned(),
                format!("-I{}", project.path().join("include").display()),
                "-DA=1".to_owned(),
                "-c".to_owned(),
                "a.c".to_owned(),
            ],
        }]);
        std::fs::write(
            project.path().join("compile_commands.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

        let flags = project_compile_flags(&container, project.path()).unwrap();

        assert_eq!(flags, vec!["-I/work/include", "-DA=1"]);
    }

    #[test]
    fn a_project_without_a_database_builds_with_no_extra_flags() {
        let project = tempfile::tempdir().unwrap();
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
        assert!(project_compile_flags(&container, project.path())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn a_broken_database_fails_the_build_instead_of_dropping_the_flags() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("compile_commands.json"), "{not json").unwrap();
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
        assert!(project_compile_flags(&container, project.path()).is_err());
    }
}

#[cfg(feature = "harness-tournament")]
impl ServiceContainer {
    /// Evaluate several harness candidates for one target and rank them on
    /// sandbox evidence.
    ///
    /// Generates one deterministic baseline plus LLM drafts, compiles each
    /// through the existing repair loop, smoke-qualifies each that compiled,
    /// and retains every candidate's evidence. Ranking is deterministic and
    /// objective; the tournament never promotes.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the candidate count is out of
    /// range or the target is unknown, or an authorization error. A tournament
    /// in which nothing compiled is a result, not an error.
    pub async fn run_harness_tournament(
        &self,
        req: crate::harness_tournament::HarnessTournamentRequest,
    ) -> Result<crate::harness_tournament::HarnessTournamentResult, ClassifiedError> {
        use crate::harness_tournament::{
            rank_candidates, CandidateOrigin, HarnessCandidateEvidence, HarnessTournamentResult,
            SmokeEvidence, HARNESS_TOURNAMENT_SCHEMA_VERSION, MAX_CANDIDATES,
        };

        // Bound first: each candidate costs a model call and two sandbox runs,
        // so an out-of-range request must not reach either.
        if req.candidates == 0 || req.candidates > MAX_CANDIDATES {
            return Err(ClassifiedError::Validation(format!(
                "a tournament needs between 1 and {MAX_CANDIDATES} candidates, not {}",
                req.candidates
            )));
        }
        let project = std::path::Path::new(&req.project);
        require_fuzzing_harness_engine(req.engine, req.lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_tournament", Some(project))
            .await?;

        let inv = self.discover(project, req.lang).await?;
        let candidate = select_target_candidate(&inv.candidates, &req.target)?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("target '{}' not found", req.target))
            })?
            .clone();

        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, &req.target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        // The deterministic baseline first, then independent model drafts. The
        // drafts differ by sampling, not by prompt, so a losing candidate is
        // never handicapped by a prompt the others did not get.
        let mut sources: Vec<(CandidateOrigin, String)> = Vec::with_capacity(req.candidates);
        sources.push((
            CandidateOrigin::Heuristic,
            heuristic_draft(&candidate, req.engine).source,
        ));
        for _ in 1..req.candidates {
            sources.push((
                CandidateOrigin::Llm,
                self.draft_harness_source(project, &candidate, req.engine)
                    .await,
            ));
        }

        let mut evidence: Vec<HarnessCandidateEvidence> = Vec::with_capacity(sources.len());
        let mut winning_sources: Vec<(usize, String)> = Vec::new();
        for (index, (origin, source)) in sources.into_iter().enumerate() {
            let source_sha256 = sha256_hex(source.as_bytes());
            match self
                .compile_source_with_repair(
                    &candidate,
                    req.engine,
                    req.lang,
                    &workspace,
                    source.clone(),
                    req.max_repairs,
                )
                .await
            {
                Ok(outcome) => {
                    // Smoke is what separates a hollow harness from a working
                    // one. A smoke that cannot run leaves the evidence absent
                    // rather than inventing a verdict.
                    let smoke = match self
                        .harness_smoke(project, &req.target, req.engine, req.lang)
                        .await
                    {
                        Ok(outcome) => Some(SmokeEvidence {
                            verdict: outcome.verdict.level,
                            execs_per_sec: outcome.summary.execs_per_sec,
                            crashes: outcome.summary.crashes,
                        }),
                        Err(error) => {
                            tracing::warn!(%error, index, "harness tournament smoke failed");
                            None
                        }
                    };
                    winning_sources.push((index, source));
                    evidence.push(HarnessCandidateEvidence {
                        index,
                        origin,
                        source_sha256,
                        compiled: true,
                        repairs_used: outcome.repairs_used,
                        compile_error: None,
                        smoke,
                    });
                }
                Err(error) => {
                    let mut message = error.to_string();
                    message.truncate(MAX_CANDIDATE_ERROR_BYTES);
                    evidence.push(HarnessCandidateEvidence {
                        index,
                        origin,
                        source_sha256,
                        compiled: false,
                        repairs_used: 0,
                        compile_error: Some(message),
                        smoke: None,
                    });
                }
            }
        }

        let ranking = rank_candidates(&evidence);
        let winner_index = ranking
            .iter()
            .copied()
            .find(|index| evidence[*index].compiled);

        // Each compile overwrote the workspace's active-harness marker and
        // binary, so the last candidate's artifacts are in place. Recompile the
        // winner so the workspace holds the selection. Bookkeeping over an
        // already-evaluated source, not new evidence.
        if let Some(winner) = winner_index {
            if let Some((_, source)) = winning_sources
                .iter()
                .find(|(index, _)| *index == winner)
                .cloned()
            {
                if let Err(error) = self
                    .compile_source_with_repair(
                        &candidate, req.engine, req.lang, &workspace, source, 0,
                    )
                    .await
                {
                    tracing::warn!(%error, "could not restore the tournament winner's artifacts");
                }
            }
        }

        Ok(HarnessTournamentResult {
            schema_version: HARNESS_TOURNAMENT_SCHEMA_VERSION,
            candidates: evidence,
            ranking,
            winner_index,
            promoted: false,
        })
    }
}

/// Bound on retained per-candidate compile diagnostics.
#[cfg(feature = "harness-tournament")]
const MAX_CANDIDATE_ERROR_BYTES: usize = 2048;

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

#[cfg(test)]
mod exact_qualification_tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use hf_core::engine::EngineKind;
    use hf_core::error::ClassifiedError;
    use hf_core::harness::{Harness, HarnessStatus};
    use hf_core::provider::{
        ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
        RouteRequest,
    };
    use hf_core::runtime::{
        CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
    };
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };
    use uuid::Uuid;

    use super::{harness_binary_name, workspace_dir, ServiceContainer};

    const TARGET: &str = "parse_entry";
    const SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";
    const APPROVING_REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["target receives fuzz input"]}"#;

    #[derive(Default)]
    struct CountingRuntime {
        calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RuntimeAdapter for CountingRuntime {
        async fn resolve_image_reference(
            &self,
            _image: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            Ok(Some(hf_test_utils::immutable_test_image()?))
        }

        async fn run_command(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::fs::create_dir_all(cwd).unwrap();
            Ok(CommandResult {
                exit_code: 0,
                stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            })
        }

        async fn run_command_streaming(
            &self,
            cmd: &[String],
            cwd: &Path,
            limits: &ResourceLimits,
            _cancel: &tokio_util::sync::CancellationToken,
            _on_line: &hf_core::runtime::LineSink<'_>,
        ) -> Result<CommandResult, ClassifiedError> {
            self.run_command(cmd, cwd, limits).await
        }

        async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, content).unwrap();
            Ok(())
        }

        async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
            Ok(std::fs::read_to_string(path).unwrap_or_default())
        }
    }

    struct CountingReviewPool {
        calls: AtomicUsize,
        replace_active_with: Mutex<Option<(PathBuf, Uuid)>>,
    }

    impl CountingReviewPool {
        fn approving() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                replace_active_with: Mutex::new(None),
            }
        }

        fn replace_active_during_review(&self, active_marker: PathBuf, replacement: Uuid) {
            *self.replace_active_with.lock().unwrap() = Some((active_marker, replacement));
        }
    }

    #[async_trait::async_trait]
    impl ProviderPool for CountingReviewPool {
        async fn chat_completion(
            &self,
            _request: &ChatRequest,
            _route: &RouteRequest,
        ) -> Result<ChatResponse, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if let Some((marker, replacement)) = &*self.replace_active_with.lock().unwrap() {
                std::fs::write(marker, replacement.to_string()).unwrap();
            }
            Ok(hf_test_utils::fixtures::make_chat_response(
                APPROVING_REVIEW,
            ))
        }

        async fn chat_completion_stream(
            &self,
            _request: &ChatRequest,
            _route: &RouteRequest,
        ) -> Result<ChatStreamResponse, ProviderError> {
            Err(ProviderError::Other {
                message: "unused".to_owned(),
            })
        }

        fn report_error(&self, _provider_id: &hf_core::types::ProviderId, _error: &ProviderError) {}

        async fn provider_statuses(&self) -> Vec<ProviderStatus> {
            Vec::new()
        }

        async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}

        async fn thaw(
            &self,
            _provider_id: &hf_core::types::ProviderId,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    fn install_workspace() {
        static ROOT: OnceLock<PathBuf> = OnceLock::new();
        let root = ROOT.get_or_init(|| {
            let root = std::env::temp_dir().join(format!("oxfuzz-exact-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let canonical = std::fs::canonicalize(&root).unwrap();
            std::fs::write(
                canonical.join(".oxfuzz-workspace.json"),
                serde_json::to_vec(&serde_json::json!({
                    "application": "oxfuzz",
                    "version": 1,
                    "canonical_root": canonical,
                }))
                .unwrap(),
            )
            .unwrap();
            canonical
        });
        std::env::set_var("HF_WORKSPACE_DIR", root);
    }

    fn qualification_test_gate() -> &'static tokio::sync::Mutex<()> {
        static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        GATE.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    async fn fixture(
        review: Arc<CountingReviewPool>,
    ) -> (
        tempfile::TempDir,
        Arc<hf_storage::Store>,
        ServiceContainer,
        Arc<CountingRuntime>,
        Uuid,
    ) {
        install_workspace();
        let project = tempfile::tempdir().unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(project.path().join("exact.db"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(CountingRuntime::default());
        let container = ServiceContainer::new(
            Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>,
            Some(review),
        )
        .with_store(Arc::clone(&store));
        let id = Uuid::new_v4();
        let workspace = workspace_dir(project.path(), TARGET);
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("harness.source"), SOURCE).unwrap();
        std::fs::write(workspace.join("harness.active"), id.to_string()).unwrap();
        std::fs::write(
            workspace.join(harness_binary_name(TARGET)),
            b"mock compiled harness",
        )
        .unwrap();
        store
            .upsert_harness(&Harness {
                id,
                target_id: Uuid::new_v4(),
                engine: EngineKind::LibFuzzer,
                source: SOURCE.to_owned(),
                language: TargetLanguage::C,
                build_cmd: hf_harness::build_command(
                    EngineKind::LibFuzzer,
                    TargetLanguage::C,
                    &harness_binary_name(TARGET),
                ),
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Compiled,
                smoke_run: None,
            })
            .await
            .unwrap();
        (project, store, container, runtime, id)
    }

    #[tokio::test]
    async fn exact_review_rejects_another_active_id_and_reuses_durable_evidence() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, _store, container, _runtime, id) = fixture(Arc::clone(&review)).await;

        let outcome = container
            .harness_review_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                id,
            )
            .await
            .unwrap();
        assert_eq!(outcome.harness_id, id);
        assert_eq!(outcome.source_sha256, super::sha256_hex(SOURCE.as_bytes()));
        container
            .harness_review_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                id,
            )
            .await
            .unwrap();
        assert_eq!(review.calls.load(Ordering::SeqCst), 1);

        let error = container
            .harness_review_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                Uuid::new_v4(),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("requested harness id"),
            "{error}"
        );
        assert_eq!(review.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_smoke_refuses_a_replaced_active_revision_before_runtime_dispatch() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, _store, container, runtime, id) = fixture(Arc::clone(&review)).await;
        let mismatch = container
            .harness_smoke_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                Uuid::new_v4(),
            )
            .await
            .unwrap_err();
        assert!(
            mismatch.to_string().contains("requested harness id"),
            "{mismatch}"
        );
        assert_eq!(review.calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
        review.replace_active_during_review(
            workspace_dir(project.path(), TARGET).join("harness.active"),
            Uuid::new_v4(),
        );

        let error = container
            .harness_smoke_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                id,
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("active harness record"),
            "{error}"
        );
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_smoke_refuses_a_changed_persisted_revision_before_dispatch() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, store, container, runtime, id) = fixture(Arc::clone(&review)).await;
        let mut changed = store.get_harness(id).await.unwrap().unwrap();
        changed.source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size == 0; }".to_owned();
        sqlx::query("UPDATE harnesses SET source = ?2, data_json = ?3 WHERE id = ?1")
            .bind(id.to_string())
            .bind(&changed.source)
            .bind(serde_json::to_string(&changed).unwrap())
            .execute(store.pool())
            .await
            .unwrap();

        let error = container
            .harness_smoke_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                id,
            )
            .await
            .expect_err("a changed record under the active id must fail closed");

        assert!(error.to_string().contains("does not match"), "{error}");
        assert_eq!(review.calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.get_harness(id).await.unwrap().unwrap().status,
            HarnessStatus::Compiled
        );
    }

    #[tokio::test]
    async fn simultaneous_exact_reviews_retain_one_provider_result() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, store, container, _runtime, id) = fixture(Arc::clone(&review)).await;
        let project_path = project.path().to_path_buf();
        let first = container.harness_review_exact(
            &project_path,
            TARGET,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            id,
        );
        let second = container.harness_review_exact(
            &project_path,
            TARGET,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            id,
        );

        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap().harness_id, id);
        assert_eq!(second.unwrap().harness_id, id);
        assert_eq!(review.calls.load(Ordering::SeqCst), 1);
        assert!(store.harness_ai_review(id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn exact_promotion_completes_with_a_waiting_workspace_cleanup() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, store, container, _runtime, id) = fixture(review).await;
        container
            .harness_smoke(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        let harness = store.get_harness(id).await.unwrap().unwrap();
        let (_, source_sha256, binary_sha256) = super::qualification_evidence(&harness).unwrap();

        let workspace_operation = container.acquire_workspace_operation().await.unwrap();
        let project_root = super::canonical_project_root(project.path()).unwrap();
        let target_revision = container
            .acquire_target_revision(project_root.as_path(), TARGET)
            .await
            .unwrap();
        let (_, workspace_gate) = super::super::workspace::workspace_operation_gate(
            &super::super::workspace::workspace_root(),
        )
        .unwrap();
        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let (acquired_tx, acquired_rx) = tokio::sync::oneshot::channel();
        let cleanup = tokio::spawn(async move {
            let _ = waiting_tx.send(());
            let _cleanup = workspace_gate.write_owned().await;
            let _ = acquired_tx.send(());
        });
        waiting_rx.await.unwrap();
        tokio::task::yield_now().await;

        let promoted = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            container.harness_promote_locked(
                project_root.as_path(),
                TARGET,
                EngineKind::LibFuzzer,
                Some(super::ExactPromotion {
                    harness_id: id,
                    source_sha256,
                    binary_sha256,
                }),
            ),
        )
        .await
        .expect("promotion must not try to take a nested workspace read")
        .unwrap();
        assert_eq!(promoted.status, HarnessStatus::Promoted);

        drop(target_revision);
        drop(workspace_operation);
        tokio::time::timeout(std::time::Duration::from_secs(1), acquired_rx)
            .await
            .expect("cleanup must acquire after promotion releases its read")
            .unwrap();
        cleanup.await.unwrap();
    }

    async fn promoted_fixture() -> (
        tempfile::TempDir,
        Arc<hf_storage::Store>,
        ServiceContainer,
        Harness,
    ) {
        let review = Arc::new(CountingReviewPool::approving());
        let (project, store, container, _runtime, _id) = fixture(review).await;
        let compiled = store.list_all_harnesses().await.unwrap().pop().unwrap();
        store
            .upsert_target(
                &TargetCandidate {
                    id: compiled.target_id,
                    project_root: project.path().to_path_buf(),
                    language: TargetLanguage::C,
                    symbol: TARGET.to_owned(),
                    kind: TargetKind::Parser,
                    location: SourceLocation {
                        file: project.path().join("parse.c"),
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
                    rationale: "test target".to_owned(),
                    reachable_functions: Vec::new(),
                    accumulated_complexity: 1,
                },
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        container
            .harness_smoke(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        let promoted = container
            .harness_promote(project.path(), TARGET, EngineKind::LibFuzzer)
            .await
            .unwrap();
        (project, store, container, promoted)
    }

    #[tokio::test]
    async fn conditional_revert_rejects_a_newer_harness_id_without_mutation() {
        let _gate = qualification_test_gate().lock().await;
        let (project, store, container, active) = promoted_fixture().await;
        let (qualification_run, source_sha256, binary_sha256) = {
            let (run, source, binary) = super::qualification_evidence(&active).unwrap();
            (run, source.to_owned(), binary.to_owned())
        };
        let workspace = workspace_dir(project.path(), TARGET);
        let before_source = std::fs::read(workspace.join("harness.source")).unwrap();
        let before_binary = std::fs::read(workspace.join(harness_binary_name(TARGET))).unwrap();
        let before_marker = std::fs::read(workspace.join("harness.active")).unwrap();
        let before_row_ids = store
            .list_harnesses(active.target_id)
            .await
            .unwrap()
            .into_iter()
            .map(|harness| harness.id)
            .collect::<Vec<_>>();
        let before_approval = store
            .harness_approval(active.id, &source_sha256, &binary_sha256)
            .await
            .unwrap();

        let mut newer = active.clone();
        newer.id = Uuid::new_v4();
        store.upsert_harness(&newer).await.unwrap();
        std::fs::write(workspace.join("harness.active"), newer.id.to_string()).unwrap();
        let marker_after_newer = std::fs::read(workspace.join("harness.active")).unwrap();

        let error = container
            .revert_harness_from_run_if_current(
                &qualification_run.to_string(),
                Some(super::super::policy::CurrentHarnessEvidence {
                    id: active.id,
                    source_sha256: &source_sha256,
                    binary_sha256: &binary_sha256,
                }),
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("active harness changed"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(workspace.join("harness.source")).unwrap(),
            before_source
        );
        assert_eq!(
            std::fs::read(workspace.join(harness_binary_name(TARGET))).unwrap(),
            before_binary
        );
        assert_eq!(
            std::fs::read(workspace.join("harness.active")).unwrap(),
            marker_after_newer
        );
        assert_eq!(
            store
                .list_harnesses(active.target_id)
                .await
                .unwrap()
                .into_iter()
                .map(|harness| harness.id)
                .collect::<Vec<_>>(),
            [before_row_ids, vec![newer.id]].concat()
        );
        assert_eq!(
            store
                .harness_approval(active.id, &source_sha256, &binary_sha256)
                .await
                .unwrap(),
            before_approval
        );
        assert_ne!(before_marker, marker_after_newer);
    }

    #[tokio::test]
    async fn conditional_revert_rejects_changed_current_binary_without_mutation() {
        let _gate = qualification_test_gate().lock().await;
        let (project, store, container, active) = promoted_fixture().await;
        let (qualification_run, source_sha256, binary_sha256) =
            super::qualification_evidence(&active).unwrap();
        let workspace = workspace_dir(project.path(), TARGET);
        let before_source = std::fs::read(workspace.join("harness.source")).unwrap();
        let before_marker = std::fs::read(workspace.join("harness.active")).unwrap();
        let before_row_ids = store
            .list_harnesses(active.target_id)
            .await
            .unwrap()
            .into_iter()
            .map(|harness| harness.id)
            .collect::<Vec<_>>();
        let before_approval = store
            .harness_approval(active.id, source_sha256, binary_sha256)
            .await
            .unwrap();
        std::fs::write(
            workspace.join(harness_binary_name(TARGET)),
            b"changed executable",
        )
        .unwrap();
        let changed_binary = std::fs::read(workspace.join(harness_binary_name(TARGET))).unwrap();

        assert!(container
            .revert_harness_from_run_if_current(
                &qualification_run.to_string(),
                Some(super::super::policy::CurrentHarnessEvidence {
                    id: active.id,
                    source_sha256,
                    binary_sha256,
                }),
            )
            .await
            .is_err());
        assert_eq!(
            std::fs::read(workspace.join("harness.source")).unwrap(),
            before_source
        );
        assert_eq!(
            std::fs::read(workspace.join(harness_binary_name(TARGET))).unwrap(),
            changed_binary
        );
        assert_eq!(
            std::fs::read(workspace.join("harness.active")).unwrap(),
            before_marker
        );
        assert_eq!(
            store
                .list_harnesses(active.target_id)
                .await
                .unwrap()
                .into_iter()
                .map(|harness| harness.id)
                .collect::<Vec<_>>(),
            before_row_ids
        );
        assert_eq!(
            store
                .harness_approval(active.id, source_sha256, binary_sha256)
                .await
                .unwrap(),
            before_approval
        );
    }

    #[tokio::test]
    async fn conditional_revert_completes_after_a_queued_workspace_cleanup() {
        let _gate = qualification_test_gate().lock().await;
        let (_project, _store, container, active) = promoted_fixture().await;
        let (qualification_run, source_sha256, binary_sha256) = {
            let (run, source, binary) = super::qualification_evidence(&active).unwrap();
            (run, source.to_owned(), binary.to_owned())
        };
        let held = container.acquire_workspace_operation().await.unwrap();
        let (_, workspace_gate) = super::super::workspace::workspace_operation_gate(
            &super::super::workspace::workspace_root(),
        )
        .unwrap();
        let (queued_tx, queued_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let cleanup = tokio::spawn(async move {
            let _cleanup = workspace_gate.write_owned().await;
            let _ = queued_tx.send(());
            let _ = release_rx.await;
        });
        tokio::task::yield_now().await;
        drop(held);
        queued_rx.await.unwrap();

        let worker = container.clone();
        let run_id = qualification_run.to_string();
        let active_id = active.id;
        let expected_source = source_sha256.clone();
        let expected_binary = binary_sha256.clone();
        let mut revert = tokio::spawn(async move {
            worker
                .revert_harness_from_run_if_current(
                    &run_id,
                    Some(super::super::policy::CurrentHarnessEvidence {
                        id: active_id,
                        source_sha256: &expected_source,
                        binary_sha256: &expected_binary,
                    }),
                )
                .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut revert)
                .await
                .is_err(),
            "conditional reversion must wait behind the queued cleanup writer"
        );
        let _ = release_tx.send(());
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut revert)
                .await
                .is_ok(),
            "conditional reversion must complete after cleanup releases the writer lease"
        );
        cleanup.await.unwrap();
    }

    #[tokio::test]
    async fn exact_promotion_rejects_mismatched_evidence_without_status_mutation() {
        let _gate = qualification_test_gate().lock().await;
        let review = Arc::new(CountingReviewPool::approving());
        let (project, store, container, _runtime, id) = fixture(review).await;
        container
            .harness_smoke(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        let harness = store.get_harness(id).await.unwrap().unwrap();
        let (_, source_sha256, binary_sha256) = super::qualification_evidence(&harness).unwrap();

        for (expected_id, source, binary) in [
            (Uuid::new_v4(), source_sha256, binary_sha256),
            (id, "0", binary_sha256),
            (id, source_sha256, "0"),
        ] {
            assert!(container
                .harness_promote_exact(
                    project.path(),
                    TARGET,
                    EngineKind::LibFuzzer,
                    expected_id,
                    source,
                    binary
                )
                .await
                .is_err());
            assert_eq!(
                store.get_harness(id).await.unwrap().unwrap().status,
                HarnessStatus::SmokePassed
            );
        }

        let promoted = container
            .harness_promote_exact(
                project.path(),
                TARGET,
                EngineKind::LibFuzzer,
                id,
                source_sha256,
                binary_sha256,
            )
            .await
            .unwrap();
        assert_eq!(promoted.status, HarnessStatus::Promoted);
    }
}
