//! Crash triage, verification, and coverage queries.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_guardrails::Action;
use hf_storage::RunRecord;
use uuid::Uuid;

use super::coverage_cache::parse_covered_functions;
use super::crash_inputs::{collect_crash_inputs, collect_legacy_crash_inputs, is_regular_file};
use super::harness_workspace::harness_binary_name;
use super::project_identity::{canonical_project_root, stored_project_matches};
use super::staging::run_output_dir;
use super::workspace::workspace_dir;
use super::{run_has_crash_evidence, LlmProviderBridge, RegressionResult, ServiceContainer};

impl ServiceContainer {
    /// Ingest and deduplicate crash artifacts from the output directory.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the output directory cannot be read.
    pub async fn triage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let run = match self.latest_run_record(project, Some(target)).await? {
            Some(run) => run,
            None if self.store.is_some() => {
                return Err(ClassifiedError::Validation(format!(
                    "no terminal run for target '{target}' has attributable crash evidence; run smoke qualification or a campaign before triage"
                )));
            }
            None => RunRecord::new(
                project.to_string_lossy(),
                EngineKind::LibFuzzer,
                None,
                Utc::now(),
            ),
        };
        self.triage_run_record(project, target, run).await
    }

    /// Triage the evidence owned by one exact persisted run.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run is missing, belongs to another
    /// project/target, is nonterminal, or its evidence is invalid.
    pub async fn triage_run(
        &self,
        project: &Path,
        target: &str,
        run_id: Uuid,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {run_id}")))?;
        if !stored_project_matches(Path::new(&run.project_root), project)
            || !run_has_crash_evidence(run.status)
            || self.run_target_id(store, &run).await?
                != Some(self.resolve_target_id_any_language(project, target).await?)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} does not own terminal evidence for target '{target}'"
            )));
        }
        self.triage_run_record(project, target, run).await
    }

    /// LLM crash verifier (self-verification L2, increment 4): for each triaged
    /// crash, ask the model whether it looks like a deterministically-reproducing
    /// genuine target bug versus a harness/setup artifact, returning a verdict
    /// aligned with `crashes` (index for index).
    ///
    /// Best-effort and advisory: with no provider configured it returns `None`
    /// for every crash (no fabricated opinion), it is bounded to a fixed number
    /// of model calls per pass, and it never reclassifies, files, or closes a
    /// crash -- the verdict only informs a human reviewer (AGENTS.md 2.12).
    /// Verify a single crash on demand (L2 increment 4c): a thin wrapper over
    /// [`Self::verify_crashes`] so a presentation layer can offer a per-crash
    /// "verify" action without running the model on every crash in a triage scan.
    /// `None` when no provider is configured or the reply is malformed.
    pub async fn verify_crash(
        &self,
        target: &str,
        crash: &hf_core::crash::Crash,
    ) -> Option<crate::verification::CrashVerdict> {
        self.verify_crashes(target, std::slice::from_ref(crash))
            .await
            .into_iter()
            .next()
            .flatten()
    }

    pub async fn verify_crashes(
        &self,
        target: &str,
        crashes: &[hf_core::crash::Crash],
    ) -> Vec<Option<crate::verification::CrashVerdict>> {
        use hf_core::provider::{ChatRequest, LlmProvider as _};
        use hf_core::types::Message;

        // Bound the model calls per triage pass so a crash flood cannot fan out
        // into an unbounded LLM spend; extra crashes get no verdict.
        const MAX_CRASH_VERIFICATIONS: usize = 20;

        let Some(pool) = self.provider_pool() else {
            return vec![None; crashes.len()];
        };
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "crash_verify");

        let mut verdicts = Vec::with_capacity(crashes.len());
        for (index, crash) in crashes.iter().enumerate() {
            if index >= MAX_CRASH_VERIFICATIONS {
                verdicts.push(None);
                continue;
            }
            let (severity, crashline, stack) = crash.casr.as_ref().map_or_else(
                || (None, None, Vec::new()),
                |casr| {
                    (
                        Some(casr.severity_short.as_str()),
                        Some(casr.crashline.as_str()),
                        casr.stack.clone(),
                    )
                },
            );
            let kind = format!("{:?}", crash.kind);
            let prompt = hf_prompt::render_crash_verify_prompt(
                target,
                &kind,
                &crash.summary,
                severity,
                crashline,
                &stack,
                crash.minimized,
            );
            let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
            let verdict = match provider.chat_completion(&req).await {
                Ok(resp) => crate::verification::parse_crash_verdict(resp.text()),
                Err(error) => {
                    tracing::warn!("crash verification for a '{target}' crash failed: {error}");
                    None
                }
            };
            verdicts.push(verdict);
        }
        verdicts
    }

    /// LLM harness verifier (self-verification L2, Option B): when the
    /// deterministic smoke verdict is a `Pass`, ask an LLM whether the harness
    /// source actually drives the target with the fuzz input, and downgrade a
    /// hollow pass that the execs/sec heuristic missed (a harness that runs fast
    /// but ignores `data`/`size`).
    ///
    /// Cost-bounded and conservative: it runs the model only on a `Pass` (the LLM
    /// can only add caution, so a Suspect/Fail is already at least as cautious),
    /// one call at most, and returns the deterministic verdict unchanged when no
    /// provider is configured or the reply is malformed. Advisory + HITL -- it
    /// changes only the advisory verdict, never promotes anything (AGENTS.md 2.12).
    pub async fn verify_harness_source(
        &self,
        target: &str,
        harness_source: &str,
        summary: &hf_core::harness::SmokeRunSummary,
        deterministic: crate::verification::HarnessVerdict,
    ) -> crate::verification::HarnessVerdict {
        use hf_core::provider::{ChatRequest, LlmProvider as _};
        use hf_core::types::Message;

        // Cap the source so a large harness cannot blow the prompt budget.
        const MAX_HARNESS_SOURCE_CHARS: usize = 6000;

        // Only a clean Pass is worth a second look; skip the model call otherwise.
        if deterministic.level != crate::verification::VerdictLevel::Pass {
            return deterministic;
        }
        let Some(pool) = self.provider_pool() else {
            return deterministic;
        };

        let source_excerpt: String = harness_source
            .chars()
            .take(MAX_HARNESS_SOURCE_CHARS)
            .collect();
        let prompt =
            hf_prompt::render_harness_verify_prompt(target, &source_excerpt, summary.execs_per_sec);
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_verify");
        let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
        match provider.chat_completion(&req).await {
            Ok(resp) => match crate::verification::parse_harness_llm_opinion(resp.text()) {
                Some(opinion) => {
                    crate::verification::merge_llm_harness_opinion(deterministic, &opinion)
                }
                None => deterministic,
            },
            Err(error) => {
                tracing::warn!("LLM harness verification for '{target}' failed: {error}");
                deterministic
            }
        }
    }

    /// Regression check: replay stored crash inputs against the current harness
    /// and report which ones still crash.
    ///
    /// The workflow is: fix the bug, recompile the harness, then run this to
    /// confirm the fix (and catch re-introductions). Prefers the persisted
    /// crashes for the project's latest run; falls back to crash inputs staged
    /// under the run output directory. Requires a compiled harness binary.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the harness is missing or the action is
    /// denied by guardrails.
    pub async fn verify_regressions(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<RegressionResult>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // Replaying crash inputs runs the (untrusted) harness in the sandbox --
        // gate it like triage.
        self.authorize_recorded(Action::Triage, "verify_regressions", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let binary_name = harness_binary_name(target);
        if !workspace.join(&binary_name).exists() {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }

        // (crash_id, input_path) pairs: persisted crashes first, else staged.
        let mut inputs: Vec<(String, PathBuf)> = Vec::new();
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        if let Some(store) = &self.store {
            if let Some(run) = &latest_run {
                let crashes = store.list_crashes_by_run(run.id).await?;
                inputs.extend(
                    crashes
                        .into_iter()
                        .map(|c| (c.id.to_string(), c.input_path)),
                );
            }
        }
        if inputs.is_empty() {
            let out_dir = match latest_run.as_ref() {
                Some(run) => run_output_dir(&workspace, run)?,
                None => workspace.join("out"),
            };
            inputs = latest_run
                .as_ref()
                .map_or_else(
                    || collect_legacy_crash_inputs(&out_dir),
                    |run| collect_crash_inputs(run.engine, &out_dir),
                )
                .into_iter()
                .map(|p| (String::new(), p))
                .collect();
        }

        let mut results = Vec::with_capacity(inputs.len());
        for (crash_id, input) in inputs {
            if !is_regular_file(&input) {
                continue;
            }
            let binary = workspace.join(harness_binary_name(target));
            let trace = self.reproduce_crash(&workspace, &binary, &input).await;
            let verified = trace.is_some();
            let still_crashes = trace.as_deref().is_some_and(hf_crash::looks_like_crash);
            let summary = if still_crashes {
                trace
                    .as_deref()
                    .unwrap_or_default()
                    .lines()
                    .find(|l| {
                        let s = l.to_ascii_lowercase();
                        s.contains("error") || s.contains("summary")
                    })
                    .unwrap_or("still crashes")
                    .trim()
                    .chars()
                    .take(200)
                    .collect()
            } else if verified {
                "no crash on replay (fixed)".to_owned()
            } else {
                "replay did not complete; result is inconclusive".to_owned()
            };
            results.push(RegressionResult {
                crash_id,
                input: input.display().to_string(),
                still_crashes,
                verified,
                summary,
            });
        }
        Ok(results)
    }

    /// Functions covered by a fuzz run, for the call-tree coverage overlay.
    ///
    /// Parses the shared cached `llvm-cov export` for per-function execution
    /// counts -- engine-agnostic, since the export comes from a purpose-built
    /// coverage binary rather than the run's. Empty when no harness was built or
    /// coverage tooling is unavailable.
    pub async fn coverage_functions(&self, project: &Path, target: &str) -> Vec<String> {
        self.coverage_export_json_cached(project, target)
            .await
            .map(|json| parse_covered_functions(&json))
            .unwrap_or_default()
    }

    /// The uncovered frontier for a target: the `file:line` locations the
    /// current corpus has not reached, extracted from the same `llvm-cov export`
    /// the covered-set overlay uses. Drives targeted harness refinement
    /// ([`Self::harness_refine`]). Empty when no C harness was built or the
    /// coverage tooling is unavailable. Cached per target by the corpus+harness
    /// signature, like [`Self::coverage_functions`].
    pub async fn coverage_uncovered(
        &self,
        project: &Path,
        target: &str,
    ) -> Vec<hf_coverage::UncoveredRegion> {
        self.coverage_export_json_cached(project, target)
            .await
            .map(|json| hf_coverage::parse_llvm_cov_uncovered(&json))
            .unwrap_or_default()
    }

    /// Line/region/function coverage totals for a fuzz run.
    ///
    /// Complements [`Self::coverage_functions`] (which names covered functions
    /// for the call-tree overlay) with the structural percentages reviewers
    /// actually report: lines, functions, and regions covered out of the total.
    /// Builds the same source-based-coverage binary in the sandbox, replays the
    /// corpus, and parses the `llvm-cov export` totals. Returns `None` when no
    /// harness was built or the coverage tooling is unavailable. Cached per
    /// target by the corpus+harness signature, like the covered-function set.
    pub async fn coverage_summary(
        &self,
        project: &Path,
        target: &str,
    ) -> Option<hf_coverage::CoverageSummary> {
        let json = self.coverage_export_json_cached(project, target).await?;
        hf_coverage::parse_llvm_cov_summary(&json)
    }
}
