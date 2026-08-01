//! Reports, SARIF, repro bundles, and external tracker handoff.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::provider::ProviderPool;
use hf_core::target::TargetLanguage;
use uuid::Uuid;

use super::crash_inputs::is_regular_file;
use super::harness_workspace::read_current_harness_source;
use super::project_identity::{canonical_project_root, defectdojo_project_name};
use super::workspace::workspace_dir;
use super::ServiceContainer;

impl ServiceContainer {
    /// Persisted crashes for the most recent matching run (empty without a
    /// store or matching runs). `target = None` selects project-wide history.
    async fn crashes_for_latest_run(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let run = self.latest_run_record(project, target).await?;
        Ok(match run {
            // Guard against any pre-existing duplicate rows (e.g. crashes
            // persisted before the deterministic-id fix): collapse by signature.
            Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
            None => Vec::new(),
        })
    }

    /// Compose the narrative report with the LLM, grounded in the fact-sheet.
    async fn compose_ai_report(
        &self,
        pool: &Arc<dyn ProviderPool>,
        facts: &str,
        data: &crate::report::ReportData,
        language: crate::report::ReportLanguage,
    ) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;

        let messages = vec![
            Message::system(crate::report::report_system_prompt(language)),
            Message::user(crate::report::report_user_prompt(facts, data, language)),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["reasoning", "code", "general"]),
            )
            .await?;
        self.diagnostics
            .record("report", &resp.model, &resp.usage)
            .await;
        let text = resp.text().trim();
        if text.is_empty() {
            return Err(ClassifiedError::Provider(
                "empty report from provider".to_owned(),
            ));
        }
        // Guarantee the campaign graphs survive even if the model dropped them.
        Ok(crate::report::ensure_graphs(
            text,
            data,
            &crate::report::Labels::english(),
        ))
    }

    /// Summarize corpus composition for the report, preferring the persisted
    /// entries (richer source tags) and falling back to the workspace listing.
    async fn collect_corpus_stats(
        &self,
        project: &Path,
        target: &str,
        target_id: Uuid,
    ) -> Result<crate::report::CorpusStats, ClassifiedError> {
        use hf_core::corpus::CorpusSource;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let entries = match &self.store {
            Some(store) if target_id != Uuid::nil() => store.list_corpus_entries(target_id).await?,
            _ => Vec::new(),
        };
        let entries = if entries.is_empty() {
            // No persisted entries: read the live corpus directory.
            let workspace = workspace_dir(project, target);
            hf_corpus::list(&workspace.join("corpus"))?.entries
        } else {
            entries
        };

        let mut stats = crate::report::CorpusStats::default();
        for e in &entries {
            stats.count += 1;
            stats.total_bytes += e.size;
            match e.source {
                CorpusSource::Seed => stats.seeds += 1,
                CorpusSource::Fuzzer => stats.from_fuzzer += 1,
                CorpusSource::Minimized => stats.minimized += 1,
                CorpusSource::Manual => {}
            }
        }
        Ok(stats)
    }

    /// Assemble a self-contained reproduction bundle for `crash` into `dest`:
    /// the current harness source, the crash input bytes, and a `REPRODUCE.md`
    /// manifest carrying the exact build and run steps. A maintainer can then
    /// reproduce the finding with only the target toolchain -- no `oxfuzz`
    /// install (VISION reproducibility). Returns the bundle directory.
    ///
    /// # Errors
    /// Returns a validation error if the harness or crash input is missing (or
    /// the input is not a regular file -- symlinks are refused, never followed),
    /// or an internal error if the bundle cannot be written.
    pub async fn export_repro_bundle(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        crash: &hf_core::crash::Crash,
        dest: &Path,
    ) -> Result<PathBuf, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let workspace = workspace_dir(&project_root, target);
        let harness_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!("no harness source for '{target}' to bundle"))
        })?;
        // Copy the crash input by value; refuse a symlinked input rather than
        // following it out of the workspace into an unrelated file.
        if !is_regular_file(&crash.input_path) {
            return Err(ClassifiedError::Validation(format!(
                "crash input {} is missing or not a regular file",
                crash.input_path.display()
            )));
        }
        let input = std::fs::read(&crash.input_path).map_err(|e| {
            ClassifiedError::Validation(format!(
                "read crash input {}: {e}",
                crash.input_path.display()
            ))
        })?;
        let harness_filename = lang.harness_filename().to_owned();
        let build = hf_harness::build_command(engine, lang, "fuzz_bin");
        let build_command = format!(
            "{} {} {} -o {}",
            build.compiler,
            build.args.join(" "),
            harness_filename,
            build.output.display()
        );
        let manifest = crate::repro::ReproManifest {
            project: project_root.to_string_lossy().into_owned(),
            target: target.to_owned(),
            language: format!("{lang:?}"),
            engine: engine.as_str().to_owned(),
            // Harnesses build with ASan by default (see `build_command`).
            sanitizer: "address".to_owned(),
            build_command,
            harness_filename,
            input_filename: "crash_input".to_owned(),
            binary_name: "fuzz_bin".to_owned(),
            crash_kind: format!("{:?}", crash.kind),
            crash_summary: crash.summary.clone(),
            stack_signature: crash.stack_signature.clone(),
            minimized: crash.minimized,
        };
        crate::repro::write_repro_bundle(dest, &manifest, &harness_source, &input)
            .map_err(|e| ClassifiedError::Internal(format!("write repro bundle: {e}")))
    }

    /// Export a reproduction bundle for a crash from the target's most recent
    /// run. Selects the crash whose id starts with `crash_id` when given, else
    /// the first crash of the run. Returns the bundle directory.
    ///
    /// # Errors
    /// Returns a validation error when the latest run has no crashes, no crash
    /// matches `crash_id`, or the harness/input cannot be read; an internal
    /// error when the bundle cannot be written.
    pub async fn export_repro_bundle_for_latest(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        crash_id: Option<&str>,
        dest: &Path,
    ) -> Result<PathBuf, ClassifiedError> {
        let crashes = self.crashes_for_latest_run(project, Some(target)).await?;
        let crash = match crash_id {
            Some(id) => crashes
                .iter()
                .find(|crash| crash.id.to_string().starts_with(id))
                .ok_or_else(|| {
                    ClassifiedError::Validation(format!(
                        "no crash matching id '{id}' in the latest run for '{target}'"
                    ))
                })?,
            None => crashes.first().ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "the latest run for '{target}' has no crashes to bundle"
                ))
            })?,
        };
        self.export_repro_bundle(project, target, engine, lang, crash, dest)
            .await
    }

    /// Export the latest run's crashes as a SARIF 2.1.0 document (string),
    /// for `GitHub` code scanning / security dashboards. Empty `results` when
    /// there are no crashes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected serialization failure.
    pub async fn export_sarif(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let crashes = self.crashes_for_latest_run(project, Some(target)).await?;
        let sarif =
            crate::sarif::crashes_to_sarif(&crashes, env!("CARGO_PKG_VERSION"), &project_root);
        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ClassifiedError::Internal(format!("serialize sarif: {e}")))
    }

    /// Compose a detailed Markdown campaign report for a target.
    ///
    /// Aggregates the discovered target, the most recent run, its triaged
    /// crashes (with CASR severity + LLM bug reports), line/region coverage, and
    /// corpus composition into one self-contained document. Missing persistence
    /// or tooling is represented honestly as unavailable data.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected internal failure.
    pub async fn generate_report(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        use crate::report::{render_markdown, ReportData};

        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        // Resolve the target candidate (best-effort) and its id.
        let candidate = self
            .resolve_target_candidate_any_language(project, target)
            .await?;
        let target_id = candidate.as_ref().map_or_else(Uuid::nil, |c| c.id);

        // Latest run + its crashes from the store, when persistence is wired.
        let (run, crashes) = if let Some(store) = &self.store {
            let run = self.latest_run_record(project, Some(target)).await?;
            let crashes = match &run {
                // Collapse any pre-existing duplicate rows by signature so the
                // report never lists the same crash twice.
                Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
                None => Vec::new(),
            };
            (run, crashes)
        } else {
            (None, Vec::new())
        };

        // Live coverage (best-effort) and corpus composition.
        let coverage = self.coverage_summary(project, target).await;
        let covered_functions = self.coverage_functions(project, target).await.len();
        let corpus = self
            .collect_corpus_stats(project, target, target_id)
            .await?;

        let data = ReportData {
            generated_at: Utc::now().to_rfc3339(),
            project: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            candidate,
            run,
            crashes,
            coverage,
            covered_functions,
            corpus,
        };

        // The deterministic fact-sheet is always correct and carries the graphs;
        // it is the no-provider fallback AND the grounded input for the LLM.
        let facts = render_markdown(&data, &crate::report::Labels::english());

        // When a provider is configured, have the LLM compose a professional
        // narrative grounded in those facts. On any failure, fall back to the
        // deterministic fact-sheet so a report is always produced.
        if let Some(pool) = self.provider_pool() {
            match self
                .compose_ai_report(&pool, &facts, &data, crate::report::ReportLanguage::En)
                .await
            {
                Ok(report) => return Ok(report),
                Err(e) => tracing::warn!("AI report composition failed, using fact-sheet: {e}"),
            }
        }
        Ok(facts)
    }

    /// Document formats this host can export a report to (see
    /// [`crate::report_export::available_formats`]).
    #[must_use]
    pub fn report_formats(&self) -> Vec<String> {
        crate::report_export::available_formats()
    }

    /// Compose the report for `target` and write it to `out_path` in `format`.
    /// Markdown and HTML always work; PDF/DOCX require pandoc (and, for PDF, a
    /// PDF engine).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if composition, format parsing, or the export
    /// (IO / external tool) fails.
    pub async fn export_report(
        &self,
        project: &Path,
        target: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        let markdown = self.generate_report(project, target).await?;
        let title = format!("oxfuzz report — {target}");
        crate::report_export::write_report(&markdown, &title, fmt, out_path)
    }

    /// Write already-composed report `markdown` (e.g. a saved draft) to
    /// `out_path` in `format`, without recomposing it.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on unknown format or export failure.
    pub fn export_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        crate::report_export::write_report(markdown, title, fmt, out_path)
    }

    /// Saved editable report drafts for the internal workbench.
    pub fn list_report_drafts(
        &self,
    ) -> Result<Vec<crate::report_store::ReportDraft>, ClassifiedError> {
        crate::report_store::list_report_drafts()
    }

    /// Save or update one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid input and storage errors for failed
    /// filesystem writes.
    pub fn save_report_draft(
        &self,
        id: Option<String>,
        title: &str,
        project: &str,
        target: Option<&str>,
        status: &str,
        content: &str,
    ) -> Result<crate::report_store::ReportDraft, ClassifiedError> {
        crate::report_store::save_report_draft(id, title, project, target, status, content)
    }

    /// Delete one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid ids and storage errors for failed
    /// filesystem deletion.
    pub fn delete_report_draft(&self, id: &str) -> Result<(), ClassifiedError> {
        crate::report_store::delete_report_draft(id)
    }

    /// Build a human-reviewable issue draft for a crash, targeting the fuzzed
    /// project's configured GitHub/GitLab repository.
    ///
    /// Non-publishing: it returns a title, Markdown body, labels, the provider,
    /// and a prefilled new-issue URL. Use [`Self::file_issue`] to actually file it.
    pub async fn issue_export(
        &self,
        project: &Path,
        crash_id: &str,
    ) -> Result<crate::workbench::IssueExport, ClassifiedError> {
        crate::workbench::issue_export(self.store.as_deref(), project, crash_id).await
    }

    /// Whether a usable issue-tracker integration is configured (provider + repo).
    #[must_use]
    pub fn issue_tracker_configured(&self) -> bool {
        crate::issue_tracker::is_configured()
    }

    /// Verify the issue-tracker URL + token without filing anything.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, tokenless, or the API rejects it.
    pub async fn issue_tracker_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::issue_tracker::load_config()?;
        let token = crate::issue_tracker::resolve_token(&cfg)?;
        let client = crate::issue_tracker::IssueTrackerClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// File a crash as an issue via the configured provider's API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the tracker is unconfigured, lacks a token,
    /// the crash is unknown, or the API rejects the request.
    pub async fn file_issue(
        &self,
        crash_id: &str,
    ) -> Result<crate::issue_tracker::CreatedIssue, ClassifiedError> {
        crate::workbench::file_issue(self.store.as_deref(), crash_id).await
    }

    /// Whether a usable `DefectDojo` config is present (for the settings UI to show
    /// a configured / not-configured state without attempting a push).
    #[must_use]
    pub fn defectdojo_configured(&self) -> bool {
        crate::defectdojo::is_configured()
    }

    /// The configured `DefectDojo` base URL (no trailing slash), or `None` when it
    /// is unconfigured / still the placeholder. Lets presentation layers open the
    /// web UI without hard-coding or re-reading the config themselves.
    #[must_use]
    pub fn defectdojo_url(&self) -> Option<String> {
        crate::defectdojo::load_config()
            .ok()
            .map(|c| c.url.trim_end_matches('/').to_owned())
    }

    /// Verify the configured `DefectDojo` URL + token by calling its API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, the token is missing, or the
    /// server is unreachable / rejects auth.
    pub async fn defectdojo_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// Push the latest run's triaged crashes to `DefectDojo` as findings.
    ///
    /// Reuses `crashes_for_latest_run` and the shared CWE/severity
    /// mapping so the `DefectDojo` push and the SARIF export never disagree. The
    /// product defaults to the project's directory name and the test to the
    /// target, so repeat pushes land in the same `DefectDojo` test and dedup.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, there are no crashes to push,
    /// or the `DefectDojo` request fails.
    pub async fn push_to_defectdojo(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<crate::defectdojo::PushOutcome, ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let crashes = self.crashes_for_latest_run(project, target).await?;
        if crashes.is_empty() {
            return Err(ClassifiedError::Validation(
                "no triaged crashes to push to DefectDojo".to_owned(),
            ));
        }
        let findings = crate::defectdojo::crashes_to_generic(&crashes);
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        let product_name = cfg
            .product_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| defectdojo_project_name(project));
        let engagement_name = cfg
            .engagement_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Fuzzing".to_owned());
        let test_title =
            Some(target.map_or_else(|| "oxfuzz".to_owned(), |t| format!("oxfuzz: {t}")));
        let import = crate::defectdojo::ImportTarget {
            product_name,
            product_type_name: cfg.resolved_product_type(),
            engagement_name,
            test_title,
            reimport: cfg.reimport,
            auto_create: cfg.auto_create,
            // This push carries only the latest run's crashes, not the target's
            // complete crash history, so it must not close still-open findings a
            // shorter/non-deterministic run happened not to rediscover.
            close_old_findings: false,
        };
        client.import(&import, &findings).await
    }
}
