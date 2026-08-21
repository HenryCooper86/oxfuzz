//! Crash triage, verification, and coverage queries.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_guardrails::Action;
use hf_storage::RunRecord;
use uuid::Uuid;

use super::coverage_cache::{coverage_signature, export_cache, parse_covered_functions};
use super::crash_inputs::{
    bucket_by_cluster, casrep_input_path, collect_casreps, collect_crash_inputs,
    collect_legacy_crash_inputs, deterministic_crash_id, is_regular_file, stage_crash_inputs,
};
use super::harness_workspace::{container_input_path, harness_binary_name};
use super::project_identity::{canonical_project_root, stored_project_matches};
use super::staging::{run_binary_path, run_output_dir, run_source_path};
use super::workspace::workspace_dir;
use super::{run_has_crash_evidence, LlmProviderBridge, RegressionResult, ServiceContainer};

impl ServiceContainer {
    async fn triage_run_record(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        const TRIAGE_BUDGET: std::time::Duration = std::time::Duration::from_mins(5);

        tokio::time::timeout(
            TRIAGE_BUDGET,
            self.triage_run_record_inner(project, target, run),
        )
        .await
        .map_err(|_| {
            ClassifiedError::Sandbox(format!(
                "triage exceeded its {} second end-to-end budget",
                TRIAGE_BUDGET.as_secs()
            ))
        })?
    }

    async fn triage_run_record_inner(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        /// Cap on LLM bug-report drafts per triage pass: a run may surface many
        /// distinct bugs, and one report each would fan out into hundreds of LLM
        /// calls. Crashes beyond the cap are still ingested and persisted, just
        /// without a drafted report.
        const MAX_BUG_REPORT_DRAFTS: usize = 20;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        self.authorize_recorded(Action::Triage, "triage_run", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let run_id = run.id;
        let engine = run.engine;
        let out_dir = run_output_dir(&workspace, &run)?;
        let run_binary = run_binary_path(&workspace, &run, target)?;
        let source_context = if run.harness_rev.is_some() {
            let source = run_source_path(&workspace, &run)?;
            std::fs::read_to_string(&source).ok()
        } else {
            None
        };

        // Prefer CASR: it reproduces each crash, classifies exploitability and
        // severity, and clusters/deduplicates -- all in the sandbox. Fall back to
        // the built-in reproduce/classify/dedup path when CASR is unavailable (no
        // harness binary, native runtime without casr, or the tool errored). The
        // captured sanitizer traces (`logs`) feed bug-report drafting; CASR-path
        // crashes carry their summary instead.
        let (mut deduped, mut logs): (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ) = match self
            .run_casr_triage(&workspace, &out_dir, &run_binary, engine, run_id, target_id)
            .await?
        {
            Some(crashes) if !crashes.is_empty() => (crashes, std::collections::HashMap::new()),
            _ => {
                self.legacy_triage(&out_dir, &workspace, &run_binary, engine, run_id, target_id)
                    .await?
            }
        };

        // Give each crash a deterministic id so persisting is idempotent: a
        // second triage of the same run replaces these rows instead of adding
        // duplicates (the report lists every persisted crash for the run).
        for crash in &mut deduped {
            crash.id = deterministic_crash_id(run_id, &crash.stack_signature, &crash.input_path);
        }

        // Persist the completed classification NOW, before the optional (and
        // slower) minimization and LLM bug-report phases. Those phases run under
        // the same end-to-end triage budget; without this early write, a run
        // with many crashes or a slow provider would time out mid-enrichment and
        // discard all classification, and because ids are deterministic the
        // re-run would time out identically -- triage could never persist. The
        // final upsert below re-writes the same rows with the enriched fields.
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }

        // Native minimizers execute against the immutable run-owned harness and
        // original crash input. Legacy records without binary digest evidence
        // remain triageable but cannot claim a verified minimized artifact.
        if run.binary_rev.is_some() {
            self.minimize_triaged_crashes(
                &workspace,
                run_id,
                engine,
                &run_binary,
                &mut deduped,
                &mut logs,
            )
            .await;
        }

        // Draft an LLM bug report for each unique crash when a provider is
        // configured, using the captured sanitizer trace (capped, see above).
        if let Some(pool) = self.provider_pool() {
            let unique = deduped.len();
            for crash in deduped.iter_mut().take(MAX_BUG_REPORT_DRAFTS) {
                let bridge = LlmProviderBridge::new(Arc::clone(&pool))
                    .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
                let log = logs
                    .get(&crash.input_path)
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| crash.summary.clone());
                // Augment the report prompt with related project context when
                // this project has been indexed; empty on any failure, which
                // renders the un-augmented prompt.
                let related =
                    crate::knowledge::triage_related_context(project, target, &crash.summary);
                let related_section = hf_prompt::render_related_context_section(&related);
                match hf_crash::draft_report_with_context(
                    crash,
                    &log,
                    source_context.as_deref(),
                    if related_section.is_empty() {
                        None
                    } else {
                        Some(related_section.as_str())
                    },
                    Box::new(bridge),
                )
                .await
                {
                    Ok(report) => crash.bug_report = Some(report),
                    Err(e) => tracing::warn!("bug report drafting failed for {}: {e}", crash.id),
                }
            }
            if unique > MAX_BUG_REPORT_DRAFTS {
                tracing::info!(
                    "capped bug-report drafting at {MAX_BUG_REPORT_DRAFTS} of {unique} unique crashes"
                );
            }
        }

        // Re-check immutable evidence after untrusted triage execution before
        // persisting any derived classification.
        let _ = run_binary_path(&workspace, &run, target)?;
        if run.harness_rev.is_some() {
            let _ = run_source_path(&workspace, &run)?;
        }
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }
        // Triage completed with classified crashes: fire event-driven
        // schedules listening for `crash.found`.
        if !deduped.is_empty() {
            self.emit_scheduler_event(
                crate::scheduler::EVENT_CRASH_FOUND,
                serde_json::json!({
                    "project": project.display().to_string(),
                    "target": target,
                    "run_id": run_id.to_string(),
                    "crashes": deduped.len(),
                }),
            )
            .await;
        }
        Ok(deduped)
    }

    async fn minimize_triaged_crashes(
        &self,
        workspace: &Path,
        run_id: Uuid,
        engine: EngineKind,
        binary: &Path,
        crashes: &mut [hf_core::crash::Crash],
        logs: &mut std::collections::HashMap<PathBuf, String>,
    ) {
        use crate::crash_minimization::{prepare, PreparedMinimization, MAX_CRASH_MINIMIZATIONS};
        let Ok(_workspace_operation) = self.acquire_workspace_operation().await else {
            tracing::warn!("crash minimization skipped because the workspace is unavailable");
            return;
        };

        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        for crash in crashes.iter_mut().take(MAX_CRASH_MINIMIZATIONS) {
            let original = crash.input_path.clone();
            let prepared = match prepare(workspace, run_id, engine, binary, &original, crash.id) {
                Ok(prepared) => prepared,
                Err(error) => {
                    tracing::warn!(
                        crash_id = %crash.id,
                        "crash minimization staging failed: {error}"
                    );
                    continue;
                }
            };
            let minimized = match prepared {
                PreparedMinimization::Unsupported => break,
                PreparedMinimization::Complete(path) => Some(path),
                PreparedMinimization::Run(run) => {
                    let result = self
                        .runtime
                        .run_command_opts(&run.command, workspace, &limits, &run.sandbox)
                        .await;
                    match result {
                        Ok(result)
                            if result.termination
                                == hf_core::runtime::CommandTermination::Completed
                                && result.exit_code == 0 =>
                        {
                            match run.publish() {
                                Ok(path) => Some(path),
                                Err(error) => {
                                    tracing::warn!(
                                        crash_id = %crash.id,
                                        "crash minimizer output was rejected: {error}"
                                    );
                                    None
                                }
                            }
                        }
                        Ok(result) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                termination = ?result.termination,
                                exit_code = result.exit_code,
                                "crash minimizer did not complete successfully"
                            );
                            None
                        }
                        Err(error) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                "crash minimizer failed: {error}"
                            );
                            None
                        }
                    }
                }
            };
            if let Some(path) = minimized {
                if let Some(log) = logs.get(&original).cloned() {
                    logs.insert(path.clone(), log);
                }
                crash.input_path = path;
                crash.minimized = true;
            }
        }
    }

    /// Fetch the raw `llvm-cov export` JSON for a target, cached per target by
    /// the corpus+harness signature. The covered-set, summary, and frontier
    /// accessors all parse from this one cached export, so the expensive (~180s)
    /// coverage pipeline runs at most once per signature rather than once per
    /// accessor. `None` when no C harness was built or the pipeline did not
    /// complete cleanly (a transient failure is not cached, so it retries).
    async fn coverage_export_json_cached(&self, project: &Path, target: &str) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        let workspace = workspace_dir(project, target);
        if !workspace.join("harness.c").exists() {
            return None;
        }
        let cache_key = format!("{}::{target}", project.display());
        let signature = coverage_signature(&workspace);
        if let Some((cached_sig, cached)) = export_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&cache_key).cloned())
        {
            if cached_sig == signature {
                return Some(cached);
            }
        }
        let json = self.run_coverage_export(&workspace).await?;
        if let Ok(mut map) = export_cache().lock() {
            map.insert(cache_key, (signature, json.clone()));
        }
        Some(json)
    }

    /// Run the C source-coverage pipeline (build with instrumentation -> replay
    /// the corpus -> `llvm-cov export`) in the sandbox for an already-resolved
    /// `workspace`, returning the raw export JSON. `None` when the pipeline does
    /// not complete cleanly (so the caller does not cache a transient failure).
    /// The caller holds the workspace-operation guard and has verified a harness
    /// exists. Prefer [`Self::coverage_export_json_cached`], which adds the
    /// guard, harness check, and per-signature cache.
    async fn run_coverage_export(&self, workspace: &Path) -> Option<String> {
        let pipeline = "clang -g -O1 -fsanitize=fuzzer -fprofile-instr-generate \
             -fcoverage-mapping *.c -o fuzz_cov 2>/dev/null \
             && LLVM_PROFILE_FILE=cov.profraw ./fuzz_cov -runs=0 corpus 2>/dev/null; \
             llvm-profdata merge -sparse cov.profraw -o cov.profdata 2>/dev/null \
             && llvm-cov export ./fuzz_cov -instr-profile=cov.profdata 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 180,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, workspace, &limits).await {
            Ok(result)
                if result.termination == hf_core::runtime::CommandTermination::Completed
                    && result.exit_code == 0 =>
            {
                Some(result.stdout)
            }
            Ok(result) => {
                tracing::warn!(
                    termination = ?result.termination,
                    exit_code = result.exit_code,
                    "coverage collection did not complete cleanly; not caching so it retries"
                );
                None
            }
            Err(e) => {
                tracing::warn!("coverage collection failed: {e}");
                None
            }
        }
    }

    /// Replay a single crash input through the compiled harness in the sandbox
    /// and return the combined stdout+stderr (the sanitizer trace). A forced
    /// stop or runtime failure is inconclusive and returns `None`.
    async fn reproduce_crash(
        &self,
        workspace: &Path,
        binary_host: &Path,
        input_host_path: &Path,
    ) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        if !binary_host.is_file() {
            return None;
        }
        let binary = container_input_path(workspace, binary_host);
        let container_input = container_input_path(workspace, input_host_path);
        let cmd = vec![binary, container_input];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 30,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            // A crashing input exits non-zero; the trace is the useful output.
            Ok(result) if result.termination == hf_core::runtime::CommandTermination::Completed => {
                Some(format!("{}\n{}", result.stdout, result.stderr))
            }
            Ok(result) => {
                tracing::warn!(termination = ?result.termination, "crash reproduction did not complete");
                None
            }
            Err(e) => {
                tracing::warn!("crash reproduction failed: {e}");
                None
            }
        }
    }

    /// Run CASR over the crash dir in the sandbox, returning one `Crash` per
    /// unique (clustered) report with its severity/analysis. Returns `None` when
    /// CASR is unavailable or produced nothing, so the caller can fall back.
    async fn run_casr_triage(
        &self,
        workspace: &Path,
        out_dir: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<Option<Vec<hf_core::crash::Crash>>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if !binary_host.is_file() {
            return Ok(None);
        }
        let binary = container_input_path(workspace, binary_host);
        if !out_dir.exists() {
            return Ok(None);
        }
        // CASR's input expectation differs by driver: `casr-afl` walks the AFL
        // output tree (out/<instance>/crashes/...), while `casr-libfuzzer` wants
        // a flat directory of crash inputs. For non-AFL engines we stage only
        // real crash inputs into a clean dir, since engines like honggfuzz mix
        // coverage maps and logs into `out` that CASR would otherwise replay.
        let crash_dir = if engine == EngineKind::AflPlusPlus {
            container_input_path(workspace, out_dir)
        } else {
            let staging = workspace
                .join("runs")
                .join(run_id.to_string())
                .join("triage")
                .join("casr_in");
            let _ = std::fs::remove_dir_all(&staging);
            if stage_crash_inputs(engine, out_dir, &staging) == 0 {
                return Ok(None);
            }
            container_input_path(workspace, &staging)
        };
        // Fresh CASR output directory each pass.
        let casr_host = workspace
            .join("runs")
            .join(run_id.to_string())
            .join("triage")
            .join("casr_out");
        let _ = std::fs::remove_dir_all(&casr_host);
        std::fs::create_dir_all(&casr_host).map_err(|error| {
            ClassifiedError::Internal(format!(
                "create CASR output directory {}: {error}",
                casr_host.display()
            ))
        })?;
        let casr_container = container_input_path(workspace, &casr_host);
        let cmd = hf_crash::casr_command(engine, &binary, &crash_dir, &casr_container, 30);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 240,
            env: std::collections::HashMap::new(),
            ptrace: true,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            extra_mounts: vec![hf_core::runtime::SandboxMount::writable(
                casr_host.clone(),
                casr_container.clone(),
            )],
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            Ok(r) if r.termination != hf_core::runtime::CommandTermination::Completed => {
                return Err(ClassifiedError::Sandbox(format!(
                    "CASR triage was force-stopped: {:?}",
                    r.termination
                )));
            }
            Ok(r) if r.exit_code != 0 => {
                tracing::warn!(
                    "casr exited {}: {}",
                    r.exit_code,
                    r.stderr.lines().last().unwrap_or_default()
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("casr run failed, falling back to built-in triage: {e}");
                return Ok(None);
            }
        }
        let reports = collect_casreps(&casr_host);
        if reports.is_empty() {
            tracing::info!("casr produced no reports; falling back to built-in triage");
            return Ok(None);
        }
        // The actual crash inputs, including AFL++'s nested
        // out/<instance>/crashes/ layout, so each casrep resolves to a real file.
        let crash_inputs = collect_crash_inputs(engine, out_dir);
        let mut crashes = reports
            .into_iter()
            .map(|(path, casr)| {
                let input_path = casrep_input_path(out_dir, &path, &crash_inputs);
                let signature = if casr.crashline.is_empty() {
                    casr.stack.first().cloned().unwrap_or_default()
                } else {
                    casr.crashline.clone()
                };
                let summary = if casr.severity_short.is_empty() {
                    casr.crashline.clone()
                } else {
                    format!("{} at {}", casr.severity_short, casr.crashline)
                };
                hf_core::crash::Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path,
                    stack_signature: signature,
                    kind: hf_crash::kind_from_short(&casr.severity_short),
                    summary,
                    minimized: false,
                    bug_report: None,
                    casr: Some(casr),
                    origin: hf_core::crash::CrashOrigin::Unknown,
                }
            })
            .collect::<Vec<_>>();
        // Bucket by CASR cluster: keep one representative per cluster (clusters
        // are CASR's own "same bug" grouping, stronger than our stack signature).
        // Crashes CASR did not cluster (cluster=None) all pass through.
        crashes = bucket_by_cluster(crashes);
        tracing::info!("casr triaged {} unique crash(es)", crashes.len());
        Ok(Some(crashes))
    }

    /// Built-in triage fallback: replay crashes in the sandbox until the set of
    /// distinct stack signatures saturates, classify, and dedup. Returns the
    /// deduped crashes plus captured sanitizer traces for bug-report drafting.
    async fn legacy_triage(
        &self,
        out_dir: &Path,
        workspace: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<
        (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ),
        ClassifiedError,
    > {
        /// Hard cap on sandbox crash replays per triage pass.
        const MAX_REPRODUCE: usize = 300;
        /// Stop reproducing after this many consecutive crashes with no new
        /// stack signature (the distinct-bug set has saturated).
        const SIGNATURE_STAGNATION: usize = 40;

        let ingested = hf_crash::ingest_for_engine(out_dir, engine, run_id, target_id)?;
        if ingested.is_truncated() {
            tracing::warn!(
                run_id = %run_id,
                artifact_limit_reached = ingested.artifact_limit_reached,
                report_limit_reached = ingested.report_limit_reached,
                "triage crash ingestion reached a safety limit"
            );
        }
        let crashes = ingested.crashes;
        let total_ingested = crashes.len();
        let mut logs: std::collections::HashMap<PathBuf, String> = std::collections::HashMap::new();
        let mut reproduced: Vec<hf_core::crash::Crash> = Vec::new();
        let mut seen_signatures: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut since_new_signature = 0usize;
        for mut crash in crashes {
            if reproduced.len() >= MAX_REPRODUCE || since_new_signature >= SIGNATURE_STAGNATION {
                break;
            }
            let log = self
                .reproduce_crash(workspace, binary_host, &crash.input_path)
                .await;
            if log.as_deref().is_none_or(|value| value.trim().is_empty()) {
                since_new_signature += 1;
            } else if let Some(log) = log.as_deref() {
                let (kind, sig, summary) = hf_crash::classify(log);
                crash.kind = kind;
                crash.summary = summary;
                if seen_signatures.insert(sig.clone()) {
                    since_new_signature = 0;
                } else {
                    since_new_signature += 1;
                }
                crash.stack_signature = sig;
            }
            if let Some(log) = log {
                logs.insert(crash.input_path.clone(), log);
            }
            reproduced.push(crash);
        }
        if reproduced.len() < total_ingested {
            tracing::info!(
                "reproduced {} of {total_ingested} crash inputs ({} distinct signatures) before saturating",
                reproduced.len(),
                seen_signatures.len()
            );
        }
        Ok((hf_crash::dedup(reproduced), logs))
    }

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
