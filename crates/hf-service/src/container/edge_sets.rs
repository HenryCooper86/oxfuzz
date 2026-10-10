//! Per-run covered edge sets and exact run-to-run edge diffs.
//!
//! A run's edge set is the union of AFL coverage-map offsets its retained
//! run-local corpus (`runs/<id>/corpus`) exercises, replayed through
//! `afl-showmap` against the run's exact staged, digest-pinned binary. Capture
//! happens best-effort at run end (journaled, never failing the run), on
//! demand (`oxfuzz runs capture-edges`), or as the closeout ladder's
//! `EdgeSet` step. The retained bitmap answers "run B lost which edges run A
//! had" — the question an edge-count delta cannot answer.
//!
//! `afl-showmap` measures AFL-instrumented binaries only, so capture applies
//! to AFL++ runs; other engines skip with a named reason (their harnesses are
//! built with `-fsanitize=fuzzer` or `hfuzz-cc`, which produce no AFL map).

use std::path::{Path, PathBuf};

use hf_core::coverage::EdgeSet;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_guardrails::Action;
use hf_storage::{RunEdgeSetRecord, RunKind, RunRecord, RunStatus};
use uuid::Uuid;

use super::crash_inputs::is_regular_file;
use super::harness_workspace::container_input_path;
use super::project_identity::{retained_run_target_selector, stored_project_matches};
use super::staging::run_binary_path;
use super::workspace::{resolve_workspace_directory, workspace_dir};
use super::{resolve_internal_run, ServiceContainer, EXACT_DOCKER_IMAGE_REV_PREFIX};

/// One closeout/afl-showmap capture replays at most this many corpus inputs,
/// mirroring the coverage-prune and seed-survival bounds.
const EDGE_SET_CAPTURE_MAX_INPUTS: usize = 10_000;
/// Wall-clock budget for one edge-set capture operation.
const EDGE_SET_CAPTURE_OPERATION_SECS: u64 = 600;
/// Per-input `afl-showmap` budget.
const EDGE_SET_CAPTURE_COMMAND_SECS: u64 = 10;
/// How many ids of each exclusive side a diff report samples. Counts are
/// exact regardless; the samples exist so a human can spot-check what moved.
const EDGE_DIFF_SAMPLE_CAP: usize = 64;

/// What an on-demand edge-set capture produced (or already had retained).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunEdgeSetCapture {
    /// The measured run.
    pub run_id: Uuid,
    /// SHA-256 of the exact staged executable the set was measured with.
    pub binary_sha256: String,
    /// Corpus inputs replayed.
    pub inputs: u64,
    /// Covered AFL map offsets.
    pub edges: u64,
    /// RFC 3339 collection time.
    pub collected_at: String,
    /// `true` when the run already retained a set: nothing was re-measured
    /// (retained evidence is immutable).
    pub already_retained: bool,
}

/// Exact set arithmetic between two runs' retained edge sets.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CoverageDiffReport {
    /// Baseline run.
    pub run_a: Uuid,
    /// Compared run.
    pub run_b: Uuid,
    /// Whether both runs measured the same staged executable. AFL assigns
    /// edge ids per build, so with different binaries the id-level samples
    /// conflate coverage change with id reassignment; the counts still answer
    /// how much the covered set moved.
    pub same_binary: bool,
    /// Edges the baseline covered.
    pub edges_a: u64,
    /// Edges the compared run covered.
    pub edges_b: u64,
    /// Edges only the baseline covered (lost by the compared run).
    pub only_a: u64,
    /// Edges only the compared run covered (gained over the baseline).
    pub only_b: u64,
    /// Edges both runs covered.
    pub common: u64,
    /// Edges either run covered.
    pub union: u64,
    /// Lowest ids exclusive to the baseline (capped at `sample_cap`).
    pub only_a_sample: Vec<u64>,
    /// Lowest ids exclusive to the compared run (capped at `sample_cap`).
    pub only_b_sample: Vec<u64>,
    /// The cap applied to both samples.
    pub sample_cap: usize,
}

/// Why this run can never carry a measured edge set, in operator terms, if it
/// cannot. These are permanent properties of the run record, so closeout maps
/// them to a terminal skip rather than a retryable failure.
fn edge_set_capture_block(run: &RunRecord) -> Option<String> {
    if run.kind != RunKind::Campaign {
        return Some(format!(
            "run '{}' is a {:?} run; edge sets are captured for campaign runs",
            run.id, run.kind
        ));
    }
    if !matches!(
        run.status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
    ) {
        return Some(format!(
            "run '{}' is still in flight; its edge set can be captured once the run is terminal",
            run.id
        ));
    }
    if run.engine != EngineKind::AflPlusPlus {
        return Some(format!(
            "run '{}' ran {}; edge-set capture replays the retained corpus through afl-showmap, \
             which measures AFL++-instrumented binaries only",
            run.id,
            run.engine.as_str()
        ));
    }
    if run.binary_rev.is_none() || run.sandbox_rev.is_none() || run.config.is_none() {
        return Some(format!(
            "run '{}' predates retained execution evidence (staged binary and image digests); \
             re-run the campaign to capture an edge set",
            run.id
        ));
    }
    None
}

/// The error `coverage_diff` returns for a run without a retained edge set:
/// names the run and how to capture one (Engineering Protocol 2.16).
fn missing_edge_set(run_id: Uuid) -> ClassifiedError {
    ClassifiedError::Validation(format!(
        "run {run_id} has no captured edge set; capture one with `oxfuzz runs capture-edges \
         {run_id}` (requires the run's retained corpus and binary to still be staged), or re-run \
         the campaign with this oxfuzz version"
    ))
}

impl ServiceContainer {
    /// The project and target selector a run's retained evidence is staged
    /// under, resolved through its persisted harness (`run.config.harness_id
    /// -> harness.target_id`) rather than re-discovery.
    pub(in crate::container) async fn run_capture_scope(
        &self,
        run: &RunRecord,
    ) -> Result<(PathBuf, String), ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("edge-set capture requires the persistent store".to_owned())
        })?;
        let harness_id = run
            .config
            .as_ref()
            .map(|config| config.harness_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run '{}' retained no harness-backed target",
                    run.id
                ))
            })?;
        let harness = store
            .get_harness(harness_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run '{}' names an unknown harness", run.id))
            })?;
        let targets = store
            .list_all_targets()
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let target = targets
            .into_iter()
            .find(|candidate| candidate.id == harness.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run '{}' names an unknown target", run.id))
            })?;
        if !stored_project_matches(&target.project_root, Path::new(&run.project_root)) {
            return Err(ClassifiedError::Validation(format!(
                "run '{}' target project does not match its retained project",
                run.id
            )));
        }
        let selector = retained_run_target_selector(run, &target)?;
        Ok((PathBuf::from(&run.project_root), selector))
    }

    /// Measure one run's covered edge set by replaying its retained run-local
    /// corpus through `afl-showmap` in the sandbox, against the run's exact
    /// staged binary (digest-checked) and recorded sandbox image.
    ///
    /// A corpus input whose replay crashes still contributes the edges it
    /// covered up to the crash (`afl-showmap` prints the partial map); a
    /// sandbox or deadline failure aborts the measurement. A run whose inputs
    /// collectively produce no edge at all fails loud: its binary is not
    /// AFL-instrumented or cannot execute them, and an empty set would
    /// silently poison every later diff.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when the run's retained evidence is missing
    /// or inconsistent, the corpus exceeds the capture bounds, or the sandbox
    /// measurement fails.
    async fn measure_run_edge_set(
        &self,
        run: &RunRecord,
        target: &str,
        resolved: &crate::config::ResolvedFuzzingRun,
    ) -> Result<RunEdgeSetRecord, ClassifiedError> {
        let workspace = workspace_dir(Path::new(&run.project_root), target);
        let corpus_relative = PathBuf::from("runs")
            .join(run.id.to_string())
            .join("corpus");
        let corpus_dir =
            resolve_workspace_directory(&workspace, &corpus_relative).map_err(|_| {
                ClassifiedError::Validation(format!(
                    "run '{}' retained corpus directory is no longer staged",
                    run.id
                ))
            })?;
        // Digest-pinned: a staged binary that changed since the run fails here.
        run_binary_path(&workspace, run, target)?;
        let binary_sha256 = run.binary_rev.clone().ok_or_else(|| {
            ClassifiedError::Validation(format!("run '{}' has no staged binary digest", run.id))
        })?;
        let sandbox_rev = run.sandbox_rev.clone().ok_or_else(|| {
            ClassifiedError::Validation(format!("run '{}' has no sandbox image identity", run.id))
        })?;
        let image_digest = sandbox_rev
            .strip_prefix(EXACT_DOCKER_IMAGE_REV_PREFIX)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run '{}' sandbox image identity is not content-addressed",
                    run.id
                ))
            })?;
        let corpus = hf_corpus::list(&corpus_dir)?;
        if corpus.entries.is_empty() {
            return Err(ClassifiedError::Validation(format!(
                "run '{}' retained no corpus inputs to measure",
                run.id
            )));
        }
        if corpus.entries.len() > EDGE_SET_CAPTURE_MAX_INPUTS {
            return Err(ClassifiedError::Validation(format!(
                "edge-set capture is limited to {EDGE_SET_CAPTURE_MAX_INPUTS} corpus inputs; run '{}' retained {}",
                run.id,
                corpus.entries.len()
            )));
        }
        let mut entries: Vec<_> = corpus.entries.iter().collect();
        entries.sort_by(|left, right| left.path.cmp(&right.path));

        let binary_container = format!("/work/runs/{}/input/harness", run.id);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            max_duration_secs: EDGE_SET_CAPTURE_COMMAND_SECS.min(resolved.duration_secs),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            image: Some(format!("sha256:{image_digest}")),
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(resolved.duration_secs);
        let mut set = EdgeSet::new();
        let mut replayed = 0_u64;
        for entry in entries {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return Err(ClassifiedError::Sandbox(
                    "edge-set capture exceeded its 10-minute operation budget".to_owned(),
                ));
            };
            let input_container = container_input_path(&workspace, &entry.path);
            let args = hf_engine::showmap::build_showmap_args(&binary_container, &input_container);
            let result = tokio::time::timeout(
                remaining,
                self.runtime
                    .run_command_opts(&args, &workspace, &limits, &sandbox),
            )
            .await
            .map_err(|_| {
                ClassifiedError::Sandbox(
                    "edge-set capture exceeded its 10-minute operation budget".to_owned(),
                )
            })?;
            let result = result?.require_completed("AFL++ edge-set capture")?;
            hf_engine::showmap::fold_showmap_into_edge_set(&mut set, &result.stdout)?;
            replayed += 1;
        }
        if set.count() == 0 {
            return Err(ClassifiedError::Validation(format!(
                "no replayed input of run '{}' produced a coverage edge; the run's binary is not \
                 AFL-instrumented or cannot execute its retained inputs",
                run.id
            )));
        }
        Ok(RunEdgeSetRecord {
            run_id: run.id,
            binary_sha256,
            sandbox_rev,
            inputs: replayed,
            edge_count: set.count(),
            edge_map: set.as_bytes().to_vec(),
            collected_at: chrono::Utc::now(),
        })
    }

    /// Capture and retain one run's covered edge set on demand. A run that
    /// already retains one is reported without re-measurement: retained
    /// evidence is immutable.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` naming the reason when the run is
    /// ineligible (not a terminal AFL++ campaign, predates retained digests)
    /// or its staged evidence is gone; `ClassifiedError::Sandbox` when the
    /// measurement fails.
    pub async fn capture_run_edge_set(
        &self,
        run_id: Uuid,
    ) -> Result<RunEdgeSetCapture, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("edge-set capture requires the persistent store".to_owned())
        })?;
        let run = self.run_record(run_id).await?;
        if let Some(reason) = edge_set_capture_block(&run) {
            return Err(ClassifiedError::Validation(reason));
        }
        if let Some(existing) = store
            .run_edge_set(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        {
            return Ok(RunEdgeSetCapture {
                run_id,
                binary_sha256: existing.binary_sha256,
                inputs: existing.inputs,
                edges: existing.edge_count,
                collected_at: existing.collected_at.to_rfc3339(),
                already_retained: true,
            });
        }
        let (project, target) = self.run_capture_scope(&run).await?;
        let resolved =
            resolve_internal_run(EngineKind::AflPlusPlus, EDGE_SET_CAPTURE_OPERATION_SECS)?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "AFL++ showmap".to_owned(),
                duration_secs: resolved.duration_secs,
            },
            "run_edge_set_capture",
            Some(&project),
        )
        .await?;
        let record = self.measure_run_edge_set(&run, &target, &resolved).await?;
        store
            .record_run_edge_set(&record)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(RunEdgeSetCapture {
            run_id,
            binary_sha256: record.binary_sha256,
            inputs: record.inputs,
            edges: record.edge_count,
            collected_at: record.collected_at.to_rfc3339(),
            already_retained: false,
        })
    }

    /// Best-effort edge-set capture at run end. Failure is journaled and
    /// logged, never propagated: a capture problem must not fail the run that
    /// produced the evidence (the closeout `EdgeSet` step or
    /// `oxfuzz runs capture-edges` can measure later).
    ///
    /// No new guardrail action is taken: the replay is part of the run's own
    /// already-authorized sandboxed execution, exactly like terminal function
    /// coverage collection.
    pub(in crate::container) async fn close_run_edge_set(&self, run: &RunRecord, target: &str) {
        // Only AFL++ binaries produce an AFL map for afl-showmap; the run
        // record at this point always carries its digests and config.
        if run.engine != EngineKind::AflPlusPlus {
            return;
        }
        let Some(store) = self.store().cloned() else {
            return;
        };
        let result = async {
            let resolved =
                resolve_internal_run(EngineKind::AflPlusPlus, EDGE_SET_CAPTURE_OPERATION_SECS)?;
            let record = self.measure_run_edge_set(run, target, &resolved).await?;
            store
                .record_run_edge_set(&record)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))
        }
        .await;
        if let Err(error) = result {
            self.run_journal
                .note(run.id, "edge_set_capture_unavailable", &error.to_string());
            tracing::warn!(run_id = %run.id, %error, "run edge-set capture is unavailable");
        }
    }

    /// The closeout ladder's edge-set step: reuse the retained set when one
    /// exists, otherwise measure and retain it. A run whose staged corpus or
    /// binary is gone skips (the evidence is permanently unavailable); a
    /// measurement failure is recorded failed and retried by a later closeout.
    pub(in crate::container) async fn closeout_edge_set(
        &self,
        run_id: Uuid,
        target: &str,
    ) -> crate::run_closeout::StepOutcome {
        use crate::run_closeout::StepOutcome;

        let Some(store) = self.store() else {
            return StepOutcome::Failed {
                error: "no persistent store".to_owned(),
            };
        };
        let run = match self.run_record(run_id).await {
            Ok(run) => run,
            Err(error) => {
                return StepOutcome::Failed {
                    error: error.to_string(),
                };
            }
        };
        if let Some(reason) = edge_set_capture_block(&run) {
            return StepOutcome::Skipped { reason };
        }
        match store.run_edge_set(run_id).await {
            Err(error) => {
                return StepOutcome::Failed {
                    error: error.to_string(),
                };
            }
            Ok(Some(record)) => {
                return StepOutcome::Completed {
                    detail: format!(
                        "edge set retained: {} edges from {} inputs",
                        record.edge_count, record.inputs
                    ),
                };
            }
            Ok(None) => {}
        }
        let workspace = workspace_dir(Path::new(&run.project_root), target);
        let run_root = workspace.join("runs").join(run_id.to_string());
        if !run_root.join("corpus").is_dir() {
            return StepOutcome::Skipped {
                reason: "the run's retained corpus directory is no longer staged".to_owned(),
            };
        }
        if !is_regular_file(&run_root.join("input").join("harness")) {
            return StepOutcome::Skipped {
                reason: "the run's retained harness binary is no longer staged".to_owned(),
            };
        }
        let resolved =
            match resolve_internal_run(EngineKind::AflPlusPlus, EDGE_SET_CAPTURE_OPERATION_SECS) {
                Ok(resolved) => resolved,
                Err(error) => {
                    return StepOutcome::Failed {
                        error: error.to_string(),
                    };
                }
            };
        let _workspace_operation = match self.acquire_workspace_operation().await {
            Ok(lease) => lease,
            Err(error) => {
                return StepOutcome::Failed {
                    error: error.to_string(),
                };
            }
        };
        match self.measure_run_edge_set(&run, target, &resolved).await {
            Ok(record) => {
                let detail = format!(
                    "captured {} edges from {} corpus inputs",
                    record.edge_count, record.inputs
                );
                match store.record_run_edge_set(&record).await {
                    Ok(()) => StepOutcome::Completed { detail },
                    Err(error) => StepOutcome::Failed {
                        error: error.to_string(),
                    },
                }
            }
            Err(error) => StepOutcome::Failed {
                error: error.to_string(),
            },
        }
    }

    /// Exact edge-set diff between two retained runs of the same project:
    /// `a` is the baseline, `b` the compared run. Counts are exact; each
    /// exclusive side also carries its lowest ids, capped at
    /// `sample_cap` in the report.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the ids are identical, name
    /// different projects, or either run lacks a captured edge set (the error
    /// names how to capture one).
    pub async fn coverage_diff(
        &self,
        run_a: Uuid,
        run_b: Uuid,
    ) -> Result<CoverageDiffReport, ClassifiedError> {
        if run_a == run_b {
            return Err(ClassifiedError::Validation(
                "select two distinct runs".to_owned(),
            ));
        }
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("coverage diff requires the persistent store".to_owned())
        })?;
        let first = self.run_record(run_a).await?;
        let second = self.run_record(run_b).await?;
        if !stored_project_matches(
            Path::new(&first.project_root),
            Path::new(&second.project_root),
        ) {
            return Err(ClassifiedError::Validation(
                "select two runs from the same project".to_owned(),
            ));
        }
        let set_a = store
            .run_edge_set(run_a)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| missing_edge_set(run_a))?;
        let set_b = store
            .run_edge_set(run_b)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| missing_edge_set(run_b))?;
        let map_a = EdgeSet::from_bytes(&set_a.edge_map)?;
        let map_b = EdgeSet::from_bytes(&set_b.edge_map)?;
        let diff = map_a.diff(&map_b, EDGE_DIFF_SAMPLE_CAP);
        Ok(CoverageDiffReport {
            run_a,
            run_b,
            same_binary: set_a.binary_sha256 == set_b.binary_sha256,
            edges_a: set_a.edge_count,
            edges_b: set_b.edge_count,
            only_a: diff.only_a,
            only_b: diff.only_b,
            common: diff.common,
            union: diff.union,
            only_a_sample: diff.only_a_sample,
            only_b_sample: diff.only_b_sample,
            sample_cap: EDGE_DIFF_SAMPLE_CAP,
        })
    }
}
