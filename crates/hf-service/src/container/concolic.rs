//! The sandboxed concolic enrichment pass.
//!
//! Every step goes through `hf-runtime` (AGENTS.md 2.12): an instrumented build
//! of an untrusted project is untrusted code.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use hf_core::harness::HarnessStatus;

use crate::concolic::{
    select_inputs, summarize, ConcolicAvailability, ConcolicOutcome, ConcolicStopReason,
};
use crate::container::crash_inputs::is_regular_file;
use crate::container::harness_workspace::read_current_harness_source;
use crate::container::workspace::{prepare_configured_workspace_root, workspace_dir};
use crate::container::ServiceContainer;
use crate::ClassifiedError;

/// A standalone driver so a libFuzzer-style harness can be explored.
///
/// `SymCC` needs a program that reads one input and exits. The generated
/// harness exposes `LLVMFuzzerTestOneInput`, so the pass stages this `main`
/// beside it.
const DRIVER_SOURCE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    if (argc < 2) { return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { return 1; }
    static uint8_t buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
"#;

/// The name of the output directory, relative to the target workspace.
const OUTPUT_DIR: &str = "concolic-out";

/// What the exploration loop actually did, as opposed to what it set out to do.
struct ExplorationRecord {
    /// Inputs the solver produced during this pass.
    solved: Vec<Vec<u8>>,
    /// Selected inputs the loop actually ran. Never the selection count: a
    /// deadline that expires before or during the loop leaves the rest
    /// unexplored, and reporting them as explored would present a pass that
    /// did nothing as a full one.
    explored: usize,
    /// Which bound ended the loop.
    stop: ConcolicStopReason,
}

impl ServiceContainer {
    /// Whether the sandbox image carries the `SymCC` wrapper.
    ///
    /// A bounded probe that runs no target. It asks the wrapper for its
    /// presence rather than only checking that the image exists:
    /// `image_present` defaults to `true` for adapters with no image concept,
    /// so an image check alone would report `SymCC` available on a native or
    /// stub runtime that has never heard of it.
    ///
    /// The probe runs in the approved workspace root. A container runtime
    /// resolves a relative working directory against the process directory and
    /// then refuses it for resolving outside that root, so a relative cwd would
    /// make the probe answer `Unavailable` on a correctly built image and take
    /// the whole subsystem down with it.
    pub async fn concolic_availability(&self) -> ConcolicAvailability {
        let Ok(root) = prepare_configured_workspace_root() else {
            return ConcolicAvailability::Unavailable {
                reason: "workspace_root_unavailable".to_owned(),
            };
        };
        let cmd = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "command -v symcc >/dev/null 2>&1".to_owned(),
        ];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 512,
            max_cpus: 1,
            max_duration_secs: 30,
            env: HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, &root, &limits).await {
            Ok(result)
                if result.termination == hf_core::runtime::CommandTermination::Completed
                    && result.exit_code == 0 =>
            {
                ConcolicAvailability::Available
            }
            _ => ConcolicAvailability::Unavailable {
                reason: "symcc_absent_from_sandbox".to_owned(),
            },
        }
    }

    /// Run one bounded concolic enrichment pass over the target's corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the toolchain is unavailable,
    /// the bounds are invalid, or the target has no promoted harness to
    /// instrument, and `ClassifiedError::Sandbox` when the instrumented build
    /// does not produce a binary. A build failure is always an error:
    /// reporting it as a completed pass that solved nothing would be
    /// indistinguishable from a pass that legitimately solved nothing
    /// (`docs/design/concolic-enrichment-design.md` section 9).
    pub async fn corpus_concolic(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<ConcolicOutcome, ClassifiedError> {
        // The pass builds into, and writes into, the shared workspace, so it
        // takes the same lease every sibling corpus operation takes.
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if let ConcolicAvailability::Unavailable { reason } = self.concolic_availability().await {
            return Err(ClassifiedError::Validation(format!(
                "concolic enrichment is unavailable: {reason}"
            )));
        }
        // An invalid manually-edited bound fails closed rather than silently
        // reverting to a policy the operator did not choose.
        let settings = crate::config::effective_concolic_settings()
            .map_err(|e| ClassifiedError::Validation(format!("concolic bounds: {e}")))?;

        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        self.require_promoted_harness(project, target, &workspace)
            .await?;

        let corpus_dir = workspace.join("corpus");
        let mut inputs: Vec<PathBuf> = std::fs::read_dir(&corpus_dir)
            .map_err(|e| ClassifiedError::Validation(format!("read corpus: {e}")))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        // Retained order, so two passes over identical state agree.
        inputs.sort();
        let existing: HashSet<String> = inputs
            .iter()
            .filter_map(|p| std::fs::read(p).ok())
            .map(|bytes| crate::concolic::content_digest(&bytes))
            .collect();
        // The same measure on both sides of the fold, so a difference between
        // them is growth and never a change of counting method.
        let corpus_size_before = hf_corpus::list(&corpus_dir)?.entries.len();

        let (selected, skipped_by_cap) = select_inputs(&inputs, &settings);
        std::fs::write(workspace.join("symcc_driver.c"), DRIVER_SOURCE)
            .map_err(|e| ClassifiedError::Validation(format!("stage driver: {e}")))?;

        let record = self
            .run_concolic_pass(&workspace, &selected, &settings)
            .await?;

        // Inputs the pass selected but never reached are skipped, whatever
        // dropped them. `explored + skipped` then still accounts for the whole
        // corpus rather than quietly losing the difference.
        let dropped = selected.len() - record.explored;
        let skipped = skipped_by_cap + dropped;
        let stop = match record.stop {
            // Nothing ended the loop from inside it, so the selection bound is
            // what limited the pass -- if it limited anything at all.
            ConcolicStopReason::CorpusExhausted if skipped_by_cap > 0 => {
                ConcolicStopReason::InputCap
            }
            other => other,
        };

        // Novel inputs are written into the corpus directory and persisted
        // through the existing corpus path, so every later consumer sees them
        // as ordinary corpus entries (spec section 4 step 4).
        let mut novel_written = 0usize;
        for bytes in &record.solved {
            let digest = crate::concolic::content_digest(bytes);
            if existing.contains(&digest) {
                continue;
            }
            if novel_written >= settings.max_solved_inputs {
                break;
            }
            let path = corpus_dir.join(format!("concolic-{digest}.bin"));
            if std::fs::write(&path, bytes).is_ok() {
                novel_written += 1;
            }
        }
        let grown = hf_corpus::list(&corpus_dir)?;
        let corpus_size_after = grown.entries.len();
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let mut persisted = grown;
        persisted.target_id = target_id;
        self.persist_corpus(target_id, &persisted).await?;

        Ok(summarize(
            record.explored,
            skipped,
            &record.solved,
            &existing,
            &settings,
            stop,
        )
        .with_corpus_sizes(corpus_size_before, corpus_size_after))
    }

    /// Confirm the target has a promoted harness, and that its C source is
    /// staged for the instrumented build.
    ///
    /// Spec section 4 step 1: a target with no promoted harness has nothing to
    /// instrument, and the pass reports that rather than instrumenting a draft.
    /// Promotion is persisted state rather than a workspace file, so the check
    /// is against the store and is bound to the exact revision staged in the
    /// workspace -- a concolic pass is not a way around human promotion.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` naming what is missing: the store,
    /// the staged harness, the promotion, or the C source the build compiles.
    async fn require_promoted_harness(
        &self,
        project: &Path,
        target: &str,
        workspace: &Path,
    ) -> Result<(), ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "concolic enrichment requires the persistent service store to confirm that a \
                 harness was promoted"
                    .to_owned(),
            )
        })?;
        let source = read_current_harness_source(workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "concolic enrichment needs a promoted harness for '{target}'; none is staged in \
                 the workspace"
            ))
        })?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let harnesses = store
            .list_harnesses(target_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        if !harnesses
            .iter()
            .any(|harness| harness.status == HarnessStatus::Promoted && harness.source == source)
        {
            return Err(ClassifiedError::Validation(format!(
                "concolic enrichment requires an explicitly promoted harness for '{target}'; the \
                 staged revision is not promoted, and instrumenting a draft would route around \
                 the human approval that promotion records"
            )));
        }
        // The build compiles `harness.c`; a promoted record whose C source is
        // absent must be diagnosed here rather than surfacing as "instrumented
        // build did not complete".
        let harness_c = workspace.join("harness.c");
        if !is_regular_file(&harness_c) {
            return Err(ClassifiedError::Validation(format!(
                "concolic enrichment found no harness.c to instrument for '{target}' at {}; \
                 compile the promoted harness first",
                harness_c.display()
            )));
        }
        Ok(())
    }

    /// Build the instrumented binary and explore each selected input.
    ///
    /// `SYMCC_INPUT_FILE` is set for every exploration and is not optional:
    /// `SymCC` marks only stdin symbolic by default, so a file-reading harness
    /// run without it solves nothing, writes nothing, and exits zero.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Sandbox` when the instrumented build does not
    /// complete successfully. A build failure is never folded into an `Ok`
    /// result: doing so would report a pass that never ran as one that ran
    /// and solved nothing, which is indistinguishable from a legitimate empty
    /// result (`docs/design/concolic-enrichment-design.md` section 9).
    async fn run_concolic_pass(
        &self,
        workspace: &Path,
        selected: &[PathBuf],
        settings: &crate::config::ConcolicSettings,
    ) -> Result<ExplorationRecord, ClassifiedError> {
        // One deadline for the whole pass, fixed before the build starts.
        // Spec section 5 bounds the whole pass, not only the explore loop:
        // giving the build its own full `total_timeout_secs` and then handing
        // the explore loop a second, freshly-started budget let the worst
        // case run to roughly twice the configured bound.
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(settings.total_timeout_secs);

        let build = vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "symcc -O1 harness.c symcc_driver.c -o concolic_target".to_owned(),
        ];
        let build_limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_secs(),
            env: HashMap::new(),
            ptrace: false,
        };
        match self
            .runtime
            .run_command(&build, workspace, &build_limits)
            .await
        {
            Ok(result)
                if result.termination == hf_core::runtime::CommandTermination::Completed
                    && result.exit_code == 0 => {}
            Ok(result) => {
                return Err(ClassifiedError::Sandbox(format!(
                    "concolic instrumented build did not complete: termination={:?}, exit_code={}",
                    result.termination, result.exit_code
                )));
            }
            Err(error) => {
                return Err(ClassifiedError::Sandbox(format!(
                    "concolic instrumented build failed: {error}"
                )));
            }
        }

        // The output directory is read wholesale below, so an earlier pass's
        // files left in it would be counted as this pass's solutions: a pass
        // that solved nothing could report a large `inputs_solved`. Reset it
        // here, immediately before the loop that fills it.
        let out_dir = workspace.join(OUTPUT_DIR);
        reset_output_dir(&out_dir)?;

        let mut solved: Vec<Vec<u8>> = Vec::new();
        let mut collected: HashSet<PathBuf> = HashSet::new();
        let mut explored = 0usize;
        // The build can itself consume the whole pass budget, so the deadline
        // is checked before the loop body runs at all: a pass with no time
        // left to explore reports `TotalTimeout` rather than `CorpusExhausted`.
        let mut stop = ConcolicStopReason::CorpusExhausted;
        for input in selected {
            if std::time::Instant::now() >= deadline {
                stop = ConcolicStopReason::TotalTimeout;
                break;
            }
            // Checked after the deadline so a pass that ran out of time is
            // reported as the timeout it was, never as a cap that had merely
            // truncated the collection.
            if solved.len() >= settings.max_solved_inputs {
                stop = ConcolicStopReason::SolvedInputCap;
                break;
            }
            let Some(name) = input.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let mut env = HashMap::new();
            env.insert("SYMCC_OUTPUT_DIR".to_owned(), OUTPUT_DIR.to_owned());
            env.insert("SYMCC_INPUT_FILE".to_owned(), format!("corpus/{name}"));
            let limits = hf_core::runtime::ResourceLimits {
                max_mem_mb: 4096,
                max_cpus: 1,
                max_duration_secs: settings.per_input_timeout_secs,
                env,
                ptrace: false,
            };
            let cmd = vec!["./concolic_target".to_owned(), format!("corpus/{name}")];
            // An input that times out or faults is one input's loss, not
            // the pass's: the loop continues and the outcome counts what
            // was found.
            let _ = self.runtime.run_command(&cmd, workspace, &limits).await;
            explored += 1;
            collect_solved(&out_dir, &mut collected, &mut solved);
        }

        Ok(ExplorationRecord {
            solved,
            explored,
            stop,
        })
    }
}

/// Empty the solver's output directory so one pass reads only its own results.
fn reset_output_dir(out_dir: &Path) -> Result<(), ClassifiedError> {
    if out_dir.exists() {
        std::fs::remove_dir_all(out_dir).map_err(|e| {
            ClassifiedError::Validation(format!(
                "clear concolic output dir {}: {e}",
                out_dir.display()
            ))
        })?;
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| ClassifiedError::Validation(format!("stage output dir: {e}")))
}

/// Read whatever the solver has written since the last look.
///
/// Collecting inside the loop rather than once at the end is what makes
/// `max_solved_inputs` a bound the pass can stop on instead of a truncation
/// applied to a finished collection (spec sections 5 and 6).
fn collect_solved(out_dir: &Path, collected: &mut HashSet<PathBuf>, solved: &mut Vec<Vec<u8>>) {
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file() && !collected.contains(path))
        .collect();
    paths.sort();
    for path in paths {
        if let Ok(bytes) = std::fs::read(&path) {
            solved.push(bytes);
            collected.insert(path);
        }
    }
}
