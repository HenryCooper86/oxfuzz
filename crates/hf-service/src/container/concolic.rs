//! The sandboxed concolic enrichment pass.
//!
//! Every step goes through `hf-runtime` (AGENTS.md 2.12): an instrumented build
//! of an untrusted project is untrusted code.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::concolic::{
    content_digest, select_inputs, summarize_with_corpus, ConcolicAvailability, ConcolicOutcome,
    ConcolicStopReason,
};
use crate::container::workspace::workspace_dir;
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

impl ServiceContainer {
    /// Whether the sandbox image carries the `SymCC` wrapper.
    ///
    /// A bounded probe that runs no target. It asks the wrapper for its
    /// presence rather than only checking that the image exists:
    /// `image_present` defaults to `true` for adapters with no image concept,
    /// so an image check alone would report `SymCC` available on a native or
    /// stub runtime that has never heard of it.
    pub async fn concolic_availability(&self) -> ConcolicAvailability {
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
        match self
            .runtime
            .run_command(&cmd, std::path::Path::new("."), &limits)
            .await
        {
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
    /// Returns `ClassifiedError::Validation` when the toolchain is unavailable
    /// or the bounds are invalid, and `ClassifiedError::Sandbox` when the
    /// instrumented build does not produce a binary. A build failure is
    /// always an error: reporting it as a completed pass that solved nothing
    /// would be indistinguishable from a pass that legitimately solved
    /// nothing (`docs/design/concolic-enrichment-design.md` section 9).
    pub async fn corpus_concolic(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<ConcolicOutcome, ClassifiedError> {
        if let ConcolicAvailability::Unavailable { reason } = self.concolic_availability().await {
            return Err(ClassifiedError::Validation(format!(
                "concolic enrichment is unavailable: {reason}"
            )));
        }
        // An invalid manually-edited bound fails closed rather than silently
        // reverting to a policy the operator did not choose.
        let settings = crate::config::effective_concolic_settings()
            .map_err(|e| ClassifiedError::Validation(format!("concolic bounds: {e}")))?;

        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let mut inputs: Vec<std::path::PathBuf> = std::fs::read_dir(&corpus_dir)
            .map_err(|e| ClassifiedError::Validation(format!("read corpus: {e}")))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        // Retained order, so two passes over identical state agree.
        inputs.sort();
        let existing: HashSet<String> = inputs
            .iter()
            .filter_map(|p| std::fs::read(p).ok())
            .map(|bytes| content_digest(&bytes))
            .collect();

        let (selected, skipped) = select_inputs(&inputs, &settings);
        let out_dir = workspace.join("concolic-out");
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| ClassifiedError::Validation(format!("stage output dir: {e}")))?;
        std::fs::write(workspace.join("symcc_driver.c"), DRIVER_SOURCE)
            .map_err(|e| ClassifiedError::Validation(format!("stage driver: {e}")))?;

        let (solved, timed_out) = self
            .run_concolic_pass(&workspace, &selected, &settings)
            .await?;

        let stop = if timed_out {
            ConcolicStopReason::TotalTimeout
        } else if skipped > 0 {
            ConcolicStopReason::InputCap
        } else {
            ConcolicStopReason::CorpusExhausted
        };

        // Novel inputs are written into the corpus directory and persisted
        // through the existing corpus path, so every later consumer sees them
        // as ordinary corpus entries (spec section 4 step 4).
        let mut novel_written = 0usize;
        for bytes in &solved {
            let digest = content_digest(bytes);
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
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let mut persisted = grown;
        persisted.target_id = target_id;
        self.persist_corpus(target_id, &persisted).await?;

        Ok(summarize_with_corpus(
            selected.len(),
            skipped,
            &solved,
            &existing,
            &settings,
            stop,
            inputs.len(),
        ))
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
        selected: &[std::path::PathBuf],
        settings: &crate::config::ConcolicSettings,
    ) -> Result<(Vec<Vec<u8>>, bool), ClassifiedError> {
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

        let mut solved = Vec::new();
        // The build can itself consume the whole pass budget. Checking the
        // same deadline here, before the loop runs at all, means a corpus too
        // small to enter the loop still reports `TotalTimeout` rather than
        // `CorpusExhausted` when there was in fact no time left to explore.
        let mut timed_out = std::time::Instant::now() >= deadline;
        if !timed_out {
            for input in selected {
                if std::time::Instant::now() >= deadline {
                    timed_out = true;
                    break;
                }
                let Some(name) = input.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let mut env = HashMap::new();
                env.insert("SYMCC_OUTPUT_DIR".to_owned(), "concolic-out".to_owned());
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
            }
        }

        let out_dir = workspace.join("concolic-out");
        if let Ok(entries) = std::fs::read_dir(&out_dir) {
            let mut paths: Vec<_> = entries
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.is_file())
                .collect();
            paths.sort();
            for path in paths {
                if let Ok(bytes) = std::fs::read(&path) {
                    solved.push(bytes);
                }
            }
        }
        Ok((solved, timed_out))
    }
}
