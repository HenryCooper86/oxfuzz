//! Run output accounting.
//!
//! A running fuzzer mutates its output tree constantly, so an entry seen by
//! `read_dir` can be gone by the time it is stat-ed. That transient race must
//! not be reported as a budget violation: doing so killed valid campaigns and
//! discarded their results. The scan therefore has three outcomes, not two.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use super::staging::RunArtifacts;

pub(super) const MAX_RUN_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_RUN_OUTPUT_ENTRIES: usize = 100_000;

/// Outcome of scanning a run-owned output tree against its retained-evidence
/// budget.
///
/// The third state matters: a running fuzzer creates, renames, and deletes
/// files continuously, so an entry enumerated by `read_dir` can vanish before
/// its `symlink_metadata` call. That transient race must not be conflated with
/// a genuine budget overflow -- doing so let the live monitor kill a perfectly
/// valid campaign and discard its results.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum OutputBudget {
    /// Definitely within budget.
    Within,
    /// A definite violation: total/file bytes or entry count over the limit, or
    /// a symlink/special file that actually exists in the tree.
    Exceeded,
    /// The scan could not be completed because the tree changed underneath it
    /// (a transient `NotFound`/read error). Neither within nor over budget.
    Indeterminate,
}

/// Scan a run-owned output tree, distinguishing a real budget overflow from a
/// transient filesystem race. A definite overflow or structural violation
/// (symlink/special file) is [`OutputBudget::Exceeded`]; a metadata/read error
/// on an individual entry is [`OutputBudget::Indeterminate`] rather than a
/// false overflow.
pub(super) fn output_budget_status(
    root: &Path,
    max_bytes: u64,
    max_entries: usize,
    max_file_bytes: u64,
) -> OutputBudget {
    let mut pending = vec![root.to_path_buf()];
    let mut total_bytes = 0_u64;
    let mut entries = 0usize;
    while let Some(directory) = pending.pop() {
        let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
            return OutputBudget::Indeterminate;
        };
        if !metadata.file_type().is_dir() {
            return OutputBudget::Exceeded;
        }
        let Ok(children) = std::fs::read_dir(&directory) else {
            return OutputBudget::Indeterminate;
        };
        for child in children {
            let Ok(child) = child else {
                return OutputBudget::Indeterminate;
            };
            entries += 1;
            if entries > max_entries {
                return OutputBudget::Exceeded;
            }
            let path = child.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                // The entry vanished between enumeration and stat -- normal
                // fuzzer churn, not an overflow. Skip it.
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return OutputBudget::Indeterminate,
            };
            if metadata.file_type().is_dir() {
                pending.push(path);
            } else if metadata.file_type().is_file() {
                if metadata.len() > max_file_bytes {
                    return OutputBudget::Exceeded;
                }
                let Some(next) = total_bytes.checked_add(metadata.len()) else {
                    return OutputBudget::Exceeded;
                };
                total_bytes = next;
                if total_bytes > max_bytes {
                    return OutputBudget::Exceeded;
                }
            } else {
                return OutputBudget::Exceeded;
            }
        }
    }
    OutputBudget::Within
}

pub(super) async fn monitor_run_output(
    output: PathBuf,
    corpus: PathBuf,
    max_output_file_bytes: u64,
    run_cancel: CancellationToken,
    stop: CancellationToken,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = interval.tick() => {
                let path = output.clone();
                let corpus_path = corpus.clone();
                // Only a *definite* overflow cancels the run. A transient scan
                // error (a file the fuzzer just deleted) is Indeterminate and is
                // retried on the next tick rather than latching a false kill.
                let exceeded_now = tokio::task::spawn_blocking(move || {
                    output_budget_status(
                        &path,
                        MAX_RUN_OUTPUT_BYTES,
                        MAX_RUN_OUTPUT_ENTRIES,
                        max_output_file_bytes,
                    ) == OutputBudget::Exceeded
                        || output_budget_status(
                            &corpus_path,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
                        ) == OutputBudget::Exceeded
                })
                .await
                .unwrap_or(false);
                if exceeded_now {
                    exceeded.store(true, std::sync::atomic::Ordering::Release);
                    run_cancel.cancel();
                    return;
                }
            }
        }
    }
}

/// Whether a finished run's artifacts may be retained. Returns false only on a
/// *definite* overflow; a transient scan race (Indeterminate) does not fail a
/// completed run, mirroring the live monitor so results are not discarded over
/// a filesystem hiccup.
pub(super) async fn run_artifacts_within_budget(
    artifacts: &RunArtifacts,
    max_output_file_bytes: u64,
) -> bool {
    let output = artifacts.output_host.clone();
    let corpus = artifacts.corpus_host.clone();
    tokio::task::spawn_blocking(move || {
        output_budget_status(
            &output,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            max_output_file_bytes,
        ) != OutputBudget::Exceeded
            && output_budget_status(
                &corpus,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            ) != OutputBudget::Exceeded
    })
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vanishing_entry_is_indeterminate_not_a_violation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("gone");

        // A path enumerated by read_dir and deleted before stat: exactly what a
        // live fuzzer does between iterations.
        let status = output_budget_status(
            &missing,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            MAX_RUN_OUTPUT_BYTES,
        );

        assert_eq!(
            status,
            OutputBudget::Indeterminate,
            "a transient read race must classify as indeterminate, not as within budget or as a violation"
        );
    }

    #[test]
    fn an_empty_tree_is_within_budget() {
        let dir = tempfile::tempdir().expect("temp dir");

        let status = output_budget_status(
            dir.path(),
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            MAX_RUN_OUTPUT_BYTES,
        );

        assert!(matches!(status, OutputBudget::Within));
    }
}
