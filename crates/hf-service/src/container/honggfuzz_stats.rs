use hf_core::{engine::FuzzProgress, error::ClassifiedError};
use hf_engine::{honggfuzz::HonggfuzzStats, runner::RunResult};
use std::{path::Path, time::Duration};

/// Drive the sandbox future while reading non-TTY honggfuzz telemetry.
pub(super) async fn poll<F, S>(
    run: F,
    output: &Path,
    interval: Duration,
    emit: &S,
) -> Result<RunResult, ClassifiedError>
where
    F: std::future::Future<Output = Result<RunResult, ClassifiedError>>,
    S: Fn(FuzzProgress) + ?Sized,
{
    tokio::pin!(run);
    let mut ticks = tokio::time::interval(interval);
    let mut last = None;
    loop {
        tokio::select! {
            result = &mut run => {
                // Capture the exit-time flush even when it falls between polls.
                observe(output, &mut last, emit).await;
                let mut result = result?;
                if let Some(snapshot) = last {
                    result.progress.push(FuzzProgress::Stats(snapshot.stats));
                }
                return Ok(result);
            }
            _ = ticks.tick() => observe(output, &mut last, emit).await,
        }
    }
}

async fn observe<S: Fn(FuzzProgress) + ?Sized>(
    output: &Path,
    last: &mut Option<HonggfuzzStats>,
    emit: &S,
) {
    let output = output.to_path_buf();
    let snapshot = match tokio::task::spawn_blocking(move || {
        hf_engine::honggfuzz::read_stats(&output)
    })
    .await
    {
        Ok(Ok(Some(snapshot))) => snapshot,
        Ok(Ok(None)) => return,
        Ok(Err(error)) => {
            // Missing/torn or invalid telemetry never changes run termination;
            // retain the previous observation and retry on the next poll.
            tracing::debug!("honggfuzz statistics read skipped: {error}");
            return;
        }
        Err(error) => {
            // A failed blocking read task leaves the sandbox future authoritative.
            tracing::debug!("honggfuzz statistics task failed: {error}");
            return;
        }
    };
    if last.as_ref() == Some(&snapshot) {
        return;
    }
    let mut live = snapshot.stats.clone();
    if let Some(previous) = last.as_ref() {
        // The CSV rate is a whole-run average. Consecutive observations give
        // the current interval rate, including measured zero during a stall.
        live.execs_per_sec = snapshot
            .observed_at
            .checked_sub(previous.observed_at)
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| {
                Some(
                    snapshot
                        .stats
                        .execs_total?
                        .checked_sub(previous.stats.execs_total?)? as f64
                        / seconds as f64,
                )
            });
    }
    if let Some(edges) = live.edges_covered {
        emit(FuzzProgress::EdgesCovered(edges));
    }
    if let Some(rate) = live.execs_per_sec {
        emit(FuzzProgress::ExecsPerSec(rate));
    }
    emit(FuzzProgress::Stats(live));
    *last = Some(snapshot);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::runtime::CommandTermination;
    use std::sync::Mutex;

    #[tokio::test]
    async fn streams_progress_during_a_plateau_and_retains_the_final_flush() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(hf_core::engine::HONGGFUZZ_STATS_FILE);
        let events = Mutex::new(Vec::new());
        let first_seen = tokio::sync::Notify::new();
        let second_seen = tokio::sync::Notify::new();
        let sink = |event| {
            if let FuzzProgress::Stats(stats) = &event {
                match stats.execs_total {
                    Some(500) => first_seen.notify_one(),
                    Some(700) => second_seen.notify_one(),
                    _ => {}
                }
            }
            events.lock().unwrap().push(event);
        };
        let run = async {
            std::fs::write(&path, "100, 90, 500, 50, 2, 1, 3, 12, 8\n").unwrap();
            tokio::time::timeout(Duration::from_secs(3), first_seen.notified())
                .await
                .unwrap();
            std::fs::write(&path, "102, 90, 700, 70, 2, 1, 3, 12, 8\n").unwrap();
            tokio::time::timeout(Duration::from_secs(3), second_seen.notified())
                .await
                .unwrap();
            std::fs::write(&path, "104, 90, 1000, 80, 2, 1, 4, 15, 8\n").unwrap();
            Ok(hf_engine::runner::RunResult {
                progress: vec![],
                termination: CommandTermination::Completed,
            })
        };
        let result = poll(run, dir.path(), std::time::Duration::from_millis(10), &sink)
            .await
            .unwrap();
        let events = events.into_inner().unwrap();
        let rates: Vec<_> = events
            .iter()
            .filter_map(|event| {
                if let FuzzProgress::ExecsPerSec(rate) = event {
                    Some(*rate)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rates, vec![50.0, 100.0, 150.0]);
        assert!(!events
            .iter()
            .any(|event| matches!(event, FuzzProgress::CrashesFound(_))));
        assert!(result.progress.iter().any(|event| matches!(event, FuzzProgress::Stats(stats) if stats.edges_covered == Some(15) && stats.hangs == Some(4))));
    }

    #[tokio::test]
    async fn missing_or_invalid_stats_do_not_block_cancellation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(hf_core::engine::HONGGFUZZ_STATS_FILE),
            "malformed\n",
        )
        .unwrap();
        let result = poll(
            async {
                Ok(hf_engine::runner::RunResult {
                    progress: vec![],
                    termination: CommandTermination::Cancelled,
                })
            },
            dir.path(),
            std::time::Duration::from_millis(10),
            &|_| panic!("invalid stats must stay unknown"),
        )
        .await
        .unwrap();
        assert_eq!(result.termination, CommandTermination::Cancelled);
        assert!(result.progress.is_empty());
    }
}
