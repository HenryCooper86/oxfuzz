//! Live one-line run status rendering.
//!
//! Both `run` and `campaign` merge the streamed [`FuzzProgress`] events into a
//! rolling [`EngineStats`] snapshot and print an afl-fuzz-style status line,
//! throttled so a fast engine cannot scroll the terminal. Only fields the
//! engine reported are printed.

use std::time::{Duration, Instant};

use hf_service::{EngineStats, FuzzProgress};

/// Minimum spacing between two printed status lines: engine stats can arrive
/// several times per second and the terminal is the bottleneck.
const STATUS_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Merges streamed [`FuzzProgress`] events into a rolling status snapshot and
/// renders an afl-fuzz-style one-liner, at most one line per interval.
///
/// Crashes are renderer-counted (engines report findings as events, so the
/// counter sums `CrashesFound` deltas); every other field comes from the
/// newest event that carries it.
pub(crate) struct StatusLine {
    stats: EngineStats,
    crashes: u64,
    last_render: Option<Instant>,
    min_interval: Duration,
}

/// The shared live-progress sink for `run` and `campaign`: engine log lines
/// and crash markers print immediately, and the rolling status line prints at
/// most once per [`STATUS_MIN_INTERVAL`].
pub(crate) fn printing_sink() -> impl Fn(FuzzProgress) + Send + Sync {
    sink(|line| println!("{line}"))
}

/// The same live-progress sink routed to stderr, for commands whose stdout
/// carries machine-readable output (`fuzz --json`).
pub(crate) fn eprinting_sink() -> impl Fn(FuzzProgress) + Send + Sync {
    sink(|line| eprintln!("{line}"))
}

/// Build a sink on one emit function so both output routes share the merge
/// and throttle logic exactly.
fn sink(emit: fn(&str)) -> impl Fn(FuzzProgress) + Send + Sync {
    let status = std::sync::Mutex::new(StatusLine::new());
    move |progress: FuzzProgress| {
        match &progress {
            FuzzProgress::LogLine(line) => emit(&format!("  {line}")),
            FuzzProgress::CrashesFound(_) => emit("  >> crash found"),
            _ => {}
        }
        let mut status = status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(line) = status.observe(&progress, Instant::now()) {
            emit(&format!("  {line}"));
        }
    }
}

impl StatusLine {
    pub(crate) fn new() -> Self {
        Self {
            stats: EngineStats::default(),
            crashes: 0,
            last_render: None,
            min_interval: STATUS_MIN_INTERVAL,
        }
    }

    /// Merge one event into the rolling status. Returns the status line to
    /// print, or `None` when the event carries no status data or the throttle
    /// interval has not elapsed since the last render.
    pub(crate) fn observe(&mut self, progress: &FuzzProgress, now: Instant) -> Option<String> {
        match progress {
            FuzzProgress::Stats(stats) => self.stats.merge_from(stats),
            FuzzProgress::ExecsPerSec(rate) if rate.is_finite() && *rate >= 0.0 => {
                self.stats.execs_per_sec = Some(*rate);
            }
            FuzzProgress::EdgesCovered(edges) => self.stats.edges_covered = Some(*edges),
            FuzzProgress::CrashesFound(count) => {
                self.crashes = self.crashes.saturating_add(u64::from(*count));
            }
            FuzzProgress::ExecsPerSec(_) | FuzzProgress::LogLine(_) | FuzzProgress::Done => {
                return None;
            }
        }
        if let Some(last) = self.last_render {
            if now.duration_since(last) < self.min_interval {
                return None;
            }
        }
        let line = self.render()?;
        self.last_render = Some(now);
        Some(line)
    }

    /// The current status text, or `None` when nothing has been observed yet
    /// (an empty line naming only `crashes=0` would be noise).
    fn render(&self) -> Option<String> {
        let mut fields = Vec::new();
        if let Some(execs) = self.stats.execs_total {
            fields.push(format!("execs={execs}"));
        }
        if let Some(rate) = self.stats.execs_per_sec {
            fields.push(format!("exec/s={rate:.0}"));
        }
        if let Some(edges) = self.stats.edges_covered {
            fields.push(format!("edges={edges}"));
        }
        if let Some(corpus) = self.stats.corpus_count {
            fields.push(format!("corpus={corpus}"));
        }
        if let Some(cycles) = self.stats.cycles_done {
            fields.push(format!("cycles={cycles}"));
        }
        if let Some(stability) = self.stats.stability_pct {
            fields.push(format!("stability={stability:.1}%"));
        }
        if fields.is_empty() && self.crashes == 0 {
            return None;
        }
        fields.push(format!("crashes={}", self.crashes));
        if let Some(hangs) = self.stats.hangs {
            fields.push(format!("hangs={hangs}"));
        }
        if let Some(age) = self.stats.last_find_age_secs {
            fields.push(format!("last_find={age}s"));
        }
        if let Some(uptime) = self.stats.uptime_secs {
            fields.push(format!("uptime={uptime}s"));
        }
        Some(fields.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use hf_service::{EngineStats, FuzzProgress};

    use super::StatusLine;

    fn full_stats() -> EngineStats {
        EngineStats {
            execs_total: Some(128_934),
            execs_per_sec: Some(842.0),
            edges_covered: Some(1523),
            cycles_done: Some(2),
            corpus_count: Some(91),
            stability_pct: Some(100.0),
            hangs: Some(0),
            last_find_age_secs: Some(14),
            uptime_secs: Some(153),
        }
    }

    #[test]
    fn render_prints_only_present_fields() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        let line = status
            .observe(&FuzzProgress::Stats(full_stats()), now)
            .expect("the first observation renders");
        assert_eq!(
            line,
            "execs=128934 exec/s=842 edges=1523 corpus=91 cycles=2 \
             stability=100.0% crashes=0 hangs=0 last_find=14s uptime=153s"
        );
    }

    #[test]
    fn sparse_snapshots_render_without_absent_fields() {
        let mut status = StatusLine::new();
        let line = status
            .observe(
                &FuzzProgress::Stats(EngineStats {
                    execs_per_sec: Some(43_690.0),
                    edges_covered: Some(58),
                    ..EngineStats::default()
                }),
                Instant::now(),
            )
            .expect("a partial snapshot renders");
        assert_eq!(line, "exec/s=43690 edges=58 crashes=0");
    }

    #[test]
    fn partial_snapshots_merge_into_a_rolling_status() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        status.observe(
            &FuzzProgress::Stats(EngineStats {
                edges_covered: Some(58),
                ..EngineStats::default()
            }),
            now,
        );
        let line = status
            .observe(
                &FuzzProgress::Stats(EngineStats {
                    execs_total: Some(1000),
                    ..EngineStats::default()
                }),
                now + Duration::from_secs(2),
            )
            .expect("the merged snapshot renders after the interval");
        assert_eq!(line, "execs=1000 edges=58 crashes=0");
    }

    #[test]
    fn scalar_events_feed_the_status_line() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        status.observe(&FuzzProgress::EdgesCovered(1024), now);
        let line = status
            .observe(
                &FuzzProgress::ExecsPerSec(842.4),
                now + Duration::from_secs(2),
            )
            .expect("scalar events render");
        assert_eq!(line, "exec/s=842 edges=1024 crashes=0");
    }

    #[test]
    fn crash_events_update_the_counter() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        let line = status
            .observe(&FuzzProgress::CrashesFound(1), now)
            .expect("a crash renders");
        assert_eq!(line, "crashes=1");
        let line = status
            .observe(&FuzzProgress::CrashesFound(1), now + Duration::from_secs(2))
            .expect("a later crash renders");
        assert_eq!(line, "crashes=2");
    }

    #[test]
    fn renders_are_throttled_to_one_per_interval() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        let event = || {
            FuzzProgress::Stats(EngineStats {
                execs_total: Some(1),
                ..EngineStats::default()
            })
        };
        assert!(
            status.observe(&event(), now).is_some(),
            "first render is immediate"
        );
        assert!(
            status
                .observe(&event(), now + Duration::from_millis(999))
                .is_none(),
            "inside the interval the update is held"
        );
        assert!(
            status
                .observe(&event(), now + Duration::from_secs(1))
                .is_some(),
            "at the interval boundary the update prints"
        );
    }

    #[test]
    fn log_lines_and_done_do_not_render_a_status() {
        let mut status = StatusLine::new();
        let now = Instant::now();
        assert!(status
            .observe(&FuzzProgress::LogLine("noise".to_owned()), now)
            .is_none());
        assert!(status.observe(&FuzzProgress::Done, now).is_none());
    }
}
