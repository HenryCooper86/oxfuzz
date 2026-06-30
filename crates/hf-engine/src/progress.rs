//! Progress and coverage parsing from engine stdout.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md` section 4.

use hf_core::coverage::CoverageReport;
use hf_core::engine::FuzzProgress;
use uuid::Uuid;

/// Parse a single line of engine stdout into a `FuzzProgress` event.
#[must_use]
pub fn parse_progress_line(line: &str) -> Option<FuzzProgress> {
    let lower = line.to_ascii_lowercase();
    // Check coverage first (libFuzzer lines contain both "cov:" and "exec/s").
    if lower.contains("cov:") || lower.contains("edges") || lower.contains("coverage") {
        if let Some(edges) =
            parse_number_near(line, "cov").or_else(|| parse_number_near(line, "edges"))
        {
            return Some(FuzzProgress::EdgesCovered(edges));
        }
    }
    if lower.contains("execs/sec") || lower.contains("exec/s") || lower.contains("execs:") {
        if let Some(eps) =
            parse_number_near(line, "execs").or_else(|| parse_number_near(line, "exec"))
        {
            return Some(FuzzProgress::ExecsPerSec(eps as f64));
        }
    }
    if is_finding_signal(&lower) {
        return Some(FuzzProgress::CrashesFound(1));
    }
    if lower.contains("done") || lower.contains("finished") {
        return Some(FuzzProgress::Done);
    }
    None
}

/// Parse a `syz-manager` status line into `(cover, executed, crashes)`.
///
/// syz-manager periodically logs a status line of the form:
/// `VMs 2, executed 12345, cover 6789, signal 5432, crashes 0, repro 0`.
/// Returns `None` for lines that are not a status line. Unlike
/// [`parse_progress_line`], this does not treat the literal `crashes 0` token
/// as a crash event -- it reports the absolute crash count instead.
#[must_use]
pub fn parse_syzkaller_status(line: &str) -> Option<(u64, u64, u64)> {
    let lower = line.to_ascii_lowercase();
    if !(lower.contains("executed") && lower.contains("cover")) {
        return None;
    }
    let cover = parse_number_near(line, "cover")?;
    let executed = parse_number_near(line, "executed")?;
    let crashes = parse_number_near(line, "crashes").unwrap_or(0);
    Some((cover, executed, crashes))
}

/// Parse every progress event present in a single line.
///
/// Unlike [`parse_progress_line`] (which returns the first match), a libFuzzer
/// pulse line carries both coverage and exec/s, so this can yield several
/// events -- useful for live stat updates as the fuzzer streams output.
#[must_use]
pub fn parse_progress_events(line: &str) -> Vec<FuzzProgress> {
    let lower = line.to_ascii_lowercase();
    let mut events = Vec::new();
    if lower.contains("cov:") || lower.contains("edges") || lower.contains("coverage") {
        if let Some(edges) =
            parse_number_near(line, "cov").or_else(|| parse_number_near(line, "edges"))
        {
            events.push(FuzzProgress::EdgesCovered(edges));
        }
    }
    if lower.contains("exec/s") || lower.contains("execs/sec") || lower.contains("execs:") {
        if let Some(eps) = parse_number_near(line, "exec") {
            events.push(FuzzProgress::ExecsPerSec(eps as f64));
        }
    }
    if is_finding_signal(&lower) {
        events.push(FuzzProgress::CrashesFound(1));
    }
    events
}

/// Whether a raw engine-stdout line reports an individual crash/finding event.
///
/// This is distinct from a periodic *status counter*: AFL++ (`uniq crashes :
/// N`, `last uniq crash : ...`) and honggfuzz (`Crashes : N`) print a crash
/// label on every status tick, whose total comes from ingesting the crash
/// directory -- counting each tick as a finding inflates the run's crash count
/// by hundreds. See `docs/standards/ENGINE_ADAPTER_STANDARD.md` section 4.
#[must_use]
pub fn line_reports_finding(line: &str) -> bool {
    is_finding_signal(&line.to_ascii_lowercase())
}

/// Whether a (lowercased) line signals a fuzzer finding -- a crash, OOM, leak,
/// or timeout. Covers libFuzzer's "Test unit written to <artifact>" save line
/// (one per saved finding of any type), the `crash-<hash>` artifact-filename
/// prefix, and the common sanitizer/signal phrasings.
///
/// It deliberately does NOT trigger on the bare substring "crash": that matches
/// AFL++/honggfuzz periodic status counters (`uniq crashes : N`, `Crashes : N`)
/// and header text (`last uniq crash : none seen yet`), producing phantom
/// crashes on every clean run. The `crash-` prefix is safe because a counter
/// never contains it (`crashes` is followed by a space/colon, not `-`).
fn is_finding_signal(lower: &str) -> bool {
    lower.contains("crash-")
        || lower.contains("addresssanitizer")
        || lower.contains("asan")
        || lower.contains("ubsan")
        || lower.contains("sigsegv")
        || lower.contains("segv")
        || lower.contains("sigabrt")
        || lower.contains("out-of-memory")
        || lower.contains("leaksanitizer")
        || lower.contains("detected memory leak")
        || lower.contains("deadly signal")
        || lower.contains("test unit written")
}

/// Parse a full stdout buffer into a list of progress events.
#[must_use]
pub fn parse_progress(stdout: &str) -> Vec<FuzzProgress> {
    stdout.lines().filter_map(parse_progress_line).collect()
}

/// Parse a `syz-manager` stdout buffer into final progress events.
///
/// syz-manager reports absolute, cumulative counters on each status line, so
/// unlike [`parse_progress`] (which treats every `crashes N` token as one
/// finding) this collapses the stream to the peak coverage and the peak crash
/// count -- yielding at most one [`FuzzProgress::EdgesCovered`] and one
/// [`FuzzProgress::CrashesFound`], matching how the service layer maxes edges
/// and sums crash events.
#[must_use]
pub fn parse_syzkaller_progress(stdout: &str) -> Vec<FuzzProgress> {
    let mut peak_cover = 0u64;
    let mut peak_crashes = 0u64;
    for line in stdout.lines() {
        if let Some((cover, _executed, crashes)) = parse_syzkaller_status(line) {
            peak_cover = peak_cover.max(cover);
            peak_crashes = peak_crashes.max(crashes);
        }
    }
    let mut events = Vec::new();
    if peak_cover > 0 {
        events.push(FuzzProgress::EdgesCovered(peak_cover));
    }
    if peak_crashes > 0 {
        events.push(FuzzProgress::CrashesFound(
            u32::try_from(peak_crashes).unwrap_or(u32::MAX),
        ));
    }
    events
}

/// Parse a coverage report from engine stdout.
///
/// `edges` is the peak edge/PC count reported in the stream, and `delta_edges`
/// is the coverage *gained over this run* (peak minus the first sample), both
/// derived directly from the engine's progress lines.
///
/// The remaining fields are not derivable from a single stdout buffer and are
/// left at their identity values here:
/// - `blocks`: engines report edges/features, not a separate basic-block count.
/// - `stagnation_secs`: a wall-clock measure across successive reports, owned by
///   `hf_coverage::CoverageTracker`, which recomputes it from `edges` and
///   ignores this field.
/// - `new_edges_files`: which corpus inputs added coverage is tracked by the
///   corpus layer when it grows the corpus, not from fuzzer stdout.
#[must_use]
pub fn parse_coverage(stdout: &str, run_id: Uuid) -> CoverageReport {
    let mut edges = 0u64;
    let mut first_edges: Option<u64> = None;
    for line in stdout.lines() {
        if let Some(n) = parse_number_near(line, "edges").or_else(|| parse_number_near(line, "cov"))
        {
            first_edges.get_or_insert(n);
            edges = edges.max(n);
        }
    }
    // Coverage is monotonic within a run, so the gain is peak minus the first
    // observed sample. `i64` because the model permits a (theoretical) regress.
    let delta_edges = edges.cast_signed() - first_edges.unwrap_or(0).cast_signed();
    CoverageReport {
        run_id,
        edges,
        blocks: 0,
        delta_edges,
        stagnation_secs: 0,
        new_edges_files: Vec::new(),
    }
}

fn parse_number_near(line: &str, keyword: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let pos = lower.find(keyword)?;
    // Search after the keyword first (most common: "cov: 10").
    let after = &line[pos + keyword.len()..];
    if let Some(n) = first_number(after) {
        return Some(n);
    }
    // Then before.
    let before = &line[..pos];
    last_number(before)
}

fn last_number(s: &str) -> Option<u64> {
    s.split(|c: char| !c.is_ascii_digit())
        .filter(|t| !t.is_empty())
        .filter_map(|t| t.parse::<u64>().ok())
        .next_back()
}

fn first_number(s: &str) -> Option<u64> {
    s.split(|c: char| !c.is_ascii_digit())
        .find(|t| !t.is_empty())
        .and_then(|t| t.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::{parse_progress_events, parse_syzkaller_status};
    use hf_core::engine::FuzzProgress;

    #[test]
    fn libfuzzer_pulse_line_yields_edges_and_execs() {
        // A real libFuzzer line carries both coverage and exec/s.
        let line =
            "#131072 pulse cov: 58 ft: 406 corp: 215/64Kb lim: 4096 exec/s: 43690 rss: 546Mb";
        let events = parse_progress_events(line);
        assert!(events
            .iter()
            .any(|e| matches!(e, FuzzProgress::EdgesCovered(58))));
        assert!(events.iter().any(
            |e| matches!(e, FuzzProgress::ExecsPerSec(v) if (*v - 43690.0).abs() < f64::EPSILON)
        ));
        assert!(!events
            .iter()
            .any(|e| matches!(e, FuzzProgress::CrashesFound(_))));
    }

    #[test]
    fn crash_line_is_detected_but_not_zero_status() {
        let finding = |line: &str| {
            parse_progress_events(line)
                .iter()
                .any(|e| matches!(e, FuzzProgress::CrashesFound(_)))
        };
        // Crashes, OOM, leaks, timeouts, and the artifact-save line are findings.
        assert!(finding("SUMMARY: AddressSanitizer: heap-buffer-overflow"));
        assert!(finding("==1== SUMMARY: libFuzzer: out-of-memory"));
        assert!(finding("SUMMARY: AddressSanitizer: detected memory leaks"));
        assert!(finding("Test unit written to /work/out/oom-da39a3ee"));
        assert!(finding(
            "artifact_prefix='/work/out/'; Test unit written to /work/out/crash-abc"
        ));
        // The literal "crashes 0" status token is not a crash event.
        assert!(!finding("VMs 4, executed 100, crashes 0"));
        // A normal libFuzzer pulse line is not a finding.
        assert!(!finding("#131072 pulse cov: 58 exec/s: 43690 rss: 546Mb"));
    }

    #[test]
    fn afl_and_honggfuzz_status_counters_are_not_per_line_crashes() {
        let finding = |line: &str| {
            parse_progress_events(line)
                .iter()
                .any(|e| matches!(e, FuzzProgress::CrashesFound(_)))
        };
        // AFL++ prints these crash *labels* on every status tick. They are
        // absolute counters (or header text), not per-line crash events -- the
        // real count comes from ingesting the crash directory. Counting each
        // tick inflates the total by hundreds, which is the bug being fixed.
        assert!(!finding(" last uniq crash : none seen yet"));
        assert!(!finding("  uniq crashes : 0"));
        assert!(!finding("  uniq crashes : 5"));
        assert!(!finding("  saved crashes : 12"));
        // honggfuzz status line, zero and non-zero.
        assert!(!finding(
            "Crashes : 0 (unique: 0, blacklist: 0, verified: 0)"
        ));
        assert!(!finding(
            "Crashes : 7 (unique: 3, blacklist: 0, verified: 0)"
        ));
        // A genuine crash artifact / sanitizer line is still a finding.
        assert!(finding(
            "artifact_prefix='/work/out/'; Test unit written to /work/out/crash-abc"
        ));
        assert!(finding(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow"
        ));
    }

    #[test]
    fn parses_syz_manager_status_line() {
        let line = "2024/01/02 03:04:05 VMs 2, executed 12345, cover 6789, signal 5432, crashes 3, repro 0";
        assert_eq!(parse_syzkaller_status(line), Some((6789, 12345, 3)));
    }

    #[test]
    fn status_line_with_zero_crashes_is_not_a_crash() {
        let line = "VMs 4, executed 100, cover 50, signal 40, crashes 0, repro 0";
        assert_eq!(parse_syzkaller_status(line), Some((50, 100, 0)));
    }

    #[test]
    fn non_status_lines_return_none() {
        assert_eq!(parse_syzkaller_status("booting test machines..."), None);
        assert_eq!(parse_syzkaller_status("cover: 10 exec/s: 5"), None);
    }

    #[test]
    fn syzkaller_progress_collapses_to_peak_cover_and_crashes() {
        use super::parse_syzkaller_progress;
        let log = "\
booting test machines...
VMs 2, executed 100, cover 50, signal 40, crashes 0, repro 0
VMs 2, executed 5000, cover 6789, signal 5432, crashes 2, repro 0
VMs 2, executed 9000, cover 6789, signal 5432, crashes 2, repro 0";
        let events = parse_syzkaller_progress(log);
        // Peak coverage, reported once.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, FuzzProgress::EdgesCovered(6789)))
                .count(),
            1
        );
        // The absolute crash count, not one-per-status-line.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, FuzzProgress::CrashesFound(2)))
                .count(),
            1
        );
        // No spurious extra crash events from the repeated status lines.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, FuzzProgress::CrashesFound(_)))
                .count(),
            1
        );
    }
}
