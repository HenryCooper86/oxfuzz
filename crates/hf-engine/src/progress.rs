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
    if lower.contains("crash")
        || lower.contains("asan")
        || lower.contains("addresssanitizer")
        || lower.contains("ubsan")
        || lower.contains("sigsegv")
        || lower.contains("sigabrt")
        || (lower.contains("sum") && lower.contains("bug"))
    {
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
    // A real crash artifact line, not the literal "crashes 0" status token.
    if (lower.contains("crash")
        || lower.contains("addresssanitizer")
        || lower.contains("ubsan")
        || lower.contains("sigsegv")
        || lower.contains("sigabrt"))
        && !lower.contains("crashes 0")
        && !lower.contains("crashes: 0")
    {
        events.push(FuzzProgress::CrashesFound(1));
    }
    events
}

/// Parse a full stdout buffer into a list of progress events.
#[must_use]
pub fn parse_progress(stdout: &str) -> Vec<FuzzProgress> {
    stdout.lines().filter_map(parse_progress_line).collect()
}

/// Parse a coverage report from engine stdout.
#[must_use]
pub fn parse_coverage(stdout: &str, run_id: Uuid) -> CoverageReport {
    let mut edges = 0u64;
    let mut _crashes = 0u32;
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(n) = parse_number_near(line, "edges").or_else(|| parse_number_near(line, "cov"))
        {
            edges = edges.max(n);
        }
        if lower.contains("crash") {
            _crashes += 1;
        }
    }
    CoverageReport {
        run_id,
        edges,
        blocks: 0,
        delta_edges: 0,
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
        assert!(
            parse_progress_events("SUMMARY: AddressSanitizer: heap-buffer-overflow")
                .iter()
                .any(|e| matches!(e, FuzzProgress::CrashesFound(_)))
        );
        // The literal "crashes 0" status token is not a crash event.
        assert!(!parse_progress_events("VMs 4, executed 100, crashes 0")
            .iter()
            .any(|e| matches!(e, FuzzProgress::CrashesFound(_))));
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
}
