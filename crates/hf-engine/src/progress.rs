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
    if lower.contains("execs/sec") || lower.contains("exec/s") {
        if let Some(eps) = parse_number_near(line, "execs") {
            return Some(FuzzProgress::ExecsPerSec(eps as f64));
        }
    }
    if lower.contains("cov:") || lower.contains("edges") || lower.contains("coverage") {
        if let Some(edges) = parse_number_near(line, "cov") {
            return Some(FuzzProgress::EdgesCovered(edges));
        }
        if let Some(edges) = parse_number_near(line, "edges") {
            return Some(FuzzProgress::EdgesCovered(edges));
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
    // Search before the keyword first.
    let before = &line[..pos];
    if let Some(n) = last_number(before) {
        return Some(n);
    }
    // Then after.
    let after = &line[pos + keyword.len()..];
    first_number(after)
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
