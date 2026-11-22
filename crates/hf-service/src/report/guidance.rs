//! Report sections that tell the reader what to do: per-finding remediation
//! and the campaign's prioritized recommendations.
//!
//! Every statement here is derived from the report's own data (the weakness
//! class of each finding, the measured run figures, coverage, and corpus), so a
//! report reads the same with or without a model configured.

use std::fmt::Write as _;

use hf_core::crash::Crash;
use hf_core::engine::EngineKind;
use hf_core::target::Sanitizer;
use hf_storage::{RunRecord, RunStatus};

use super::{human_duration, inline_code, Labels, ReportData};
use crate::weakness::{classify, guidance};

/// Line coverage below which the report recommends widening the harness.
const COVERAGE_RECOMMENDATION_PERCENT: f64 = 80.0;
/// A campaign shorter than this is called short.
const SHORT_CAMPAIGN_SECS: i64 = 3600;
/// Peak executions per second below which harness profiling is recommended.
const LOW_THROUGHPUT_PER_SEC: f64 = 1000.0;
/// Findings itemized in the recommendations; the rest are referenced as a group.
const ITEMIZED_FINDINGS: usize = 10;

/// The engine's product name, as its own documentation writes it.
pub(super) const fn engine_name(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::Syzkaller => "syzkaller",
        EngineKind::GoNative => "Go native fuzzing",
        EngineKind::Atheris => "Atheris",
        EngineKind::Jazzer => "Jazzer",
        EngineKind::JazzerJs => "Jazzer.js",
    }
}

pub(super) const fn status_label(status: RunStatus, labels: &Labels) -> &'static str {
    match status {
        RunStatus::Pending => labels.status_pending,
        RunStatus::Running => labels.status_running,
        RunStatus::Done => labels.status_completed,
        RunStatus::Failed => labels.status_failed,
        RunStatus::Cancelled => labels.status_cancelled,
    }
}

/// The rating band of a 0-10 security-severity score: the bands CVSS v3 uses.
pub(super) const fn severity_band(score: f64, labels: &Labels) -> &'static str {
    if score >= 9.0 {
        labels.severity_critical
    } else if score >= 7.0 {
        labels.severity_high
    } else if score >= 4.0 {
        labels.severity_medium
    } else {
        labels.severity_low
    }
}

/// `Critical (9.0)`: the band and the score it was derived from.
pub(super) fn severity_rating(crash: &Crash, labels: &Labels) -> String {
    let score = crate::sarif::security_severity(crash);
    format!(
        "{}{}{score:.1}{}",
        severity_band(score, labels),
        labels.narrative_open_paren,
        labels.narrative_close_paren
    )
}

/// An integer with thousands separators (`998,483`).
pub(super) fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A rate rounded to whole executions, grouped.
pub(super) fn grouped_rate(rate: f64) -> String {
    // A rate is finite and non-negative by the time it is stored; rounding a
    // fraction of an execution away is the intended display precision.
    grouped(rate.round().max(0.0) as u64)
}

/// The crash line CASR reported, or `-` when it reported none.
pub(super) fn location(crash: &Crash) -> String {
    crash
        .casr
        .as_ref()
        .map(|casr| casr.crashline.clone())
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "-".to_owned())
}

/// `CWE-125 Out-of-bounds Read`.
pub(super) fn weakness_label(crash: &Crash) -> String {
    let (id, name) = classify(crash).cwe();
    format!("{id} {name}")
}

/// Weakness and severity bullets, then impact, remediation, and verification
/// for one finding.
pub(super) fn render_finding_guidance(md: &mut String, crash: &Crash, labels: &Labels) {
    let class = classify(crash);
    let text = guidance(class, labels.language);
    let _ = writeln!(md);
    let _ = writeln!(md, "**{}** {}", labels.impact_heading, text.impact);
    let _ = writeln!(md);
    let _ = writeln!(md, "**{}**", labels.remediation_heading);
    let _ = writeln!(md);
    for (index, step) in text.remediation.iter().enumerate() {
        let _ = writeln!(md, "{}. {step}", index + 1);
    }
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "**{}** {}",
        labels.verification_heading, labels.verification_text
    );
}

/// The prioritized next steps for the campaign.
pub(super) fn render_recommendations(
    md: &mut String,
    data: &ReportData,
    harness_defects: usize,
    labels: &Labels,
) {
    let mut items: Vec<String> = Vec::new();

    let untriaged = super::untriaged_crashing_inputs(data);
    if untriaged > 0 {
        items.push(
            labels
                .rec_triage_pending
                .replace("{n}", &untriaged.to_string()),
        );
    }

    if harness_defects > 0 {
        items.push(
            labels
                .rec_harness_defects
                .replace("{n}", &harness_defects.to_string()),
        );
    }

    // Findings, most severe first; the table order breaks ties so a reader can
    // match "Finding N" to the table.
    let mut ranked: Vec<(usize, &Crash)> = data
        .crashes
        .iter()
        .chain(&data.earlier_findings)
        .enumerate()
        .collect();
    ranked.sort_by(|(left_index, left), (right_index, right)| {
        crate::sarif::security_severity(right)
            .total_cmp(&crate::sarif::security_severity(left))
            .then(left_index.cmp(right_index))
    });
    for (index, crash) in ranked.iter().take(ITEMIZED_FINDINGS) {
        let (cwe, name) = classify(crash).cwe();
        let step = guidance(classify(crash), labels.language)
            .remediation
            .first()
            .copied()
            .unwrap_or_default();
        items.push(
            labels
                .rec_fix_finding
                .replace("{n}", &(index + 1).to_string())
                .replace(
                    "{severity}",
                    severity_band(crate::sarif::security_severity(crash), labels),
                )
                .replace("{cwe}", cwe)
                .replace("{name}", name)
                .replace("{location}", &inline_code(&location(crash)))
                .replace("{step}", step),
        );
    }
    if ranked.len() > ITEMIZED_FINDINGS {
        items.push(
            labels
                .rec_more_findings
                .replace("{n}", &(ranked.len() - ITEMIZED_FINDINGS).to_string()),
        );
    }
    if !ranked.is_empty() {
        items.push(labels.rec_verify_fixes.to_owned());
    }

    if let Some(run) = &data.run {
        if stopped_at_first_crash(run, data.crashes.len()) {
            items.push(labels.rec_first_crash.to_owned());
        }
    }

    if let Some(coverage) = data.coverage {
        let missing = coverage
            .functions_total
            .saturating_sub(coverage.functions_covered);
        if coverage.line_percent() < COVERAGE_RECOMMENDATION_PERCENT || missing > 0 {
            items.push(
                labels
                    .rec_coverage
                    .replace("{percent}", &format!("{:.1}", coverage.line_percent()))
                    .replace("{missing}", &missing.to_string())
                    .replace("{total}", &coverage.functions_total.to_string()),
            );
        }
    }

    if let Some(run) = &data.run {
        if let Some(secs) = run_seconds(run) {
            if secs < SHORT_CAMPAIGN_SECS {
                items.push(
                    labels
                        .rec_duration
                        .replace("{duration}", &human_duration(secs)),
                );
            }
        }
        match run.config.as_ref().map(|config| config.sanitizer) {
            Some(Sanitizer::Address) => items.push(labels.rec_sanitizer_address_only.to_owned()),
            Some(Sanitizer::None) => items.push(labels.rec_sanitizer_none.to_owned()),
            _ => {}
        }
        if let Some(rate) = run.execs.filter(|rate| *rate < LOW_THROUGHPUT_PER_SEC) {
            items.push(labels.rec_throughput.replace("{rate}", &grouped_rate(rate)));
        }
    }

    if data.corpus.seeds == 0 && data.run.is_some() {
        items.push(labels.rec_seeds.to_owned());
    }

    if data.crashes.is_empty()
        && data.earlier_findings.is_empty()
        && untriaged == 0
        && data.run.is_some()
    {
        let coverage = data.coverage.map_or_else(
            || labels.coverage_unknown.to_owned(),
            |coverage| format!("{:.1}%", coverage.line_percent()),
        );
        items.push(labels.rec_clean.replace("{coverage}", &coverage));
    }

    let _ = writeln!(md, "## {}", labels.recommendations_section);
    let _ = writeln!(md);
    for (index, item) in items.iter().enumerate() {
        let _ = writeln!(md, "{}. {item}", index + 1);
    }
    let _ = writeln!(md);
}

/// Whole seconds the run took, once it ended.
fn run_seconds(run: &RunRecord) -> Option<i64> {
    run.ended_at
        .map(|ended| (ended - run.started_at).num_seconds().max(0))
}

fn stopped_at_first_crash(run: &RunRecord, findings: usize) -> bool {
    let (Some(config), Some(ended)) = (run.config.as_ref(), run.ended_at) else {
        return false;
    };
    // `to_std` fails only for a negative span (an end stamped before the
    // start); that run took no measurable time.
    let elapsed = (ended - run.started_at).to_std().unwrap_or_default();
    crate::container::stopped_at_first_crash(
        run.engine,
        config.max_cpus,
        config.duration,
        run.crash_count.unwrap_or(findings as u64),
        run.status == RunStatus::Done,
        elapsed,
    )
}
