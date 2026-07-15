//! Tests for the Markdown campaign report renderer.

use std::path::PathBuf;

use hf_core::crash::{BugReport, CasrReport, Crash, CrashKind, CrashSeverity};
use hf_core::engine::EngineKind;
use hf_core::target::{InputSurface, SourceLocation, TargetCandidate, TargetKind, TargetLanguage};
use hf_coverage::CoverageSummary;
use hf_service::report::{
    ensure_graphs, render_markdown, report_system_prompt, report_user_prompt, CorpusStats,
    ReportData,
};
use hf_storage::{RunRecord, RunStatus};
use uuid::Uuid;

fn sample_target() -> TargetCandidate {
    TargetCandidate {
        id: Uuid::nil(),
        project_root: PathBuf::from("/proj"),
        language: TargetLanguage::C,
        symbol: "parse_header".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/parse.c"),
            line: 42,
            col: 1,
        },
        signature: Some("int parse_header(const uint8_t*, size_t)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 12,
        fit_score: 0.87,
        sanitizers: vec![],
        rationale: "Hot parser on attacker-controlled bytes.".to_owned(),
        reachable_functions: vec!["validate".to_owned(), "decode".to_owned()],
        accumulated_complexity: 30,
    }
}

fn sample_crash() -> Crash {
    Crash {
        id: Uuid::nil(),
        run_id: Uuid::nil(),
        target_id: Uuid::nil(),
        input_path: PathBuf::from("/work/out/crash-001"),
        stack_signature: "parse_header+0x20".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow in parse_header".to_owned(),
        minimized: true,
        bug_report: Some(BugReport {
            title: "Heap overflow in parse_header".to_owned(),
            summary: "An oversized length field overflows the heap buffer.".to_owned(),
            repro_steps: "Run the harness on crash-001.".to_owned(),
            stack: "parse_header\nmain".to_owned(),
            severity_guess: "High".to_owned(),
            root_cause: Some("Length field is used unchecked as a memcpy size.".to_owned()),
            suggested_fix: Some("Bound the length against the buffer size.".to_owned()),
        }),
        casr: Some(CasrReport {
            severity: CrashSeverity::Exploitable,
            severity_short: "heap-buffer-overflow(write)".to_owned(),
            crashline: "src/parse.c:48:5".to_owned(),
            stack: vec!["parse_header".to_owned(), "main".to_owned()],
            cluster: Some(1),
        }),
    }
}

fn populated() -> ReportData {
    ReportData {
        generated_at: "2026-06-28T00:00:00Z".to_owned(),
        project: "/proj".to_owned(),
        target: "parse_header".to_owned(),
        tool_version: "0.1.0".to_owned(),
        candidate: Some(sample_target()),
        run: Some(RunRecord {
            id: Uuid::nil(),
            project_root: "/proj".to_owned(),
            engine: EngineKind::LibFuzzer,
            status: RunStatus::Done,
            kind: hf_storage::RunKind::Campaign,
            started_at: "2026-06-28T00:00:00Z".parse().unwrap(),
            ended_at: Some("2026-06-28T00:10:00Z".parse().unwrap()),
            config: None,
            edges: None,
            execs: None,
            crash_count: None,
            harness_rev: None,
            binary_rev: None,
            evidence_dir: None,
            context_rev: None,
        }),
        crashes: vec![sample_crash()],
        coverage: Some(CoverageSummary {
            lines_covered: 120,
            lines_total: 200,
            functions_covered: 7,
            functions_total: 10,
            regions_covered: 40,
            regions_total: 80,
        }),
        covered_functions: 7,
        corpus: CorpusStats {
            count: 25,
            total_bytes: 4096,
            seeds: 2,
            from_fuzzer: 20,
            minimized: 3,
        },
    }
}

#[test]
fn report_has_title_and_core_sections() {
    let md = render_markdown(&populated());
    assert!(md.starts_with("# "), "starts with an H1 title");
    assert!(md.contains("parse_header"), "names the target");
    assert!(md.contains("## Executive Summary"));
    assert!(md.contains("## Target"));
    assert!(md.contains("## Coverage"));
    assert!(md.contains("## Corpus"));
    assert!(md.contains("## Findings"));
}

#[test]
fn report_renders_crash_detail_and_severity() {
    let md = render_markdown(&populated());
    assert!(
        md.contains("Heap overflow in parse_header"),
        "bug report title"
    );
    assert!(md.contains("Exploitable"), "CASR severity");
    assert!(md.contains("heap-buffer-overflow(write)"));
    assert!(md.contains("src/parse.c:48:5"), "crash line");
    // Coverage percentages appear.
    assert!(
        md.contains("60.0%") || md.contains("60%"),
        "line coverage percent"
    );
}

#[test]
fn report_includes_graphs_for_severity_and_coverage() {
    let md = render_markdown(&populated());
    assert!(md.contains("## Visual Summary"), "has a visual summary");
    // Mermaid graphs render in any modern Markdown viewer.
    assert!(md.contains("```mermaid"), "embeds a mermaid graph");
    assert!(md.contains("pie showData"), "severity/kind pie chart");
    assert!(md.contains("xychart-beta"), "coverage bar chart");
    assert!(md.contains("Exploitable"), "severity slice present");
    // Unicode coverage bars render literally everywhere.
    assert!(md.contains('█'), "unicode coverage bar");
}

#[test]
fn coverage_bar_is_proportional() {
    // A full report at 60% line coverage should show ~12/20 filled cells.
    let md = render_markdown(&populated());
    let line = md
        .lines()
        .find(|l| l.starts_with("Lines "))
        .expect("coverage bar line");
    let filled = line.chars().filter(|&c| c == '█').count();
    assert_eq!(filled, 12, "60% -> 12/20 cells");
}

#[test]
fn ai_prompt_is_grounded_in_the_fact_sheet() {
    let data = populated();
    let facts = render_markdown(&data);
    let prompt = report_user_prompt(&facts, &data);
    // The whole fact-sheet is embedded so the model has the real numbers.
    assert!(prompt.contains(&facts), "embeds the fact-sheet verbatim");
    assert!(prompt.contains("parse_header"), "names the target");
    // Anti-hallucination + structure instructions are present.
    assert!(prompt.contains("Do not invent"), "forbids fabrication");
    assert!(prompt.contains("mermaid"), "requires keeping graphs");
    assert!(prompt.contains("Executive Summary"));
    assert!(prompt.contains("Remediation") || prompt.contains("remediation"));
    // The system prompt sets the persona and the no-fabrication rule.
    assert!(report_system_prompt().contains("security engineer"));
    assert!(report_system_prompt().contains("NEVER invent"));
}

#[test]
fn ensure_graphs_appends_when_model_drops_them() {
    let data = populated();
    // Model output with no mermaid blocks -> graphs must be re-added.
    let without = "# Report\n\nSome AI prose without any charts.";
    let fixed = ensure_graphs(without, &data);
    assert!(fixed.contains("```mermaid"), "graphs guaranteed");
    assert!(fixed.contains("Composed by hobot_fuzz"), "footer stamped");

    // Model output that already has a graph -> not duplicated.
    let with = "# Report\n\n```mermaid\npie showData\n    \"X\" : 1\n```\n";
    let kept = ensure_graphs(with, &data);
    assert_eq!(kept.matches("```mermaid").count(), 1, "no duplicate graphs");
}

#[test]
fn empty_report_is_honest_not_fabricated() {
    let data = ReportData {
        generated_at: "2026-06-28T00:00:00Z".to_owned(),
        project: "/proj".to_owned(),
        target: "lonely".to_owned(),
        tool_version: "0.1.0".to_owned(),
        candidate: None,
        run: None,
        crashes: vec![],
        coverage: None,
        covered_functions: 0,
        corpus: CorpusStats::default(),
    };
    let md = render_markdown(&data);
    assert!(md.contains("# "), "still has a title");
    assert!(
        md.contains("No crashes") || md.contains("0 crashes"),
        "honest empty findings"
    );
    assert!(
        !md.contains("### Finding"),
        "must not emit a crash detail block when there are no findings"
    );
    assert!(
        md.contains("not available")
            || md.contains("not been recorded")
            || md.contains("not discovered"),
        "honest 'not available' states for missing run/coverage/target"
    );
}
