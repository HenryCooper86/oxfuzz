//! Markdown campaign report.
//!
//! After a discover -> harness -> run -> triage cycle, [`render_markdown`]
//! composes a detailed, self-contained Markdown document summarizing the
//! campaign: the target, run configuration, coverage, corpus, and every triaged
//! crash (CASR severity + LLM bug report). The output is plain `CommonMark`
//! with `GitHub`-flavored tables, so it pastes into any Markdown tool unchanged.
//!
//! [`ReportData`] is an owned snapshot with no store/runtime references, so the
//! renderer is a pure function and fully unit-testable;
//! [`crate::ServiceContainer::generate_report`] gathers it from the store,
//! coverage, and workspace.

use std::fmt::Write as _;

use hf_core::crash::{Crash, CrashSeverity};
use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;
use hf_coverage::CoverageSummary;
use hf_storage::RunRecord;

/// The language a report is composed in.
///
/// Serializes as the identifiers the desktop app's `Locale` already uses, so the
/// GUI passes its current selection through unchanged. Two variants because two
/// languages exist; a third later is a compile error at every match site, which
/// is the intended behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportLanguage {
    /// English. The default when a caller specifies nothing.
    #[default]
    En,
    /// Simplified Chinese.
    Zh,
}

impl std::str::FromStr for ReportLanguage {
    type Err = ClassifiedError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "en" => Ok(Self::En),
            "zh" => Ok(Self::Zh),
            other => Err(ClassifiedError::Validation(format!(
                "unknown report language '{other}'; accepted values are 'en' and 'zh'"
            ))),
        }
    }
}

/// The title of the native save dialog a desktop shell opens when exporting a
/// composed report.
///
/// Lives here rather than in the shell because the shell is a thin presentation
/// layer with no localization table of its own, and this string names the same
/// artifact `Labels::report_noun` does. It is chrome, not report body content,
/// so it is not part of [`Labels`] -- the renderer never writes it.
///
/// The default export filename stays the ASCII `oxfuzz_report_{target}.{ext}`:
/// that is a technical artifact name, not prose.
#[must_use]
pub const fn export_dialog_title(language: ReportLanguage) -> &'static str {
    match language {
        ReportLanguage::En => "Export fuzzing report",
        ReportLanguage::Zh => "导出模糊测试报告",
    }
}

/// Corpus composition for the report.
#[derive(Debug, Clone, Copy, Default)]
pub struct CorpusStats {
    pub count: usize,
    pub total_bytes: u64,
    pub seeds: usize,
    pub from_fuzzer: usize,
    pub minimized: usize,
}

/// An owned snapshot of everything a campaign report renders. Gathered by
/// [`crate::ServiceContainer::generate_report`]; rendered by [`render_markdown`].
#[derive(Debug, Clone)]
pub struct ReportData {
    /// RFC3339 timestamp the report was generated.
    pub generated_at: String,
    /// Project root path (as configured).
    pub project: String,
    /// Target symbol the campaign fuzzed.
    pub target: String,
    /// `oxfuzz` version that produced the report.
    pub tool_version: String,
    /// The discovered target, if it could be resolved.
    pub candidate: Option<TargetCandidate>,
    /// The most recent run for the project, if any.
    pub run: Option<RunRecord>,
    /// Triaged, deduplicated crashes for the run.
    pub crashes: Vec<Crash>,
    /// Line/function/region coverage, if it could be computed.
    pub coverage: Option<CoverageSummary>,
    /// Number of project functions covered by the corpus.
    pub covered_functions: usize,
    /// Corpus composition.
    pub corpus: CorpusStats,
}

/// Every piece of report scaffolding the renderer writes itself.
///
/// A struct rather than a key-to-string map: a map's failure mode is a missing
/// or misspelled key rendering silently as the key, which no gate catches. Here
/// a missing translation does not compile.
///
/// Data flowing through the report -- paths, signatures, stack frames, engine
/// names, figures -- is never routed through this struct and is never
/// translated.
pub struct Labels {
    // Document header
    pub title_prefix: &'static str,
    pub project: &'static str,
    pub target: &'static str,
    pub generated: &'static str,
    pub tool: &'static str,
    // Section headings
    pub executive_summary: &'static str,
    pub visual_summary: &'static str,
    pub target_section: &'static str,
    pub run_section: &'static str,
    pub coverage_section: &'static str,
    pub corpus_section: &'static str,
    pub findings_section: &'static str,
    pub finding_prefix: &'static str,
    // Executive summary narrative
    pub status_unknown: &'static str,
    pub engine_unknown: &'static str,
    pub coverage_unknown: &'static str,
    pub no_crashes_summary: &'static str,
    pub crashes_summary_lead: &'static str,
    pub crashes_summary_unit: &'static str,
    pub crashes_summary_of_which: &'static str,
    pub crashes_summary_rank: &'static str,
    pub inline_engine: &'static str,
    pub inline_status: &'static str,
    // Punctuation the renderer joins around label/value slots wherever the
    // same mark serves the same purpose -- reused rather than duplicated
    // per-callsite (e.g. `narrative_comma` also separates the corpus
    // bullet's two values; the parens here also wrap the bug-report
    // severity guess). Not markdown (`**` stays literal in templates -- it
    // is formatting, not punctuation); these are the comma/parentheses/full
    // stop a language's own convention supplies (e.g. Chinese "，（）。").
    pub narrative_comma: &'static str,
    pub narrative_open_paren: &'static str,
    pub narrative_close_paren: &'static str,
    pub narrative_full_stop: &'static str,
    // Executive summary bullets
    pub unique_crashes: &'static str,
    pub exploitable_line: &'static str,
    pub corpus_line: &'static str,
    pub corpus_input_unit: &'static str,
    pub line_coverage: &'static str,
    pub line_coverage_unit: &'static str,
    // Visual summary
    pub coverage_bold: &'static str,
    pub bar_lines: &'static str,
    pub bar_functions: &'static str,
    pub bar_regions: &'static str,
    pub chart_coverage_title: &'static str,
    pub chart_percent_covered: &'static str,
    pub chart_crash_severity: &'static str,
    pub chart_crash_kinds: &'static str,
    pub no_visual_data: &'static str,
    // Shared table headers
    pub col_property: &'static str,
    pub col_value: &'static str,
    // Target table
    pub no_target_metadata: &'static str,
    pub row_symbol: &'static str,
    pub row_kind: &'static str,
    pub row_language: &'static str,
    pub row_signature: &'static str,
    pub row_input_surface: &'static str,
    pub row_complexity: &'static str,
    pub row_accumulated_complexity: &'static str,
    pub row_reachable_functions: &'static str,
    pub row_fit_score: &'static str,
    // Run table
    pub no_run_recorded: &'static str,
    pub row_engine: &'static str,
    pub row_status: &'static str,
    pub row_started: &'static str,
    pub row_ended: &'static str,
    pub row_duration: &'static str,
    pub row_sanitizer: &'static str,
    pub row_budget: &'static str,
    // Coverage table
    pub no_coverage_data: &'static str,
    pub col_metric: &'static str,
    pub col_covered: &'static str,
    pub col_total: &'static str,
    pub col_percent: &'static str,
    pub functions_exercised: &'static str,
    // Corpus table
    pub row_entries: &'static str,
    pub row_total_size: &'static str,
    pub row_seeds: &'static str,
    pub row_from_fuzzer: &'static str,
    pub row_minimized: &'static str,
    // Findings table
    pub col_index: &'static str,
    pub col_severity: &'static str,
    pub col_location: &'static str,
    pub no_crashes_found: &'static str,
    // Finding detail
    // bullet_colon is the ": " joiner every "- Label: value" line in the
    // document uses (also the H1 title, the "## Finding N:" heading, and the
    // executive-summary bullets) -- one field, reused everywhere the mark is
    // the same, rather than a colon field per call site.
    pub bullet_colon: &'static str,
    pub bullet_kind: &'static str,
    pub bullet_stack_signature: &'static str,
    pub bullet_input: &'static str,
    pub bullet_casr_severity: &'static str,
    pub bullet_crash_line: &'static str,
    pub bullet_cluster: &'static str,
    pub bullet_minimized: &'static str,
    pub bool_yes: &'static str,
    pub bool_no: &'static str,
    pub stack_trace: &'static str,
    pub bug_report_heading: &'static str,
    pub severity_guess_label: &'static str,
    pub reproduction: &'static str,
    pub root_cause: &'static str,
    pub suggested_fix: &'static str,
    // CASR exploitability terms. Scaffolding, not data: these are literals the
    // renderer writes. See the design's section 6.
    pub casr_exploitable: &'static str,
    pub casr_probably_exploitable: &'static str,
    pub casr_not_exploitable: &'static str,
    pub casr_undefined: &'static str,
    // Footer
    pub generated_by: &'static str,
    pub footer_on: &'static str,
    pub composed_by: &'static str,
    // Exported-document metadata, not report body content: the noun in the
    // title an export builds, which reaches the reader as the HTML document's
    // <title>. The renderer never writes it, but it is still prose that follows
    // the report's language, so it belongs with the labels rather than being a
    // literal at the export call site.
    pub report_noun: &'static str,
}

impl Labels {
    /// The English label set. These strings reproduce the renderer's original
    /// hardcoded literals exactly.
    #[must_use]
    pub const fn english() -> Self {
        Self {
            title_prefix: "Fuzzing Report",
            project: "Project",
            target: "Target",
            generated: "Generated",
            tool: "Tool",
            executive_summary: "Executive Summary",
            visual_summary: "Visual Summary",
            target_section: "Target",
            run_section: "Run",
            coverage_section: "Coverage",
            corpus_section: "Corpus",
            findings_section: "Findings",
            finding_prefix: "Finding",
            status_unknown: "no run recorded",
            engine_unknown: "n/a",
            coverage_unknown: "not available",
            no_crashes_summary: "No crashes were found in the most recent campaign",
            crashes_summary_lead: "The campaign surfaced",
            crashes_summary_unit: "unique crash(es)",
            crashes_summary_of_which: "of which",
            crashes_summary_rank: "rank as exploitable or probably exploitable",
            inline_engine: "engine",
            inline_status: "status",
            narrative_comma: ", ",
            narrative_open_paren: " (",
            narrative_close_paren: ")",
            narrative_full_stop: ".",
            unique_crashes: "Unique crashes",
            exploitable_line: "Exploitable / probably exploitable",
            corpus_line: "Corpus",
            corpus_input_unit: "input(s)",
            line_coverage: "Line coverage",
            line_coverage_unit: "lines",
            coverage_bold: "Coverage",
            bar_lines: "Lines",
            bar_functions: "Functions",
            bar_regions: "Regions",
            chart_coverage_title: "Coverage (%)",
            chart_percent_covered: "Percent covered",
            chart_crash_severity: "Crash severity",
            chart_crash_kinds: "Crash kinds",
            no_visual_data: "No coverage or crash data yet to visualize.",
            col_property: "Property",
            col_value: "Value",
            no_target_metadata: "Target metadata was not available (not discovered).",
            row_symbol: "Symbol",
            row_kind: "Kind",
            row_language: "Language",
            row_signature: "Signature",
            row_input_surface: "Input surface",
            row_complexity: "Complexity",
            row_accumulated_complexity: "Accumulated complexity",
            row_reachable_functions: "Reachable functions",
            row_fit_score: "Fit score",
            no_run_recorded: "No run has been recorded for this project.",
            row_engine: "Engine",
            row_status: "Status",
            row_started: "Started",
            row_ended: "Ended",
            row_duration: "Duration",
            row_sanitizer: "Sanitizer",
            row_budget: "Budget",
            no_coverage_data:
                "Coverage was not available (no harness built, or coverage tooling absent).",
            col_metric: "Metric",
            col_covered: "Covered",
            col_total: "Total",
            col_percent: "Percent",
            functions_exercised: "project function(s) are exercised by the corpus.",
            row_entries: "Entries",
            row_total_size: "Total size",
            row_seeds: "Seeds",
            row_from_fuzzer: "From fuzzer",
            row_minimized: "Minimized",
            col_index: "#",
            col_severity: "Severity",
            col_location: "Location",
            no_crashes_found: "No crashes were found. There is nothing to triage.",
            bullet_colon: ": ",
            bullet_kind: "Kind",
            bullet_stack_signature: "Stack signature",
            bullet_input: "Input",
            bullet_casr_severity: "CASR severity",
            bullet_crash_line: "Crash line",
            bullet_cluster: "Cluster",
            bullet_minimized: "Minimized",
            bool_yes: "yes",
            bool_no: "no",
            stack_trace: "Stack trace:",
            bug_report_heading: "Bug report",
            severity_guess_label: "severity guess: ",
            reproduction: "Reproduction:",
            root_cause: "Root cause:",
            suggested_fix: "Suggested fix:",
            casr_exploitable: "Exploitable",
            casr_probably_exploitable: "Probably exploitable",
            casr_not_exploitable: "Not exploitable",
            casr_undefined: "Undefined",
            generated_by: "Generated by oxfuzz",
            footer_on: "on",
            composed_by: "Composed by oxfuzz",
            report_noun: "report",
        }
    }

    /// Resolve the label set for `language`.
    #[must_use]
    pub const fn for_language(language: ReportLanguage) -> Self {
        match language {
            ReportLanguage::En => Self::english(),
            ReportLanguage::Zh => Self::chinese(),
        }
    }
}

impl Labels {
    /// The Simplified Chinese label set.
    ///
    /// CASR exploitability terms carry the original in parentheses: translated
    /// for the reader, greppable and matchable against CASR output.
    #[must_use]
    pub const fn chinese() -> Self {
        Self {
            title_prefix: "模糊测试报告",
            project: "项目",
            target: "目标",
            generated: "生成时间",
            tool: "工具",
            executive_summary: "摘要",
            visual_summary: "图表概览",
            target_section: "目标",
            run_section: "运行",
            coverage_section: "覆盖率",
            corpus_section: "语料库",
            findings_section: "发现项",
            finding_prefix: "发现项",
            unique_crashes: "去重后的崩溃数",
            exploitable_line: "可利用 / 可能可利用",
            corpus_line: "语料库",
            line_coverage: "行覆盖率",
            coverage_bold: "覆盖率",
            bar_lines: "行",
            bar_functions: "函数",
            bar_regions: "区域",
            chart_coverage_title: "覆盖率 (%)",
            chart_percent_covered: "覆盖百分比",
            chart_crash_severity: "崩溃严重程度",
            chart_crash_kinds: "崩溃类型",
            no_visual_data: "暂无可视化所需的覆盖率或崩溃数据。",
            col_property: "属性",
            col_value: "值",
            no_target_metadata: "目标元数据不可用（尚未发现）。",
            row_symbol: "符号",
            row_kind: "类型",
            row_language: "语言",
            row_signature: "签名",
            row_input_surface: "输入面",
            row_complexity: "复杂度",
            row_accumulated_complexity: "累计复杂度",
            row_fit_score: "适配评分",
            no_run_recorded: "该项目尚无运行记录。",
            row_engine: "引擎",
            row_status: "状态",
            row_started: "开始时间",
            row_ended: "结束时间",
            row_duration: "时长",
            row_sanitizer: "消毒器",
            row_budget: "预算",
            col_metric: "指标",
            col_covered: "已覆盖",
            col_total: "总计",
            col_percent: "百分比",
            row_entries: "条目数",
            row_total_size: "总大小",
            row_seeds: "种子",
            row_from_fuzzer: "来自模糊测试",
            row_minimized: "已最小化",
            col_index: "序号",
            col_severity: "严重程度",
            col_location: "位置",
            bullet_kind: "类型",
            bullet_stack_signature: "堆栈签名",
            bullet_input: "输入",
            bullet_casr_severity: "CASR 严重程度",
            bullet_crash_line: "崩溃位置",
            bullet_cluster: "簇",
            bullet_minimized: "已最小化",
            stack_trace: "堆栈：",
            no_crashes_found: "未发现崩溃，无需分类定级。",
            bug_report_heading: "缺陷报告",
            reproduction: "复现步骤：",
            root_cause: "根本原因：",
            suggested_fix: "修复建议：",
            casr_exploitable: "可利用 (Exploitable)",
            casr_probably_exploitable: "可能可利用 (Probably exploitable)",
            casr_not_exploitable: "不可利用 (Not exploitable)",
            casr_undefined: "未确定 (Undefined)",
            generated_by: "由 oxfuzz 生成",
            status_unknown: "无运行记录",
            engine_unknown: "不适用",
            coverage_unknown: "不可用",
            no_crashes_summary: "最近一次测试活动未发现崩溃",
            crashes_summary_lead: "本次测试活动发现",
            crashes_summary_unit: "个去重崩溃",
            crashes_summary_of_which: "其中",
            crashes_summary_rank: "个被判定为可利用或可能可利用",
            narrative_comma: "，",
            narrative_open_paren: "（",
            narrative_close_paren: "）",
            narrative_full_stop: "。",
            bullet_colon: "：",
            inline_engine: "引擎",
            inline_status: "状态",
            corpus_input_unit: "个输入",
            line_coverage_unit: "行",
            row_reachable_functions: "可达函数",
            no_coverage_data: "覆盖率不可用（未构建测试桩，或缺少覆盖率工具）。",
            functions_exercised: "个项目函数被语料库覆盖。",
            bool_yes: "是",
            bool_no: "否",
            severity_guess_label: "严重程度推测：",
            footer_on: "于",
            composed_by: "由 oxfuzz 撰写",
            report_noun: "报告",
        }
    }
}

/// Render a campaign report as GitHub-flavored Markdown.
#[must_use]
pub fn render_markdown(data: &ReportData, labels: &Labels) -> String {
    let mut md = String::with_capacity(4096);

    let _ = writeln!(
        md,
        "# {}{}`{}`",
        labels.title_prefix, labels.bullet_colon, data.target
    );
    let _ = writeln!(md);
    let _ = writeln!(md, "| | |");
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| {} | `{}` |", labels.project, data.project);
    let _ = writeln!(md, "| {} | `{}` |", labels.target, data.target);
    let _ = writeln!(md, "| {} | {} |", labels.generated, data.generated_at);
    let _ = writeln!(md, "| {} | oxfuzz {} |", labels.tool, data.tool_version);
    let _ = writeln!(md);

    render_executive_summary(&mut md, data, labels);
    render_visual_summary(&mut md, data, labels);
    render_target(&mut md, data, labels);
    render_run(&mut md, data, labels);
    render_coverage(&mut md, data, labels);
    render_corpus(&mut md, data, labels);
    render_findings(&mut md, data, labels);

    let _ = writeln!(md, "---");
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "_{} {} {} {}{}_",
        labels.generated_by,
        data.tool_version,
        labels.footer_on,
        data.generated_at,
        labels.narrative_full_stop
    );
    md
}

fn render_executive_summary(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.executive_summary);
    let _ = writeln!(md);

    let total = data.crashes.len();
    let exploitable = data
        .crashes
        .iter()
        .filter(|c| {
            matches!(
                c.casr.as_ref().map(|r| r.severity),
                Some(CrashSeverity::Exploitable | CrashSeverity::ProbablyExploitable)
            )
        })
        .count();
    let status = data.run.as_ref().map_or_else(
        || labels.status_unknown.to_owned(),
        |r| format!("{:?}", r.status),
    );
    let engine = data.run.as_ref().map_or_else(
        || labels.engine_unknown.to_owned(),
        |r| format!("{:?}", r.engine),
    );
    let cov = data.coverage.map_or_else(
        || labels.coverage_unknown.to_owned(),
        |c| format!("{:.1}% {}", c.line_percent(), labels.line_coverage_unit),
    );

    if total == 0 {
        let _ = writeln!(
            md,
            "{summary}{op}{engine_word} {engine}{comma}{status_word} {status}{cp}{stop}",
            summary = labels.no_crashes_summary,
            op = labels.narrative_open_paren,
            engine_word = labels.inline_engine,
            comma = labels.narrative_comma,
            status_word = labels.inline_status,
            cp = labels.narrative_close_paren,
            stop = labels.narrative_full_stop,
        );
    } else {
        let _ = writeln!(
            md,
            "{lead} **{total} {unit}**{comma}{of_which} **{exploitable}** {rank}{op}{engine_word} {engine}{comma}{status_word} {status}{cp}{stop}",
            lead = labels.crashes_summary_lead,
            unit = labels.crashes_summary_unit,
            comma = labels.narrative_comma,
            of_which = labels.crashes_summary_of_which,
            rank = labels.crashes_summary_rank,
            op = labels.narrative_open_paren,
            engine_word = labels.inline_engine,
            status_word = labels.inline_status,
            cp = labels.narrative_close_paren,
            stop = labels.narrative_full_stop,
        );
    }
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- {}{}**{total}**",
        labels.unique_crashes, labels.bullet_colon
    );
    let _ = writeln!(
        md,
        "- {}{}**{exploitable}**",
        labels.exploitable_line, labels.bullet_colon
    );
    let _ = writeln!(
        md,
        "- {}{}**{cov}**",
        labels.line_coverage, labels.bullet_colon
    );
    let _ = writeln!(
        md,
        "- {}{}**{} {}**{}{}",
        labels.corpus_line,
        labels.bullet_colon,
        data.corpus.count,
        labels.corpus_input_unit,
        labels.narrative_comma,
        human_bytes(data.corpus.total_bytes)
    );
    let _ = writeln!(md);
}

/// Visual summary: graphs that render in any Markdown tool (Mermaid charts for
/// rich viewers, plus Unicode bars that render literally everywhere).
fn render_visual_summary(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.visual_summary);
    let _ = writeln!(md);

    // Coverage bars (universal) first, then Mermaid charts (rich viewers).
    if let Some(c) = data.coverage {
        let _ = writeln!(md, "**{}**", labels.coverage_bold);
        let _ = writeln!(md);
        let _ = writeln!(md, "```text");
        let _ = writeln!(
            md,
            "{:<9} {}",
            labels.bar_lines,
            coverage_bar(c.line_percent())
        );
        let _ = writeln!(
            md,
            "{:<9} {}",
            labels.bar_functions,
            coverage_bar(c.function_percent())
        );
        let _ = writeln!(
            md,
            "{:<9} {}",
            labels.bar_regions,
            coverage_bar(c.region_percent())
        );
        let _ = writeln!(md, "```");
        let _ = writeln!(md);
        let _ = writeln!(md, "{}", coverage_mermaid(c, labels));
        let _ = writeln!(md);
    }

    // Severity distribution pie (only meaningful with crashes).
    if !data.crashes.is_empty() {
        let _ = writeln!(md, "{}", severity_pie_mermaid(&data.crashes, labels));
        let _ = writeln!(md);
        let _ = writeln!(md, "{}", kind_pie_mermaid(&data.crashes, labels));
        let _ = writeln!(md);
    }

    if data.coverage.is_none() && data.crashes.is_empty() {
        let _ = writeln!(md, "_{}_", labels.no_visual_data);
        let _ = writeln!(md);
    }
}

/// A 20-cell Unicode block bar with a trailing percentage, e.g.
/// `████████████░░░░░░░░  60.0%`.
fn coverage_bar(percent: f64) -> String {
    const CELLS: usize = 20;
    let filled = ((percent / 100.0) * CELLS as f64).round() as usize;
    let filled = filled.min(CELLS);
    let bar: String = "█".repeat(filled) + &"░".repeat(CELLS - filled);
    format!("{bar}  {percent:.1}%")
}

/// A Mermaid bar chart of coverage percentages.
///
/// Every interpolated label is quoted. `xychart-beta`'s lexer accepts bare
/// ASCII words but rejects bare CJK ("Lexical error ... Unrecognized text."),
/// so an unquoted `x-axis` category list turns the whole Chinese chart into a
/// syntax error. Quoting is also valid for English and renders identically.
fn coverage_mermaid(c: CoverageSummary, labels: &Labels) -> String {
    format!(
        "```mermaid\n\
         xychart-beta\n\
         \x20   title \"{}\"\n\
         \x20   x-axis [\"{}\", \"{}\", \"{}\"]\n\
         \x20   y-axis \"{}\" 0 --> 100\n\
         \x20   bar [{:.1}, {:.1}, {:.1}]\n\
         ```",
        labels.chart_coverage_title,
        labels.bar_lines,
        labels.bar_functions,
        labels.bar_regions,
        labels.chart_percent_covered,
        c.line_percent(),
        c.function_percent(),
        c.region_percent()
    )
}

/// Resolve a CASR severity to its label. `Debug` output is the raw enum
/// identifier, not the human-readable phrase; it matches the label for two
/// of four variants by coincidence (`Exploitable`, `Undefined`) and differs
/// in spacing and case for the other two (`ProbablyExploitable` /
/// "Probably exploitable", `NotExploitable` / "Not exploitable").
const fn casr_severity_label(severity: CrashSeverity, labels: &Labels) -> &'static str {
    match severity {
        CrashSeverity::Exploitable => labels.casr_exploitable,
        CrashSeverity::ProbablyExploitable => labels.casr_probably_exploitable,
        CrashSeverity::NotExploitable => labels.casr_not_exploitable,
        CrashSeverity::Undefined => labels.casr_undefined,
    }
}

/// A Mermaid pie chart of crash exploitability (CASR severity).
///
/// Unlike `xychart-beta`, the `pie` grammar reads the title as the rest of the
/// line, so a bare CJK title parses; the slice labels are quoted regardless.
fn severity_pie_mermaid(crashes: &[Crash], labels: &Labels) -> String {
    let mut exploitable = 0;
    let mut probably = 0;
    let mut not_exploitable = 0;
    let mut undefined = 0;
    for c in crashes {
        match c.casr.as_ref().map(|r| r.severity) {
            Some(CrashSeverity::Exploitable) => exploitable += 1,
            Some(CrashSeverity::ProbablyExploitable) => probably += 1,
            Some(CrashSeverity::NotExploitable) => not_exploitable += 1,
            _ => undefined += 1,
        }
    }
    let mut out = format!(
        "```mermaid\npie showData\n    title {}\n",
        labels.chart_crash_severity
    );
    for (label, n) in [
        (labels.casr_exploitable, exploitable),
        (labels.casr_probably_exploitable, probably),
        (labels.casr_not_exploitable, not_exploitable),
        (labels.casr_undefined, undefined),
    ] {
        if n > 0 {
            let _ = writeln!(out, "    \"{label}\" : {n}");
        }
    }
    out.push_str("```");
    out
}

/// A Mermaid pie chart of crash kinds (ASan/UBSan/SEGV/...).
///
/// Same quoting rules as [`severity_pie_mermaid`]: bare CJK title is accepted,
/// slice labels are quoted.
fn kind_pie_mermaid(crashes: &[Crash], labels: &Labels) -> String {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for c in crashes {
        *counts.entry(format!("{:?}", c.kind)).or_default() += 1;
    }
    let mut out = format!(
        "```mermaid\npie showData\n    title {}\n",
        labels.chart_crash_kinds
    );
    for (label, n) in counts {
        let _ = writeln!(out, "    \"{label}\" : {n}");
    }
    out.push_str("```");
    out
}

fn render_target(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.target_section);
    let _ = writeln!(md);
    let Some(c) = &data.candidate else {
        let _ = writeln!(md, "_{}_", labels.no_target_metadata);
        let _ = writeln!(md);
        return;
    };
    let _ = writeln!(md, "| {} | {} |", labels.col_property, labels.col_value);
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| {} | `{}` |", labels.row_symbol, c.symbol);
    let _ = writeln!(md, "| {} | {:?} |", labels.row_kind, c.kind);
    let _ = writeln!(md, "| {} | {:?} |", labels.row_language, c.language);
    let _ = writeln!(
        md,
        "| {} | `{}:{}:{}` |",
        labels.col_location,
        c.location.file.display(),
        c.location.line,
        c.location.col
    );
    if let Some(sig) = &c.signature {
        let _ = writeln!(md, "| {} | `{sig}` |", labels.row_signature);
    }
    let _ = writeln!(
        md,
        "| {} | {:?} |",
        labels.row_input_surface, c.input_surface
    );
    let _ = writeln!(md, "| {} | {} |", labels.row_complexity, c.complexity);
    let _ = writeln!(
        md,
        "| {} | {} |",
        labels.row_accumulated_complexity, c.accumulated_complexity
    );
    let _ = writeln!(
        md,
        "| {} | {} |",
        labels.row_reachable_functions,
        c.reachable_functions.len()
    );
    let _ = writeln!(md, "| {} | {:.2} |", labels.row_fit_score, c.fit_score);
    let _ = writeln!(md);
    if !c.rationale.trim().is_empty() {
        let _ = writeln!(md, "> {}", c.rationale.trim());
        let _ = writeln!(md);
    }
}

fn render_run(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.run_section);
    let _ = writeln!(md);
    let Some(r) = &data.run else {
        let _ = writeln!(md, "_{}_", labels.no_run_recorded);
        let _ = writeln!(md);
        return;
    };
    let _ = writeln!(md, "| {} | {} |", labels.col_property, labels.col_value);
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| {} | {:?} |", labels.row_engine, r.engine);
    let _ = writeln!(md, "| {} | {:?} |", labels.row_status, r.status);
    let _ = writeln!(
        md,
        "| {} | {} |",
        labels.row_started,
        r.started_at.to_rfc3339()
    );
    if let Some(ended) = r.ended_at {
        let _ = writeln!(md, "| {} | {} |", labels.row_ended, ended.to_rfc3339());
        let secs = (ended - r.started_at).num_seconds().max(0);
        let _ = writeln!(md, "| {} | {} |", labels.row_duration, human_duration(secs));
    }
    if let Some(cfg) = &r.config {
        let _ = writeln!(md, "| {} | {:?} |", labels.row_sanitizer, cfg.sanitizer);
        if let Some(d) = cfg.duration {
            let budget = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            let _ = writeln!(md, "| {} | {} |", labels.row_budget, human_duration(budget));
        }
    }
    let _ = writeln!(md);
}

fn render_coverage(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.coverage_section);
    let _ = writeln!(md);
    let Some(c) = data.coverage else {
        let _ = writeln!(md, "_{}_", labels.no_coverage_data);
        let _ = writeln!(md);
        return;
    };
    let _ = writeln!(
        md,
        "| {} | {} | {} | {} |",
        labels.col_metric, labels.col_covered, labels.col_total, labels.col_percent
    );
    let _ = writeln!(md, "|---|---:|---:|---:|");
    let _ = writeln!(
        md,
        "| {} | {} | {} | {:.1}% |",
        labels.bar_lines,
        c.lines_covered,
        c.lines_total,
        c.line_percent()
    );
    let _ = writeln!(
        md,
        "| {} | {} | {} | {:.1}% |",
        labels.bar_functions,
        c.functions_covered,
        c.functions_total,
        c.function_percent()
    );
    let _ = writeln!(
        md,
        "| {} | {} | {} | {:.1}% |",
        labels.bar_regions,
        c.regions_covered,
        c.regions_total,
        c.region_percent()
    );
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "{} {}",
        data.covered_functions, labels.functions_exercised
    );
    let _ = writeln!(md);
}

fn render_corpus(md: &mut String, data: &ReportData, labels: &Labels) {
    let s = &data.corpus;
    let _ = writeln!(md, "## {}", labels.corpus_section);
    let _ = writeln!(md);
    let _ = writeln!(md, "| {} | {} |", labels.col_property, labels.col_value);
    let _ = writeln!(md, "|---|---|");
    let _ = writeln!(md, "| {} | {} |", labels.row_entries, s.count);
    let _ = writeln!(
        md,
        "| {} | {} |",
        labels.row_total_size,
        human_bytes(s.total_bytes)
    );
    let _ = writeln!(md, "| {} | {} |", labels.row_seeds, s.seeds);
    let _ = writeln!(md, "| {} | {} |", labels.row_from_fuzzer, s.from_fuzzer);
    let _ = writeln!(md, "| {} | {} |", labels.row_minimized, s.minimized);
    let _ = writeln!(md);
}

/// Escape a value for safe inclusion in a Markdown table cell or heading.
///
/// LLM- and CASR-derived text (summaries, titles, crashlines, signatures) can
/// contain `|` (which breaks a table's column count), backticks (which break a
/// code span), or newlines (which split a row/heading). Mirrors the automotive
/// report's `escape_inline`.
fn escape_inline(value: &str) -> String {
    value
        .replace(['\n', '\r'], " ")
        .replace('`', "'")
        .replace('|', "\\|")
}

fn render_findings(md: &mut String, data: &ReportData, labels: &Labels) {
    let _ = writeln!(md, "## {}", labels.findings_section);
    let _ = writeln!(md);
    if data.crashes.is_empty() {
        let _ = writeln!(md, "{}", labels.no_crashes_found);
        let _ = writeln!(md);
        return;
    }

    // Summary table.
    let _ = writeln!(
        md,
        "| {} | {} | {} | {} | {} |",
        labels.col_index,
        labels.bullet_kind,
        labels.col_severity,
        labels.col_location,
        labels.row_signature
    );
    let _ = writeln!(md, "|---:|---|---|---|---|");
    for (i, c) in data.crashes.iter().enumerate() {
        let severity = c.casr.as_ref().map_or(labels.casr_undefined, |r| {
            casr_severity_label(r.severity, labels)
        });
        let location = c
            .casr
            .as_ref()
            .map(|r| r.crashline.clone())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| "-".to_owned());
        let _ = writeln!(
            md,
            "| {} | {:?} | {} | `{}` | `{}` |",
            i + 1,
            c.kind,
            escape_inline(severity),
            escape_inline(&location),
            escape_inline(&truncate(&c.stack_signature, 60))
        );
    }
    let _ = writeln!(md);

    // Per-crash detail.
    for (i, c) in data.crashes.iter().enumerate() {
        render_crash_detail(md, i + 1, c, labels);
    }
}

fn render_crash_detail(md: &mut String, n: usize, c: &Crash, labels: &Labels) {
    let title = c
        .bug_report
        .as_ref()
        .map(|b| b.title.clone())
        .filter(|t| !t.trim().is_empty())
        .unwrap_or_else(|| c.summary.clone());
    let _ = writeln!(
        md,
        "### {} {n}{}{}",
        labels.finding_prefix,
        labels.bullet_colon,
        escape_inline(&title)
    );
    let _ = writeln!(md);
    let _ = writeln!(
        md,
        "- {}{}`{:?}`",
        labels.bullet_kind, labels.bullet_colon, c.kind
    );
    let _ = writeln!(
        md,
        "- {}{}`{}`",
        labels.bullet_stack_signature, labels.bullet_colon, c.stack_signature
    );
    let _ = writeln!(
        md,
        "- {}{}`{}`",
        labels.bullet_input,
        labels.bullet_colon,
        c.input_path.display()
    );
    let _ = writeln!(
        md,
        "- {}{}{}",
        labels.bullet_minimized,
        labels.bullet_colon,
        if c.minimized {
            labels.bool_yes
        } else {
            labels.bool_no
        }
    );

    if let Some(casr) = &c.casr {
        let _ = writeln!(
            md,
            "- {}{}**{}**{}{}{}",
            labels.bullet_casr_severity,
            labels.bullet_colon,
            casr_severity_label(casr.severity, labels),
            labels.narrative_open_paren,
            casr.severity_short,
            labels.narrative_close_paren
        );
        if !casr.crashline.is_empty() {
            let _ = writeln!(
                md,
                "- {}{}`{}`",
                labels.bullet_crash_line, labels.bullet_colon, casr.crashline
            );
        }
        if let Some(cluster) = casr.cluster {
            let _ = writeln!(
                md,
                "- {}{}{cluster}",
                labels.bullet_cluster, labels.bullet_colon
            );
        }
        if !casr.stack.is_empty() {
            let _ = writeln!(md);
            let _ = writeln!(md, "{}", labels.stack_trace);
            let _ = writeln!(md);
            let _ = writeln!(md, "```");
            for frame in &casr.stack {
                let _ = writeln!(md, "{frame}");
            }
            let _ = writeln!(md, "```");
        }
    }

    if let Some(report) = &c.bug_report {
        let _ = writeln!(md);
        let _ = writeln!(
            md,
            "**{}**{}{}{}{}",
            labels.bug_report_heading,
            labels.narrative_open_paren,
            labels.severity_guess_label,
            report.severity_guess,
            labels.narrative_close_paren
        );
        let _ = writeln!(md);
        if !report.summary.trim().is_empty() {
            let _ = writeln!(md, "{}", report.summary.trim());
            let _ = writeln!(md);
        }
        if !report.repro_steps.trim().is_empty() {
            let _ = writeln!(
                md,
                "_{}_ {}",
                labels.reproduction,
                report.repro_steps.trim()
            );
            let _ = writeln!(md);
        }
        if let Some(root_cause) = report
            .root_cause
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let _ = writeln!(md, "_{}_ {}", labels.root_cause, root_cause.trim());
            let _ = writeln!(md);
        }
        if let Some(fix) = report
            .suggested_fix
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            let _ = writeln!(md, "_{}_", labels.suggested_fix);
            let _ = writeln!(md, "```diff");
            let _ = writeln!(md, "{}", fix.trim());
            let _ = writeln!(md, "```");
            let _ = writeln!(md);
        }
    }
    let _ = writeln!(md);
}

// -- AI composition ----------------------------------------------------------

/// System prompt for the LLM that composes the professional narrative report.
#[must_use]
pub fn report_system_prompt(language: ReportLanguage) -> String {
    let base = "You are a senior security engineer writing a professional fuzzing campaign \
                report for an engineering and security audience. You write clearly and \
                authoritatively, with concrete, actionable analysis. You NEVER invent facts: \
                every number, severity, file path, and stack frame must come verbatim from \
                the data you are given. If a figure is absent, say it was not measured \
                rather than guessing.";
    match language {
        ReportLanguage::En => base.to_owned(),
        ReportLanguage::Zh => format!(
            "{base} You write the report in Simplified Chinese for a Chinese-reading \
             engineering audience."
        ),
    }
}

/// Build the user prompt: the grounded fact-sheet plus composition rules.
///
/// The fact-sheet (`facts`) is the deterministic [`render_markdown`] output --
/// every real number and the pre-rendered Mermaid graphs -- so the model has no
/// reason to fabricate. The rules pin structure and require the graphs be kept.
#[must_use]
pub fn report_user_prompt(facts: &str, data: &ReportData, language: ReportLanguage) -> String {
    let language_rules = match language {
        ReportLanguage::En => String::new(),
        ReportLanguage::Zh => "Write the entire report in Simplified Chinese, including \
             all section headings and prose.\n\n\
             Keep the following verbatim in their original form, never translated or \
             transliterated: file paths, stack frames, symbol and function names, crash \
             signatures, engine names, sanitizer names, CWE identifiers, and all figures. \
             A translated stack frame no longer matches the crash it came from.\n\n"
            .to_owned(),
    };
    format!(
        "Compose a comprehensive, professional fuzzing report in GitHub-flavored \
         Markdown for target `{target}` in project `{project}`.\n\n\
         Use ONLY the facts and figures in the data sheet below. Do not invent \
         crash counts, severities, coverage numbers, file paths, or stack frames. \
         Preserve every ```mermaid``` code block and Markdown table from the data \
         sheet verbatim, placing them in the most relevant section.\n\n\
         Structure the report with these sections (use `##` headings):\n\
         1. Executive Summary - audience-appropriate overview of risk and outcome.\n\
         2. Methodology - engine, sanitizer, duration, corpus, coverage approach.\n\
         3. Coverage Analysis - interpret the coverage figures and what they imply \
         about untested code; include the coverage graphs.\n\
         4. Findings - for EACH crash: a clear title, impact, likely root cause, \
         exploitability rationale (from the CASR severity), and concrete \
         remediation guidance. Include the severity graphs.\n\
         5. Risk Assessment - prioritize the findings and state residual risk.\n\
         6. Recommendations - prioritized, actionable next steps (fixes, more \
         fuzzing, harness/corpus improvements).\n\
         7. Conclusion.\n\n\
         Write in prose, not just bullet lists. Be specific and technical. If \
         there are no crashes, focus on coverage achieved, residual risk, and how \
         to drive deeper.\n\n\
         Output ONLY the Markdown report, starting with a single `#` title. Do not \
         wrap the whole thing in a code fence.\n\n\
         {language_rules}---\n\
         # DATA SHEET (ground truth)\n\n\
         {facts}",
        target = data.target,
        project = data.project,
    )
}

/// Guarantee the report carries the campaign graphs: if the model's output
/// dropped the Mermaid blocks, append a deterministic Visual Summary so graphs
/// are always present. Also stamps the generator footer.
///
/// Takes `labels` rather than deciding a language itself: the caller already
/// knows the report's language (it built the fact-sheet the model was
/// grounded in), so the re-injected graphs and the footer this function
/// stamps match the language of the report they are appended to.
#[must_use]
pub fn ensure_graphs(ai_markdown: &str, data: &ReportData, labels: &Labels) -> String {
    let mut out = ai_markdown.trim_end().to_owned();
    if !out.contains("```mermaid") {
        let mut visual = String::new();
        render_visual_summary(&mut visual, data, labels);
        if visual.contains("```mermaid") || visual.contains('█') {
            out.push_str("\n\n");
            out.push_str(&visual);
        }
    }
    let _ = write!(
        out,
        "\n---\n\n_{} {} {} {}{}_\n",
        labels.composed_by,
        data.tool_version,
        labels.footer_on,
        data.generated_at,
        labels.narrative_full_stop
    );
    out
}

// -- formatting helpers ------------------------------------------------------

fn human_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kb = bytes as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1} KiB");
    }
    format!("{:.1} MiB", kb / 1024.0)
}

fn human_duration(secs: i64) -> String {
    if secs < 60 {
        return format!("{secs}s");
    }
    let m = secs / 60;
    let s = secs % 60;
    if m < 60 {
        return format!("{m}m {s}s");
    }
    let h = m / 60;
    let m = m % 60;
    format!("{h}h {m}m")
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}
