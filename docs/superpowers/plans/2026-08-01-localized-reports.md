# Localized Report Generation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce campaign reports in Simplified Chinese when the caller asks for Chinese, keeping every technical token verbatim.

**Architecture:** A `ReportLanguage` value travels from the caller into `hf-service`. The deterministic fact sheet's scaffolding moves out of hardcoded literals into a `Labels` struct with one constructor per language, so a missing translation is a compile error. The LLM narrative prompt gains a language instruction and a token-preservation rule. Because the scaffolding is translated in Rust rather than by the model, the no-provider fallback report is Chinese too.

**Tech Stack:** Rust 1.94.0 (pinned in `rust-toolchain.toml`), serde, React 19 + TypeScript for the desktop caller, Tauri v2.

**Design spec:** `docs/superpowers/specs/2026-08-01-localized-reports-design.md`

**Task map:** Task 1 adds the language type. Task 2 is a pure refactor that makes the report translatable without translating anything, proven by the existing test suite passing unchanged. Task 3 adds the Chinese translation. Task 4 localizes the narrative prompts. Task 5 threads the parameter through the three calling surfaces. Tasks 1 through 4 are `hf-service`-only; only Task 5 touches a presentation crate.

## Global Constraints

- Rust toolchain is pinned to `1.94.0` by `rust-toolchain.toml`.
- Clippy runs `pedantic` workspace-wide with `-D warnings`. **Never add inline lint suppressions** (`#[allow(clippy::...)]`). Fix the code or move the rule to the owning config with a justifying comment.
- **No emoji anywhere** in code, comments, commit messages, or docs. Chinese characters are not emoji and are expected in this work.
- All domain logic lives in `hf-service`. `hf-cli`, `hf-web`, and `hf-gui` are thin presentation layers doing only input, output, and rendering. Task 5 passes a value; it adds no logic.
- Rust casing: `snake_case` files and functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants.
- **Technical tokens are never translated.** File paths, stack frames, symbol and function names, crash signatures, engine names, sanitizer names, CWE identifiers, and all figures render byte-identical in both languages.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Baseline on `main` at the time of writing: `cargo test -p hf-service` passes; `crates/hf-service/tests/report.rs` holds the existing report tests. Every task must leave that suite green.
- After each task: `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `cargo check -p hf-service --all-targets`, `cargo check -p hf-service --no-default-features`. That last one has caught two real defects in this repository that no other gate could see.

---

## File Structure

**Created:** none. This feature extends existing files rather than adding new ones, because the label set belongs with the renderer that consumes it.

**Modified:**

| Path | Change |
| --- | --- |
| `crates/hf-service/src/report.rs` | Adds `ReportLanguage` and `Labels`; `render_markdown` and both prompt builders take a language |
| `crates/hf-service/src/container/export.rs` | `generate_report`, `export_report`, and `compose_ai_report` take and forward the language |
| `crates/hf-service/src/lib.rs` | Re-exports `ReportLanguage` |
| `crates/hf-service/tests/report.rs` | Existing tests updated for the new signature; new localization tests added |
| `crates/hf-cli/src/main.rs` | `report` subcommand gains `--lang` |
| `crates/hf-web/src/router.rs` | Report request body gains an optional `language` |
| `crates/hf-gui/src-tauri/src/commands.rs` | `generate_report` and `export_report` commands take a `language` |
| `crates/hf-gui/src/views/*` | The report caller passes `useI18n().locale` |

---

### Task 1: The `ReportLanguage` value

**Files:**
- Modify: `crates/hf-service/src/report.rs`
- Modify: `crates/hf-service/src/lib.rs`
- Test: `crates/hf-service/tests/report.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: `hf_service::ReportLanguage` with variants `En` and `Zh`, `Default` returning `En`, serde as `"en"` / `"zh"`, and `FromStr` rejecting anything else with `ClassifiedError::Validation`. Tasks 2 through 5 all take this type.

- [ ] **Step 1: Write the failing tests**

Append to `crates/hf-service/tests/report.rs`:

```rust
#[test]
fn report_language_serializes_as_the_desktop_locale_identifiers() {
    // The desktop app stores "en" / "zh" in localStorage under hf_locale and
    // passes that value straight through. These identifiers are the contract.
    assert_eq!(
        serde_json::to_string(&ReportLanguage::En).unwrap(),
        "\"en\""
    );
    assert_eq!(
        serde_json::to_string(&ReportLanguage::Zh).unwrap(),
        "\"zh\""
    );
    assert_eq!(
        serde_json::from_str::<ReportLanguage>("\"zh\"").unwrap(),
        ReportLanguage::Zh
    );
}

#[test]
fn report_language_defaults_to_english() {
    assert_eq!(ReportLanguage::default(), ReportLanguage::En);
}

#[test]
fn report_language_parses_the_two_accepted_identifiers() {
    assert_eq!("en".parse::<ReportLanguage>().unwrap(), ReportLanguage::En);
    assert_eq!("zh".parse::<ReportLanguage>().unwrap(), ReportLanguage::Zh);
}

#[test]
fn report_language_rejects_an_unknown_identifier_by_naming_the_accepted_ones() {
    let err = "fr".parse::<ReportLanguage>().unwrap_err();
    let message = err.to_string();
    // The message must tell the caller what IS accepted, not just that "fr"
    // was wrong -- this reaches a CLI user and a REST client.
    assert!(message.contains("en"), "message should name en: {message}");
    assert!(message.contains("zh"), "message should name zh: {message}");
}
```

Add `use hf_service::ReportLanguage;` to that file's imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: compilation failure, `cannot find type ReportLanguage in this scope` or an unresolved import.

- [ ] **Step 3: Implement the type**

Add near the top of `crates/hf-service/src/report.rs`:

```rust
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
```

Confirm `ClassifiedError` is already imported in `report.rs`; if not, add `use hf_core::error::ClassifiedError;`.

In `crates/hf-service/src/lib.rs`, add `ReportLanguage` to the existing `pub use report::{...}` list, keeping it alphabetical. If no such re-export exists, add `pub use report::ReportLanguage;` beside the other `pub use` lines.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: PASS, and every pre-existing test in that file still passes.

- [ ] **Step 5: Run the gates**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo check -p hf-service --no-default-features
```

All must be clean.

- [ ] **Step 6: Commit**

```bash
git add crates/hf-service/src/report.rs crates/hf-service/src/lib.rs crates/hf-service/tests/report.rs
git commit -m "$(cat <<'EOF'
feat: add a ReportLanguage value for localized reports

Serializes as the same en/zh identifiers the desktop app stores in localStorage,
so the GUI can pass its current locale through without a mapping layer. An
unknown identifier is rejected with a message naming the accepted values,
because that error reaches CLI users and REST clients directly.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Make the report translatable without translating it

This task introduces `Labels` with an English constructor only, and rewires `render_markdown` to read every piece of scaffolding from it. **No output changes.** The existing tests in `crates/hf-service/tests/report.rs` are the proof: they assert on English report content today and must pass unchanged afterwards.

Separating this from the translation matters. If translation and refactor land together, a rendering regression and a translation error are indistinguishable.

**Files:**
- Modify: `crates/hf-service/src/report.rs`
- Modify: `crates/hf-service/src/container/export.rs:295`
- Test: `crates/hf-service/tests/report.rs`

**Interfaces:**
- Consumes: `ReportLanguage` from Task 1.
- Produces: `pub struct Labels` with `Labels::english()`, `Labels::chinese()`, and `Labels::for_language(ReportLanguage) -> Labels`; `render_markdown(data: &ReportData, labels: &Labels) -> String`. Task 3 fills in `chinese()`. Task 5 calls `for_language`.

- [ ] **Step 1: Write the failing test**

Append to `crates/hf-service/tests/report.rs`:

```rust
#[test]
fn english_labels_render_the_same_report_as_before() {
    // Task 2 is a pure refactor: the English rendering must be byte-identical
    // to what the hardcoded literals produced. These headings are exactly the
    // ones the pre-refactor renderer emitted.
    let md = render_markdown(&populated(), &Labels::english());
    for heading in [
        "## Executive Summary",
        "## Visual Summary",
        "## Target",
        "## Run",
        "## Coverage",
        "## Corpus",
        "## Findings",
    ] {
        assert!(md.contains(heading), "missing {heading}");
    }
    assert!(md.contains("# Fuzzing Report:"));
    assert!(md.contains("| Property | Value |"));
    assert!(md.contains("| Metric | Covered | Total | Percent |"));
    assert!(md.contains("| # | Kind | Severity | Location | Signature |"));
}
```

Add `Labels` to the file's `use hf_service::report::{...}` import.

- [ ] **Step 2: Run it to verify it fails**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: compilation failure — `Labels` does not exist and `render_markdown` takes one argument.

- [ ] **Step 3: Add the `Labels` struct with its English constructor**

Add to `crates/hf-service/src/report.rs`. Every field is `&'static str`. The list below is complete for the current renderer; derive it by walking `render_markdown` top to bottom.

```rust
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
    // Executive summary bullets
    pub unique_crashes: &'static str,
    pub exploitable_line: &'static str,
    pub corpus_line: &'static str,
    pub line_coverage: &'static str,
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
    pub col_metric: &'static str,
    pub col_covered: &'static str,
    pub col_total: &'static str,
    pub col_percent: &'static str,
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
    // Finding detail
    pub bullet_kind: &'static str,
    pub bullet_stack_signature: &'static str,
    pub bullet_input: &'static str,
    pub bullet_casr_severity: &'static str,
    pub bullet_crash_line: &'static str,
    pub bullet_cluster: &'static str,
    pub bullet_minimized: &'static str,
    pub stack_trace: &'static str,
    pub no_crashes_found: &'static str,
    pub bug_report_heading: &'static str,
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
            unique_crashes: "Unique crashes",
            exploitable_line: "Exploitable / probably exploitable",
            corpus_line: "Corpus",
            line_coverage: "Line coverage",
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
            row_fit_score: "Fit score",
            no_run_recorded: "No run has been recorded for this project.",
            row_engine: "Engine",
            row_status: "Status",
            row_started: "Started",
            row_ended: "Ended",
            row_duration: "Duration",
            row_sanitizer: "Sanitizer",
            row_budget: "Budget",
            col_metric: "Metric",
            col_covered: "Covered",
            col_total: "Total",
            col_percent: "Percent",
            row_entries: "Entries",
            row_total_size: "Total size",
            row_seeds: "Seeds",
            row_from_fuzzer: "From fuzzer",
            row_minimized: "Minimized",
            col_index: "#",
            col_severity: "Severity",
            col_location: "Location",
            bullet_kind: "Kind",
            bullet_stack_signature: "Stack signature",
            bullet_input: "Input",
            bullet_casr_severity: "CASR severity",
            bullet_crash_line: "Crash line",
            bullet_cluster: "Cluster",
            bullet_minimized: "Minimized",
            stack_trace: "Stack trace:",
            no_crashes_found: "No crashes were found. There is nothing to triage.",
            bug_report_heading: "Bug report",
            reproduction: "Reproduction:",
            root_cause: "Root cause:",
            suggested_fix: "Suggested fix:",
            casr_exploitable: "Exploitable",
            casr_probably_exploitable: "Probably exploitable",
            casr_not_exploitable: "Not exploitable",
            casr_undefined: "Undefined",
            generated_by: "Generated by oxfuzz",
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
```

`Labels::chinese()` does not exist yet, so `for_language` will not compile. Add a temporary stub that Task 3 replaces:

```rust
impl Labels {
    /// Filled in by Task 3. Returning the English set keeps this task a pure
    /// refactor with no behavior change.
    #[must_use]
    pub const fn chinese() -> Self {
        Self::english()
    }
}
```

- [ ] **Step 4: Rewire `render_markdown` to read from `Labels`**

Change the signature to `pub fn render_markdown(data: &ReportData, labels: &Labels) -> String` and replace every hardcoded scaffolding literal with the matching field. Work top to bottom so nothing is missed. Two examples:

```rust
// before
let _ = writeln!(md, "# Fuzzing Report: `{}`", data.target);
// after
let _ = writeln!(md, "# {}: `{}`", labels.title_prefix, data.target);
```

```rust
// before
let _ = writeln!(md, "| Metric | Covered | Total | Percent |");
// after
let _ = writeln!(
    md,
    "| {} | {} | {} | {} |",
    labels.col_metric, labels.col_covered, labels.col_total, labels.col_percent
);
```

Thread `labels` into every private helper `render_markdown` calls, including `render_visual_summary`, `severity_pie_mermaid`, `kind_pie_mermaid`, and the coverage chart builder. Do not change any data interpolation, any Markdown separator row such as `|---|---|`, or the `█`/`░` bar characters.

Update the single production caller at `crates/hf-service/src/container/export.rs:295` to `render_markdown(&data, &crate::report::Labels::english())` for now; Task 5 replaces that with the real language.

Update the six existing `render_markdown(...)` calls in `crates/hf-service/tests/report.rs` to pass `&Labels::english()`.

- [ ] **Step 5: Run the full report suite to verify no behavior changed**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: PASS, including every pre-existing assertion. A failure here means the refactor changed the English output, which is the defect this task's structure exists to surface.

- [ ] **Step 6: Run the gates**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo check -p hf-service --all-targets
cargo check -p hf-service --no-default-features
```

- [ ] **Step 7: Commit**

```bash
git add crates/hf-service/src/report.rs crates/hf-service/src/container/export.rs crates/hf-service/tests/report.rs
git commit -m "$(cat <<'EOF'
refactor: read report scaffolding from a Labels struct

Moves every heading, table label, chart label and note the renderer writes into
a struct with one field each, so a language can supply a different set. The
English constructor reproduces the previous literals exactly and the existing
report tests pass unchanged, which is what proves this changed no output.

A struct rather than a key-to-string map: a map's failure mode is a missing key
rendering silently as the key itself, which no gate catches.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: The Chinese label set

**Files:**
- Modify: `crates/hf-service/src/report.rs`
- Test: `crates/hf-service/tests/report.rs`

**Interfaces:**
- Consumes: `Labels` and `render_markdown(data, labels)` from Task 2.
- Produces: a real `Labels::chinese()`. Nothing downstream changes shape.

- [ ] **Step 1: Write the failing tests**

Append to `crates/hf-service/tests/report.rs`:

```rust
#[test]
fn chinese_labels_translate_the_scaffolding_in_both_directions() {
    let md = render_markdown(&populated(), &Labels::chinese());

    // Present: the Chinese headings.
    for heading in ["## 摘要", "## 图表概览", "## 目标", "## 运行", "## 覆盖率", "## 语料库", "## 发现"] {
        assert!(md.contains(heading), "missing Chinese heading {heading}");
    }

    // Absent: the English ones. Asserting only presence would pass against a
    // chinese() that returned the English set, which is exactly the stub Task 2
    // left behind.
    for heading in [
        "## Executive Summary",
        "## Visual Summary",
        "## Target",
        "## Run",
        "## Coverage",
        "## Corpus",
        "## Findings",
    ] {
        assert!(!md.contains(heading), "English heading leaked: {heading}");
    }
}

#[test]
fn technical_tokens_are_byte_identical_across_languages() {
    let data = populated();
    let en = render_markdown(&data, &Labels::english());
    let zh = render_markdown(&data, &Labels::chinese());

    // A translated stack frame no longer matches the crash it came from and
    // cannot be grepped. These must survive untouched.
    for token in [
        data.target.as_str(),
        data.project.as_str(),
    ] {
        assert!(en.contains(token), "English lost {token}");
        assert!(zh.contains(token), "Chinese lost {token}");
    }
    for crash in &data.crashes {
        let signature = crash.stack_signature.as_str();
        assert!(zh.contains(signature), "Chinese lost signature {signature}");
        let input = crash.input_path.display().to_string();
        assert!(zh.contains(&input), "Chinese lost input path {input}");
    }
}

#[test]
fn casr_terms_keep_the_original_alongside_the_translation() {
    // Translated for the reader, original preserved so the term stays greppable
    // and matchable against CASR output.
    let zh = Labels::chinese();
    assert!(zh.casr_exploitable.contains("Exploitable"));
    assert!(zh.casr_exploitable.contains("可利用"));
    assert!(zh.casr_not_exploitable.contains("Not exploitable"));
    assert!(zh.casr_undefined.contains("Undefined"));
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p hf-service --test report 2>&1 | tail -30`

Expected: `chinese_labels_translate_the_scaffolding_in_both_directions` fails on the *absence* assertions, because Task 2's stub returns the English set. That failure is the point: it proves the test can detect an untranslated label set.

- [ ] **Step 3: Replace the stub with the real Chinese set**

Replace `Labels::chinese()` in `crates/hf-service/src/report.rs`:

```rust
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
            findings_section: "发现",
            finding_prefix: "发现",
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
            bullet_stack_signature: "调用栈签名",
            bullet_input: "输入",
            bullet_casr_severity: "CASR 严重程度",
            bullet_crash_line: "崩溃位置",
            bullet_cluster: "聚类",
            bullet_minimized: "已最小化",
            stack_trace: "调用栈：",
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
            no_crashes_summary: "最近一次测试未发现崩溃",
            crashes_summary_lead: "本次测试发现",
            crashes_summary_unit: "个去重崩溃，",
            crashes_summary_of_which: "其中",
            crashes_summary_rank: "个被判定为可利用或可能可利用",
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
        }
    }
}
```


**A translation risk specific to this set.** Four fields are sentence fragments
the renderer concatenates: `crashes_summary_lead`, `crashes_summary_unit`,
`crashes_summary_of_which`, and `crashes_summary_rank`. English assembles them
as `lead {n} unit of_which {m} rank`. The Chinese above is written so the same
slot order produces a natural sentence:

    本次测试发现 5 个去重崩溃，其中 2 个被判定为可利用或可能可利用

That is a coincidence of these two languages, not a guarantee. **Render the
assembled sentence and read it** before considering this done -- fragment
concatenation is where localization normally breaks, because a translator sees
each fragment in isolation and never sees the sentence. If it reads wrongly,
report it rather than reordering the renderer; the fix would be a structural
change and belongs to the controller.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: PASS, including the English tests from Task 2, which must be unaffected.

- [ ] **Step 5: Confirm the both-directions test can actually fail**

Temporarily change one field in `chinese()` back to its English string, run
`cargo test -p hf-service --test report chinese_labels 2>&1 | tail -10`, and
confirm it goes RED. Restore the Chinese string and confirm GREEN again. Report
both results. A test nobody has watched fail is not yet a test.

- [ ] **Step 6: Run the gates**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo check -p hf-service --no-default-features
```

- [ ] **Step 7: Commit**

```bash
git add crates/hf-service/src/report.rs crates/hf-service/tests/report.rs
git commit -m "$(cat <<'EOF'
feat: add the Simplified Chinese report label set

Translates every heading, table label, chart label and note. CASR exploitability
terms keep the original in parentheses, so the term reads naturally and stays
greppable and matchable against CASR output.

The localization test asserts the Chinese headings are present AND the English
ones absent. A presence-only assertion would pass against a set that translated
nothing.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Localize the narrative prompts

**Files:**
- Modify: `crates/hf-service/src/report.rs`
- Modify: `crates/hf-service/src/container/export.rs:40-60`
- Test: `crates/hf-service/tests/report.rs`

**Interfaces:**
- Consumes: `ReportLanguage` from Task 1.
- Produces: `report_system_prompt(language: ReportLanguage) -> String` and `report_user_prompt(facts: &str, data: &ReportData, language: ReportLanguage) -> String`. Task 5 forwards the language into `compose_ai_report`.

- [ ] **Step 1: Write the failing tests**

Append to `crates/hf-service/tests/report.rs`:

```rust
#[test]
fn chinese_prompt_asks_for_chinese_and_pins_the_untranslatable_tokens() {
    let data = populated();
    let facts = render_markdown(&data, &Labels::chinese());
    let prompt = report_user_prompt(&facts, &data, ReportLanguage::Zh);

    assert!(
        prompt.contains("Simplified Chinese"),
        "prompt must name the output language"
    );
    // Without this rule the model transliterates symbol names and paths, which
    // destroys the report's value as evidence.
    for token in ["file paths", "stack frames", "crash signatures", "CWE"] {
        assert!(prompt.contains(token), "token rule missing: {token}");
    }
}

#[test]
fn english_prompt_carries_no_translation_instruction() {
    let data = populated();
    let facts = render_markdown(&data, &Labels::english());
    let prompt = report_user_prompt(&facts, &data, ReportLanguage::En);

    assert!(!prompt.contains("Simplified Chinese"));
}

#[test]
fn both_prompts_still_ground_the_model_in_the_data_sheet() {
    let data = populated();
    for (language, labels) in [
        (ReportLanguage::En, Labels::english()),
        (ReportLanguage::Zh, Labels::chinese()),
    ] {
        let facts = render_markdown(&data, &labels);
        let prompt = report_user_prompt(&facts, &data, language);
        // The anti-fabrication rules must survive localization.
        assert!(prompt.contains("Do not invent"));
        assert!(prompt.contains("mermaid"));
        assert!(prompt.contains(&facts));
    }
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: compilation failure — both prompt functions currently take fewer arguments.

- [ ] **Step 3: Add the language to both prompt builders**

Change `report_system_prompt` to take a language and return `String`:

```rust
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
```

In `report_user_prompt`, add the parameter and insert the language block immediately before the `---\n# DATA SHEET` separator, so it sits after the structural rules and before the grounding data:

```rust
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
```

Interpolate `{language_rules}` into the existing `format!` at that position. Leave every other instruction unchanged.

Update the call site in `crates/hf-service/src/container/export.rs:50-51`: `compose_ai_report` gains a `language: ReportLanguage` parameter and passes it to both builders. Its single caller at line 301 passes `ReportLanguage::En` for now; Task 5 replaces that.

Two existing tests call these builders and will not compile until updated:

- `crates/hf-service/tests/report.rs:175` — `report_user_prompt(&facts, &data)` becomes `report_user_prompt(&facts, &data, ReportLanguage::En)`
- `crates/hf-service/tests/report.rs:185-186` — `report_system_prompt()` becomes `report_system_prompt(ReportLanguage::En)` in both assertions

Keep their assertions exactly as they are. They check the grounding rules survive, and those must not change.

Note `crates/hf-service/src/automotive_report.rs` has its own `automotive_report_system_prompt` and `automotive_report_user_prompt`. Those are a different feature and are out of scope. Do not touch them.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p hf-service --test report 2>&1 | tail -20`

Expected: PASS.

- [ ] **Step 5: Run the gates**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo check -p hf-service --all-targets
cargo check -p hf-service --no-default-features
```

- [ ] **Step 6: Commit**

```bash
git add crates/hf-service/src/report.rs crates/hf-service/src/container/export.rs crates/hf-service/tests/report.rs
git commit -m "$(cat <<'EOF'
feat: localize the report narrative prompts

The Chinese prompt asks for Simplified Chinese output and pins the tokens that
must survive untranslated: file paths, stack frames, symbol names, crash
signatures, engine and sanitizer names, CWE identifiers and figures.

The anti-fabrication rules are unchanged. Because the data sheet handed to the
model already carries Chinese labels, the existing instruction to preserve every
Mermaid block verbatim now preserves the translation rather than fighting it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Thread the language through the calling surfaces

**Files:**
- Modify: `crates/hf-service/src/container/export.rs`
- Modify: `crates/hf-cli/src/main.rs`
- Modify: `crates/hf-web/src/router.rs`
- Modify: `crates/hf-gui/src-tauri/src/commands.rs`
- Modify: `crates/hf-gui/src/views/` (the view calling `generate_report`)
- Test: `crates/hf-service/tests/report.rs`

**Interfaces:**
- Consumes: everything from Tasks 1 through 4.
- Produces: `generate_report(project, target, language)` and `export_report(project, target, format, out_path, language)`.

- [ ] **Step 1: Add the language parameter in the service**

In `crates/hf-service/src/container/export.rs`:

- `generate_report` gains `language: ReportLanguage` as its last parameter. Replace the `Labels::english()` placeholder from Task 2 with `Labels::for_language(language)`, and pass `language` to `compose_ai_report`.
- `export_report` gains `language: ReportLanguage` as its last parameter and forwards it to `generate_report`.

- [ ] **Step 2: Update the CLI**

In `crates/hf-cli/src/main.rs`, add to the `report` subcommand's argument struct:

```rust
        /// Report language: en or zh. Defaults to en.
        #[arg(long, default_value = "en")]
        lang: String,
```

Parse it with `lang.parse::<hf_service::ReportLanguage>()?` and pass the result to `generate_report` at line 1762. The `?` propagates the `ClassifiedError::Validation` from Task 1, so an unknown value is rejected with a message naming `en` and `zh`.

- [ ] **Step 2b: Localize the exported document's title and language attribute**

Two English strings live on the export path and are not covered by `Labels`,
because they are not report body content:

- `crates/hf-service/src/container/export.rs:338` builds the exported document's
  title as `format!("oxfuzz report -- {target}")`. The word "report" is English
  regardless of the report's language.
- `crates/hf-service/src/report_export.rs:181` emits `<html lang="en">` in the
  HTML template unconditionally. That attribute is not cosmetic: screen readers
  use it to choose a voice, and browsers use it for font and line-breaking
  decisions. A Chinese document declaring `lang="en"` is wrong for assistive
  technology.

Fix both:

- Add a `report_noun` field to `Labels` (English `"report"`, Chinese `"报告"`),
  and build the title from it. Keep the em dash and the target interpolation.
- Give `report_export::write_report` a language, and emit `lang="zh-CN"` for
  Chinese and `lang="en"` for English. Use `zh-CN` rather than `zh`: it is the
  BCP 47 tag for Simplified Chinese, and it matches what the desktop app already
  sets on `document.documentElement.lang` (`crates/hf-gui/src/i18n.tsx:397`).

The existing test at `crates/hf-service/src/report_export.rs:360` asserts on the
`<title>`; extend it rather than replacing it, and add one asserting the `lang`
attribute changes with the language.

- [ ] **Step 3: Update the REST API**

In `crates/hf-web/src/router.rs`, add to the report request body struct:

```rust
    #[serde(default)]
    language: hf_service::ReportLanguage,
```

`#[serde(default)]` plus the `Default` impl from Task 1 means an omitted field is English. Pass `req.language` to `generate_report` at line 1833.

- [ ] **Step 4: Update the Tauri commands**

In `crates/hf-gui/src-tauri/src/commands.rs`, add `language: Option<String>` to both `generate_report` and `export_report`. Resolve it the same way in each:

```rust
    let language = match language {
        Some(value) => value
            .parse::<hf_service::ReportLanguage>()
            .map_err(|error| error.to_string())?,
        None => hf_service::ReportLanguage::default(),
    };
```

Pass it through to the service call. Add no other logic; the command delegates.

- [ ] **Step 5: Update all three desktop call sites**

There are three, in two files. Missing any one leaves that path producing English reports while the rest of the app is Chinese, which is the exact bug this feature exists to remove.

| File and line | Call |
| --- | --- |
| `crates/hf-gui/src/views/TriageView.tsx:121` | `invoke<string>("generate_report", reportArgs())` |
| `crates/hf-gui/src/views/TriageView.tsx:150` | `invoke<string \| null>("export_report", { ... })` |
| `crates/hf-gui/src/views/DashboardView.tsx:291` | `invoke<string>("generate_report", { ... })` |

In each file, take `locale` from the existing i18n hook:

```tsx
const { t, locale } = useI18n();
```

Then add `language: locale` to the argument object. For `TriageView.tsx:121` the arguments come from a `reportArgs()` helper, so add the field inside that helper rather than at the call site, which covers both of that file's calls if they share it — check whether line 150 uses it too, and if not, add the field there as well.

`locale` is already `"en"` or `"zh"`, matching the wire values from Task 1, so no mapping is needed.

Verify none was missed:

```bash
grep -n 'generate_report\|export_report' crates/hf-gui/src/views/*.tsx
```

Every hit must pass a `language`.

- [ ] **Step 6: Add the end-to-end service test**

Append to `crates/hf-service/tests/report.rs`:

```rust
#[test]
fn language_selects_the_label_set() {
    // The wiring test: for_language must route to the matching constructor.
    let data = populated();
    let en = render_markdown(&data, &Labels::for_language(ReportLanguage::En));
    let zh = render_markdown(&data, &Labels::for_language(ReportLanguage::Zh));

    assert!(en.contains("## Findings"));
    assert!(zh.contains("## 发现"));
    assert_ne!(en, zh);
}
```

- [ ] **Step 7: Verify**

```bash
cargo test -p hf-service --test report 2>&1 | tail -20
cargo test --workspace 2>&1 | tail -10
cargo check --workspace
cargo clippy --workspace -- -D warnings
cargo check -p hf-service --no-default-features
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run build
npm --prefix crates/hf-gui run lint
```

All must pass. `cargo check --workspace` is what proves the three presentation crates still compile against the changed signatures.

- [ ] **Step 8: Commit**

```bash
git add crates/hf-service crates/hf-cli crates/hf-web crates/hf-gui
git commit -m "$(cat <<'EOF'
feat: let callers choose the report language

generate_report and export_report take a ReportLanguage. The desktop app passes
its current UI locale, the CLI gains --lang, and REST takes an optional language
field. Omitting it anywhere yields English, unchanged from previous behavior.

Scheduled campaigns pass nothing and so produce English reports. That follows
from having no persisted setting, which is deliberate: a stored language could
disagree with the UI selection with no visible cause.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Verify in the running app**

Build and drive it, because this feature's whole point is what a user sees:

```bash
HF_SKIP_DEFECTDOJO=1 ./scripts/build-app.sh
open "target/release/bundle/macos/oxfuzz.app"
```

Switch the interface to Chinese, generate a report for a target with crash data, and read it. Confirm the headings, tables and chart labels are Chinese, and confirm a stack frame and a file path in the findings are byte-identical to the English rendering. Report what you saw.

If no LLM provider is configured, the fallback fact sheet appears instead. That path must also be Chinese; it is the case this design specifically protects.
