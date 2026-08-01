# Localized Automotive Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the automotive campaign report in Simplified Chinese when the caller asks for Chinese, including the AI interpretation, without weakening the evidence validation that keeps the report honest.

**Architecture:** An `AutomotiveLabels` set carries every user-facing literal the renderer emits, with compiler-checked English and Chinese constructors. The existing `ReportLanguage` is reused. `validate_ai_interpretation` becomes language-aware so a Chinese interpretation is accepted rather than discarded. The language is threaded from the CLI, REST, the Tauri command and `AutomotiveView`.

**Tech Stack:** Rust 1.94, `hf-service`; TypeScript/React 19 in `hf-gui`.

Design: `docs/superpowers/specs/2026-08-01-automotive-localized-reports-design.md`

## Global Constraints

- Rust toolchain pinned to `1.94.0` by `rust-toolchain.toml`.
- Clippy runs `pedantic` workspace-wide with `-D warnings`. **Never add inline lint suppressions** (`#[allow(clippy::...)]`). Fix the code, or move the rule to the owning config with a justifying comment.
- **No emoji anywhere** in code, comments, commit messages or docs. Chinese characters are not emoji and are expected in this work.
- All domain logic lives in `hf-service`. `hf-cli`, `hf-web` and `hf-gui` are thin presentation layers doing only input, output and rendering. Task 4 passes a value; it adds no logic.
- Rust casing: `snake_case` files and functions, `PascalCase` types, `SCREAMING_SNAKE_CASE` constants.
- **Technical tokens are never translated.** Evidence citations `[OP:<id>]`, `[STATE:<digest>]`, `[TRANSCRIPT:<sha256>]`; pipeline stage identifiers (`capabilities`, `analyze_capture`, `generate_mutations`, and siblings); protocol, bus, ECU and adapter names; SHA-256 digests; file paths; every figure. These render byte-identical in both languages.
- **Citations are validated, not merely displayed.** `validate_ai_interpretation` matches `[OP:...]`, `[STATE:...]` and `[TRANSCRIPT:...]` against known identifiers. A translated citation discards the whole interpretation, so the token rule is load-bearing here in a way it was not for the main report.
- **Every assertion must be able to fail.** Before committing a test, name the single-line production change that would turn it red. If you cannot name one, rewrite it. Two traps produced eight passing-but-vacuous tests on the previous branch: asserting a substring that some *other*, shared code path also emits (so the assertion was already true before the change under test), and asserting the absence of a pattern the code never produces in any language. Where a test guards one call site among several rendering similar text, prove it: revert that one site, confirm red, restore.
- **Do not add a field list to this plan.** The previous branch pinned a 75-field list, six fix rounds grew the struct to 101, and the plan was never reconciled -- it ended up contradicting both the code and itself. `AutomotiveLabels` in the source is the authoritative list; the compiler enforces that both constructors cover it.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Baseline: this branch forks from `localized-reports-20260801`, so `ReportLanguage`, `Labels` and `--report-lang` already exist. `cargo test --workspace` passes at 2582. Every task must leave it green.
- After each task: `cargo fmt --all`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo check -p hf-service --no-default-features`. That last one has caught two real defects in this repository that no other gate could see. Task 4 additionally runs `npm run lint` and `npm run test` in `crates/hf-gui`.

---

## File Structure

**Created:** none. This feature extends existing files, because the label set belongs beside the renderer that consumes it.

**Modified:**

| File | Change |
| --- | --- |
| `crates/hf-service/src/automotive_report.rs` | `AutomotiveLabels`, localized prompts, language-aware validation |
| `crates/hf-service/src/automotive.rs` | composition threads the language |
| `crates/hf-service/tests/automotive_report.rs` | existing tests updated, new tests added |
| `crates/hf-cli/src/main.rs` | `automotive report` gains `--report-lang` |
| `crates/hf-web/src/router.rs` | request body gains an optional `language` |
| `crates/hf-gui/src-tauri/src/commands.rs` | command gains `language: Option<String>` |
| `crates/hf-gui/src/views/AutomotiveView.tsx` | passes the locale; two title sites localized |
| `crates/hf-gui/src/i18n.extra.ts` | new `automotive.report.*` title keys, both blocks |

---

## Task 1: The label set, English only

Introduce `AutomotiveLabels` and thread it through the renderer with today's exact English text. **No output changes in this task.** This is the relocation, and its whole value is that it is provably behavior-preserving.

**Files:**
- Modify: `crates/hf-service/src/automotive_report.rs`
- Modify: `crates/hf-service/src/automotive.rs` (the one production `render_automotive_report` call)
- Test: `crates/hf-service/tests/automotive_report.rs`

**Interfaces:**
- Consumes: `ReportLanguage` from the localized-reports work, at `crate::report::ReportLanguage`.
- Produces: `pub struct AutomotiveLabels` with `english()`, and `render_automotive_report(data: &AutomotiveReportData, labels: &AutomotiveLabels) -> String`. Task 2 adds `chinese()` and `for_language()`.

- [ ] **Step 1: Capture the current output as a baseline**

Before touching anything, render both a populated and an empty fixture and save the exact bytes. This is the evidence that Task 1 changed nothing.

```bash
cargo test -p hf-service --test automotive_report 2>&1 | tail -5
```

Write a temporary test that prints `render_automotive_report(&report_data())` to a file under the scratchpad, run it, and keep that file. Delete the temporary test before committing.

- [ ] **Step 2: Write the failing test**

```rust
#[test]
fn english_labels_render_todays_exact_text() {
    let report = render_automotive_report(&report_data(), &AutomotiveLabels::english());
    assert!(report.contains("# Automotive Fuzzing Campaign Report:"));
    assert!(report.contains("## Executive Summary"));
    assert!(report.contains("## Limitations"));
    assert!(report.contains("## Recommendations"));
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cargo test -p hf-service --test automotive_report english_labels 2>&1 | tail -20`

Expected: compilation failure -- `AutomotiveLabels` does not exist and `render_automotive_report` takes one argument.

- [ ] **Step 4: Add the struct and the English constructor**

Declare `pub struct AutomotiveLabels` with one `&'static str` field per user-facing literal, and `pub const fn english() -> Self` returning today's text verbatim.

Apply the extraction rule from the design, section 5: **every literal the renderer emits that a reader sees, and that is not a technical token under Global Constraints, is a field.** Work through all 56 emit sites in `render_automotive_report` and its eight `render_*` helpers.

Two shapes need care:

- Multi-line `writeln!` strings using Rust's `\` continuation. A line-oriented grep cannot see these, and missing them is the single most likely way to under-count. Read the function bodies rather than grepping.
- Literals that pair a technical identifier with a description, such as `("capabilities", "inspect the pinned adapter capabilities")`. The identifier stays inline; only the description becomes a field.

- [ ] **Step 5: Thread `&AutomotiveLabels` through the renderer**

`render_automotive_report` and each `render_*` helper take `labels: &AutomotiveLabels`. Update the single production caller in `crates/hf-service/src/automotive.rs` (find it by name; it is near the top of the composition path) to pass `AutomotiveLabels::english()` for now. Task 4 replaces that.

Update the five existing `render_automotive_report` calls in `crates/hf-service/tests/automotive_report.rs` to pass `&AutomotiveLabels::english()`. Keep every existing assertion exactly as it is -- they are the guard that this task changed nothing.

- [ ] **Step 6: Prove the output is byte-identical**

Re-render the same fixtures and diff against the Step 1 baseline.

```bash
diff <baseline> <new>
```

Expected: no differences. If anything differs, a literal was altered rather than relocated. Fix it before continuing; do not adjust the baseline.

Record the diff result in your report. This is the task's primary evidence.

- [ ] **Step 7: Run the gates and commit**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo check -p hf-service --no-default-features
git add -A && git commit
```

---

## Task 2: The Chinese label set

**Files:**
- Modify: `crates/hf-service/src/automotive_report.rs`
- Test: `crates/hf-service/tests/automotive_report.rs`

**Interfaces:**
- Consumes: `AutomotiveLabels` from Task 1.
- Produces: `AutomotiveLabels::chinese()` and `AutomotiveLabels::for_language(ReportLanguage) -> AutomotiveLabels`. Task 4 calls `for_language`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn chinese_labels_translate_the_scaffolding_in_both_directions() {
    let zh = render_automotive_report(&report_data(), &AutomotiveLabels::chinese());
    assert!(zh.contains("## 摘要"), "{zh}");
    assert!(
        !zh.contains("## Executive Summary"),
        "an English heading survived into the Chinese render:\n{zh}"
    );
}

#[test]
fn technical_tokens_are_byte_identical_across_languages() {
    let data = report_data();
    let en = render_automotive_report(&data, &AutomotiveLabels::english());
    let zh = render_automotive_report(&data, &AutomotiveLabels::chinese());

    // Assert on whole citations built from the fixture, not on the "[OP:"
    // prefix. A prefix cannot be translated, so counting prefixes passes
    // whatever happens to the identifier inside. Citations are validated
    // against known identifiers, so a translated one does not merely become
    // unmatchable -- it discards the interpretation that carries it.
    for operation in &data.operations {
        let citation = format!("[OP:{}]", operation.id);
        assert!(
            zh.contains(citation.as_str()),
            "{citation} is missing from the Chinese render"
        );
        assert_eq!(
            en.matches(citation.as_str()).count(),
            zh.matches(citation.as_str()).count(),
            "{citation} occurs a different number of times per language"
        );
    }

    // Protocol and mode names are configuration the operator set; translating
    // one would stop it matching what they configured.
    for name in data
        .safety
        .allowed_protocols
        .iter()
        .chain(data.safety.allowed_modes.iter())
    {
        assert!(
            zh.contains(name.as_str()),
            "{name} was translated or dropped from the Chinese render"
        );
    }
}
```

Derive every asserted token from the fixture rather than hardcoding it, so the test keeps guarding the real values if the fixture changes. Extend the same treatment to state digests and transcript hashes, which reach the report through their own render paths.

- [ ] **Step 2: Run them to verify they fail**

Run: `cargo test -p hf-service --test automotive_report 2>&1 | tail -20`

Expected: compilation failure -- `chinese()` does not exist.

- [ ] **Step 3: Add `chinese()` and `for_language()`**

One Chinese literal per field. The compiler rejects any omission, which is the point of the struct.

Terminology is already established by the product and must be followed rather than reinvented. `crates/hf-gui/src/i18n.extra.ts` carries 320 `automotive.*` keys with Chinese translations, including 44 under `automotive.report.*`. Consult it for any term that appears there. Known bindings:

| English | Chinese | Source |
| --- | --- | --- |
| campaign | 测试活动 | used across the GUI without exception |
| findings | 发现项 | the GUI's term, and the main report's |
| evidence-backed | 基于证据 | `automotive.report.evidenceBacked` |
| corpus | 语料库 | `i18n.extra.ts` |
| engine | 引擎 | `i18n.extra.ts` |
| sanitizer | 消毒器 | `i18n.extra.ts` |

Punctuation follows the main report's rule: full-width `，（）。：` carry their own spacing, so a field holding `", "` in English holds `"，"` in Chinese with no ASCII space. Where a field holds a separator shared with English, check every consuming site.

**The Limitations bullets and the advisory notice deserve more care than any heading.** They exist to stop a reader concluding more than the evidence supports -- that protocol-state digests are not code coverage, that a completed operation is not an absence of defects, that virtual evidence does not validate a physical ECU. Translate the force of the claim, not only its words. A hedge that reads weaker in Chinese than in English is a defect in this section even though it would be cosmetic elsewhere.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p hf-service --test automotive_report 2>&1 | tail -20`

- [ ] **Step 5: Verify the guardrails by reading, not only asserting**

Render the Chinese report and read the Limitations section and the advisory notice end to end. Confirm each claim is as strong in Chinese as in English. Report anything you softened or were unsure about rather than leaving it to review.

- [ ] **Step 6: Run the gates and commit**

---

## Task 3: Language-aware validation and prompts

This is the task the design exists for. Without it a Chinese interpretation is rejected and every Chinese AI report silently degrades to the deterministic one.

**Files:**
- Modify: `crates/hf-service/src/automotive_report.rs`
- Modify: `crates/hf-service/src/automotive.rs`
- Test: `crates/hf-service/tests/automotive_report.rs`

**Interfaces:**
- Produces: `automotive_report_system_prompt(language) -> String`, `automotive_report_user_prompt(facts, data, language) -> String`, `validate_ai_interpretation(interpretation, data, language)`, and `append_ai_interpretation(facts, interpretation, model, labels)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn a_chinese_interpretation_validates_under_zh_and_not_under_en() {
    let data = report_data();
    let zh_interpretation = chinese_interpretation_citing_known_evidence(&data);

    assert!(
        validate_ai_interpretation(&zh_interpretation, &data, ReportLanguage::Zh).is_ok(),
        "a Chinese interpretation with Chinese headings must validate under Zh"
    );
    assert!(
        validate_ai_interpretation(&zh_interpretation, &data, ReportLanguage::En).is_err(),
        "the English arm must still require English headings"
    );
}

#[test]
fn english_validation_is_unchanged() {
    let data = report_data();
    let valid = english_interpretation_citing_known_evidence(&data);
    assert!(validate_ai_interpretation(&valid, &data, ReportLanguage::En).is_ok());
}

#[test]
fn citation_checks_survive_in_chinese() {
    let data = report_data();
    // A Chinese interpretation citing an operation that does not exist must
    // still be rejected. Language awareness must not weaken evidence checking.
    let bogus = chinese_interpretation_citing("[OP:does-not-exist]");
    assert!(validate_ai_interpretation(&bogus, &data, ReportLanguage::Zh).is_err());
}
```

- [ ] **Step 2: Run them to verify they fail**

Expected: compilation failure -- `validate_ai_interpretation` takes two arguments.

- [ ] **Step 3: Make the required headings label fields**

The four headings currently hardcoded in `validate_ai_interpretation` become fields on `AutomotiveLabels`, with their existing English text in `english()` and translations in `chinese()`. Validation resolves them through `AutomotiveLabels::for_language(language)`.

**Change nothing else in that function.** The size bound, the code-fence rejection, the operation, state and transcript citation checks, and the requirement that an interpretation cite at least one piece of retained evidence when operations exist all stay exactly as they are. If you find yourself editing any of them, stop and report it.

- [ ] **Step 4: Localize the prompts**

Both builders take a `ReportLanguage`. The Chinese variants add the output-language instruction and a token-preservation rule naming the citation formats explicitly, since a translated citation would fail the validation added above.

Keep every existing grounding instruction unchanged. Those rules are what stop the model inventing evidence, and the design's rejected alternatives record why weakening them for translation would be wrong.

- [ ] **Step 5: Translate the advisory notice**

`append_ai_interpretation` takes `labels` and renders its heading and its advisory sentence from them. The model identifier stays verbatim.

This notice is what tells a reader the AI section is advisory and that retained evidence remains authoritative. Give it the same care as the Limitations bullets.

- [ ] **Step 6: Update the callers**

`crates/hf-service/src/automotive.rs` calls all four functions in its composition path. Pass `ReportLanguage::En` for now; Task 4 replaces it. Find them by name -- the file is large.

The existing tests in `crates/hf-service/tests/automotive_report.rs` that call these functions will not compile until updated. Add `ReportLanguage::En` and keep their assertions unchanged.

- [ ] **Step 7: Prove the validation change is load-bearing**

Revert the language resolution to the hardcoded English headings, confirm `a_chinese_interpretation_validates_under_zh_and_not_under_en` goes red, restore, confirm green. Report that evidence.

- [ ] **Step 8: Run the gates and commit**

---

## Task 4: Thread the language through the surfaces

**Files:**
- Modify: `crates/hf-service/src/automotive.rs`
- Modify: `crates/hf-cli/src/main.rs`
- Modify: `crates/hf-web/src/router.rs`
- Modify: `crates/hf-gui/src-tauri/src/commands.rs`
- Modify: `crates/hf-gui/src/views/AutomotiveView.tsx`
- Modify: `crates/hf-gui/src/i18n.extra.ts`

- [ ] **Step 1: Add the parameter to the service methods**

`generate_automotive_report` and `generate_automotive_report_with_settings` gain `language: ReportLanguage` as their last parameter, and pass it to the renderer, the prompts, the validation and `append_ai_interpretation`, replacing every `ReportLanguage::En` placeholder Tasks 1 and 3 left behind.

Find the placeholders with:

```bash
grep -n 'ReportLanguage::En' crates/hf-service/src/automotive.rs
```

- [ ] **Step 2: Update every call site**

Enumerate them rather than trusting this list, which was accurate when written:

```bash
grep -rn 'generate_automotive_report' --include='*.rs' crates/
```

| Site | What to pass |
| --- | --- |
| `crates/hf-cli/src/main.rs` | the new `--report-lang` flag |
| `crates/hf-web/src/router.rs` | the request body's `language` field |
| `crates/hf-gui/src-tauri/src/commands.rs` | the command's resolved `language` |
| `crates/hf-service/src/automotive.rs` (three in-file tests) | `ReportLanguage::En` |

Three of these are mechanical. On the previous branch the equivalent step had nine call sites where the plan named three, and one of them needed a decision rather than a default -- so count them yourself.

- [ ] **Step 3: The CLI flag**

The `automotive report` subcommand gains `--report-lang`, matching the name settled on the previous branch. `--lang` already means the target's source language on `discover` and `harness`; do not reuse it.

- [ ] **Step 4: The REST field**

```rust
    #[serde(default)]
    language: hf_service::ReportLanguage,
```

`#[serde(default)]` plus the enum's `Default` means an omitted field is English, so existing clients are unaffected. Follow whatever request struct the automotive route already uses; if that struct is shared with a route that produces no prose, give this route its own rather than advertising a language the other cannot use.

- [ ] **Step 5: The Tauri command**

`language: Option<String>`, resolved the same way the main report's commands resolve it:

```rust
    let language = match language {
        Some(value) => value
            .parse::<hf_service::ReportLanguage>()
            .map_err(|error| error.to_string())?,
        None => hf_service::ReportLanguage::default(),
    };
```

Add no other logic; the command delegates.

- [ ] **Step 6: The desktop view**

`AutomotiveView.tsx` destructures `locale` from `useI18n()` and passes it on the report invocation.

It also builds an English draft title at two sites -- the saved draft and the export. Both become `automotive.report.*` i18n keys with `{project}` interpolation, added to **both** the English and Chinese blocks of `i18n.extra.ts` in their sorted positions. English values must be byte-identical to the literals they replace, so the English path does not change.

Locate them with:

```bash
grep -n 'Automotive campaign report' crates/hf-gui/src/views/AutomotiveView.tsx
```

- [ ] **Step 7: Tests**

Each of the two title sites needs a test that fails if its localization is reverted, following the source-regex convention in `crates/hf-gui/src/__tests__/`. Add a catch-all that fails if an English report-title literal reappears in this view, and state in a comment which views it covers -- on the previous branch a catch-all claimed more scope than it scanned.

On the Rust side, add a test that the language reaches the renderer: a Chinese request must produce Chinese scaffolding. Prove it by severing the parameter and confirming red.

- [ ] **Step 8: Run every gate and commit**

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo check -p hf-service --no-default-features
cd crates/hf-gui && npm run lint && npm run test
```

---

## Verification

The branch is done when `scripts/tests/gates.sh` passes all ten gates and:

1. `oxfuzz automotive report <project> --report-lang zh` emits a Chinese report whose citations, stage identifiers, digests, paths and figures match the English rendering byte for byte.
2. A Chinese AI interpretation validates rather than being discarded.
3. Omitting the language anywhere yields today's English output, unchanged.
4. Rendering the Chinese report and reading the Limitations section confirms each caveat is as strong as its English counterpart.
