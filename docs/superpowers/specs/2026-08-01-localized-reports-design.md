# Localized Report Generation Design

Status: **approved design**. Owner: `hf-service`, with thin parameter passing in
`hf-cli`, `hf-web`, and `hf-gui`.

## 1. Goal

Produce campaign reports in Simplified Chinese when the caller asks for Chinese,
so that an operator running the desktop app in Chinese receives a Chinese report
rather than an English one.

Scope of this increment:

- a `ReportLanguage` value threaded from the caller into report composition;
- the deterministic report scaffolding becomes translatable through a
  compiler-checked label struct;
- the LLM narrative prompt gains a language instruction and an explicit
  token-preservation rule;
- the desktop app passes its current UI locale; the CLI gains `--lang`; REST
  takes an optional field.

Out of scope: any language beyond English and Simplified Chinese, a persisted
language setting, translation of the GUI beyond what already exists, and
localization of any surface other than reports.

## 2. Approved Product Decisions

1. A Chinese report is Chinese throughout -- headings, table labels, chart
   labels, and narrative -- except for technical tokens, which stay verbatim.
2. Technical tokens preserved verbatim: file paths, stack frames, symbol and
   function names, crash signatures, engine names, sanitizer names, CWE
   identifiers, and every figure. A translated stack frame no longer matches the
   crash it came from and cannot be grepped, which would make the report useless
   as evidence.
3. The language is an explicit parameter with an English default. No persisted
   setting exists, so no hidden state can silently change a report's language.
4. The deterministic scaffolding is translated in Rust, not by the model. This
   also makes the no-provider fallback report Chinese, since that path emits the
   fact sheet directly.
   Note added during implementation: routing CASR severities through their
   labels changes the *English* render for two of four variants, because
   `Debug` emits `ProbablyExploitable` where the label reads `Probably
   exploitable`. That is an improvement and it stands. English output being
   byte-identical is the goal for pure relocations, not an absolute -- where a
   label replaces a raw enum identifier, the label is what should have been
   rendered all along.
5. CASR exploitability classifications render translated with the original in
   parentheses, for example `可利用 (Exploitable)`. They are classifications
   rather than identifiers, so a reader benefits from the translation, while the
   parenthetical keeps the term greppable and matchable against CASR output.
6. Two language variants, not an extensible framework. A third language later
   is a compile error at each match site, which is the desired behavior.

## 3. Motivation and Local Gap

The desktop app is already bilingual. `crates/hf-gui/src/i18n.tsx` stores a
locale in `localStorage` under `hf_locale` and exposes it through `useI18n()`,
and `crates/hf-gui/src/i18n.extra.ts` carries English and Chinese dictionaries.
An operator can run the entire interface in Chinese.

Reports are not affected by that choice. The locale never leaves the browser:
`hf-service` has no concept of a language, and `ServiceContainer::generate_report`
takes only a project and a target. So an operator reading a Chinese interface
generates an English report.

Report composition has two layers, and both are English today:

- `hf_service::report::render_markdown` builds a deterministic fact sheet.
  Its structure is hardcoded English: `## Executive Summary`, `## Target`,
  `## Run`, `## Coverage`, `## Corpus`, `## Findings`, `### Finding {n}`, plus
  Markdown tables and pre-rendered Mermaid graphs. 101 distinct user-facing
  literals, as shipped -- the estimate while designing was roughly 81, and
  implementation found the rest.
- `compose_ai_report` in `crates/hf-service/src/container/export.rs` feeds that
  fact sheet to the provider pool under `report_system_prompt` and
  `report_user_prompt`, which instruct the model to invent nothing and to
  preserve every Mermaid block and table verbatim.

When no provider is configured, the fact sheet is returned as the report. Any
design that translates only the narrative therefore leaves that path entirely
English.

## 4. Architectural Ownership

| Concern | Owner |
| --- | --- |
| Language value and parsing | `hf-service::report` |
| Deterministic label set | `hf-service::report::Labels` |
| Narrative instructions | `hf-service::report` prompt builders |
| Composition | `hf-service::container::export` |
| Language selection | the caller: `hf-gui`, `hf-cli`, `hf-web` |

Layering is unchanged. All report logic stays in `hf-service`; the presentation
crates only pass a value they already hold. No new crate, no new dependency, no
new feature flag.

## 5. The Language Value

```rust
/// The language a report is composed in. Serializes as the same identifiers the
/// desktop app's `Locale` uses, so the GUI can pass its selection unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReportLanguage {
    #[default]
    En,
    Zh,
}
```

`FromStr` accepts `en` and `zh`; anything else is a
`ClassifiedError::Validation` naming the accepted values, consistent with how
other invalid parameters are rejected across the service.

Two variants because two languages exist. Adding a third later produces a
compile error at every match site, which is the point.

## 6. The Deterministic Half

`render_markdown` currently hardcodes its scaffolding. It gains a `&Labels`
parameter:

```rust
pub struct Labels {
    pub title: &'static str,
    pub executive_summary: &'static str,
    pub visual_summary: &'static str,
    pub target: &'static str,
    pub run: &'static str,
    pub coverage: &'static str,
    pub corpus: &'static str,
    pub findings: &'static str,
    pub finding_n: &'static str,
    // table column headers, table row labels, bullet labels, chart labels,
    // the italic no-data notes, and the footer
}

impl Labels {
    #[must_use] pub const fn english() -> Self { /* one literal per field */ }
    #[must_use] pub const fn chinese() -> Self { /* one literal per field */ }
    #[must_use] pub const fn for_language(language: ReportLanguage) -> Self {
        match language {
            ReportLanguage::En => Self::english(),
            ReportLanguage::Zh => Self::chinese(),
        }
    }
}
```

The field list above is abbreviated for readability. The authoritative list is
`Labels` in `crates/hf-service/src/report.rs` -- 101 fields as shipped. The
implementation plan enumerates a smaller set, because six fix rounds grew the
struct after the plan was written and the plan was not kept in step. Read the
struct, not the plan, for the current field set; the compiler enforces that
`english()` and `chinese()` both cover it in full.

A struct rather than a key-to-string map is deliberate. A map's failure mode is
a missing or misspelled key rendering silently as the key itself, which no gate
catches -- the same shape as a test whose assertion cannot fail. A struct makes
that state unrepresentable: a missing translation does not compile.

### What belongs in `Labels`, and what does not

`Labels` holds scaffolding: text `render_markdown` itself writes. Data flowing
*through* the report -- paths, signatures, stack frames, engine names, figures --
is never routed through it and is never translated.

The CASR exploitability terms sit on that boundary and are resolved explicitly.
`Exploitable`, `Probably exploitable`, `Not exploitable`, and `Undefined` are
string literals in `render_markdown` today, not values carried in the data, so
they are scaffolding and live in `Labels` as four fields. Per decision 2.5 the
Chinese constructor renders them translated with the original in parentheses,
for example `可利用 (Exploitable)`; the English constructor renders them
unchanged. This keeps the term readable and greppable at once, and keeps the
rule "data is never translated" true without exception.

## 7. The Narrative Half

`report_system_prompt` and `report_user_prompt` take a `ReportLanguage`. For
`Zh` they add two rules:

1. Write the entire report in Simplified Chinese.
2. Keep the following verbatim in their original form, never translated or
   transliterated: file paths, stack frames, symbol and function names, crash
   signatures, engine names, sanitizer names, CWE identifiers, and all figures.

The existing instruction to preserve every Mermaid block and Markdown table
verbatim now reinforces the translation rather than fighting it: the fact sheet
handed to the model already carries Chinese labels, so preserving it verbatim
preserves them.

`ensure_graphs` is unchanged. It re-injects graphs the model dropped, and those
graphs come from the already-translated fact sheet.

## 8. Surfaces

| Surface | How the language arrives |
| --- | --- |
| Desktop | The `generate_report` and `export_report` Tauri commands take a `language` field; the view passes `useI18n().locale`. |
| CLI | `oxfuzz report --lang zh`, defaulting to `en`. |
| REST | An optional `language` field on the report request body, defaulting to `en`. |

Absent means English everywhere. Scheduled campaigns pass nothing and therefore
produce English reports; that is the accepted consequence of having no persisted
setting, and is recorded here rather than discovered later.

## 9. Failure Semantics

No new runtime failure modes.

An unrecognized language identifier is rejected before any composition work
begins, but the mechanism differs by surface. The CLI and both desktop commands
parse the string through `FromStr` and surface
`ClassifiedError::Validation` naming the accepted values. The REST route types
the field as `ReportLanguage` directly, so serde rejects it during body
deserialization and axum answers 422 -- `FromStr` is never reached. Serde's
message also names the accepted variants, so the user-visible outcome is
equivalent.

A model that ignores the language instruction cannot be detected cheaply, and
this design does not attempt to. Because the scaffolding is translated in Rust,
the worst outcome is a document with Chinese structure and English prose, not an
English document. Stated as a known limitation rather than papered over.

Reports already persisted as drafts keep the language they were composed in.
Nothing re-translates stored content.

### 9.1 Known limitation: enum values render in English

Several report values come from Rust enums rendered with `Debug`. Some of those
are technical tokens this design already pins as verbatim, and they are correct
as they stand:

- `EngineKind` and `Sanitizer` -- a translated engine name no longer matches what
  the operator configured.
- `TargetLanguage` -- `C`, `Rust`, `Go` are the languages' own names.
- `CrashKind` -- `Asan`, `Ubsan`, `Segv` are sanitizer and signal names.

Three are not technical tokens and remain untranslated anyway:

- `RunStatus`, in the executive summary and the Run table (`Done`, `Failed`).
- `TargetKind` and `InputSurface`, in the Target table.

So a Chinese report shows a Chinese label beside an English value in those rows:
`| 状态 | Done |`. This was found during implementation, weighed, and
deliberately left: translating them is the same mechanical mapping the CASR
severities now use, but it widens a feature already larger than planned, and
these values sit in summary tables rather than in the findings a reader acts on.

Recorded here rather than left to be rediscovered. Closing it is a bounded
follow-up: one mapping helper per enum, following
`report::casr_severity_label`.

CASR exploitability severities are **not** in this list -- they are translated
everywhere they render, per decision 2.5.

### 9.2 Known limitation: scheduled reports are always English

`ServiceContainer::generate_report` takes the language as an explicit parameter,
so every caller must supply one. All but one have a language to supply: the CLI
has `--lang`, the REST route has a request field, the desktop commands have the
resolved UI locale, `export_report` has its own parameter, and the tests choose
one.

The exception is `scheduler::save_crash_report`, which composes a report when a
scheduled campaign finishes. There is no request in scope, and the desktop
locale lives in the frontend i18n layer and is never persisted to the service,
so the scheduler cannot discover the user's language. It passes
`ReportLanguage::En`.

The consequence is visible to users: someone running the interface in Chinese
receives Chinese reports when they ask for one, and English reports when a
schedule produces one for them.

This is the case the rejected `[report] language` setting in section 12 would
have solved. That rejection stands for interactive reports -- a persisted
setting that can disagree with the visible UI selector is worse than an explicit
parameter. But it is the natural fix here, because a scheduled report has no UI
session to disagree with. Closing this properly means a stored preference that
the scheduler reads and the interactive paths ignore, which is a design decision
beyond this feature's scope.

Recorded so the English scheduled report is a known limitation rather than an
accident of parameter threading.

### 9.3 Known limitation: re-exporting a saved draft declares English

`ServiceContainer::export_report` composes and exports in one step, so it knows
the language and stamps it on the document (title noun, and the HTML `lang`
attribute). `export_markdown` does not compose: it writes back content that was
already composed, which the Workbench "Composed Reports" list and the automotive
report path both use.

Nothing tells it what language that content is in. Report drafts do not record
the language they were composed in, and the exporting user's current UI locale
is not the same thing -- a report composed in Chinese can be exported by the
same user after switching the interface back to English, and vice versa.
Passing the locale would therefore be wrong exactly as often as it is right.
It passes `ReportLanguage::En`, which is the documented default and matches the
behavior before this feature.

The visible consequence is narrow: a Chinese draft exported to HTML from the
Workbench carries `lang="en"`. The body is unaffected -- the stored Markdown is
written out unchanged -- so this is an accessibility-metadata defect, not a
language defect. Closing it means persisting the language on the draft record,
which is a schema change.

## 10. Testing Strategy

No test invokes a provider.

1. **Structure is translated, both directions.** `render_markdown` with
   `Labels::chinese()` asserts the Chinese headings are present *and* that the
   English headings are absent. A one-directional assertion would pass against a
   `Labels::chinese()` that returned English strings.
2. **Technical tokens survive.** A fixture carrying a file path, a stack frame,
   and a crash signature renders those byte-identical under both languages.
3. **The wire contract holds.** `ReportLanguage` round-trips `"en"` and `"zh"`,
   pinning agreement with the desktop app's `Locale` values.
4. **Prompts differ by language.** `report_user_prompt(.., Zh)` contains the
   Simplified Chinese instruction and the token-preservation rule;
   `report_user_prompt(.., En)` contains neither.
5. **Rejection.** An unrecognized identifier yields
   `ClassifiedError::Validation` naming the accepted values.

## 11. Success Criteria

1. Generating a report from the desktop app with the interface in Chinese
   produces a report whose headings, tables, chart labels, and prose are Chinese.
2. The same report keeps every file path, stack frame, crash signature, engine
   name, sanitizer name, CWE identifier, and figure byte-identical to the
   English rendering of the same data.
3. With no provider configured, the Chinese fallback report is still Chinese.
4. `oxfuzz report --lang zh` and a REST request with `"language": "zh"` produce
   the same structure as the desktop path.
5. Omitting the language anywhere yields an English report, unchanged from
   today's behavior.
6. A missing Chinese translation is a compile error, not a silently untranslated
   string.
7. The mandated gates pass in `AGENTS.md` 4.5 order.

## 12. Rejected Alternatives

**Translate only the narrative.** One prompt instruction, no changes to
`report.rs`. Rejected because it produces a visibly mixed-language document --
Chinese prose under English headings -- and leaves the no-provider fallback
entirely English, which is exactly the case where a user has least recourse.

**Let the model translate the fact sheet too.** No Rust changes at all.
Rejected on two counts: the no-provider path stays English, and instructing the
model to translate labels directly contradicts the verbatim-preservation rule
that currently stops it fabricating figures. Weakening that rule to allow
translation would weaken the grounding that keeps report numbers honest.

**A key-to-string map per locale**, mirroring `i18n.extra.ts`. Rejected because
its failure mode is silent: a missing or misspelled key renders as the raw key
and no gate catches it. The compiler-checked struct costs the same effort and
makes the failure impossible.

**A persisted `[report] language` setting.** Would give scheduled and CLI
reports a language without plumbing. Rejected because it duplicates the existing
UI language selector and the two can disagree, so a user reading a Chinese
interface could still receive English reports with no visible cause. Revisit if
headless Chinese reports are actually wanted.

**Translating technical tokens.** Most thoroughly Chinese, and it would destroy
the report's value as evidence: a translated stack frame no longer matches the
crash, and a reader cannot grep for it.
