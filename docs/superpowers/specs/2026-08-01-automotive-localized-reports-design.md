# Localized Automotive Report Design

Status: **approved design**. Owner: `hf-service`, with thin parameter passing in
`hf-cli`, `hf-web`, and `hf-gui`.

Depends on the localized-reports work (merge request !133), which introduces
`ReportLanguage`. That type does not exist on `main`. This work forks from
`localized-reports-20260801` and cannot merge before it.

## 1. Goal

Produce the automotive campaign report in Simplified Chinese when the caller
asks for Chinese, so that the always-present Automotive surface stops being the
one place a Chinese-reading operator receives an English document.

Scope of this increment:

- an `AutomotiveLabels` set covering every user-facing literal
  `render_automotive_report` emits;
- localized prompts for the AI interpretation;
- `validate_ai_interpretation` becomes language-aware, so a Chinese
  interpretation is accepted rather than silently rejected;
- the language threaded from the CLI, REST, the Tauri command and
  `AutomotiveView`.

Out of scope: any language beyond English and Simplified Chinese, persisting a
language on stored drafts, and localizing the physical-bench surfaces.

## 2. Why this is not just "the same again"

The main report's design transfers almost wholesale, with one exception that
changes the shape of the work and one that changes its stakes.

### 2.1 Validation currently hard-requires English headings

`validate_ai_interpretation` rejects any interpretation missing all four of:

```
### Evidence-backed interpretation
### Hypotheses
### Missing evidence
### Recommended next actions
```

Instructing the model to write Chinese makes it emit Chinese headings, so
validation fails and `generate_automotive_report` falls back to the
deterministic report. The failure is silent in the sense that matters: the user
asked for an AI interpretation, got a valid-looking report without one, and
nothing says why.

The main report had no equivalent. `ensure_graphs` re-injects missing graphs; it
does not reject the document.

**Decision.** The four headings become label fields, and validation checks the
headings for the language the report was requested in. The rest of validation --
the size bound, the code-fence rejection, and every citation check -- is
untouched.

The alternative of validating structure rather than literal headings was
considered and rejected for this increment: it is a larger change to a
safety-relevant function, and it would still need the labels for rendering. It
remains the better long-term shape and is recorded as a follow-up.

### 2.2 The Limitations section is a guardrail, not prose

`render_limitations` exists to stop a reader over-claiming from automotive
evidence:

- protocol-state digests are not line, function, region, or edge coverage;
- a completed operation confirms contract-valid execution, not the absence of
  security defects;
- offline and virtual evidence does not validate a physical ECU, a vehicle
  network, timing behavior, or bench wiring;
- an AI interpretation is advisory and cannot authorize execution or establish a
  finding.

A Chinese report whose findings are readable and whose caveats are not is worse
than an English one, because the reader absorbs the conclusions and skips the
limits. The same argument applies to the advisory notice
`append_ai_interpretation` places above the model's prose.

These translations carry more risk than any heading and are called out for
particular care in review.

## 3. Technical Tokens

The rule is inherited: technical tokens render byte-identical in both
languages. The automotive set is different from the main report's, and one part
of it is load-bearing beyond greppability.

**Never translated, and validated:**

- evidence citations `[OP:<id>]`, `[STATE:<digest>]`, `[TRANSCRIPT:<sha256>]`.
  `validate_ai_interpretation` checks each against the known operation ids,
  state digests and transcript hashes. A translated or transliterated citation
  is not merely unmatchable by a reader -- it fails validation and discards the
  whole interpretation.

**Never translated:**

- pipeline stage identifiers: `capabilities`, `analyze_capture`,
  `generate_mutations`, and their siblings. They name real stages.
- protocol and bus names, ECU identifiers, adapter names.
- SHA-256 digests, file paths, workspace-relative evidence directories.
- every figure.

Stage identifiers appear paired with a human description. The identifier stays;
the description translates.

## 4. Architectural Ownership

| Concern | Owner |
| --- | --- |
| Language value | `hf-service::report` (existing `ReportLanguage`) |
| Automotive label set | `hf-service::automotive_report::AutomotiveLabels` |
| Automotive prompts | `hf-service::automotive_report` |
| Interpretation validation | `hf-service::automotive_report` |
| Composition | `hf-service::automotive` |
| Language selection | the caller: `hf-gui`, `hf-cli`, `hf-web` |

Layering is unchanged. `ReportLanguage` is reused rather than duplicated; there
is no second language type.

## 5. The Label Set

`render_automotive_report` and its eight `render_*` helpers take an
`&AutomotiveLabels`. The struct has `english()`, `chinese()` and
`for_language()`, exactly as `Labels` does, and for the same reason: a missing
translation must not compile.

**This design does not enumerate the fields, and the implementation plan must
not either.** On the previous branch the plan pinned a 75-field list, six fix
rounds grew the struct to 101, and the plan was never brought back into step --
so it ended up contradicting both the code and itself. The lesson is that a
hand-maintained copy of a field list is a liability, not a specification.

The rule instead: **every literal `render_automotive_report` emits that a reader
sees, and that is not a technical token under section 3, is a field.** The
authoritative list is the struct. The compiler enforces that both constructors
cover it. Reviewers verify the rule was applied by rendering both languages and
reading the output, not by counting against a list in a document.

Expect roughly 60 to 90 fields across 56 emit sites. That is an estimate for
planning, not a target to hit.

## 6. Prompts and Validation

`automotive_report_system_prompt(language)` and
`automotive_report_user_prompt(facts, data, language)` follow the main report's
shape. The Chinese variants add the output-language instruction and the
token-preservation rule from section 3, naming the citation formats explicitly.

`validate_ai_interpretation(interpretation, data, language)` checks the four
required headings for that language. Everything else in the function is
unchanged, including the requirement that an interpretation cite at least one
piece of retained evidence when operations exist.

`append_ai_interpretation(facts, interpretation, model, labels)` translates its
advisory notice and its heading. The model identifier stays verbatim.

## 7. Surfaces

| Surface | How the language arrives |
| --- | --- |
| Desktop | `AutomotiveView` passes the active `useI18n()` locale |
| CLI | `oxfuzz automotive report ... --report-lang zh`, matching the flag name settled on the previous branch |
| REST | an optional `language` field on the automotive report request |

`generate_automotive_report` and
`generate_automotive_report_with_settings` gain the parameter. As on the
previous branch, every call site must pass a deliberate value; the count is to
be established by grep at implementation time rather than asserted here.

`AutomotiveView.tsx` builds an English draft title at two sites (the saved draft
and the export). Both become `automotive.report.*` i18n keys, following the four
title sites fixed on the previous branch.

## 8. Failure Semantics

No new runtime failure modes.

An unrecognized language is rejected before composition, by the same mechanism
as the main report on each surface.

A model that ignores the language instruction still produces a valid document:
the scaffolding is translated in Rust. With validation now language-aware, a
model that emits English headings when Chinese was requested has its
interpretation rejected and the deterministic report is returned -- the same
outcome as any other validation failure, and the correct one.

## 9. Known Limitations

### 9.1 Stored drafts do not record a language

`save_report_draft` takes no language, so a re-exported automotive draft
declares English in its `lang` attribute, exactly as main-report drafts do.
This is the localized-reports design's section 9.3, inherited unchanged.
Closing it is a schema change and was deliberately deferred.

### 9.2 Operation statuses are translated, unlike the main report's

This section originally claimed automotive statuses reach the report through
`Debug`, as the main report's `RunStatus` does, and so would stay English.
**That premise was wrong**, and Task 1 found it.

The main report really does emit `format!("{:?}", r.status)`. The automotive
renderer does not: `status_name` is a hand-written `match` from
`AutomotiveOperationStatus` to display text, and it was a presentation mapping
before this work began. Section 5's extraction rule therefore applies to it, and
its four arms are label fields.

**Decision:** they are translated. A hand-written display mapping is a label by
definition, and the argument that settled CASR severities on the previous branch
applies unchanged -- a reader benefits from the translation, and nothing depends
on the English spelling.

What does remain English is any value that genuinely reaches the report through
`Debug` rather than through a mapping. Task 2 should confirm which those are by
reading, rather than trusting this document a second time.

### 9.5 The interpretation size bound is bytes, so Chinese gets less of it

`validate_ai_interpretation` rejects an interpretation over 24000 **bytes**. A
CJK character costs three bytes in UTF-8 where a Latin one costs one, so a
Chinese interpretation has roughly a third of the character budget an English
one does -- about 8000 characters against 24000.

The bound was deliberately not touched when validation became language-aware,
because widening a safety limit is not a translation change. The practical
impact is low: 8000 Chinese characters is a long interpretation, and the
consequence of hitting the bound is a clear rejection rather than a silent
truncation.

Recorded because the asymmetry only became reachable when Chinese did, and it
existed nowhere in writing before.

### 9.4 Operation result summaries stay English

`automotive::automotive_result_summary` builds sentences like
`42 decoded event(s); 1 protocol-state signature(s)` and stores them on the
operation record. They reach the report as *data*, not as renderer literals, so
`AutomotiveLabels` does not cover them and they render English inside an
otherwise Chinese table cell and bullet.

Threading a language into that function would be the wrong fix: it constructs
the operation record, which is also returned over REST to consumers that have
nothing to do with reports, so a language parameter there would bake report
presentation into shared data.

The right fix is to make `result_summary` structured -- the counts and the
variant, rendered at report time through the label set -- which is a change to
the data model rather than to the renderer, and is deliberately out of this
increment.

**This is an exception to success criterion 1**, recorded here rather than left
for a reader to discover: the criterion says tables and bullets are Chinese, and
these two cells are not.

### 9.3 Heading-literal coupling remains

Validation still matches literal headings; it just matches the right ones per
language. A third language means another arm. Replacing literal matching with a
structural check is the durable fix and is recorded here rather than done.

## 10. Testing Strategy

No test invokes a provider.

1. **Structure is translated, both directions.** Render with `chinese()` and
   assert Chinese headings present *and* English headings absent.
2. **Technical tokens survive.** A fixture carrying an operation id, a state
   digest, a transcript hash, a stage identifier and a path renders those
   byte-identical under both languages.
3. **Citations survive specifically.** `[OP:...]`, `[STATE:...]` and
   `[TRANSCRIPT:...]` are byte-identical, and an interpretation carrying them
   still validates under `Zh`.
4. **Validation is language-aware.** A Chinese interpretation with Chinese
   headings validates under `Zh` and fails under `En`; the English case still
   behaves as it does today.
5. **The guardrails are translated.** The Limitations bullets and the advisory
   notice are asserted by exact assembled text in both languages.
6. **The prompts differ by language**, and the English prompt carries no
   translation instruction.

Every assertion must be able to fail. Name the single-line production change
that turns each red. Where a test guards one call site among several rendering
similar text, revert that site and confirm red. Eight tests on the previous
branch passed for reasons unrelated to the behavior they named; two shapes
account for all of them, both recorded in that branch's plan.

## 11. Success Criteria

1. Generating an automotive report from the desktop app with the interface in
   Chinese produces a report whose headings, tables, bullets, limitations and
   narrative are Chinese, with the single documented exception of operation
   result summaries (section 9.4), which arrive as data rather than as
   renderer literals.
2. Evidence citations, stage identifiers, protocol names, digests, paths and
   figures are byte-identical to the English rendering of the same data.
3. A Chinese AI interpretation passes validation rather than being discarded.
4. With no provider configured, the Chinese deterministic report is still
   Chinese.
5. Omitting the language anywhere yields an English report, unchanged from
   today's behavior.
6. A missing Chinese translation is a compile error.
7. The mandated gates pass in `AGENTS.md` 4.5 order.

## 12. Rejected Alternatives

**A second language enum for automotive.** Rejected: `ReportLanguage` already
carries the meaning and the wire format the desktop app sends.

**Sharing `Labels` between the two reports.** Rejected: the two documents share
almost no vocabulary, and a union struct would force every automotive field on
the main report and vice versa, making the compiler's completeness check
meaningless for both.

**Translating evidence citations.** Rejected on stronger grounds than the main
report's token rule: citations are validated against known identifiers, so
translating one discards the interpretation that carries it.

**Enumerating the field list in the plan.** Rejected on evidence from the
previous branch, where the pinned list drifted from the code and from itself.
The struct is the list.
