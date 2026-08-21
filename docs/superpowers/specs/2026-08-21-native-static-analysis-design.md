# Native Static Analysis Design

Status: **draft**. Owner: `hf-analysis` and `hf-discovery`.

## 1. Goal

Replace the sandboxed Semgrep CE enrichment with a static analyzer oxfuzz owns
end to end: a tree-sitter query engine plus a bounded intra-procedural pass,
running in-process over the parse `hf-discovery` already performs.

The motivation is capability ownership, not licensing. Semgrep CE is LGPL-2.1
invoked as a separate process and the bundled rules are MIT with notices
retained, which is a defensible position today. What that position costs is a
third-party binary in the sandbox image, a pinned version to track, and 11,543
lines of Rust that exist only because the analyzer is a foreign subprocess:
9,865 lines of orchestration and interrupted-run recovery, plus 1,678 lines
defending against its JSON.

Findings remain advisory static-analysis signals that improve fuzz-target
prioritization. They are not confirmed vulnerabilities, and they are not
authority to generate, promote, build, or execute a harness. That constraint
from the design this supersedes is unchanged and non-negotiable.

Delivered in two phases:

- **Phase 1** reproduces the signal of the 49 bundled rules and proves, by
  measurement against the live Semgrep path, that target ranking does not
  regress. Semgrep is then deleted.
- **Phase 2** adds what a general-purpose SAST structurally cannot produce:
  pattern hits joined to reachability and input surface.

Phase 2 is described here only far enough to show that phase 1 does not block
it. It gets its own design before implementation.

## 2. What This Supersedes

This design reverses three decisions in
`2026-07-28-semgrep-target-enrichment-design.md` section 2. Each reversal is a
consequence of the analyzer becoming an in-process pure function, not a change
of product intent.

| Superseded | Replacement | Why |
| --- | --- | --- |
| 1. Normal target discovery does not run Semgrep. | Native analysis runs as part of every C/C++ discovery. | The cost was a sandboxed subprocess over a staged source snapshot. The native cost is one query-cursor pass over a tree already in memory. There is nothing left to opt out of. |
| 2. The user opts in after or as part of C/C++ discovery. | No opt-in. Signals are part of what `discover` returns. | Opt-in existed to gate an expensive, failure-prone operation. Neither property survives. |
| 6. Any error rejects the whole enrichment; partial findings never affect ranking. | Analysis is advisory and best-effort; truncation is surfaced, not fatal. | All-or-nothing existed because a subprocess can die mid-stream leaving untrusted partial JSON. A pure function over a parsed tree has no partial state. See section 11. |

Decision 7 ("extends the existing discovery subsystem instead of introducing a
generic static-analysis framework or agent-created tool") is **upheld**.
`hf-analysis` is not a framework: it has a fixed, embedded rule set, no plugin
surface, no runtime rule loading, and no agent-authored rules. It is a separate
crate for testability, not for extensibility. See section 16.

Decisions 3, 4, and 5 are unchanged: capped boosts affect prioritization
automatically, the base score stays immutable and visible, and no rule content
is ever fetched from a network.

## 3. Upstream Baseline

The 49 bundled `0xdea/semgrep-rules` C/C++ rules were inventoried on
2026-08-21 at the pinned snapshot.

Operators used across all 49:

```
640 pattern          97 pattern-not-inside    34 metavariable-pattern
134 patterns         76 pattern-inside        32 metavariable-regex
110 pattern-either   54 pattern-not           10 focus-metavariable
```

No rule uses `mode: taint`, `pattern-sources`, `pattern-sinks`,
`metavariable-comparison`, or `pattern-regex`. Semgrep's genuinely hard
capability, interprocedural taint tracking, is not exercised by this rule set at
all. Every operator in use is syntactic.

By difficulty the rules split cleanly:

- **29 rules** match a call or expression shape with metavariable constraints
  (`gets($X)`, `memcpy($D, $S, sizeof($S))`). These map onto tree-sitter queries
  directly.
- **20 rules** use the statement-sequence ellipsis: a pattern of the form
  `A; ... ; B` within one block, usually with a `pattern-not` that cancels the
  match when a killing statement appears between them. Example, from the
  double-free rule: match `free($P); ... ; free($P);` but not when
  `$P = ...` occurs in between.

The bug classes needing sequence analysis, by upstream checklist name: double
free, use after free, incorrect use of free, mismatched memory management (C and
C++ variants), off-by-one, integer truncation, integer wraparound, signed and
unsigned conversion, unchecked malloc return, unterminated strncpy, incorrect
strncat use, incorrect sizeof use, use of source size in copy, write into stack
buffer, return of stack address, pointer subtraction, putenv with a stack
variable, setuid and setgid ordering, and regex denial of service.

All 49 rules carry `cwe:`, `references:`, and `vulnerability_class:` metadata.
That is what makes section 6 executable.

## 4. Product Decisions

1. Native analysis runs automatically during C and C++ discovery.
2. The base `TargetCandidate.fit_score` is never overwritten. The boost is an
   overlay, exactly as today.
3. The boost model is unchanged from the superseded design: per-distinct-rule
   severity weights, summed, capped at `0.20`, added to the base and capped at
   `1.0`, rounded to two decimals.
4. Rules are embedded at compile time. There is no runtime rule directory, no
   user-supplied rules, and no network fetch.
5. Findings are advisory. Nothing downstream may treat a finding as a
   vulnerability, a crash, or execution authority.
6. Phase 1 ships behind a feature flag with Semgrep still available, so both
   paths can be measured against each other on real projects.
7. Semgrep is deleted only after the section 12 gate passes.

## 5. Architectural Ownership

### 5.1 `hf-analysis` (new crate)

Fuzzing-domain crate. Depends on `hf-core`, `tree-sitter`, `tree-sitter-c`,
`tree-sitter-cpp`. Depends on nothing else in the workspace.

```
crates/hf-analysis/
  src/lib.rs        public API, rule-set compilation
  src/catalog.rs    rule metadata: id, CWE, severity, bug class
  src/query.rs      tree-sitter Query execution into raw captures
  src/sequence.rs   intra-procedural pass for the sequence rules
  src/finding.rs    the Finding type
  rules/c/*.scm     C rules
  rules/cpp/*.scm   C++ rules
```

Public API:

```rust
/// The compiled rule set for one language. Compiled once per process.
pub fn rules_for(lang: TargetLanguage) -> &'static RuleSet;

impl RuleSet {
    /// Match every rule against one already-parsed translation unit.
    ///
    /// Pure: performs no I/O, builds no parser, and does not own the tree.
    pub fn analyze(&self, tree: &Tree, source: &str) -> Vec<Finding>;
}

pub struct Finding {
    pub rule_id: &'static str,
    pub cwe: &'static str,
    pub severity: Severity,
    pub span: SourceSpan,
}
```

`RuleSet` is built in a `OnceLock` per language. `tree_sitter::Query`
compilation is not free and there are tens of them; compiling per file would
cost more than matching. This mirrors `hf_harness::lint::compiled_rules`.

`analyze` takes a tree it did not build. That is what makes the marginal cost a
query-cursor pass rather than a parse, and what makes the crate testable from a
source string with no fixture project on disk.

### 5.2 `hf-discovery`

Owns everything about candidates; `hf-analysis` never learns what a
`TargetCandidate` is.

- `scanner.rs`: one call added inside the existing per-file loop in `scan_c`,
  after `extract_functions`, passing the same `&tree` and `&src`.
- `enrichment.rs` (new): the producer-agnostic join and scoring extracted from
  `semgrep.rs`. See section 9.
- `semgrep.rs`: keeps its normalization and sandbox contract during phase 1,
  but delegates scoring to `enrichment.rs` rather than owning it (section 9).
  Deleted at the end of phase 1.

### 5.3 `hf-service`

No new orchestration. The native path has no operation to coordinate, no
snapshot to stage, no cancellation protocol, and no recovery. `semgrep.rs` and
`semgrep_recovery.rs` are untouched during phase 1 and deleted with it.

### 5.4 Presentation

During phase 1, unchanged. At deletion the Discover view loses the
start/cancel/status controls, because there is no longer an operation to start,
and renders signals as part of the inventory. This is a visible behavior change,
not an internal swap, and is called out in section 13.

## 6. Rule Derivation and Provenance

Rules are **re-derived from the primary standards each upstream rule cites**,
not translated from the upstream patterns.

Every one of the 49 rules names its CWE and its references, most commonly the
SEI CERT C Coding Standard. Those, plus the C and C++ language definitions, are
the source material. The upstream rule list is used only as a **coverage
checklist**: which bug classes to cover, and nothing else.

Rationale. A bug class is not copyrightable; a specific pattern expression
plausibly is. Re-deriving means the result is not a derivative work, so
`third_party/semgrep-rules` is deleted outright and no attribution obligation
survives. Given that the entire point of this work is capability ownership,
carrying a permanent MIT notice for rules we rewrote would defeat it.

The cost is honest and accepted: re-derivation is slower per rule, and
"did we lose coverage" cannot be answered by comparing pattern structure. It is
answered by the measurement in section 12, which is a better question anyway.

Each rule file carries a header comment naming its CWE and the standard clause
it was written from, so a reviewer can check the derivation against the source
rather than against Semgrep.

## 7. Rule Expression

### 7.1 Shape rules

A tree-sitter query with captures and predicates. The `@hit` capture is the
span reported.

```scheme
; CWE-242: Use of Inherently Dangerous Function
; SEI CERT C: STR31-C
(call_expression
  function: (identifier) @fn
  (#eq? @fn "gets")) @hit
```

`pattern-inside` and `pattern-not-inside` become ancestor checks over the
captured node. `metavariable-regex` becomes `#match?`. `focus-metavariable`
becomes the choice of which capture is `@hit`.

### 7.2 Sequence rules

A query captures the participating sites; a Rust pass in `sequence.rs` decides
whether they form a match.

```scheme
; CWE-415: Double Free
; SEI CERT C: MEM30-C
(call_expression
  function: (identifier) @free
  arguments: (argument_list (identifier) @ptr)
  (#eq? @free "free")) @site
```

The pass then, per enclosing block:

1. groups `@site` captures by the text of `@ptr`;
2. orders them by byte offset;
3. for each ordered pair, scans the statements strictly between them for a
   **kill**: an assignment to `@ptr`, taking its address, or passing it to a
   function that could reassign it through a pointer-to-pointer parameter;
4. reports the second site when no kill is found.

The kill set is the entire correctness question for these 20 rules. It is
deliberately **over-approximating**: any statement the pass cannot prove
harmless counts as a kill and suppresses the finding. A missed finding costs a
slightly-too-low ranking for one function. A false finding costs operator trust
in the whole signal, and trust does not come back. Section 14 makes the
over-approximation testable rather than aspirational.

Scope is one function body. No interprocedural reasoning, no alias analysis, no
path sensitivity. Rules whose upstream form needs more than that are recorded in
section 17 as uncovered rather than approximated badly.

## 8. Finding Contract

```rust
pub struct Finding {
    /// Stable oxfuzz rule identifier, e.g. "double-free". Never a raptor id.
    pub rule_id: &'static str,
    /// Primary CWE the rule was derived from, e.g. "CWE-415".
    pub cwe: &'static str,
    pub severity: Severity,   // Info | Warning | Error
    pub span: SourceSpan,     // one-based line, zero-based column, ordered
}
```

Severity carries the same weights as the superseded design, so the boost math is
unchanged: `Error` 0.10, `Warning` 0.05, `Info` 0.01.

`rule_id` values are ours. They are not the upstream `raptor-*` ids, and no
mapping table between the two is maintained: the rules were re-derived, so a
one-to-one correspondence is not claimed and should not be implied.

## 9. Shared Enrichment Scoring

The join and boost math move out of `semgrep.rs` into
`hf-discovery/src/enrichment.rs`, keyed on a producer-agnostic signal:

```rust
pub struct EnrichmentSignal {
    pub relative_path: PathBuf,
    pub start_line: u32,
    pub start_col: u32,
    /// Distinct-rule counting key.
    pub rule_key: String,
    pub weight: f64,
}

pub fn score_overlay(
    inventory: &TargetInventory,
    signals: &[EnrichmentSignal],
) -> Vec<TargetScore>;
```

`uniquely_containing_candidate`, distinct-rule counting, the `0.20` cap, the
`1.0` effective cap, two-decimal rounding, and the deterministic tie-break order
move unchanged, and their existing tests move with them.

This is load-bearing for phase 1, not a tidy-up. If each path carried its own
scoring, a ranking delta between them would be unattributable: matcher or math,
no way to tell. Sharing the scoring makes every delta attributable to matching
alone, by construction. Both producers map into `EnrichmentSignal`; Semgrep's
mapping is deleted with it.

## 10. Data Flow

```text
discover(project, lang)
  |
  +- scan_c: for each source file
  |    parse                       -> tree
  |    extract_functions(&tree,..) -> candidates, call graph      [existing]
  |    analyze(&tree, &src)        -> Vec<Finding>                [new]
  |
  +- rank()                        -> TargetInventory (base fit scores)
  +- enrichment::score_overlay()   -> score overlay
```

The overlay is computed from the same parse, in the same call, as the candidates
it scores. It therefore cannot be stale with respect to the sources, and
`SemgrepOverlayState` has no native equivalent to represent.

For contrast, the path this replaces: operator starts an operation, a source
snapshot is staged and digested, a sandbox runs a pinned subprocess, JSON is
normalized through 1,678 lines of validation, findings are mapped and scored,
and the resulting overlay may already be stale against sources that moved
underneath it.

## 11. Failure Semantics

`analyze` returns `Vec<Finding>`, not `Result`. A rule that can fail discovery
would be worse than no rule at all.

- **Malformed rule**: caught by a test that compiles every embedded rule
  (section 14), so it fails CI rather than a user's scan.
- **Unparseable or non-UTF-8 source**: already skipped by `scan_c` with a
  warning, before analysis is reached. Unchanged.
- **Pathological input**: findings are capped per file and per project.
  `hf-analysis` owns these constants; it does not borrow
  `hf-discovery::semgrep::MAX_FINDINGS`, which is deleted in phase 1d. The
  initial project cap matches that rule's `50_000` so behavior is unchanged at
  the boundary. Reaching a cap is recorded and surfaced, not silent.

On superseded decision 6 (all-or-nothing): that rule existed because a
subprocess can die mid-stream and leave untrusted partial JSON, which must not
be allowed to shift a ranking. A pure function over an already-parsed tree has
no such state. The one genuinely partial outcome is hitting a cap, and its
posture matches what `scan_c` already does when it skips an unreadable file: the
inventory is partial, that fact is surfaced, and discovery proceeds. Making
truncation fatal would be a stricter rule than discovery applies to itself.

## 12. Phase 1 Gate: A/B Measurement

Phase 1 is not done when the rules are written. It is done when the ranking is
shown not to regress.

**Instrument.** A development-only CLI path that runs both enrichments over one
inventory and reports the comparison. It is deliberately throwaway and is
deleted with Semgrep.

**Primary metric: top-N set agreement.** oxfuzz fuzzes the top of the ranking,
so what matters is whether the same functions are selected, not whether the
boosts are numerically identical. Report the symmetric difference of the top-10
and top-25 candidate sets between the two overlays.

**Secondary metric: rank displacement.** For candidates in either top-25, the
change in position. Surfaces near-misses the set comparison hides.

**Diagnostic: finding-level diff.** Signals present in one path and not the
other, keyed on `(relative_path, start_line)`. Not a pass/fail metric, because
re-derived rules are not expected to fire identically. It is how a human
investigates a ranking delta that the primary metric flagged.

The join key is `(relative_path, start_line)` and not CWE, because
`SemgrepFinding` does not retain CWE metadata and this design does not add
fields to a code path scheduled for deletion.

**Gate:** on an agreed set of real C/C++ projects, top-10 set agreement is
exact, and every top-25 displacement is either zero or explained by a
finding-level diff a reviewer accepts. The project set and the reviewed
explanations are recorded in the implementation plan.

## 13. Phasing and Deletion

**Phase 1a.** `hf-analysis` with the 29 shape rules. `enrichment.rs` extraction.
Both paths available; native behind `native-analysis`, off by default.

**Phase 1b.** The sequence pass and the remaining 20 bug classes.

**Phase 1c.** Run the section 12 gate. Record results.

**Phase 1d.** Deletion, in one change so no intermediate state ships a
half-removed subsystem:

- `crates/hf-discovery/src/semgrep.rs` (1,678 lines)
- `crates/hf-service/src/semgrep.rs` (7,439 lines)
- `crates/hf-service/src/semgrep_recovery.rs` (2,426 lines)
- `third_party/semgrep-rules`, `third_party/semgrep`
- the Semgrep layer, rules copy, wrapper, and digest script in
  `docker/sandbox/Dockerfile`
- `scripts/semgrep-tree-digest.py`, `scripts/tests/test_validate_semgrep_smoke.py`
- the `semgrep-enrichment` feature across `hf-discovery`, `hf-service`,
  `hf-web`, `hf-cli`, `hf-gui/src-tauri`
- REST routes `/semgrep/*`, the Tauri commands, and the GUI operation controls
- the `semgrep_enrichment_runs`, `semgrep_findings`, and
  `semgrep_target_scores` tables, via a migration
- `native-analysis` becomes unconditional; the flag is removed with the
  alternative it selected against

Phase 1d must state the storage migration explicitly: the three Semgrep tables
are dropped and the native overlay is recomputed on demand rather than
persisted, because it is now cheap enough to recompute and can never be stale.

**Phase 2** joins hits to reachability and input surface. Separate design.

## 14. Testing Strategy

TDD throughout, per `AGENTS.md` 2.7.

**Rule compilation.** One test compiles every embedded `.scm` for every
language. A malformed query cannot reach a user.

**Per-rule fixtures.** Every rule ships a positive and a negative fixture: a
minimal translation unit that must match, and one that must not. The negative
fixture is the one that matters; it is where over-approximation is proven rather
than asserted. Fixtures are source strings in the test, not files on disk.

**Kill-set tests for sequence rules.** For each sequence rule, a fixture per
kill kind: reassignment, address-taken, passed to a pointer-to-pointer
parameter, and a case with no kill that must match. These are the tests that
decide whether the false-positive posture in section 7.2 is real.

**Determinism.** The same source analyzed twice yields byte-identical findings
in the same order. Ordering is by span, then rule id.

**Scoring parity.** The extracted `enrichment.rs` retains the existing Semgrep
scoring tests unchanged, so the cap, rounding, and tie-break behavior is proven
identical before and after the move.

**Integration.** Discovery over a fixture project produces the expected overlay,
and a candidate with no findings has a boost of exactly zero.

**No sandbox test.** The analyzer executes nothing and reads nothing outside the
tree it was handed, so it needs no sandbox coverage. That absence is the point.

## 15. Success Criteria

1. The section 12 gate passes on the agreed project set.
2. `third_party/semgrep-rules` and `third_party/semgrep` are gone, with no
   attribution obligation carried forward.
3. The sandbox image no longer installs Semgrep or its Python dependency layer.
4. Discovery produces enrichment signals with no operator action, no subprocess,
   and no sandbox.
5. Net lines removed exceeds lines added.
6. Every rule file cites the CWE and standard clause it was derived from.

Criterion 5 is a claim to verify, not an assumption. The 9,900 lines being
removed are subprocess machinery, and the analyzer replacing them is a query
engine plus a bounded pass; if the arithmetic turns out the other way, that is
worth knowing before phase 1d rather than after.

## 16. Rejected Alternatives

**Port the upstream patterns and keep MIT attribution.** Faster, and the A/B
would agree more closely. Rejected because the result is plausibly a derivative
work, so the notice and `third_party/semgrep-rules` would stay in the repository
permanently. The Semgrep binary would leave and the attribution would not, which
defeats the goal.

**A YAML rule DSL of our own.** Most familiar to anyone coming from Semgrep and
the easiest mechanical port. Rejected as the most expensive path: it means
building and maintaining a pattern language, and it is the option most likely to
reinvent Semgrep badly. tree-sitter's query language is already a real,
tested pattern language for the parser we already link.

**Hardcoded Rust matchers per rule.** Most precise and fastest, no query engine
to debug. Rejected because 49 hand-written AST walkers is materially more code
than 49 queries, and rules stop being reviewable as data in a pull request.

**A module inside `hf-discovery` rather than a crate.** Simplest data flow, tree
never crosses a boundary. Rejected on testability: phase 1's entire value is a
fixture corpus proving no regression, which is cleaner in a crate whose only job
is matching. `hf-discovery` is also already four concerns deep.

**Splitting a generic engine from the C/C++ rules.** Rejected as speculative.
The rules are C/C++ only and so is the engine's reason to exist.

**Keeping Semgrep for non-C/C++ languages.** Rejected because the bundled rule
set is C/C++ only; there is no other language coverage to lose.

## 17. Open Questions

1. **Which projects form the gate set in section 12?** It needs real C/C++
   codebases with enough candidates for a top-25 to be meaningful. Must be
   agreed before phase 1c.
2. **Which upstream bug classes end up uncovered?** Section 7.2 caps the
   sequence pass at one function body with no aliasing. Some upstream rules may
   need more to fire usefully. Each such rule is recorded as uncovered, with the
   reason, rather than approximated into a false-positive source. The list is
   not knowable until phase 1b.
3. **Does the native overlay need persistence at all?** Section 13 assumes not,
   since it is cheap to recompute and never stale. If the GUI needs overlay
   history across sessions, that assumption changes and the migration in phase 1d
   changes with it.
4. **Does `hf-analysis` belong to the C/C++ scanner only?** `scan_go` and
   `scan_python` are lexical, not tree-sitter, so there is no tree to hand over.
   Native analysis is C/C++ only, exactly as Semgrep enrichment is today.
