# Native Static Analysis Design

Status: **superseded in part**. Owner: `hf-analysis` and `hf-discovery`.

**Read section 22 first.** Sections 1 through 20 were written to replace
Semgrep. Measurement in phase 1c showed that replacing it would lose most of
its coverage, so the decision changed: the native analyzer ships *alongside*
Semgrep. Everything about the analyzer's design still holds; every statement
about deleting Semgrep does not.

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
   need more to fire usefully. Each such rule is recorded in section 18 rather
   than approximated into a false-positive source. The full list is not knowable
   until phase 1b.
3. **Does the native overlay need persistence at all?** Section 13 assumes not,
   since it is cheap to recompute and never stale. If the GUI needs overlay
   history across sessions, that assumption changes and the migration in phase 1d
   changes with it.
4. **Does `hf-analysis` belong to the C/C++ scanner only?** `scan_go` and
   `scan_python` are lexical, not tree-sitter, so there is no tree to hand over.
   Native analysis is C/C++ only, exactly as Semgrep enrichment is today.

## 18. Recorded as Uncovered

Bug classes present in the upstream rule set that this design deliberately does
not cover. Each entry is a decision, not a gap to close later: a ranking delta
in the section 12 gate traced to an entry here is explained, not a failure.

Phase 1a and 1b append to this list as coverage decisions are made.

### 18.1 `high-entropy-assignment` (phase 1a)

Upstream flags string literals whose Shannon entropy suggests an embedded
credential or key. Not covered.

It is a heuristic over literal content, not a bug class: entropy is a property
of the bytes, and the same threshold that catches a hardcoded key also catches a
base64 test vector, a lookup table, and a UUID. More importantly it is not a
*fuzzing* signal. A hardcoded secret does not make a function a better fuzz
target, so even a correct finding would move the ranking for a reason unrelated
to what the ranking is for.

Secret detection is a real need and a different tool's job. If oxfuzz ever wants
it, it belongs in its own subsystem with its own output, not as a prioritization
boost.

### 18.2 `interesting-api-calls` (phase 1a)

Upstream flags calls to a broad list of APIs a reviewer might want to look at.
Not covered.

It is an attention-directing heuristic for a human auditor, and its severity is
`INFO` for that reason. As a ranking input it is close to noise: the list is
wide enough that a large fraction of non-trivial C functions match something,
which pushes every candidate's boost up by the same amount and moves no
candidate relative to another. A signal that shifts everything equally carries
no ranking information while still consuming part of the `0.20` cap that
sharper rules need.

The bug classes it gestures at that *are* fuzzing-relevant are already covered
by specific rules with real severities.

### 18.3 Deferred to phase 1b, not uncovered (phase 1a)

Four bug classes are query-expressible only as the *absence* of something, and
tree-sitter queries have no negation. Each needs the same Rust pass phase 1b
builds for the sequence rules, so they are deferred rather than approximated:

- **Omitted break in a switch case** (CWE-484). Requires "this case clause does
  not end in break, return, or goto", which is a property of the last statement
  in a block.
- **Missing default case** (CWE-478). Requires "no default label among these
  children".
- **Missing return on a path** (CWE-393). Requires a path-sensitive walk of the
  function body.
- **Incorrect unsigned comparison** (CWE-697). Requires knowing an operand is
  unsigned. Without types, matching `x < 0` would flag every correct signed
  comparison in the project, which is the false-positive posture section 7.2
  rejects.

Phase 1a therefore ships 21 of the 29 shape rules: 27 in scope less these four.
The section 12 gate must treat a delta traced to one of these as explained.

### 18.4 Uncovered pending type information (phase 1b)

The pass has no type information: it sees an identifier, not whether that
identifier is signed, unsigned, or a pointer. Four upstream classes need exactly
that, and matching them without it would flag correct code far more often than
defective code.

- **Incorrect unsigned comparison** (CWE-697). `x < 0` is a defect only when `x`
  is unsigned; without types, matching it flags every correct signed comparison
  in the project.
- **Integer truncation** (CWE-197). Needs the widths of both sides of an
  assignment.
- **Signed to unsigned conversion** (CWE-195). Needs the signedness of an
  argument against the parameter it is passed to.
- **`sizeof` on a pointer** (CWE-467). `sizeof(p)` is a defect only when `p` is a
  pointer rather than an array, and the two are spelled identically at a use
  site.

These are not deferred-for-effort. They are blocked on information the design
does not gather, and unblocking them means adding type resolution, which is a
larger change than the analyzer itself. Revisit only with a separate design.

### 18.5 Reconciliation against the upstream checklist

All 49 upstream rules, each with exactly one disposition. This is the input the
phase 1c gate needs: a ranking delta traced to a row here is explained, not a
failure.

**Covered: 34 of 49**, by 32 oxfuzz rules. Three upstream pairs collapse, because
re-derivation grouped by defect rather than by function name:
`strcpy`/`strcat` with `sprintf`/`vsprintf` into `unbounded-string-copy`;
`snprintf`/`vsnprintf` with `strlcpy`/`strlcat` into
`unchecked-truncating-write`.

| Upstream | oxfuzz rule |
| --- | --- |
| insecure-api-gets | `dangerous-function-gets` |
| insecure-api-ato | `unchecked-conversion-ato` |
| unchecked-ret-scanf | `unchecked-return-scanf` |
| insecure-api-scanf | `unbounded-scanf-conversion`, `unbounded-string-scan` |
| insecure-api-alloca | `dangerous-function-alloca` |
| insecure-api-strcpy-strcat | `unbounded-string-copy` |
| insecure-api-sprintf-vsprintf | `unbounded-format-write` |
| insecure-api-mktemp-tmpnam-tempnam | `insecure-temporary-file` |
| insecure-api-rand-srand | `weak-pseudo-random` |
| insecure-api-signal | `signal-handler-race` |
| insecure-api-access-stat | `toctou-access-check` |
| command-injection | `os-command-execution` |
| unsafe-strlen | `strlen-sum-overflow` |
| unchecked-ret-setuid-seteuid | `unchecked-privilege-drop` |
| unsafe-ret-snprintf-vsnprintf | `unchecked-truncating-write` |
| unsafe-ret-strlcpy-strlcat | `unchecked-truncating-write` |
| incorrect-use-of-memset | `memset-argument-order` |
| overlapping-source-destination | `overlapping-copy` |
| format-string-bugs | `non-literal-format-string` |
| argv-envp-access | `environment-input` |
| memory-address-exposure | `address-disclosure` |
| suspicious-assert | `assignment-in-assertion` |
| typos | `assignment-in-condition` |
| double-free | `double-free` |
| use-after-free | `use-after-free` |
| incorrect-use-of-free | `free-of-non-heap` |
| integer-wraparound | `allocation-size-multiplication` |
| use-of-source-size-in-copy | `source-size-in-copy` |
| off-by-one | `loop-bound-off-by-one` |
| ret-stack-address | `returned-stack-address` |
| unterminated-string-strncpy | `unterminated-strncpy` |

| regex-dos | `catastrophic-regex` |
| pointer-subtraction | `pointer-subtraction-size` |

**Not covered: 15 of 49**, each with a reason.

| Upstream | Disposition |
| --- | --- |
| high-entropy-assignment | Permanently uncovered, 18.1 |
| interesting-api-calls | Permanently uncovered, 18.2 |
| incorrect-unsigned-comparison | Pending type information, 18.4 |
| integer-truncation | Pending type information, 18.4 |
| signed-unsigned-conversion | Pending type information, 18.4 |
| incorrect-use-of-sizeof | Pending type information, 18.4 |
| missing-break-in-switch | Needs absence analysis; queries have no negation |
| missing-default-in-switch | Needs absence analysis; queries have no negation |
| missing-return | Needs a path-sensitive walk of the function body |
| mismatched-memory-management | Needs new/delete to allocation pairing across a variable |
| mismatched-memory-management-cpp | Same as above |
| incorrect-order-setuid-setgid | Needs ordering between two *different* events; the pass pairs a repeated event or an event and a use, not two distinct calls |
| unchecked-ret-malloc | Needs a null-check kill the kill set does not yet model |
| incorrect-use-of-strncat | Covered in the second widening round by `strncat-constant-bound`: a constant bound cannot express remaining space. |
| write-into-stack-buffer | Needs to know an object is a stack allocation |
| putenv-stack-var | Withdrawn in the widening phase: the defect is putenv of a *stack* variable and the corpus accepts a `static` one, but storage class is not information this analyzer gathers. Two known false positives were worse than a gap. |

The last five are effort, not information: each is reachable by extending the
pass, and none was worth extending it for inside phase 1b. They are the natural
content of a phase 1e if the section 12 gate shows the coverage gap matters.

## 19. Phase 1c Measurement

Run 2026-08-21 against the 48 annotated fixtures in
`third_party/semgrep-rules/rules/c`, using the corpus harness in
`crates/hf-analysis/tests/corpus_coverage.rs`.

```text
fixtures read      : 48
hit                : 95
miss               : 124
not attempted      : 79   (upstream rule uncovered by design, sections 18.1-18.4)
false positive     : 14
improvement        : 0    (Semgrep documents 8 misses; we caught none of them)
recall on attempted: 43.4%
```

Line alignment was spot-checked before trusting the number: on `double-free.c`
the harness expects findings at lines 23 and 58 and the analyzer reports exactly
those, so the misses are real rather than an off-by-one in the annotation
parser.

### 19.1 Misses by upstream rule

| Upstream rule | Misses |
| --- | ---: |
| off-by-one | 18 |
| use-of-source-size-in-copy | 14 |
| unsafe-ret-snprintf-vsnprintf | 13 |
| typos | 13 |
| integer-wraparound | 13 |
| use-after-free | 7 |
| unterminated-string-strncpy | 6 |
| suspicious-assert | 6 |
| format-string-bugs | 6 |
| overlapping-source-destination | 5 |
| insecure-api-scanf | 4 |
| unsafe-ret-strlcpy-strlcat | 3 |
| regex-dos | 3 |
| ret-stack-address, pointer-subtraction, memory-address-exposure, incorrect-use-of-memset | 2 each |
| unsafe-strlen, insecure-api-strcpy-strcat, incorrect-use-of-free, double-free, argv-envp-access | 1 each |

The pattern is one thing, not twenty: each re-derived rule matches **one** shape
of its defect, and the upstream rule matches several. `integer-wraparound`
covers many wrapping computations; ours covers a product used as an allocation
size. `typos` covers a family of operator confusions; ours covers assignment in
an `if` or `while` condition. `off-by-one` covers many bound errors; ours covers
a `<=` loop against a length call.

One miss is not narrowness but the deliberate kill set: `double-free.c:88` frees
the same pointer twice with an unrelated call between the two, and section 7.2
suppresses that on purpose. That one is working as designed, and it is the cost
that section named in advance.

### 19.2 False positives

14, clustered in four rules:

| Rule | Count | Cause |
| --- | ---: | --- |
| `os-command-execution` | 6 | Flags every `system`/`exec*` call; the upstream rule flags only calls whose argument is not a literal. |
| `weak-pseudo-random` | 2 | Flags `rand` unconditionally; the fixture marks seeded-from-entropy uses as acceptable. |
| `unbounded-scanf-conversion` | 2 | Flags a `%s` conversion that the fixture bounds by other means. |
| `unbounded-string-copy` | 2 | Flags `sprintf` where the fixture marks a bounded use as acceptable. |
| `environment-from-variable` | 2 | Flags every `putenv` of a variable; the upstream rule flags only stack-allocated arguments. |

These are the opposite failure from the misses: too broad rather than too narrow,
and every one is a rule that ignores context the upstream rule reads.

## 20. Phase 1c Gate Decision: FAIL

**Phase 1d must not proceed.** The native analyzer is not yet a replacement for
the rule set it would delete.

Two independent reasons, either sufficient on its own:

1. **Recall is 43.4% on the classes we claim to cover.** Section 18.5 records 34
   of 49 upstream classes as covered. Measured, those 34 classes catch fewer
   than half the cases their upstream counterparts catch. The reconciliation
   table described intent; this is the first measurement of effect, and the two
   do not agree.
2. **14 false positives.** Section 7.2 commits to the opposite posture --
   suppress rather than over-report, because a false finding costs operator
   trust that does not come back. Five rules violate that commitment.

What this does **not** show: that the approach is wrong. The machinery works, the
harness is sound, the shared scoring holds, and C++ went from zero coverage to
32 rules. What it shows is that a re-derived rule written to one shape of a
defect is not equivalent to an upstream rule written to several, and that
writing 32 rules is perhaps a third of the work rather than most of it.

### 20.1 What phase 1d becomes

Not deletion. A phase **1b-2**, widening rules against the corpus:

- Widen the five over-broad rules to read the context their upstream
  counterparts read. This is a correctness fix, not coverage work, and should
  land first: shipping a false positive is worse than shipping a gap.
- Widen the top five by miss count -- `off-by-one`,
  `use-of-source-size-in-copy`, `unsafe-ret-snprintf-vsnprintf`, `typos`,
  `integer-wraparound` -- which account for 71 of the 124 misses between them.
- Re-run section 19 after each, and record the number. The harness makes this a
  measurement rather than an argument.

### 20.2 What the gate should require next time

Section 12 set no numeric bar, which made "does it pass" a judgement call at the
worst moment. Concretely, before deleting Semgrep:

- **Zero false positives** on the corpus, or each one individually justified in
  writing.
- **Recall at or above 90%** on the classes section 18.5 claims to cover.
- Misses on uncovered classes are expected and not counted.

### 20.3 What was right to keep

The corpus harness itself. It is `#[ignore]`d, reads third-party fixtures only
from a test, and turned an unfalsifiable claim into a number in one run. Had
phase 1d proceeded on the reconciliation table alone, oxfuzz would have deleted
a working subsystem and replaced it with one that finds 43% as much.

## 21. Widening Phase: False Positives Eliminated

Re-measured 2026-08-21 after the false-positive work in spec section 20.1.

```text
hit                : 79     (was 95)
miss               : 139    (was 124)
false positive     : 0      (was 14)
recall on attempted: 36.2%  (was 43.4%)
```

**Zero false positives**, which is half of the section 20.2 bar. Recall fell,
and the fall is the point rather than a side effect: 14 of the earlier 95 hits
were rules firing on anything that looked vaguely relevant, and the same
breadth produced the 14 false positives. Removing the breadth removed both.

### 21.1 What changed

- **`os-command-execution` and `unbounded-string-scan` now require a
  caller-chosen argument.** The corpus flags `system(string)` where `string` is
  a parameter and accepts `system(buf)` where `buf` is a local literal; the
  analyzer was not reading that distinction at all.
- **A one-step taint pass** backs that check. A name is caller-chosen if it is a
  parameter, if it was assigned from something already caller-chosen or from a
  known untrusted source, or if it is the destination of a string builder whose
  source was caller-chosen. That last case is what catches
  `snprintf(buf, ..., user); popen(buf, ...)`, which a parameter check alone
  misses. It is deliberately not "any call propagates", which would taint most
  locals in a function and reintroduce the over-reporting.
- **`sprintf` split out of `unbounded-string-copy`** into
  `unbounded-format-write`, which requires an unbounded conversion in the format
  literal. `sprintf(buf, "n: %d", n)` is bounded; `%s` is not.
- **`weak-pseudo-random` narrowed** to `rand` and `srand`. The corpus accepts a
  properly seeded `random()`.
- **`environment-from-variable` withdrawn.** The defect is `putenv` of a *stack*
  variable and the corpus accepts a `static` one, but storage class is not
  information this analyzer gathers. Two known false positives were worse than a
  gap, so coverage drops from 34 classes to 33 and section 18.5 says so.

### 21.2 The gate still fails

Recall of 36.2% is far from the 90% bar. The 139 misses remain what section 19.1
described: each rule matches one shape where the upstream rule matches several.
That work is untouched and is the whole remaining distance.

Correcting section 18.5 downward rather than leaving it at 34 matters more than
the number: the table is the evidence phase 1d reads, and a table describing
intent rather than measured behavior is how a subsystem gets deleted on a
promise.

## 22. Decision: Ship Alongside, Do Not Replace

Taken 2026-08-21 after the phase 1c measurement.

The native analyzer ships enabled by default and runs during every C and C++
discovery. **Semgrep stays**, unchanged, as the explicitly requested deeper
enrichment operation. Nothing is deleted: `third_party/semgrep-rules`,
`third_party/semgrep`, the sandbox layer, and the three service modules all
remain.

### 22.1 Why

The replacement plan rested on the reconciliation table in section 18.5, which
recorded 33 of 49 upstream classes as covered. Measured against the upstream
corpus, those classes catch 42.7% of what their counterparts catch. Deleting
Semgrep would have traded a mature rule set for one that finds fewer than half
as many defects, and four widening rounds moved recall about two points each --
a rate that puts the 90% bar many sessions away, with part of it unreachable
without type information (section 18.4).

The premise that made replacement attractive was that owning the analysis means
removing the alternative. It does not. The costs the design set out to avoid --
a pinned foreign binary, a registry fetch, 9,865 lines of subprocess machinery --
are costs of Semgrep being *the only* analyzer, and they are unchanged by adding
a second one. What the native analyzer buys is real and independent of deletion:

- **C++ goes from zero coverage to 36 rules.** Semgrep's bundled rule set is
  C-only, so this is coverage that did not exist in any form before.
- **Every discovery gets a signal at no cost.** The analyzer reuses the parse
  `scan_c` already performs, so it needs no operator action, no sandbox, no
  subprocess, and no staleness model. Semgrep enrichment remains an explicit
  operation because it is an expensive one.
- **Zero false positives on the corpus.** A signal an operator can trust
  without checking is worth more than a broader one they cannot.

### 22.2 How the two coexist

They do not merge, and that is deliberate. Two overlays are produced at
different times from different evidence:

- **Native**: computed during `discover_analyzed`, from the same parse as the
  candidates, always current with the sources.
- **Semgrep**: computed by an explicit operation over a staged snapshot, and
  able to be stale relative to sources that moved under it.

Merging them would either double-count a defect both found or hide that both
found it, and the second is the more useful fact: agreement between two
independent analyzers is evidence about a target, not noise. Both overlays
leave `TargetCandidate.fit_score` untouched, so a consumer can always see the
base score and what each producer moved it to.

### 22.3 What this changes in the sections above

- **Section 1**: the goal is a second analyzer, not a replacement. The two-phase
  framing stands; "then Semgrep is deleted" does not.
- **Section 2**: the three superseded decisions from the Semgrep design remain
  superseded *for the native path only*. Semgrep keeps its opt-in operation, its
  all-or-nothing failure semantics, and its absence from ordinary discovery.
- **Section 13**: phase 1d is withdrawn. There is no deletion, no storage
  migration, and no removal of the `semgrep-enrichment` feature.
- **Section 20**: the gate stands as a measurement and no longer gates anything.
  Recall is now a quality target for the native analyzer rather than a
  precondition for deleting a subsystem.

### 22.4 What is still worth doing

Widening remains valuable, at a lower priority and without a deadline: every
rule added is signal oxfuzz did not have, and the corpus harness makes each
round measurable. The bar in section 20.2 is retained as a quality goal.

The one thing that should not be revisited without new evidence is deletion. If
some later phase reaches parity, that is when to reopen it -- with a
measurement, not a table of intent.
