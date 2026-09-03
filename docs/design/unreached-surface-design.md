# Unreached Surface

Status: **planned**. Owner: `hf-service`, joining `hf-discovery` ranking with
retained coverage across every run of a project.

## 1. Goal

`coverage-blocker-design.md` answers "what is the current harness failing to
reach?" -- uncovered functions with an observed call path from covered code.
That question presupposes a harness that already reaches nearby.

This subsystem answers the prior question: **which entry points has no harness
ever reached at all, and which one deserves the next harness?** A parser that no
run has ever touched does not appear in a blocker list, because a blocker list
is computed relative to what one harness covered.

It proposes. It writes no harness.

## 2. Feature and Ownership

Enabled by the `unreached-surface` feature in `hf-service`, which implies
`coverage-blockers` for the shared coverage cache access. Ranking lives in
`hf-service`; `hf-discovery`'s candidate ranking is consumed unchanged.

## 3. Evidence Sources

Three, all retained:

- `hf-discovery`'s ranked `TargetCandidate` list, including its semgrep
  enrichment and reachability annotations, **used as produced**;
- the union of covered function sets across every retained coverage measurement
  for the project, not just the latest run; and
- the harness and run history for the project: whether a harness was ever
  authored against a candidate, and how that harness ended.

The third source is the one fuzzctl structurally cannot consult. Its
`suspicious_points` re-ranks candidates against the latest coverage report and
has no memory: a function whose harness was attempted three times and failed to
compile every time ranks identically to one nobody has tried.

## 4. What Makes A Candidate Unreached

A candidate is unreached when its function does not appear in the union of
covered functions across every retained measurement for the project.

Absence from that union is a statement about what was measured, not about what
is reachable. Where the project has **no** completed coverage measurement at
all, the subsystem reports `Unavailable` with a reason code and returns **no
list**. A ranked list of "unreached" functions derived from zero measurements
would name every function in the project and would be fabrication presented as
analysis.

## 5. Attempt History

Each unreached candidate carries the retained history of harnesses authored
against it:

- **`NeverAttempted`** -- no harness names this candidate.
- **`AttemptedCompileFailed`** -- a harness was drafted and did not compile, with
  the attempt count.
- **`AttemptedSmokeFailed`** -- a harness compiled and failed smoke
  qualification.
- **`QualifiedYetUnreached`** -- a harness reached qualification, yet the
  function is absent from every coverage union. This is the most informative
  state in the subsystem: the harness runs and does not exercise what it was
  written for, so the next harness needs a different shape rather than a fix.

## 6. Ranking

Deterministic, in sequence:

1. `hf-discovery`'s existing candidate rank, preserved -- the discovery layer
   already weighs input-facing surface, semgrep findings, and complexity, and
   restating that judgment here would give one meaning two homes;
2. attempt history, in the section 5 order; then
3. function name, for stability.

Discovery rank leads because this subsystem adds exactly one fact discovery
cannot know -- that nothing has ever covered this -- and that fact is a filter,
not a re-ranking. A high-value parser whose one harness failed to compile is
still the better next target than an untried helper, because a compile failure
is usually cheap to fix and the value gap is not.

Attempt history is therefore reported for every candidate but only orders the
ties, which are real: candidates frequently share a discovery score. Within one
score, effort already spent is the sensible discriminator.

fuzzctl instead adds unexplained constants (`+26` for absence from a report,
`+18` for coverage under twenty per cent) directly onto the discovery score,
which overwrites the discovery judgment with arithmetic.

## 7. Rejected Alternatives

- **Re-scoring discovery candidates with coverage weights** -- overwrites a
  ranking built from richer evidence with an unexplained constant.
- **Using only the latest run's coverage** -- a candidate covered by a harness
  retired two runs ago would be reported as never reached.
- **Using the retained `reachable_functions` set** -- rejected in
  `coverage-blocker-design.md` section 3 for the same reason: a bounded set
  cannot establish absence.
- **Reporting a list when no measurement exists** -- see section 4.
- **Merging this into the blocker explorer** -- the two answer different
  questions against different evidence; one type with two meanings would be
  worse than two types.
- **Drafting the proposed harness** -- harness drafting has an approval path.

## 8. Verification Criteria

- A project with no completed coverage measurement yields `Unavailable` and an
  empty list.
- A function covered in any retained measurement never appears as unreached.
- Discovery's relative order is preserved among candidates with equal attempt
  history.
- `QualifiedYetUnreached` is reported when a qualified harness names the
  candidate and the function is absent from every coverage union.
- Attempt history changes the order only between candidates of equal discovery
  rank; it never reorders candidates whose discovery ranks differ.
- Ranking is total and stable.

## 9. Coverage Attribution

`coverage_attribution` is the sibling view over the whole inventory rather
than the uncovered subset: every discovered candidate, attributed against the
same union of retained coverage, ordered for the next harness.

The attribution set of a candidate is itself plus its retained
`reachable_functions`. `covered / total` over that set is the covered share,
and the tier names its shape: `untouched` (nothing covered), `partial` (the
frontier where coverage stalls), `saturated` (the whole attribution set
covered). Ordering is tier first -- untouched, then partial, then saturated --
with discovery's own order deciding inside each tier.

This is deliberately not the rejected re-scoring of section 7: no constant is
added to any discovery score, and discovery's relative order is preserved
within every tier. Coverage decides only which tier a candidate headlines in,
which is the one fact discovery cannot know. The practical effect is that a
target the retained measurements already saturate stops headlining the
next-harness list even when its static score is the highest in the project.

Two scope limits, stated rather than implied:

- `saturated` claims the *attribution set* is covered -- the candidate and its
  retained reachable functions -- not that the target has no more surface. The
  reachable set is bounded (section 7), so it cannot establish absence
  elsewhere; a code change or a wider reachability pass can reopen a
  saturated target, and the next measurement will.
- The no-measurement rule of section 4 applies unchanged: zero measurements
  yield `Unavailable` and no list, because attribution derived from nothing
  measured would be fabrication.

Evidence sources are those of section 3 (the same covered-function union,
gathered per project), so the two views can never disagree about what was
measured. Exposed as `oxfuzz attribution` beside `oxfuzz unreached`.
