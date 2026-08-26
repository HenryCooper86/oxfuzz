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
- **`AttemptedCovered`** -- a harness reached qualification, yet the function is
  absent from every coverage union. This is the most informative state in the
  subsystem: the harness runs and does not exercise what it was written for.

## 6. Ranking

Deterministic, in sequence:

1. `hf-discovery`'s existing candidate rank, preserved -- the discovery layer
   already weighs input-facing surface, semgrep findings, and complexity, and
   restating that judgment here would give one meaning two homes;
2. attempt history, in the section 5 order, so a never-attempted candidate
   precedes one that has already consumed effort; then
3. function name, for stability.

Discovery rank leads because this subsystem adds exactly one fact discovery
cannot know -- that nothing has ever covered this -- and that fact is a filter,
not a re-ranking. fuzzctl instead adds unexplained constants (`+26` for absence
from a report, `+18` for coverage under twenty per cent) directly onto the
discovery score, which overwrites the discovery judgment with arithmetic.

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
- `AttemptedCovered` is reported when a qualified harness names the candidate
  and the function is absent from every coverage union.
- Ranking is total and stable.
