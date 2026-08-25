# Coverage Blocker Explorer

Status: **active implementation**. Owner: `hf-service`, reusing the cached
`llvm-cov` export and the discovery call graph, with rendering in `hf-gui`.

## 1. Goal

When coverage plateaus, "62% of lines" says nothing about what to do next. This
subsystem names the uncovered functions that would unlock the most still-
unreached code, shows where the fuzzer actually got to relative to each, and
proposes one concrete next experiment.

It proposes only. Refining a harness and growing a corpus already have approved
paths, and the explorer does not add a second one.

## 2. Feature and Ownership

The subsystem is enabled by the `coverage-blockers` feature in `hf-service`.
`hf-service` owns blocker discovery, ranking, and experiment selection. REST and
Tauri serialize the service view. React renders it and never recomputes a rank
or an experiment.

## 3. Evidence Sources

Two, both already owned by the service:

- the per-signature cached `llvm-cov export`, which yields the covered function
  set and the uncovered regions with their `file:line` locations; and
- the discovery call graph (`caller -> direct project callees`), which supplies
  the edges a path needs.

The cache is keyed by a corpus-plus-harness signature and recomputes when either
changes, so a served measurement is current for the workspace it describes. What
must still be reported is whether a measurement exists at all: no harness built,
or a coverage pipeline that did not complete, yields an explicit unavailable
state with a reason code and **no blocker list**. A blocker list derived from no
measurement would be fabrication.

The retained per-target `reachable_functions` set is deliberately not used here.
It is a set, not a graph, and bounded to 64 entries, so it cannot produce a path
and cannot establish absence.

## 4. Blockers

A blocker is a function that appears in the uncovered regions and is not in the
covered set. Each carries:

- **unlocked reach** -- the number of still-uncovered project functions
  transitively reachable from it through the call graph, excluding itself. This
  is the leverage: how much closed-off code opens if the fuzzer gets here. The
  walk is cycle-safe.
- **frontier distance** -- the shortest number of call edges from any covered
  function to this one. This is how far the fuzzer stopped short. The walk is
  seeded with every covered function at once, so the distance is measured from
  the closest one rather than from an entry point.
- **nearest covered function** and **path** -- the covered function that distance
  was measured from, and the call path from it to the blocker. Because every
  covered function seeds the walk, no covered function ever appears inside the
  path after its first element.
- **location** -- the `file:line` of its first uncovered region, when llvm-cov
  recorded one.

A blocker with no path from any covered function reports distance, nearest
covered function, and path as unavailable. It is not distance zero and not an
empty path: the fuzzer has no observed route to it at all, which is a different
and more serious statement than "it is nearby".

Unlocked reach counts functions rather than summing cyclomatic complexity. The
scanner's per-function complexity map is not exposed on `TargetInventory`, and
inventing a complexity figure from what is exposed would be a number with no
evidence behind it.

## 5. Ranking

Deterministic, in sequence:

1. higher unlocked reach;
2. shorter frontier distance, with unavailable ranking after every known
   distance; then
3. function name, so equal evidence yields a stable order.

Leverage leads because the point is to find the blocker worth attacking, not the
nearest one. Distance breaks ties so that between two equally valuable blockers,
the cheaper one wins.

A consequence worth stating: anything on the path to a blocker also reaches it,
so it has at least that blocker's leverage plus one. Leverage-first ranking
therefore surfaces the shallowest uncovered function on a chain, which is also
the one an experiment can act on first.

## 6. Next Experiment

One typed proposal per target, from a fixed vocabulary:

- **`grow_corpus`** -- the top blocker has an observed path from covered code.
  The fuzzer reaches the caller but never takes the branch, which is an input
  problem. The proposal names the first function on that path the measurement
  shows as uncovered, which is the first thing an input actually has to reach.
  Because the walk is seeded with every covered function, that hop is never
  something the fuzzer already reaches.
- **`refine_harness`** -- the top blocker has no path from any covered function.
  No input to the current harness can get there, so the harness shape is the
  problem, not the corpus.
- **`no_experiment_available`** -- there is no coverage measurement, or nothing
  uncovered was found. Reported with a reason code rather than an empty
  suggestion.

The proposal carries a reason code and the function to aim at. It starts
nothing.

## 7. Rejected Alternatives

- **Ranking by uncovered region count alone** -- computable from the export
  without a call graph, but it says nothing about what reaching the function
  would unlock, which is the whole question.
- **Ranking by frontier distance first** -- produces quick wins and buries the
  one blocker that would open a subsystem.
- **Summing cyclomatic complexity for unlocked reach** -- the per-function
  complexity map is not exposed; deriving one would be a figure with no evidence
  behind it.
- **Using the retained `reachable_functions` set** -- a bounded set cannot
  produce a path, and absence from it does not establish unreachability.
- **Re-measuring coverage on every exploration** -- the pipeline is a sandbox
  build plus a corpus replay; the cache already invalidates on corpus or harness
  change.
- **Reporting a blocker list when no measurement exists** -- it would be
  fabrication presented as analysis.
- **Running the proposed experiment** -- refine and corpus growth already have
  approved paths; a second entrypoint would duplicate their approval surface.
- **Having an LLM author the experiment** -- model opinions stay advisory, and a
  deterministic proposal from observed evidence is reconstructable.

## 8. Verification Criteria

- Unlocked reach counts only still-uncovered transitively reachable functions
  and terminates on a cyclic call graph.
- Frontier distance is the shortest edge count from a covered function, and the
  path begins at that function.
- A blocker with no covered route reports distance, nearest, and path as
  unavailable.
- Ranking follows unlocked reach, then distance, then name; unavailable distance
  ranks last among equals.
- Distance is measured from the closest covered function, and the reported path
  starts there rather than at an entry point.
- `grow_corpus` names the first function on the path the measurement shows as
  uncovered.
- `refine_harness` is chosen exactly when the top blocker has no covered route.
- An absent measurement yields `no_experiment_available` and an empty blocker
  list.
- The explorer executes nothing.
- Feature-disabled builds compile and hide the surface.
