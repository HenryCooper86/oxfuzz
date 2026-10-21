# Clang path-sensitive harness evidence

Status: implemented behind opt-in clang-analysis exploration. Owners: hf-service, hf-discovery, hf-harness.
Risk: High. Extends the delivered optional clang-analysis subsystem.

## Purpose and milestones

Preserve heuristic shortlisting, then replace guesses about selected C/C++
functions with located compiler and path-sensitive evidence. Continue in the
existing isolated worktree. This design is the implementer's choice under the
user's instruction to continue all milestones, and preserves the existing
source-review and human execution-approval rules.

- M2: compiler CFGs, branch conditions and precisely labeled parameter uses.
- M3: real LLVM 18 Static Analyzer exploration, parameter-origin flow through
  symbolic values, branch-state pruning, and bounded call witnesses.
- M4: evidence-backed harness plans, including input bindings, guard guidance,
  produced handles and accessible caller options. No name-based ownership guesses.
- M5: a reproducible baseline/enriched comparison prepared for the user's chosen
  model; collect actual results only through existing qualification approvals.

## Engine and evidence strength

The helper uses Clang CFG::buildCFG and a statically registered custom checker
through CreateAnalysisConsumer/AddCheckerRegistrationFn. It links the existing
image's clang-cpp/LLVM 18 libraries; the Rust process never links or runs LLVM.
Do not parse debug dumps or pretend AST traversal is symbolic execution.

CFG records identify their owning unit-qualified function, block IDs and
successors, located condition text and referenced parameter indices. References
in a condition are syntactic evidence, not proof of value flow. Constant-pruned
successors remain visibly absent; loops and other blocks remain represented.

The path checker seeds top-frame parameters using Clang's taint API with
parameter-specific tags, retaining their original symbolic values in ProgramState.
It records explicit calls visited by the symbolic engine, the root and current
caller, argument origins and concrete scalars, and ranges/nullness for the
original root inputs. Reassigning a parameter must not relabel its replacement
as the original input. A missing taint relation means unknown provenance unless
the value is a concrete scalar. It does not prove independence.

Branch observations retain the root, located condition, current input ranges,
and whether true/false assumptions produce a state. An impossible branch is
pruned under its full analyzer state. Retained min/max/nullness values are only
a projection: disjoint ranges, relations between inputs and other predicates
may be omitted, so those bounds alone do not explain every branch decision. A missing call witness always
means unknown, including when the graph contains a call below contradictory
guards. No project-wide unreachable or concrete executable-input claim follows.

Track symbolic return-value producers and subsequent argument use by symbol
identity, with located call evidence. A producer/use relation is not an
ownership-transfer, destruction, or mandatory initialization assertion. API
models absent from Clang remain unknown. Explicit same-unit inlining can appear
in witnesses; symbolic CTU, indirect target resolution, implicit constructor/
destructor completeness, arbitrary library models, SMT seed solving, and
whole-program infeasibility proofs are outside these bounded capabilities.
These are explicit unsupported categories, not silently successful analyses.

## Opt-in and budgets

Keep clang-analysis off by default. Add optional [clang_analysis.exploration]
configuration; absent retains the exact graph-only behavior and protocol.
When present, resolve and retain all choices before sandbox dispatch:

| setting | default | accepted range |
| --- | --- | --- |
| max_nodes | 10000 | 1..=1000000 |
| max_block_visits | 4 | 1..=64 |
| max_records | 256 | 1..=10000 |
| max_cfg_blocks | 2048 | 1..=100000 |
| max_inline_depth | 4 | 1..=16 |

Existing total deadline, memory, output bytes and snapshot limits still apply.
Node and block limits configure the actual analyzer. Record/CFG limits stop
collection at whole records and report omissions/exhaustion. Do not drop an
unsupported command argument to make analysis succeed. Root selectors carry
selected source spans/symbols from the persisted shortlist; overloads and build
variants remain separate. The analyzer may visit helper definitions but only
requested root evidence is published. Queries remain bounded by the operation's
outer sandbox limits even when LLVM schedules additional function analysis.

## Protocol and retention

Keep request/response version 1 for graph-only requests. Advanced request
version 2 carries exploration limits and exact root selectors. Response version
2 retains all version-1 graph fields and a required exploration envelope with:

- engine identity clang-static-analyzer-range-v1 and resolved limits;
- root function IDs, located CFGs and block/condition records;
- modeled call witnesses, argument origins, input ranges and producer relations;
- branch observations, exhaustion indicators and omitted-record counts.

IDs refer to the same normalized function table. Root selectors and limits
participate in the input fingerprint. Foreign JSON validation checks versions,
references, coordinates, indices, counts, and bounded strings. Version-1 durable
results remain readable as historical graph evidence. The decoder never
silently treats malformed advanced output as graph-only success.

Use existing immutable operation/result rows and model-context records; no
parallel persistence path or unlogged model input. Advanced compact sections
persist as renderer version 2; historical version-1 full JSON rows remain
readable. Changes in mode, limits,
source, invocation, selected roots or helper image invalidate current use.
Retain exact toolchain and helper/image identity. Existing cancellation,
ownership, recovery, project cleanup and knowledge cleanup apply unchanged.

## Harness planning and prompts

hf-discovery owns pure evidence slicing and planning. A selected root receives
bounded whole-record evidence only for its own exploration. Plans retain source
IDs/locations rather than free-form uncited claims. Exact duplicate call and
branch observations contribute no additional guidance: retain each once, while
preserving distinct retained constraints, outcomes, locations and callers.
Select branch alternatives before modeled calls and raw CFGs so repetitive
exploration cannot crowd all guard guidance out of a bounded context. Preserve
the helper's omission count, whose missing contents are unknown; context selection
adds excluded distinct records, not coalesced duplicate observations.

Guidance includes observed input bindings, guard conditions, return-value
producer/use relations and accessible caller paths. Do not infer pointer/length
pairing or object ownership from identifier names. Keep an unmodified fuzz-input
path; exercise evidenced guard cases as alternatives rather than reject inputs
that fail them. Include empty/truncated cases when valid for the API, and null
cases only when its declarations or usage establish that they are permitted.
Never replace every fuzzed input with fixed values or fabricate solved seeds.

hf-prompt labels CFG uses as syntax, ranges/flow/branch states as modeled
Static Analyzer evidence, and graph routes as potential calls. Advanced context
uses a deterministic prompt-local declaration table instead of repeating long
unit-qualified identities at every reference; each original identity remains
mapped once, and overloads/build variants remain separate. Graph-only rendering
is unchanged. Project strings remain escaped data. Unknown, unsupported and
exhausted categories are visible. The existing whole-section byte limit and
omitted counts include advanced records and plans. Persist the exact rendered
section before either draft mode calls a provider. Missing evidence preserves
ordinary drafting. Storage failures still stop analysis-bearing dispatch.

## Evaluation

Prepare a fixed, versioned C/C++ cohort with source digests, target IDs, shared
seeds/budgets, analysis mode, immutable images and exact provider/model identity.
Compare baseline without retained Clang evidence against advanced evidence in
separate databases/workspaces. The user chose BigModel GLM through its standard API, with at most twelve
draft/review calls. Credentials remain in an external private environment file;
no key is retained in a comparison packet or repository file. Cap the initial comparison
at twelve draft/review calls, with no repair rounds unless separately budgeted.

Use existing service-owned drafting, build/review, qualification and run APIs.
The evaluation wrapper only prepares/imports commands and summarizes retained
records. Generated source receives the existing independent LLM review and
human approval before execution. Preparation can finish before a model is
configured; actual measurements remain unavailable rather than synthetic.

Retain per-trial draft and review usage, analysis seconds, compile outcome,
observed target entry, downstream function/edge coverage, execution rate and
wall time separately. Missing counters remain unavailable, never zero. Refuse
comparisons with different source/model/budget/seed/image identities. Reports
state cohort size and distinguish transport fixtures from effectiveness data.

## Verification

Real LLVM container fixtures cover contradictory nested guards, feasible call
ranges, overwritten/derived inputs, pointer data flow, recursive/loop budgets,
producer-to-consumer values, overloads and invalid protocol/references. A
structurally present call below contradictory guards must have no modeled call
witness and must remain unknown at the whole-call level. The inner branch's
true assumption is explicitly pruned under its outer range.

Rust tests cover foreign JSON rejection, whole-record budgets, root isolation,
planner evidence references, v1 retention, freshness and exact pre-dispatch
persistence through both draft modes. Evaluation tests reject mixed identities,
unreviewed execution and invented missing metrics. Run repository quality gates
and real helper/service qualification before claiming a milestone complete.

Final verification completed on 2026-10-21: workspace formatting, fixing and
verifying all-target Clippy with default and disabled defaults, the optional
Clang feature and all 23 product feature selections, workspace compilation and
tests, feature behavior, strict private-item rustdoc, dependency policy,
coverage measurement, performance benchmark compilation/report tests, script
and translation checks, and frontend tests/build/lint all passed. Coverage on
Darwin is diagnostic; the Linux baseline was not evaluated on this host.
The final CLI also passed graph-only and exploration delivery against both
minimal Ubuntu and sandbox-derived LLVM images, with 17 extractor tests per
image. Independent implementation and comparison audits found no remaining
material issues.

## Primary references

The [initial real-model comparison](../acceptance/clang-effectiveness-2026-10-20.md)
records twelve standard BigModel calls and six human-approved sandbox trials.
All compiled and entered their targets; aggregate target-branch coverage did
not improve. This is measured integration evidence, not a general quality claim.

- LLVM 18 AnalysisConsumer.h: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/clang/include/clang/StaticAnalyzer/Frontend/AnalysisConsumer.h
- LLVM 18 Taint.h: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/clang/include/clang/StaticAnalyzer/Checkers/Taint.h
- LLVM 18 ConstraintManager.h: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/clang/include/clang/StaticAnalyzer/Core/PathSensitive/ConstraintManager.h
