# Corpus & Coverage Design

Status: **draft**. Owner: `hf-corpus` + `hf-coverage`.

## 1. Goal

Manage seed corpora, grow them during fuzzing, prune redundant entries, and
track coverage deltas to detect stagnation and trigger new harness proposals.

## 2. Corpus

```rust
pub struct Corpus {
    pub id: Uuid,
    pub target_id: Uuid,
    pub root: PathBuf,
    pub entries: Vec<CorpusEntry>,
}

pub struct CorpusEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source: CorpusSource, // Seed | Fuzzer | Minimized | Manual
    pub coverage_hash: Option<String>,
}
```

## 3. Operations

- **Seed** -- initialize from project-supplied seeds or LLM-suggested seeds.
- **Grow** -- pull new coverage-inducing inputs from engine output queue.
- **Prune** -- remove entries that no longer increase coverage.
- **Survive** -- measure seed survival: each corpus seed runs once through
  `afl-showmap` on the promoted AFL++ harness and is classified against the
  empty input's edge tuples. A seed covering at least one tuple the empty
  input does not reaches past the harness's entry validation (`survives`); a
  seed whose coverage never leaves that footprint dies at entry -- the most
  common reason a seed corpus finds nothing. Seeds that produce no map are
  `not_measured`, never guessed at. Read-only, gated on an explicitly promoted
  AFL++ harness like coverage pruning, and advisory: it tells the operator
  which seeds to regenerate, it does not delete or gate anything.
- **Regenerate** -- act on the survival metric: one bounded pass removes the
  generated seeds flagged `dies_at_entry`, requests that many replacements
  from the provider, writes them, and re-measures so the outcome reports how
  the replacements fared. Eligibility is the reserved generated-seed name
  namespace (`seed_`, `llmseed_`, `regen_` prefixes): a filesystem listing
  carries no durable source tag, and every other entry is an input a fuzzer
  or a human earned. Provider-only replacements (heuristic replacements for
  dead seeds would die the same way); one round per invocation, idempotent.
- **Merge** -- combine corpora across engines for the same target.
- **Snapshot** -- copy the retained flat corpus into an empty run-owned corpus
  before sandbox execution.
- **Merge snapshot** -- hash-deduplicate new run-owned inputs back into the
  retained corpus after execution.

### 3.1 Bounded filesystem contract

All payload reads are bounded before allocation. The default `CorpusLimits`
budget is 100,000 inspected directory entries, 16 MiB per input, and 512 MiB
of aggregate corpus data. Explicit-limit APIs may lower but never raise this
safety ceiling. Directory traversal is sorted by filename so that hashing,
collision naming, and returned entry order are deterministic.

`snapshot` and `merge_snapshot` are the service boundary for fuzz runs. They:

1. accept flat, real directories only;
2. fail closed if either input directory contains a symlink, directory,
   socket, or other non-regular entry;
3. complete bounded reads, hashes, deduplication, and combined-budget checks
   before writing any destination payload;
4. replace each destination through a fresh-inode atomic write; and
5. never overwrite different content that shares a filename.

`snapshot` requires an empty run-owned destination. `merge_snapshot` skips
content already retained by SHA-256, tags additions as `Fuzzer`, and reports
the number added. Generic `list`, `grow`, and `absorb` retain compatibility
with existing callers by ignoring static non-regular candidate entries, but
those entries still consume the traversal budget and are never followed.

Engine discoveries are normalized before the retained merge:

| Engine | Run-owned discovery source | Retention flow |
| --- | --- | --- |
| AFL++ | `out/queue` or `out/<instance>/queue` | `grow(run_corpus, run_out)`, then `merge_snapshot` |
| honggfuzz | top-level `--output` files | `grow(run_corpus, run_out)`, then `merge_snapshot` |
| libFuzzer | inputs added in place to `run_corpus` | `merge_snapshot` directly |

Crash artifacts and engine bookkeeping are excluded by `grow`; they remain in
the run-owned output tree for crash ingestion and evidence retention.

### 3.2 One canonical corpus per target, shared across engines

A target has exactly one retained corpus: `<workspace>/corpus`, where the
workspace is scoped per project and target but never per engine. Every engine
run for the target -- AFL++, honggfuzz, libFuzzer -- seeds from that single
root and feeds it, so findings compound across engines:

1. **Seed**: `hf-service` `snapshot`s the canonical root into the run-owned,
  disposable `runs/<run_id>/corpus` before sandbox execution. The canonical
  root itself is mounted read-only and is immutable while the engine runs.
2. **Grow + merge**: after the sandbox exits, engine discoveries are
  normalized (`grow` for AFL++/honggfuzz output; libFuzzer writes in place)
  and `merge_snapshot` hash-deduplicates the run snapshot back into the
  canonical root.
3. **Absorb**: crash reproducers surfaced by triage are `absorb`ed into the
  same canonical root, closing the run -> triage -> corpus loop for every
  engine.

Run state stays per-run: `runs/<run_id>/{corpus,out}` and the engine queue are
disposable evidence owned by that run id. Only the retained seed corpus is
shared. Persisted corpus rows reconcile exactly against the canonical survivor
set after every mutation (`replace_corpus_entries` with the exact `list`
output of the root).

**Transition**: there is none -- this layout predates the cross-engine
guarantee and no engine-scoped corpus location ever existed on disk, so no
legacy per-engine corpus needs reconciliation and nothing is destroyed. The
integration test `hf-service/tests/corpus_sharing.rs` pins the property: two
engines seed from one root, absorbed crash survivors from one engine's run
feed the next engine's run, pre-existing content is never lost, and persisted
rows match the survivor set.

### 3.3 Deterministic run seeds and replay

Reproducibility is a run property layered on top of the shared corpus: every
persisted run config records a `seed` (`u64`, derived deterministically from
the run id when not supplied), and `ServiceContainer::replay_run` re-executes
a run through the normal run path with that exact seed, persisting a new row
whose config links back via `replay_of`. Seed flags per engine are specified
in `docs/standards/ENGINE_ADAPTER_STANDARD.md` section 3.1. Replay pins the
RNG seed, not the corpus: the run still seeds from the canonical root's
current state, which may have grown since the original run. A replay is a new
execution, so the recorded engine and duration must still be admitted by the
current operator policy. The current sandbox resource limits apply to that new
execution; lowering a limit or disabling an engine cannot be bypassed through
historical run data.

Coverage-guided minimization is an execution workflow, not a direct corpus
filesystem operation. The service accepts only the exact promoted libFuzzer
harness revision, verifies its persisted smoke evidence, and requires the
high-risk execution guardrail before launch. It stages the qualified source,
binary, and a bounded corpus snapshot below a unique run directory. The
primary workspace and snapshot are mounted read-only; only the empty,
run-owned merge output is writable. Live and terminal budgets bound both trees.
Only a successfully completed `-merge=1` command may feed the output through
the bounded `minimize` API and exact database reconciliation. Qualification,
sandbox, timeout, output, or persistence failures leave the retained corpus
untouched and are returned to the caller.

Whole-directory transactions were rejected: they require platform-specific
directory exchange primitives and do not compose with a retained directory
that may be observed by the UI. Instead, all validation is front-loaded and
each accepted file is committed atomically.

## 4. Coverage

```rust
pub struct CoverageReport {
    pub run_id: Uuid,
    pub edges: u64,
    pub blocks: u64,
    pub delta_edges: i64,
    pub stagnation_secs: u64,
    pub new_edges_files: Vec<PathBuf>,
}
```

When `stagnation_secs` exceeds a threshold, `hf-service` may propose a new
harness variant or a custom mutator to the user. The proposal escalates as the
plateau drags on, counted in whole windows of the threshold: improving the
mutation inputs (seeds / dictionary / custom mutator) first, then regenerating
the harness, and finally recommending to stop spending on the target.

The feature-gated coverage-per-cost advisor extends this signal across a bounded
set of comparable completed campaigns. It uses explicit engine hourly rates,
attributable model spend, edge deltas, corpus additions, and crash deltas to
produce deterministic proposals. It never dispatches a run or promotes a
harness. The complete contract and safety boundary are defined in
`proof-carrying-campaign-intelligence.md`.

## 5. Tests

- Unit: prune removes a duplicate-coverage entry.
- Unit: stagnation flag triggers when delta_edges == 0 for N seconds.
- Integration: oversized payloads and excessive directory entries fail before
  a destination payload is written.
- Integration: snapshots reject symlinks and non-regular entries.
- Integration: listing and snapshot merging are deterministic and bounded.
