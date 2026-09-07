# Run Closeout

Status: **active**. Owner: `hf-service`, over retained SQLite closeout records.

## 1. Goal

After a run ends, seven closeout decisions should be retained: triage,
minimization, corpus absorption, exact coverage availability, blocker evidence
availability, disposition derivation, and a trust report. The steps that can be
bound to the run compose existing service operations. Coverage and blocker
steps explicitly retain that evidence as unavailable until exact run-bound
source coverage exists.

Closeout runs that chain once per run, records what each step did, and can be
resumed.

## 2. Feature and Ownership

Enabled by the `run-closeout` feature in `hf-service`, which implies
`triage-disposition`, `campaign-trust`, `unreached-surface`, and
`coverage-blockers`. Closeout composes existing service operations and
implements none of their logic itself.

## 3. Durability

Closeout stores one outcome per `(run_id, step)` in the SQLite
`run_closeout_steps` table. This table is separate from the recovery operation
log. Each outcome is committed before the next step begins. A read operation
returns these rows without executing or resuming the chain.

The retained rows let an interrupted closeout resume at the first retryable
step without repeating successful triage, minimization, or corpus absorption.
Reading the chain never resumes it. The current coverage and blocker steps only
retain their exact-evidence limitation and never replay a corpus.

Rows written before exact run-bound coverage policy existed require a
conservative compatibility rule. A retained `Completed` outcome for coverage or
blockers is presented as unavailable because its evidence came from mutable
workspace state. Retained reads perform only that projection and never execute
work. An explicit resume invalidates any terminal trust result associated with
those legacy rows and records the exact unavailable outcomes used by current
closeout.

## 4. Step Outcomes

Four, all recorded:

- **`Completed`** -- with a reference to what the step produced.
- **`Skipped`** -- with a reason code. A run with no crashes skips minimization,
  and that is a correct outcome, not a failure.
- **`Failed`** -- with a `ClassifiedError`. A failed step does not abort the
  chain by default; steps that do not consume its output still run.
- **`Blocked`** -- with the failed dependency. It is nonterminal and is retried
  after that dependency succeeds. Legacy dependency-failure skip records decode
  to this value.

The distinction between `Skipped` and `Failed` is load-bearing. A closeout
reporting "minimization did not run" without saying whether there was nothing to
minimize or minimization broke is not worth reading.

## 5. Step Order

Fixed, by data dependency:

1. **triage** -- attributes origin and produces crash records.
2. **minimize** -- reports minimization already performed during triage and is
   skipped when triage retained no crashes; it does not run a second minimizer.
3. **corpus absorb** -- folds run inputs into the retained corpus.
4. **coverage** -- reports unavailable until exact run-bound source coverage is
   durably retained. Current-workspace coverage is never attributed to an old
   run.
5. **blockers** -- likewise reports unavailable without exact run-bound source
   coverage and directs the operator to current-workspace analysis.
6. **disposition** -- consumes triage output and any remediation records.
7. **trust report** -- consumes every prior step and is therefore last.

The trust report is last on purpose: it audits the closeout that produced it,
so a step that failed appears as an `Unavailable` gate rather than being
silently absent.

Only terminal campaign runs (`Done`, `Failed`, or `Cancelled`) are admitted.
Runs without a retained harness-backed target scope, including current
syzkaller records with no `FuzzRunConfig`, are read as unavailable with a
service-owned reason and cannot start closeout.
The retained target project must agree with the run project; a run cannot use a
harness or target owned by another project to start closeout.
An exclusive per-run file lease covers the complete closeout pass, including
calls from independent service containers. The closeout executor does not hold
a workspace lease because composed operations acquire their own workspace and
target leases.

## 6. Rejected Alternatives

- **An in-memory step loop** -- section 3.
- **Aborting the chain on the first failure** -- coverage failing should not
  prevent disposition derivation, which does not consume it.
- **Running closeout automatically at run end** -- closeout performs sandboxed
  work, and starting sandboxed work without an approval surface contradicts
  AGENTS.md 2.12. Closeout is offered when a run ends; it is invoked
  deliberately.
- **Adding new analysis inside closeout** -- closeout composes; any new analysis
  is its own subsystem with its own design.
- **A single combined result document** -- each step already persists its own
  output; a merged copy would be a second home for the same meaning.

## 7. Verification Criteria

- A closeout interrupted mid-chain resumes at the first non-terminal step.
- A run with no crashes records minimization as `Skipped` with a reason, not
  `Failed`.
- A failed step does not prevent later steps that do not consume its output.
- The trust report step observes the outcomes of the steps before it.
- Retrying a changed earlier outcome refreshes the trust report and releases
  retryable blocked dependents.
- Unknown retained step or outcome values fail as durable-data errors and never
  trigger work.
- Reading retained state and reading campaign trust invoke no runtime or
  provider operation.
- Legacy coverage and blocker completions are read as unavailable, and an
  explicit resume refreshes trust without replaying current-workspace evidence.
- Re-running a completed closeout is a no-op that reports the retained result.
