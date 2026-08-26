# Run Closeout

Status: **planned**. Owner: `hf-service`, over the existing recovery write-ahead
log.

## 1. Goal

After a run ends, seven things should happen: triage, minimization, corpus
absorption, coverage measurement, blocker exploration, disposition derivation,
and a trust report. Each already exists and each is invoked separately. Nothing
chains them, so a finished run sits half-analyzed until someone remembers the
next command.

Closeout runs that chain once per run, records what each step did, and can be
resumed.

## 2. Feature and Ownership

Enabled by the `run-closeout` feature in `hf-service`, which implies
`triage-disposition`, `campaign-trust`, `unreached-surface`, and
`coverage-blockers`. Closeout composes existing service operations and
implements none of their logic itself.

## 3. Durability

Closeout is a durable operation on the existing `hf-service::recovery`
write-ahead log, not an in-process loop. Each step's terminal state is recorded
before the next begins.

This is what a resumable chain buys: a closeout interrupted after coverage
resumes at blocker exploration. fuzzctl's `post-cycle` holds its step list in
memory, so an interruption re-runs every step from the start, including the
expensive corpus replay that coverage measurement performs.

## 4. Step Outcomes

Three, all recorded:

- **`Completed`** -- with a reference to what the step produced.
- **`Skipped`** -- with a reason code. A run with no crashes skips minimization,
  and that is a correct outcome, not a failure.
- **`Failed`** -- with a `ClassifiedError`. A failed step does not abort the
  chain by default; steps that do not consume its output still run.

The distinction between `Skipped` and `Failed` is load-bearing. A closeout
reporting "minimization did not run" without saying whether there was nothing to
minimize or minimization broke is not worth reading.

## 5. Step Order

Fixed, by data dependency:

1. **triage** -- attributes origin and produces crash records.
2. **minimize** -- skipped when triage retained no crashes.
3. **corpus absorb** -- folds run inputs into the retained corpus.
4. **coverage** -- measures against the absorbed corpus, so it must follow it.
5. **blockers** -- consumes the coverage measurement.
6. **disposition** -- consumes triage output and any remediation records.
7. **trust report** -- consumes every prior step and is therefore last.

The trust report is last on purpose: it audits the closeout that produced it,
so a step that failed appears as an `Unavailable` gate rather than being
silently absent.

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
- Re-running a completed closeout is a no-op that reports the retained result.
