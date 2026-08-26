# Campaign Trust Report

Status: **planned**. Owner: `hf-service`, over retained target, run, harness,
corpus, coverage, and crash state.

## 1. Goal

"The campaign ran for six hours" is not evidence that its output means anything.
A harness that never reached the parser, a corpus of one empty file, or a
coverage pipeline that never completed all produce a run that looks finished and
supports no conclusion.

This subsystem answers one question per target and run: **which claims about
this campaign are supported by retained evidence, and which are not?** It
produces a gate audit, one verdict per claim, and an overall determination that
names what may not yet be asserted.

## 2. Feature and Ownership

Enabled by the `campaign-trust` feature in `hf-service`, which implies
`triage-disposition`. `hf-service` owns the gates and the verdict. Presentation
layers render and never recompute.

## 3. Gates Are Grouped By The Claim They Support

fuzzctl groups its gates by subsystem (`core`, `campaign`, `coverage`,
`triage`, `advanced`), which tells a reader where a check lives rather than what
it establishes. This subsystem groups by claim, because the report exists to
qualify claims:

- **"A harness exercises the target."** Harness lint is clean of errors; a
  harness compiled; a smoke run qualified.
- **"The fuzzer had inputs to work from."** A corpus exists and is non-empty.
- **"The fuzzer ran."** A run record exists and reached a terminal state; the
  engine reported execution progress.
- **"Coverage was measured."** A coverage measurement exists for this
  harness-and-corpus signature.
- **"Coverage reached target code."** The measurement attributes covered lines
  to project sources rather than only to the generated harness.
- **"Crashes were triaged."** Every retained crash for the run carries an
  attributed origin and a disposition.
- **"The findings are worth reporting."** At least one crash reaches a
  disposition of `ReachabilityUnproven` or better.

## 4. Gate Verdicts

Four values, and the distinction between the last two is the point of the
design:

- **`Supported`** -- retained evidence establishes the claim.
- **`Refuted`** -- retained evidence establishes that the claim is false. A
  harness that failed to compile refutes "a harness exercises the target".
- **`Unsupported`** -- evidence exists and does not establish the claim. A
  coverage measurement that attributes nothing to project sources leaves
  "coverage reached target code" unsupported.
- **`Unavailable`** -- the measurement does not exist, with a reason code. No
  coverage run has completed, so nothing at all is known about coverage.

fuzzctl collapses the last two into `warn`, which makes "we looked and it is
bad" indistinguishable from "we never looked". Those demand different next
actions and the report must not merge them.

Every gate carries a `FindingEvidenceReference` list -- the same evidence
vocabulary the proof card uses, extended with the record kinds a campaign gate
cites (harness, corpus, coverage measurement). A gate with no evidence is
`Unavailable` by construction; it cannot be `Supported`.

## 5. Overall Determination

Evaluated in order, so the four are total and mutually exclusive:

1. **`Untrustworthy`** -- the gate for "a harness exercises the target" or for
   "the fuzzer ran" is `Refuted`. Nothing downstream means anything.
2. **`Unqualified`** -- no core gate is refuted, and at least one gate is
   `Unavailable`. The campaign may be fine; it has not been measured. This
   outranks a refutation elsewhere, because an unmeasured gate could itself be a
   refutation once measured.
3. **`Qualified`** -- nothing is `Unavailable`, and at least one gate is
   `Refuted` or `Unsupported`. Every such gate is named.
4. **`Trusted`** -- every gate is `Supported`.

The determination carries the list of claims the report does **not** license,
so a consumer exporting a SARIF or DefectDojo record can refuse to assert
coverage-informed completeness that no measurement supports.

## 6. Scope

Per target and per run. fuzzctl computes one blob per target against whatever
run it last found, which silently mixes evidence from different harnesses. A
trust report names the run it audits, and a target-level view is the ordered
list of its run reports, not a merge of them.

## 7. Rejected Alternatives

- **One global readiness blob per target** -- mixes evidence across harnesses
  and runs and cannot be cited.
- **Reusing `WorkbenchReadiness`** -- that is a dashboard next-action note for
  the whole workspace, not a per-run evidence audit; overloading it would give
  one type two meanings.
- **A percentage-ready figure** -- the same false precision rejected in
  `triage-disposition-design.md` section 8.
- **Fixed coverage thresholds as pass criteria** -- fuzzctl gates on
  `line >= 40 and function >= 50`. Those numbers suit one project shape and
  misjudge every other; the gate asserts that coverage reached target code at
  all, which is checkable without inventing a threshold.
- **Blocking a run on an untrustworthy report** -- the report qualifies claims;
  starting and stopping runs already has an approval path.

## 8. Verification Criteria

- A gate with no cited evidence is always `Unavailable`.
- A missing coverage measurement yields `Unavailable`, never `Unsupported`.
- A refuted harness gate forces `Untrustworthy` regardless of other gates.
- A report names the run it audits, and two runs of one target produce two
  reports.
- The unlicensed-claims list is non-empty whenever the determination is below
  `Trusted`.
