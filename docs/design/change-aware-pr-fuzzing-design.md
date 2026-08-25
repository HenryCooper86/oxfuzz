# Change-Aware Pull-Request Fuzzing

Status: **active implementation**. Owner: `hf-service`, with persisted targets
and runs in `hf-storage`, publication through the existing issue-tracker and
DefectDojo integrations, and rendering in `hf-gui`.

## 1. Goal

Answer one question about a proposed source change, from retained evidence
only: does this change introduce a finding or lose coverage that the base
revision did not have?

The subsystem maps a source diff to the discovered targets it affects, compares
retained base and head run evidence, and offers a human-approved publication of
the result. It does not check out revisions, stage sources, or start campaigns.
Execution remains on the existing approved `run_fuzzer` path, so this phase adds
no second execution route.

## 2. Feature and Ownership

The subsystem is enabled by the `change-aware` feature in `hf-service`, which
depends on `proof-carrying` for the evidence vocabulary it reuses. `hf-service`
owns diff parsing, affected-target mapping, comparability, finding
classification, and coverage regression. REST and Tauri serialize service
requests and views. React renders the comparison and collects the publication
approval; it never reclassifies a finding or recomputes a regression.

## 3. Diff Input

Two accepted inputs produce the same parsed value:

1. **Revision range** -- the service resolves `git diff --unified=0 <base>...<head>`
   in the project through the existing read-only `hf_runtime::scrubbed_command("git")`
   idiom already used to resolve the origin remote. Revision arguments are
   validated against a conservative grammar before they reach the command, and
   the command is never composed through a shell.
2. **Supplied diff** -- an operator or CI pipeline supplies unified-diff text
   directly, for contexts that have the patch but no checkout.

The parser accepts unified diffs only. It records, per changed file, the old and
new paths and the changed line ranges on the new side. Renames are recorded with
both paths. Binary files, mode-only changes, and deleted files are retained as
changed files with no line ranges, because a target cannot overlap a range that
does not exist. Bounded: a diff above the configured byte ceiling, an
unparseable hunk header, or a hunk whose line counts do not agree with its body
is rejected with a named reason rather than partially parsed. A partially
understood diff would under-report affected targets, which is the one failure
mode this subsystem must not have silently.

## 4. Affected-Target Mapping

Each discovered target for the project is classified against the parsed diff:

- **`changed`** -- the target's own definition overlaps a changed line range in
  the same file. Exact, from the persisted `SourceLocation` (`file`, `line`,
  `end_line`).
- **`reaches_change`** -- the target does not itself overlap, but a changed
  function name appears in the target's retained reachable set. Approximate.
- **`unknown`** -- neither holds, or the evidence needed to decide is missing:
  the target has no `end_line`, the project has no retained reachable sets, or
  the target's reachable set was truncated at its retention bound.

There is deliberately no `unaffected` value. The retained reachable set is
syntactic, bounded to 64 entries per target, and does not model function
pointers or virtual dispatch, so absence from it is not evidence of
unreachability. Reporting `unaffected` would convert missing analysis into a
safety claim, which the product position forbids.

Changed function names are resolved by intersecting changed line ranges with the
persisted definition ranges of all discovered functions in the project, not by
re-parsing source. The mapping therefore never reads the working tree.

## 5. Change-Aware Campaign Plan

From the mapping the service emits an ordered plan: the affected targets, their
classification, the reason each was selected, and the retained base run that
would serve as the comparison baseline for each. The plan is advisory input to
the existing approved run path. It starts nothing, and it carries no schedule,
budget, or approval of its own.

## 6. Base and Head Comparability

Two retained runs are comparable for a pull-request comparison when all hold:

- both are terminal `Done` campaign runs for the same target;
- their engines match;
- their starting corpus digests (`corpus_rev`) match;
- their sandbox image identities (`sandbox_rev`) match and are exact; and
- their source revisions (`source_rev`) differ.

The existing coverage-baseline rules require whole-context equality
(`context_rev`), which combines source, corpus, and sandbox. A pull-request
comparison changes the source by definition, so reusing that rule would make
every comparison incomparable. This subsystem therefore compares the components
rather than the combined digest, and requires the source component to differ.

Any unmet condition yields an explicit incomparable result naming the first
condition that failed. An incomparable pair never produces a coverage verdict or
a finding classification.

## 7. Finding Classification

Findings are compared by retained stack signature, the same identity triage
already uses for deduplication:

- **`introduced`** -- present in the head run, absent from the base run;
- **`carried_over`** -- present in both; and
- **`resolved`** -- present in the base run, absent from the head run.

A signature the base run could not have observed is not `introduced`. When the
base run retains no crash evidence at all, every head finding is `unknown`
rather than `introduced`, because an empty base is indistinguishable from an
unexamined one.

## 8. Coverage Regression

Coverage regression is the peak-edge delta between comparable runs, taken from
the retained `edges` of each run. A regression is reported when head peak edges
are below base peak edges by at least the configured percentage. A run missing
retained peak edges makes the coverage comparison unavailable, not zero.

## 9. Publication

A completed comparison may be published through the existing integrations:
issue-tracker creation with the established dedup marker, and DefectDojo import.
Publication is a separate, explicitly human-approved step guarded by a
`PublishChangeComparison` guardrail action. The comparison itself never
publishes, and a publication carries the retained run identities and evidence
references so a reader can reconstruct the claim.

## 10. Rejected Alternatives

- **Reusing `context_rev` equality for comparability** -- the source differs by
  definition in a pull request, so every comparison would be refused.
- **Reporting targets as `unaffected`** -- the reachable set is bounded and
  syntactic; absence from it is missing analysis, not proven unreachability.
- **Re-parsing the working tree to resolve changed functions** -- the comparison
  would then depend on mutable state instead of the retained discovery evidence
  the classification is attributed to.
- **Checking out revisions and driving both campaigns** -- a second execution
  and staging path with its own approval surface; the existing approved run path
  already produces the evidence this phase consumes.
- **Classifying findings by summary or crash kind** -- stack signature is the
  identity triage already dedupes on; anything looser would invent or hide
  introduced findings.
- **Publishing automatically on a regression** -- publication is outward-facing
  and stays human-approved.

## 11. Verification Criteria

- Malformed, oversized, and non-unified diffs are rejected with named reasons.
- Renames, binary files, deletions, and new files map to the documented values.
- A target overlapping a changed hunk is `changed`; a target reaching a changed
  function only through the call graph is `reaches_change`; missing or truncated
  evidence is `unknown`.
- Comparability requires matching engine, target, corpus, and sandbox with a
  differing source revision, and names the first failed condition otherwise.
- Introduced, carried-over, and resolved findings follow stack-signature
  identity, and an empty base run yields `unknown`.
- Coverage regression uses retained peak edges of comparable runs only, and is
  unavailable rather than zero when either is missing.
- Publication requires human approval and reuses existing dedup markers.
- No revision checkout, campaign, harness, or target binary executes on the host.
- Feature-disabled builds compile and hide the change-aware surface.
- Tests use retained fixtures and execute no fuzzer or generated harness.
