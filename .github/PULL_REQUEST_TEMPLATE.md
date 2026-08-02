<!--
GitHub twin of .gitlab/merge_request_templates/Default.md. Keep the two aligned:
the checklist tracks the AGENTS.md engineering and safety protocol, which is
mandatory for the whole repository. Read AGENTS.md before opening this PR.
-->

## Summary

Describe the user-visible outcome and the problem this pull request solves.

## Changes

- Describe the implementation changes here.

## Architecture and safety

- [ ] Business logic remains in `hf-service`; presentation layers remain thin.
- [ ] Generated harnesses, fuzzing engines, and crash parsing remain inside
      `hf-runtime`.
- [ ] Human promotion is still bound to the exact harness revision.
- [ ] Network, resource, workspace, and automotive policy boundaries are not
      weakened.
- [ ] Any design or public contract change includes the owning documentation.
- [ ] Not applicable; this change does not affect architecture or safety.

Explain any checked safety-sensitive change and link the relevant design:

## Verification

List the exact commands and results used to verify this change.

```text

```

- [ ] Tests were added before production code where behavior changed.
- [ ] Applicable Rust gates passed in the order required by `AGENTS.md`
      (`scripts/tests/gates.sh` runs them; CI runs the same gates).
- [ ] Applicable frontend tests, production build, bundle budget, and lint
      passed.
- [ ] No generated harness or fuzzer was executed on the host.

## Documentation and release impact

- [ ] README, guides, in-app Help, and screenshots are current or not affected.
- [ ] Configuration, migrations, compatibility, and known limitations are
      documented or not affected.
- [ ] Release artifacts are not included in the commit.
- [ ] Secrets, runtime databases, corpora, crash artifacts, and private target
      material are not included.

## Reviewer notes

Call out the highest-risk files, unresolved tradeoffs, and the best place to
start the review.
