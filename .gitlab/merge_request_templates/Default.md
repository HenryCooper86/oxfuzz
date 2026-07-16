## Summary

Describe the user-visible outcome and the problem this merge request solves.

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
- [ ] Applicable Rust gates passed in the order required by `AGENTS.md`.
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
