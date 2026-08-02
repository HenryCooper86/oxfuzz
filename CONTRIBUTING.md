# Contributing to oxfuzz

Thank you for helping improve oxfuzz. This repository treats generated
code, fuzzing engines, crash inputs, and external targets as untrusted. Read
`AGENTS.md` before opening a change; its engineering and safety protocol is
mandatory for the entire repository.

## Before you change code

1. Read `docs/design/DESIGN_OVERVIEW.md` and the detailed design for the
   subsystem you are changing.
2. Read `docs/standards/TEST_STRATEGY.md` and
   `docs/standards/ENGINEERING_STANDARDS.md`.
3. For delegation or autonomy changes, also read
   `docs/standards/AGENT_AUTONOMY.md`.
4. State the problem, scope, risk tier, success criteria, and rejected
   alternatives in the issue or merge request.
5. Add a failing test before production code, then implement the smallest
   coherent fix and refactor with the test green.

Business logic belongs in `hf-service`. The CLI, REST API, Tauri commands, and
React views should remain thin presentation/transport layers. Dependencies
point inward toward `hf-core`, and new subsystems require feature flags.

## Safety requirements

- Never execute a generated harness, engine binary, or crash parser on the
  host. Route builds and execution through `hf-runtime`.
- Preserve exact-revision human promotion before a full campaign.
- Do not weaken network blocking, resource limits, workspace boundaries, or
  guardrail interception.
- Do not use a physical automotive interface for routine development or tests.
- Keep API keys, target source, runtime databases, corpora, and crash artifacts
  out of commits and screenshots.
- Report security-sensitive findings through `SECURITY.md`, not a public issue.

## Quality gates

After Rust changes, run the mandatory gates in this order and fix every warning:

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --workspace -- -D warnings
cargo clippy --workspace -- -D warnings
cargo check --workspace
cargo doc --workspace --no-deps
```

Run Rust tests through the required output filter. The repository wrapper keeps
the command consistent:

```bash
./scripts/cargo-test-filtered.sh --workspace
```

For frontend changes:

```bash
npm --prefix crates/hf-gui ci
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run build
npm --prefix crates/hf-gui run lint
```

Use `./scripts/tests/gates.sh` for the full local gate set, or
`./scripts/tests/gates.sh <gate>` for one of `fmt`, `clippy`, `check`, `test`,
`doc`, `deny`, `script-tests`, `frontend-test`, `frontend-lint`.

The same gates run in CI, so a green local run predicts a green pipeline.
`.gitlab-ci.yml` is the merge gate on this remote; `.github/workflows/ci.yml`
runs the same gates on the public GitHub repository. Both invoke
`scripts/tests/gates.sh` by gate name rather than restating commands, so the
three cannot drift apart. See `docs/guides/CI.md` for the pipeline layout and
the one-time OrbStack GitLab runner setup.

## Documentation and screenshots

Update the top-level README, user guides, design documents, and standards when
behavior or a public contract changes. Follow
`docs/screenshots/README.md` when refreshing product images. Documentation must
describe current behavior without implying that AI output overrides deterministic
results, guardrails, or human approval.

## Commits and merge requests

- Keep one concern per change and write English commit messages.
- Explain user impact, architectural impact, safety impact, verification, and
  known limitations in the merge request.
- Link the relevant tests and retain evidence for release-sensitive changes.
- Do not merge with failing pipelines, unresolved high-risk review findings, or
  undocumented safety boundary changes.

See `docs/guides/RELEASE_CHECKLIST.md` before preparing a release artifact.
