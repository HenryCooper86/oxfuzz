## What and why

What does this change do, and what problem does it solve? Link the issue if
there is one (for example `Fixes #123`).

## How it was tested

The commands you ran and what they showed. Note anything you could not test
locally, such as Docker-backed or live-provider paths.

```text

```

## Checklist

- [ ] `cargo fmt --all` and
      `cargo clippy -p <crate> --all-targets -- -D warnings` pass for the
      crates I touched.
- [ ] Tests cover the change, and `cargo test -p <crate>` passes for each
      touched crate (or `npm --prefix crates/hf-gui test` for frontend changes).
- [ ] Business logic is in `hf-service`; CLI, REST, and desktop code only wire
      it up.
- [ ] Safety: generated harnesses, engines, and crash inputs still run only
      inside the `hf-runtime` sandbox, and this does not weaken human approval,
      guardrails, network blocking, or resource limits. If it touches any of
      these, I explained how above.
- [ ] Documentation is updated if user-visible behavior changed, with an entry
      under `Unreleased` in `CHANGELOG.md`.
- [ ] No secrets, API keys, runtime databases, corpora, crash artifacts, or
      private target material are included.
