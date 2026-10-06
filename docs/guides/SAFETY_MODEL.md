# Safety Model

[← Back to the README](../../README.md)

Defense in depth, non-negotiable:

1. **Sandboxed build & run** -- every harness build, fuzzer invocation, and
   crash parse goes through Docker-backed `hf-runtime`; engine binaries and
   generated harnesses are treated as untrusted and never execute on the host.
2. **Middleware interception** -- `hf-guardrails` scores each action, enforces a
   permission policy, and detects agent loops.
3. **Human-approved execution** -- generated harnesses are reviewed by an LLM
   triage step *and* a human before running. Smoke evidence and approval are
   persisted against the exact active revision; regenerating invalidates the
   approval. Crash artifacts are parsed in the sandbox and never touch the host
   outside the workspace.

**Generated harnesses are never run on the host. Human approval authorizes a
sandboxed run of the exact promoted revision; it never weakens isolation.**

## How approval reaches the gate

The desktop app asks through an interactive dialog. The CLI and `serve`
processes read consent from the environment instead (`.env.example` documents
every variable):

- `HF_AUTO_APPROVE=1` -- with the default guardrail policy, approves the
  high-risk actions (harness compile, harness run, fuzzer launch) for an
  unattended process. Leave it unset until you have decided to trust the
  reviewed harness.
- `HF_GUARDRAILS=permissive` -- auto-approves every action with an audit
  trail. For trusted local loops only.
- `HF_USE_DOCKER=0` -- forces the non-executing stub runtime; every build and
  fuzz run then fails closed instead of leaving the sandbox. There is no
  configuration that runs a harness on the host.
