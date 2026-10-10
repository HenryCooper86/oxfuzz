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

### Opting out of the LLM review (offline operation)

The LLM triage step in point 3 is mandatory by default. An operator may
explicitly skip it -- per invocation with `oxfuzz harness --no-llm-review`, or
deployment-wide with `harness.allow_unreviewed_smoke = true` in `oxfuzz.toml`
-- so smoke qualification works offline or without a provider key. The bypass
is never silent or default: each one is persisted as a marked,
digest-bound review record (`verdict: "bypassed"`, `reviewer: "none"`) and a
guardrail policy-decision row, and the approval surface shows it as a bypass
rather than a review. The human promotion gate is unchanged, and a bypass
never overturns a persisted negative LLM verdict. Residual risk: without the
model review, only the 13-rule lexical lint and the human promoter's own
reading stand between generated harness code and the sandbox.

**Generated harnesses are never run on the host. Human approval authorizes a
sandboxed run of the exact promoted revision; it never weakens isolation.**

## How approval reaches the gate

The desktop app asks through an interactive dialog. The CLI asks on the
terminal when it has one: with stdin and stderr both TTYs, a high-risk action
prints one line naming the action and its detail and waits for `y` (this once),
`n` (deny), or `a` (always allow that action kind for the rest of the process;
never persisted). Empty, unrecognized, or missing input denies -- the prompt
fails closed, and every outcome is echoed to the transcript and persisted in
the policy audit trail.

Piped, CI, and other headless launches never prompt and never block on input:
the CLI (like `serve`, which always runs unattended) reads consent from the
environment instead (`.env.example` documents every variable):

- `HF_AUTO_APPROVE=1` -- with the default guardrail policy, approves the
  high-risk actions (harness compile, harness run, fuzzer launch) for an
  unattended process. It also approves without prompting on a terminal. Leave
  it unset until you have decided to trust the reviewed harness.
- `HF_GUARDRAILS=permissive` -- auto-approves every action with an audit
  trail. For trusted local loops only.
- `HF_USE_DOCKER=0` -- forces the non-executing stub runtime; every build and
  fuzz run then fails closed instead of leaving the sandbox. There is no
  configuration that runs a harness on the host.
