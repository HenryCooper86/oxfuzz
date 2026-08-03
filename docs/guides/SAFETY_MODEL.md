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
