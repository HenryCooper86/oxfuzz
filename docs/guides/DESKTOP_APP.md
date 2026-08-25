# The Desktop App

[← Back to the README](../../README.md)

The desktop app (Tauri v2 + React 19) is the primary way to drive oxfuzz. It
links the `hf-service` core directly, so the AI Assistant, discovery, fuzzing,
and triage all run locally with the same sandboxing and guardrails as the CLI.

```bash
./scripts/build-app.sh        # builds target/release/bundle/macos/oxfuzz.app + .dmg
open target/release/bundle/macos/oxfuzz.app
```

On first launch a short setup wizard configures your LLM provider, checks the
sandbox, and points oxfuzz at your first project. After that the left
sidebar is your control panel. Pipeline surfaces cover the Dashboard, AI
Assistant, guided workflow, Discover, Harness, Run, Triage, and Corpus. Library
and operations surfaces add Projects, Artifacts, Reports, Run History, Policy
Audit, Agents, Skills, Knowledge, Automation, Automotive, DefectDojo, Help &
Docs, and Settings.

### A campaign, end to end

**0. Confirm readiness and the next operator action.** The Dashboard summarizes
sandbox and engine readiness, retained evidence, harness promotion state,
recent campaigns, and crash handoff. A blocked requirement stays visible
instead of being hidden behind a generic status.

**1. Discover the attack surface.** Point oxfuzz at a C/C++ project and it
scans for fuzzable functions, ranking them into a Target Inventory by fit score,
input surface, complexity, and reachability from entry points.

![Discover -- ranked Target Inventory](../screenshots/discover.png)

**2. Generate, qualify, and promote a harness.** Pick a target and the agent
drafts a harness, compiles it in the sandbox, runs bounded smoke qualification,
and prepares a seed corpus. You then review and explicitly promote that exact
revision before any full campaign can start. Regeneration invalidates the prior
promotion.

![Harness -- promoted revision and five-step sandbox qualification flow](../screenshots/harness.png)

**3. Run the fuzzer.** Launch an enabled engine against the promoted harness.
The Run view shows campaign limits and retained metrics -- executions/sec,
coverage edges, elapsed time, and findings -- with cooperative cancellation for
an active sandboxed run.

![Run -- approved target, bounded campaign configuration, and retained metrics](../screenshots/run.png)

**When the harness will not build.** A failed compile usually means oxfuzz does
not know the include directories, defines, and language standard the project's
own build uses. The compile step then offers Build Doctor: it reads the project
root, reports which build system it found and on what marker files, and says
whether a compile database can be generated here. If it can, the exact commands
are shown in full before anything happens; you approve them, and they run in the
sandbox, not on your machine. Running the plan creates an oxfuzz-owned
`.oxfuzz-build/` directory inside your project, which is part of what you are
approving.

Not every build system can be handled in the current sandbox image. Make and
Autotools need `bear` to observe a build, and Meson and Bazel need their own
tools; none of those are installed. In those cases Build Doctor names the
missing tool rather than offering a plan that would fail. A run whose commands
all succeed but produces no compile database is reported as a failure, because
the database is the evidence, not the exit code.

**4. Triage the crashes.** Crashes are ingested, deduplicated by stack
signature, minimized, and classified with CASR for severity and exploitability.
The agent can draft a report from retained evidence for human review, and the
result can be exported or handed off to DefectDojo.

![Triage -- deduplicated sanitizer crash and exploitability classification](../screenshots/triage.png)

**Prove a fix, do not assert one.** The selected finding carries a Patch to
Proof panel. Paste a candidate unified diff and a bounded follow-up fuzzing
duration, and oxfuzz persists an unverified draft. The draft shows the exact
scope approval will bind: the patch, minimized reproducer, harness, original
binary, sandbox image, and verification specification digests. Nothing is
built or executed until you approve that scope and confirm the run.

Verification then runs entirely in the sandbox, in five recorded stages:
original replay, patch and build, patched replay, regression corpus, and
bounded follow-up fuzzing. The result is `verified` only when all five stages
pass against the approved inputs; a reproduced crash after patching is
`rejected`, and missing or interrupted evidence is `inconclusive` with a named
reason rather than a silent pass. The outcome is persisted, so closing the
application does not lose it -- a run interrupted by a restart is reported as
inconclusive and can be attempted again. The finding's proof card reflects that
same service-owned result; a draft, a model response, or a clean patched replay
on its own never marks a finding fixed.

**Review a proposed change.** The Change Review view answers one question about
a pull request from retained evidence: does this change introduce a finding or
lose coverage that the base revision did not have? Give it a base and head
revision, or paste a unified diff, and it maps the change onto the discovered
targets. A target whose definition overlaps a changed line is reported as
changed; a target that only reaches the change through the call graph is
reported as approximate. Nothing is ever reported as unaffected, because the
retained call graph is bounded and syntactic.

Comparing two retained runs requires them to be genuinely comparable: same
target, engine, starting corpus, and sandbox image, with a differing source
revision. An incomparable pair is reported as such, naming the condition that
failed, rather than producing a coverage number that would not mean anything.
For a comparable pair oxfuzz reports which findings the head revision
introduced, which it carried over, and which it resolved, alongside the edge
coverage delta. Publishing the comparison to the configured issue tracker or
DefectDojo is a separate step that you approve explicitly; the comparison never
publishes itself.

**Review retained evidence.** The Artifacts view collects persisted crash
reproducers and corpus inputs across the selected project in one place. Reports,
run history, policy audit, and evidence export provide the wider audit trail.

![Artifacts -- crashes and corpus](../screenshots/artifacts.png)

### Talk to it instead

Everything above is also available conversationally. The **AI Assistant** uses
the same service tools for discovery, harnessing, running, and triage. It can
recommend and prepare work, but it cannot turn a draft into an approved full
campaign by itself. Guardrails, sandbox policy, and the human promotion record
remain authoritative.

### Settings

The Settings panel is the single source of truth for operator configuration:
LLM providers, enabled fuzzing engines, run defaults, sandboxed campaign limits,
storage cleanup, and external integrations. Mandatory sandboxing, blocked
fuzzer networking, and human promotion before full campaigns are displayed as
enforced guarantees rather than switches.

![Fuzzing settings -- engine availability, campaign limits, and mandatory protections](../screenshots/settings.png)

> The GUI also runs in the browser against the REST API for development:
> `cd crates/hf-gui && npm run dev:web` (talks to `oxfuzz serve` over HTTP).
