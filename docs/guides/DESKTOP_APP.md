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

**Finding defects that do not crash.** A sanitizer finds memory faults. It does
not find a decoder that returns the wrong answer, a round trip that loses data,
or an invariant that quietly stops holding. The Oracle Studio lets you state such
a property and check it on every input.

Six kinds are available. Three are stateless: differential (the target and a
reference implementation must agree), round trip (decoding an encoded value must
reproduce it), and invariant (a predicate must hold after every call). Three go
further: metamorphic (transforming an input must relate its result to the
original's -- unchanged, not smaller, or not larger), stateful (a sequence of
operations derived from one input, checked after every step), and resource (a
measurement the target reports must not grow by more than an allowance across
one call, which catches leaks that return correct answers).

You name the functions and describe what the property means; oxfuzz shows the
exact harness that produces, which you review before building it through the
usual compile and run steps. Each kind expects a specific signature for the
functions it calls -- shown next to the fields -- and a mismatch fails the build
naming the symbol, rather than compiling into an oracle that tests nothing.

A metamorphic relation is chosen from a fixed set rather than typed, because an
expression would be code going straight into the harness. Stateful oracles need
a step ceiling and resource oracles a growth allowance; both are part of what you
review, and a stateful oracle without a ceiling would loop on a large input
instead of finding anything.

An oracle harness deliberately stops the process when the property is violated;
that is the signal. A resulting finding is identified as a violation of that
named property, and for the sequence and resource kinds it also records which
step failed or how much the measurement grew. A memory-safety crash in the same harness stays a memory-safety
finding, because only the recorded property marker makes it an oracle violation.

**Choosing between harnesses.** One draft is a sample of one. The compile step
offers a tournament: oxfuzz generates several candidates for the same target --
one deterministic template baseline plus independent model drafts -- compiles
each in the sandbox, and smoke-qualifies each that built. Every candidate's
evidence is kept, not just the winner's, so you can see what the selection beat:
whether it built, how many repair passes it needed, its compile diagnostics if it
failed, and its smoke verdict and throughput if it ran.

Ranking is deterministic and uses only what was observed -- built before not
built, then smoke verdict, then fewer repairs, then throughput. No model opinion
enters it, and throughput never outranks a better verdict, because a harness that
does nothing quickly is not better than one that does the right thing. A
tournament selects; it does not promote. Promotion stays the explicit step you
take after reviewing the winner.

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

**When coverage stops climbing.** "62% of lines" does not say what to do next.
The Corpus view offers a blocker exploration: it names the uncovered functions
that would unlock the most still-unreached code, shows how far each sits from
where the fuzzer actually got to, and gives the call path from that frontier to
the blocker. A blocker with no observed route from covered code is reported as
having none -- which is a different and more serious statement than "it is
nearby", and usually means the harness itself cannot get there.

It also proposes one concrete next experiment: grow the corpus when the fuzzer
reaches a caller but never takes the branch, or refine the harness when nothing
covered has a route at all. The proposal names the function to aim at and the
reason behind it. It is advisory and starts nothing; you run the existing refine
or corpus step yourself. If no coverage measurement exists yet, that is what it
says, rather than showing an empty blocker list.

**Review retained evidence.** The Artifacts view collects persisted crash
reproducers and corpus inputs across the selected project in one place. Reports,
run history, policy audit, and evidence export provide the wider audit trail.

![Artifacts -- crashes and corpus](../screenshots/artifacts.png)

**Automotive state sequences.** For a protocol whose defects depend on the order
of calls, the Automotive view's Stateful Lab shows which protocol states the
retained evidence actually reached and proposes an ordered plan for reaching what
it has not. The plan is advisory: you run its steps through the usual automotive
operations, and the lab itself opens no interface.

Two things are deliberate. Only virtual CAN and offline capture can be
sequenced -- the physical bench cannot, because each physical transmission
requires its own fresh approval and a sequence would turn one approval into many
transmissions. And the lab reports no coverage percentage unless you supply a
reviewed state model: retained evidence shows which states were reached but
cannot show how many exist, and treating the observed set as the total would
report every campaign as complete coverage of itself.


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
