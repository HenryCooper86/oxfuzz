import{u as k,r as u,j as e,V as S,B as g,L as E,o as p,G as x,S as C,d as R,e as A,P as f}from"./index-DeaNy47A.js";import{M as D,r as j,c as T,a as I}from"./reportPreviewCode-fK0huJGw.js";const _=[{id:"start",title:"Getting Started"},{id:"pipeline",title:"The Fuzzing Pipeline"},{id:"library",title:"Library & Resources"},{id:"config",title:"Configuration"},{id:"reference",title:"Reference"}],P=`
# Welcome to hobot_fuzz

**hobot_fuzz is an AI-assisted fuzzing workbench.** You point it at a codebase
and it ranks candidate targets, drafts and qualifies test harnesses, runs real
fuzzing engines inside a mandatory sandbox, and retains evidence for the bugs
it finds. Human approval is bound to the exact harness revision allowed to
enter a full campaign.

## What is fuzzing?

Fuzzing throws millions of malformed and random inputs at a program as fast as
possible, watching for any that make it crash or misbehave. Each crash is a
potential bug, often a security vulnerability. It is one of the most effective
ways to find serious bugs -- and normally a lot of expert work. hobot_fuzz
coordinates that work with AI and deterministic tooling.

## The safety model (why this is safe to run)

Fuzzing runs untrusted, possibly-malformed code. hobot_fuzz uses defense in
depth so nothing dangerous happens without you:

- **Sandboxed execution.** Every harness build and fuzz run happens inside a
  Docker sandbox, never directly on your machine.
- **Human-in-the-loop (HITL) gates.** Generated harness source is reviewed by an
  LLM triage step *and* by you before it is promoted for full campaigns.
- **No generated host execution.** Generated harnesses and fuzzing engines
  never execute on the host. Approval authorizes the exact promoted revision
  for a bounded sandboxed campaign; it never weakens isolation.

## Who it is for

- **Developers** hardening their code who are not fuzzing experts.
- **Security teams** scaling up testing without hand-writing every harness.
- **Anyone curious** about what fuzzing finds in a codebase.

Continue to **First Run** to get set up, then **The Fuzzing Pipeline** to run
your first campaign. Every technical term is defined in the **Glossary**.
`,L=`
# First Run

The first time you open hobot_fuzz you get a short **Setup Wizard**. You can
re-run it any time from **Settings -> General -> Run Setup Wizard**.

## What you need

| You need | Why |
| --- | --- |
| **An AI provider key** | The AI writes the harness code and drafts bug reports. |
| **Docker** | Runs the sandbox that isolates untrusted code. Install OrbStack or Docker Desktop; the app can start Docker for you. |
| **A project to test** | A folder of C or C++ source works best today. |

You do **not** need to install fuzzing engines yourself -- they are bundled
inside the sandbox image.

## The setup wizard, step by step

1. **Welcome** -- an overview.
2. **Providers** -- paste your **API key**, set the **Model** (e.g. \`gpt-4o\`)
   and **Base URL**. This is the one required step: without a provider the AI
   cannot write harnesses or reports.
3. **Sandbox** -- confirms the mandatory Docker boundary and shows how to build
   the sandbox image.
4. **Guardrails** -- the human-approval gates for compiling harnesses and
   starting runs.
5. **Storage** -- where run data, corpora, and crashes live (informational).
6. **Complete** -- click **Get Started**.

You can add providers and tune enabled engines and bounded resource limits later
in **Settings**. Sandbox isolation, blocked networking, and human approval are
enforced guarantees rather than editable switches. On first launch the app also
builds the sandbox image, which can take a few minutes.

## Then what?

The bottom **Status Bar** shows green dots once Docker, the sandbox image, and
the fuzzing engines are ready. When they are, head to **The Fuzzing Pipeline**.
`,N=`
# The Fuzzing Pipeline

hobot_fuzz follows one connected flow. The **Progress** panel (top-right
**Progress** toggle) and the **Fuzzing Workflow** screen both track it, and it is
saved per project, so switching projects keeps each one's progress.

## The four core stages

1. **Discover targets** -- scan the project and rank the functions most worth
   fuzzing.
2. **Generate harness** -- five sub-steps: draft the harness, compile it in the
   sandbox, smoke-test it, **review & approve** it, then seed a starter corpus.
3. **Run fuzzer** -- drive a real engine against the target and watch live
   progress.
4. **Triage crashes** -- reproduce, classify by severity, deduplicate, and draft
   bug reports.

**Corpus** (seed / grow / prune) is an *ongoing* resource used throughout the
loop, not a final step.

## The happy path

1. **Open a project** (sidebar "Open project", or the Workflow project gate).
2. **Discover** -- click **Discover**; ranked targets appear.
3. **Harness** -- the top target is auto-selected. **Build & Smoke-Test** runs
   draft -> compile -> smoke -> seeds, then you **Approve for Campaigns**.
4. **Run** -- **Run Fuzzer** (needs a project, a target, and a harness that is
   both **built** and **approved**).
5. **Triage** -- runs automatically when a run finishes with crashes; otherwise
   click **Scan for Crashes**.

## Two ways to drive it

- **Fuzzing Workflow** screen -- the whole flow as one stacked accordion, no
  jumping between pages. Best when you want to click through each stage.
- **AI Assistant** (chat) -- tell the agent what you want in plain English
  ("discover targets and fuzz the riskiest one") and it drives the tools for
  you, asking approval at the gates.

Each stage also has its own dedicated sidebar screen if you prefer to work them
one at a time.
`,O=`
# Dashboard

**Purpose:** a per-project overview -- readiness, targets, harnesses, runs, and
crashes -- plus report authoring and issue hand-off. It is scoped to one active
project at a time; with no project selected it prompts you to choose one.

**Tabs** (navigate with Left/Right/Home/End arrow keys):

- **Overview** -- Operational Readiness score and blockers, a metric grid
  (Targets / Harnesses / Runs / Crashes / Corpus), an attention list, and review
  queues. The card headers deep-link to the full screens (Harness, Runs,
  Discover, Artifacts).
- **Reports** -- compose and save Markdown reports. **Generate** builds a draft
  from the latest campaign data; **Save draft** stores it; **Copy** copies the
  Markdown.
- **Repro** -- builds an exact \`hobot-fuzz regress\` command per crash to copy.
- **Review** -- queues of reports, harnesses, and crashes awaiting a human.
- **GitLab / GitHub** -- turn a crash into an issue draft, then **Copy** it or
  **File** it directly through the provider API (needs a repo + token in
  Settings -> Issue Tracker).
- **Health** -- engine readiness and DefectDojo status.

**Preconditions:** **Draft report** needs both an active project and a target.
Issue export needs a project so the Git remote can be resolved.
`,F=`
# AI Assistant (Chat)

**Purpose:** a conversational agent that can drive the whole fuzzing flow with
tool calls, with per-project history.

**What you can do:**

- **Send a message** -- the agent streams its tool activity ("Calling tool: ...")
  as it works. It can discover, generate harnesses, run fuzzers, triage, and
  manage the corpus for you.
- **Auto / Plan** mode -- Plan asks the agent to lay out a plan before acting.
- **Attach a project folder** so tools run in the right workspace.
- **Choose an agent** (default "orchestrator") and a **model**.
- **Undo last turn**, **Clear history**, **roll back to a turn**, and create
  **branches** of a conversation.
- **Approve / Deny** guardrail prompts inline when the agent hits an approval
  gate.

**Sending:** if "Send on Enter" is on (Settings), Enter sends and Shift+Enter is
a newline; if off, **Cmd/Ctrl+Enter** sends.

**Preconditions & gotchas:** conversations are per project. Without a configured
provider the assistant replies that it could not generate a response -- add one
in **Settings -> Providers**. Pick a project folder so the agent can run tools.
`,H=`
# Fuzzing Workflow

**Purpose:** the entire pipeline on one page. Pick a project, then work a
Discover -> Harness -> Run -> Triage accordion without leaving the screen.
Corpus sits below as an ongoing tool.

**What you can do:**

- **Choose Folder...** to set the project (or pick a recent one). Everything
  below the project gate is disabled until a project is chosen.
- Expand any stage to work it inline. The active stage auto-expands as the
  pipeline advances, and a stage that reports back (e.g. Run asking to
  regenerate a harness) expands the right section for you.

**What it shows:** a numbered status badge per stage (number / check / dash for
skipped) and a colored left border (accent = current, green = done).
`,M=`
# Discover (Target Discovery)

**Purpose:** scan a C/C++ project to find the functions most worth fuzzing,
ranked by a fit score.

**What you can do:**

- Pick the **language** (C or C++) and click **Discover** (it reads "Scanning..."
  while it works). Disabled until a project is set.
- Expand a candidate to see its **call tree**. Expanding fetches per-function
  coverage -- meaningful only after at least one run.

**What it shows:** "N candidates found", sorted by fit score. Each candidate
lists its symbol, kind, \`file:line\`, a plain-language rationale, fit score,
complexity, and a reachability badge ("reaches N ..."). The chosen language flows
into Harness.

**Note:** discovery today covers C and C++ (tree-sitter) plus a lexical Rust
scan. Harness generation additionally supports Rust via cargo-fuzz.
`,W=`
# Harness (Harness Generation)

**Purpose:** generate an LLM-authored harness for a target, compile and
smoke-test it in the sandbox, then explicitly **approve** it for campaigns.

**The five steps:**

1. **Generate** -- the AI writes the harness source (\`harness_draft\`).
2. **Compile** -- build it in the sandbox. Marks done only when it compiles.
3. **Run Smoke Test** -- a short fuzz run to confirm the harness actually
   exercises the target.
4. **Approve** -- **Approve for Campaigns** after a clean smoke test, or
   **Approve with Known Findings** if the smoke test itself crashed. This is the
   human gate: approval binds that exact source + engine + target.
5. **Generate Seeds** -- create a starter corpus.

**Build & Smoke-Test** (the primary button) runs steps 1-3 and seeds in one go,
but deliberately stops before approval so a human always reviews.

**Selectors:** Target (sorted by fit), Engine (libFuzzer / AFL++ / honggfuzz /
ClusterFuzzLite; Rust restricts to libFuzzer / ClusterFuzzLite), and Language
(C / C++ / Rust).

**Gotchas:** regenerating or recompiling a harness invalidates a prior approval
-- you must approve again, because the source the engine will run has changed. If
a harness was already built earlier, this screen hydrates it and shows an
"Existing harness" banner.
`,G=`
# Run (Fuzz Run)

**Purpose:** drive a fuzzing engine (or a Syzkaller kernel campaign) against the
target inside the sandbox and watch live progress.

**What you can do:**

- **Run Fuzzer** (or **Launch Campaign** for Syzkaller). Set the **engine**,
  **duration** (seconds), and target symbol.
- **Stop** a run in progress.
- If coverage stalls, the screen may offer **Regenerate harness** (jumps to
  Harness).

**Preconditions (important):** a normal run needs a target whose harness is
both **built** (a real on-disk check) **and approved** (promoted for the matching
engine). The target label tells you which: "(approved)", "(approval required)",
or "(not built)". Warnings link straight to the Harness screen to fix it. A
Syzkaller kernel campaign instead needs a project plus kernel artifacts (bzImage,
rootfs, SSH key, manager.cfg).

**Web mode:** harness-based user-space runs use the authenticated REST/SSE
transport, including exact-run progress, status, and cancellation. Syzkaller is
desktop-only because it launches local kernel/VM artifacts and may use KVM.

**What it shows:** live stat cards (edges covered, crashes, execs/sec), a
post-run summary, coverage-stall / auto-revert notices, and a streaming log.
`,U=`
# Triage (Crash Triage)

**Purpose:** ingest, classify, and deduplicate the crashes from the last run,
and compose a report.

**What you can do:**

- **Scan for Crashes** -- ingests crashes, runs CASR severity/exploitability
  analysis, and dedups them by stack signature.
- **Compose Report** -- generates a Markdown report and saves it as a draft.
- **Push to DefectDojo** -- appears when crashes exist and DefectDojo is
  configured.
- Export the report as Markdown, HTML, PDF, or DOCX (PDF/DOCX need \`pandoc\`).

**Gotchas:** triage needs a run to have happened. When a run finishes *with*
crashes, hobot_fuzz **auto-triages and auto-composes a report once** for you.
Syzkaller kernel runs are excluded here -- their crashes live in the Syzkaller
workdir -- so the button is disabled with an explanation.

**What it shows:** a crash list (kind, severity badge, filename) and a detail
panel with the CASR analysis, stack signature, and the drafted bug report.

**Reading a finding:** *Kind* is the error class (e.g. "Asan" = a memory bug
caught by AddressSanitizer). *Severity* rates danger -- "Exploitable" means an
attacker could likely abuse it. Each finding is a real, reproduced crash.
`,$=`
# Corpus (Corpus Management)

**Purpose:** seed, grow, prune, and inspect the collection of example inputs the
fuzzer mutates, for the selected target.

**What you can do** (all disabled until a target is selected):

- **Generate with AI** -- ask the LLM to synthesize seed inputs.
- **Seed** -- create a starter corpus.
- **Grow** -- expand the corpus.
- **Prune** -- minimize it (confirms first).
- **List** -- show the current entries.

**Gotchas:** the corpus is scoped to the selected target's workspace. With no
target it prompts you to pick one in Harness. A good starter corpus helps the
fuzzer find bugs faster.

**What it shows:** a table of File, SHA256 (truncated), Source, and Size.
`,B=`
# Projects

**Purpose:** manage the project folders you have scanned or fuzzed.

**What you can do:**

- **Add project** -- pick a folder, make it active, and jump to Discover.
- Per project: **Discover**, **Run**, remove from recents (the **X** -- local
  only, keeps your data), and **delete all data** (the trash icon -- destructive
  and irreversible; removes the DB records and the on-disk workspace).

**Gotcha:** the **X** only forgets the folder in the recents list; the **trash**
icon permanently deletes everything for that project.
`,K=`
# Artifacts

**Purpose:** browse crash reproducers and corpus inputs across all projects and
runs.

**What you can do:** filter, **Rescan**, **Export** (desktop only), **Clear all**,
and delete individual crashes or corpus entries. It auto-scans on open.

**What it shows:** a "Crashes" section and a "Corpus" section with counts. A
failed load shows a distinct error state, not an empty one.
`,V=`
# Reports (Composed Reports)

**Purpose:** the home for every composed report across projects and targets.

**What you can do:** filter reports, **Open** one to preview and export it
(Markdown / HTML / PDF / DOCX), **push** it to DefectDojo, or delete it.

**Where they come from:** Triage produces reports automatically when a run finds
crashes, and you can compose them by hand from the Dashboard.

**What it shows:** a list (title, status, target, updated time) and a preview
modal that renders Markdown tables and Mermaid diagrams.
`,q=`
# Run History

**Purpose:** every fuzz run for the active project, with trends and a two-run
comparison.

**What you can do:**

- Select up to two runs to **compare**.
- Per run: toggle its **coverage curve**, or delete it. **Clear all** wipes the
  history.
- **Auto-revert policy** -- when a new harness revision drops coverage past a
  threshold, hobot_fuzz can automatically revert (or just flag) it. Configure it
  **Global** (writes the main config) or **Per project** (an override), with a
  notify-only option. Harness-revision changes are marked on the trend charts,
  where you can diff and revert to an earlier revision.

**What it shows:** trend charts (coverage / throughput / crashes), comparison
cards, and per-run rows (engine, target, status, harness revision, edges, execs,
crashes, duration).

**Gotcha:** the regression comparison only fires between runs with comparable
conditions (same target, engine, duration, resources, sanitizer, corpus, and
environment).
`,X=`
# Policy Audit

**Purpose:** a durable timeline of every auto-revert policy decision, so an
automated revert is always explainable after the fact.

**What you can do:** scope to **This project** or **All projects** and review the
events.

**What it shows:** counts of reverted vs flagged, and per-event rows (project,
target, coverage drop %, from/to revision, timestamp).
`,Y=`
# Agents

**Purpose:** author the AI agents that drive the fuzzing runtime -- their role,
allowed tools, skills, and system prompt.

**What you can do:** create a **New agent**, or **Edit**, **Duplicate**, or
delete a custom one. The editor sets the name, id (a safe slug), description,
role, autonomy, system prompt, allowed-tools checkboxes, skills, model tags,
temperature, and max iterations.

**Gotcha:** built-in agents cannot be deleted, only **reset** to their shipped
definition.
`,J=`
# Skills

**Purpose:** reusable playbooks injected into an agent's context (for example,
target triage or harness authoring).

**What you can do:** create a **New skill**, or **Edit**, **Duplicate**, or
delete a custom one. A skill has a name (slug), version, description, domain
tags, and a Markdown body.

**Gotcha:** built-in skills reset rather than delete.
`,Z=`
# Knowledge

**Purpose:** what hobot_fuzz has learned (targets, runs, crashes) plus a
full-text (BM25) search over your project's code and documents.

**What you can do:**

- **Index project** to make it searchable, then **Search**.
- **Add document** to ingest a PDF, Office file, or HTML page (converted to
  text).
- **Clear** the knowledge base.

**Preconditions:** search and ingest need an active project, and search is
disabled until the project has been indexed. A configured database
(\`HF_DB_PATH\`, created by \`hobot-fuzz init\`) is required.
`,Q=`
# Automation

**Purpose:** schedule headless background fuzzing campaigns that rotate through a
project's targets on an interval, a cron schedule, or once.

**What you can do:** choose a project folder, pick a scope (all promoted targets
or a single target), a trigger (interval / cron / once), a per-run duration, and
a budget (max runs or minutes), then **Schedule** it. Pause, resume, or delete
campaigns, and set the max number that run concurrently.

**Preconditions (important):** only targets with a **promoted (approved)
harness** are schedulable. If a project has none, the form explains this and the
**Schedule** button stays disabled. Give the campaign an absolute project folder
-- it owns its path independently of the project you have open. Intervals must be
at least 10 seconds; cron needs five fields; "once" needs an RFC3339 timestamp.

**Heads-up:** when a scheduled campaign finds crashes, the app raises a toast
notification wherever you are.
`,ee=`
# Automotive Protocols

**Purpose:** analyze immutable automotive captures, inspect sidecar
capabilities, prepare deterministic mutations and typed replay plans, and
review retained operation evidence without weakening the normal sandbox and
approval boundaries.

**Default posture:** the subsystem is compile-time optional and disabled by
runtime policy until an operator configures it in **Settings -> Automotive**.
Protocol names describe the contract vocabulary; the pinned sidecar's validated
capabilities determine what the current build can actually decode or execute.

**Available workflows:**

- **Offline capture analysis** stages a digest-verified capture read-only and
  decodes it in a network-disabled sidecar sandbox. It never opens a vehicle
  interface.
- **Mutation and virtual replay** creates deterministic mutations and a typed
  plan. Execution is limited to a configured \`vcanN\` interface and still
  passes service policy, guardrails, sandbox checks, and confirmation.
- **Physical bench** is disabled by default and is not enabled from this
  workspace. Each operation requires an exact allowlist plus fresh,
  plan-scoped human approval after the plan and budgets are known.
- **Campaign synthesis and report** turns retained operations, failures,
  protocol states, result counts, safety posture, and evidence digests into a
  deterministic report. **Compose with AI** optionally appends a provider-neutral
  interpretation whose operation/state/transcript citations must match retained
  evidence. AI prose is advisory and cannot alter or authorize a replay plan.

Agents may propose analysis or replay plans, but cannot enable the feature,
choose an unlisted interface, manufacture approval evidence, or relax limits.
Capability inspection is evidence, not permission to send traffic. Default
tests and release checks never connect to a physical interface.

**What it shows:** policy state, offline analysis controls, adapter capability
evidence, virtual/physical readiness explanations, bounded mutation controls,
retained operation history, and report metrics for operations, failures,
unique states, and promoted state evidence. Every composed report is also saved
as a draft in **Reports**, where it can be reviewed and exported.
`,te=`
# DefectDojo

**Purpose:** DefectDojo is an open-source vulnerability-management platform.
hobot_fuzz can push triaged crashes to it as findings and embed its web UI right
inside the app.

**What you can do:** open it in-app (**DefectDojo** in the sidebar, shown once
configured), **Reload** it, **Open in browser**, or **Start** it when hobot_fuzz
manages the local instance.

**Preconditions:** desktop-only (the web build opens DefectDojo in your browser).
The instance takes about a minute to boot; the view shows a spinner until it is
ready. Configure it in **Settings -> Integrations**.
`,oe=`
# Settings

Settings is a full-window editor. Config-backed sections use validated forms;
**Fuzzing** and **Providers** also offer a lossless **FORM / RAW** TOML toggle.
One **Save Changes** button persists the active editable section.

**Sections:**

- **General** -- config/data directories, language, theme, font size, macOS
  window chrome, the sandbox **Architecture** (arm64 / amd64; changing it
  rebuilds the image), and **Run Setup Wizard**.
- **Providers** -- add and configure LLM providers (OpenAI, OpenAI-compatible,
  Anthropic, DeepSeek, Gemini, Ollama, Azure): model, base URL, API key, tags,
  cost, concurrency, context window, and **Test Connection**.
- **Fuzzing** -- enable production engines, choose the default, and set bounded
  duration, CPU, and memory limits. Mandatory sandboxing, blocked networking,
  and human approval are displayed as enforced protections.
- **Automotive** -- configure the separately sandboxed sidecar, protocols,
  modes, limits, and explicit physical-bench allowlists when that feature is
  available.
- **Storage** -- the service-resolved workspace path and a confirmed
  **Clear Workspace** operation.
- **Integrations** -- DefectDojo connection and **Test connection**.
- **Issue Tracker** -- GitHub/GitLab repo and token for filing issues, with
  **Test connection**.
- **About** -- version, license, and links.
`,ae=`
# Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| **Cmd/Ctrl + K** | Open the command palette (jump to any screen) |
| Arrow Up / Down, Enter, Esc | Navigate and choose inside the command palette |
| **Cmd/Ctrl + Enter** | Send a chat message (when "Send on Enter" is off) |
| Enter | Send a chat message (when "Send on Enter" is on; Shift+Enter is a newline) |
| Left / Right / Home / End | Move between Dashboard tabs |
| Enter | Run Discover / Knowledge search from their input fields |
| Enter / Esc | Confirm / cancel a dialog |
| Arrow keys / Home / End / Esc | Navigate dropdown menus |

The command palette (Cmd/Ctrl+K) is the fastest way around the app.
`,re=`
# Troubleshooting

Common messages and what they mean.

## Setup and sandbox

- **"Docker isn't running"** -- start Docker/OrbStack. The status bar tries to
  start it and build the sandbox image automatically.
- **"Fuzzing sandbox image not built"** -- the image is still building or failed;
  give it a few minutes on first launch.
- **"Syzkaller is not available in web mode"** -- kernel/VM campaigns require
  the trusted local desktop workflow; user-space fuzz runs remain available.

## Provider / AI

- **"No provider"** or **"Make sure a provider is configured in Settings"** --
  add an LLM provider and API key in **Settings -> Providers**, then **Test
  Connection**.

## Pipeline gating

- **"Select a project folder..."** -- open a project first (sidebar "Open
  project").
- **"The active harness binary is missing"** -- build the harness on the Harness
  screen.
- **"...has not been explicitly approved for full campaigns"** -- approve the
  harness (Harness -> Approve for Campaigns). Runs require a built **and**
  approved harness.
- **"...found no crashes -- nothing to triage"** -- the run was clean; there is
  nothing to triage (this stage is marked skipped).

## Automation

- **"This project has no promoted harness yet"** -- promote a harness first;
  only approved targets are schedulable.
- **"Interval must be ... >= 10", "Cron must have 5 fields", "Once must be an
  RFC3339 timestamp"** -- fix the trigger value.

## Knowledge

- **"No database configured (HF_DB_PATH). Run \`hobot-fuzz init\`"** -- initialize
  the config/database once from the CLI.

## Recovery

- **"N interrupted runs recovered"** -- a run was stopped by a crash or quit;
  your crashes and corpus on disk are intact. Dismiss the banner to clear it.
`,se=`
# Command-Line Equivalent

Everything the app does is also available as the \`hobot-fuzz\` CLI, over the same
service core. A full campaign:

\`\`\`bash
hobot-fuzz init                                              # one-time config/db setup
hobot-fuzz discover /path/to/project --lang c               # step 1
hobot-fuzz harness  /path/to/project --target parse_value --engine libfuzzer   # steps 2-3
hobot-fuzz run      /path/to/project --target parse_value --engine libfuzzer --duration 30m   # steps 4-5
hobot-fuzz triage   /path/to/project --target parse_value   # step 6
hobot-fuzz corpus   /path/to/project --target parse_value --op seed|grow|prune|list

# Optional automotive feature: report retained offline/virtual evidence.
hobot-fuzz automotive report /path/to/project --output automotive-report.html --format html
hobot-fuzz automotive report /path/to/project --ai
\`\`\`

There is also \`hobot-fuzz serve\` (REST + SSE API) and \`hobot-fuzz tui\` (a
terminal UI). See the project README for the full command reference.
`,ne=`
# Glossary

- **Fuzzing** -- automatically throwing huge numbers of malformed/random inputs
  at a program to find inputs that crash it.
- **Target** -- a specific function or entry point you want to fuzz, usually one
  that handles untrusted input (a parser, decoder, etc.).
- **Harness** -- the small piece of test code that feeds fuzz bytes into the
  target. hobot_fuzz writes this for you.
- **Fuzzing engine** -- the tool that generates inputs and runs the target
  millions of times: libFuzzer, AFL++, honggfuzz, plus ClusterFuzzLite and
  Syzkaller.
- **Corpus** -- the collection of example inputs the fuzzer keeps and mutates. A
  good starter ("seed") corpus speeds up bug-finding.
- **Coverage** -- how much of the program's code the fuzzer has exercised. More
  coverage means more behavior explored. "Edges" are coverage transitions.
- **Crash** -- an input that makes the program fail (segfault, abort, memory
  error). Each unique crash is a candidate bug.
- **Triage** -- sorting crashes: grouping duplicates, judging severity, and
  writing up each one.
- **Sanitizer / ASan** -- a debugging tool compiled into the target that detects
  subtle memory bugs (like buffer overflows) the moment they happen.
- **CASR** -- the analyzer hobot_fuzz uses to rate a crash's severity and
  exploitability and to cluster similar crashes.
- **Exploitable** -- a severity rating meaning an attacker could likely turn the
  crash into a real security compromise.
- **Stack signature** -- a fingerprint of a crash's call stack, used to dedup
  crashes that are really the same bug.
- **Sandbox** -- the isolated Docker environment where untrusted code is built
  and run so it cannot harm your machine.
- **Promote / Approve** -- the human step that marks a smoke-tested harness as
  trusted for full campaigns.
- **Smoke test** -- a short fuzz run that confirms a fresh harness actually
  exercises the target before a full campaign.
- **HITL (human-in-the-loop)** -- the principle that a person approves the
  risky actions instead of the AI doing them unsupervised.
- **LLM provider** -- the AI service (e.g. OpenAI) that powers the assistant; you
  supply an API key.
- **DefectDojo** -- an open-source platform for managing vulnerabilities;
  hobot_fuzz can push findings to it.
`,ie=[{id:"welcome",group:"start",title:"Welcome & Safety Model",keywords:"intro overview what is fuzzing safe sandbox hitl",body:P},{id:"first-run",group:"start",title:"First Run & Setup",keywords:"wizard provider api key docker install onboarding getting started",body:L},{id:"pipeline",group:"start",title:"The Pipeline & Happy Path",keywords:"flow stages order discover harness run triage corpus workflow",body:N},{id:"dashboard",group:"pipeline",title:"Dashboard",keywords:"workbench overview readiness reports repro review health metrics",body:O},{id:"chat",group:"pipeline",title:"AI Assistant (Chat)",keywords:"agent conversation tools plan auto branches rollback model",body:F},{id:"workflow",group:"pipeline",title:"Fuzzing Workflow",keywords:"accordion connected flow one page stages",body:H},{id:"discover",group:"pipeline",title:"Discover Targets",keywords:"scan candidates ranking fit score reachability call graph c cpp",body:M},{id:"harness",group:"pipeline",title:"Generate Harness",keywords:"draft compile smoke approve promote seeds engine language rust",body:W},{id:"run",group:"pipeline",title:"Run the Fuzzer",keywords:"campaign engine duration syzkaller kernel edges execs stop coverage",body:G},{id:"triage",group:"pipeline",title:"Triage Crashes",keywords:"casr severity dedup stack signature bug report defectdojo export",body:U},{id:"corpus",group:"pipeline",title:"Manage the Corpus",keywords:"seed grow prune minimize inputs ai generate",body:$},{id:"projects",group:"library",title:"Projects",keywords:"recent add delete remove folder workspace",body:B},{id:"artifacts",group:"library",title:"Artifacts",keywords:"crashes corpus inputs browse export clear",body:K},{id:"reports",group:"library",title:"Reports",keywords:"composed markdown html pdf docx export preview",body:V},{id:"runs",group:"library",title:"Run History",keywords:"trends compare coverage curve auto-revert regression harness revision",body:q},{id:"audit",group:"library",title:"Policy Audit",keywords:"auto-revert events timeline reverted flagged",body:X},{id:"agents",group:"library",title:"Agents",keywords:"roles tools skills system prompt autonomy custom built-in",body:Y},{id:"skills",group:"library",title:"Skills",keywords:"playbooks domain built-in custom root.md",body:J},{id:"knowledge",group:"library",title:"Knowledge",keywords:"bm25 search index ingest documents pdf learned",body:Z},{id:"automation",group:"library",title:"Automation",keywords:"schedule campaign cron interval headless promoted concurrency budget",body:Q},{id:"automotive",group:"library",title:"Automotive",keywords:"can uds pcap offline vcan replay sidecar physical bench policy evidence ai campaign report export state",body:ee},{id:"defectdojo",group:"library",title:"DefectDojo",keywords:"vulnerability management findings embed push integration",body:te},{id:"settings",group:"config",title:"Settings",keywords:"providers fuzzing automotive sandbox engines storage integrations issue tracker form raw toml",body:oe},{id:"shortcuts",group:"reference",title:"Keyboard Shortcuts",keywords:"hotkeys command palette cmd k ctrl",body:ae},{id:"troubleshooting",group:"reference",title:"Troubleshooting",keywords:"errors problems docker provider gating messages fix help",body:re},{id:"cli",group:"reference",title:"Command-Line Equivalent",keywords:"cli terminal hobot-fuzz commands serve tui",body:se},{id:"glossary",group:"reference",title:"Glossary",keywords:"definitions terms vocabulary meaning",body:ne}],de=[{id:"start",title:"快速开始"},{id:"pipeline",title:"模糊测试流水线"},{id:"library",title:"库与资源"},{id:"config",title:"配置"},{id:"reference",title:"参考"}],ce=`
# 欢迎使用 hobot_fuzz

**hobot_fuzz 是一个 AI 辅助的模糊测试工作台。** 你把它指向一个代码库，它会对候选
目标进行排名、起草并验证测试桩、在强制沙箱内运行真正的模糊测试引擎，并保留缺陷证据。
人工批准绑定到获准进入完整测试活动的确切测试桩修订版本。

## 什么是模糊测试？

模糊测试会尽可能快地向程序抛出数百万个畸形和随机输入，观察是否有任何输入使其崩溃或
行为异常。每个崩溃都是一个潜在的缺陷，往往是安全漏洞。它是发现严重缺陷最有效的方法之
一——通常还需要大量专家工作。hobot_fuzz 使用 AI 和确定性工具来协调这项工作。

## 安全模型（为什么运行它是安全的）

模糊测试会运行不受信任、可能畸形的代码。hobot_fuzz 采用纵深防御，确保没有你的参与
就不会发生任何危险的事情：

- **沙箱化执行。** 每次测试桩构建和模糊测试运行都发生在 Docker 沙箱内，绝不会直接在
  你的机器上进行。
- **人工介入(HITL)关卡。** 生成的测试桩源码会先由 LLM 分类定级步骤审查，*再*由你审
  查，之后才会被批准用于完整的测试活动。
- **不在主机上执行生成代码。** 生成的测试桩和模糊测试引擎绝不会在主机上执行。批准仅
  授权确切的已批准修订版本在受限沙箱中运行，绝不会削弱隔离边界。

## 它适合谁

- **开发者**——想加固自己的代码但并非模糊测试专家。
- **安全团队**——想扩大测试规模而无需手写每一个测试桩。
- **任何好奇者**——想了解模糊测试能在代码库中发现什么。

请继续阅读**首次运行**完成设置，然后阅读**模糊测试流水线**运行你的第一个测试活动。每
个技术术语都在**术语表**中有定义。
`,le=`
# 首次运行

第一次打开 hobot_fuzz 时，你会看到一个简短的**设置向导**。你可以随时从
**设置 -> 常规 -> 运行设置向导**重新运行它。

## 你需要什么

| 你需要 | 原因 |
| --- | --- |
| **一个 AI 提供方密钥** | AI 负责编写测试桩代码并起草缺陷报告。 |
| **Docker** | 运行隔离不受信任代码的沙箱。请安装 OrbStack 或 Docker Desktop；应用可以为你启动 Docker。 |
| **一个待测试的项目** | 目前一个 C 或 C++ 源码文件夹的效果最好。 |

你**无需**自己安装模糊测试引擎——它们已经打包在沙箱镜像中。

## 设置向导，逐步说明

1. **欢迎** —— 概述。
2. **提供方** —— 粘贴你的 **API 密钥**，设置**模型**（例如 \`gpt-4o\`）和 **Base URL**。
   这是唯一必需的步骤：没有提供方，AI 就无法编写测试桩或报告。
3. **沙箱** —— 确认强制使用的 Docker 隔离边界，并显示沙箱镜像的构建方式。
4. **安全护栏** —— 编译测试桩和启动运行的人工批准关卡。
5. **存储** —— 运行数据、语料库和崩溃的存放位置（仅供参考）。
6. **完成** —— 点击 **Get Started**。

你可以稍后在**设置**中添加提供方、调整启用的引擎和受限资源。沙箱隔离、网络阻断和人工批准
是不可关闭的安全保证，而不是可编辑开关。首次启动时，应用还会构建沙箱镜像，这可能需要几
分钟。

## 然后呢？

底部的**状态栏**会在 Docker、沙箱镜像和模糊测试引擎就绪后显示绿点。就绪之后，前往
**模糊测试流水线**。
`,ue=`
# 模糊测试流水线

hobot_fuzz 遵循一条连贯的流程。**进度**面板（右上角的**进度**开关）和**模糊测试工作
流**界面都会跟踪它，并且它是按项目保存的，因此切换项目时会保留各自的进度。

## 四个核心阶段

1. **发现目标** —— 扫描项目并对最值得模糊测试的函数进行排名。
2. **生成测试桩** —— 五个子步骤：起草测试桩、在沙箱中编译、冒烟测试、**审查并批准**，然
   后播种一个初始语料库。
3. **运行模糊测试** —— 用真实引擎针对目标运行，并观察实时进度。
4. **分类定级崩溃** —— 复现、按严重程度分类、去重并起草缺陷报告。

**语料库**（播种 / 扩充 / 精简）是贯穿整个循环使用的*持续性*资源，而非最后一步。

## 顺利流程

1. **打开一个项目**（侧边栏的"打开项目"，或工作流的项目入口）。
2. **发现** —— 点击**发现**；排名后的目标随即出现。
3. **测试桩** —— 自动选中排名最高的目标。**构建并冒烟测试**会依次运行
   起草 -> 编译 -> 冒烟 -> 种子，然后你**批准用于测试活动**。
4. **运行** —— **运行模糊测试**（需要一个项目、一个目标，以及一个既**已构建**又**已批准**
   的测试桩）。
5. **分类定级** —— 当运行结束且存在崩溃时自动运行；否则点击**扫描崩溃**。

## 两种驱动方式

- **模糊测试工作流**界面 —— 将整个流程呈现为一个堆叠式折叠面板，无需在页面间跳转。当你
  想逐阶段点击时最合适。
- **AI 助手**（聊天） —— 用自然语言告诉智能体你想要什么（"发现目标并模糊测试风险最高的
  那个"），它就会为你驱动各种工具，并在关卡处征求批准。

如果你更喜欢逐个处理，每个阶段也都有自己专属的侧边栏界面。
`,pe=`
# 仪表盘

**用途：** 按项目提供概览——就绪情况、目标、测试桩、运行和崩溃——以及报告撰写和问题移
交。它一次只作用于一个活动项目；未选择项目时，会提示你选择一个。

**标签页**（用 Left/Right/Home/End 方向键导航）：

- **概览** —— 运行就绪度评分和阻塞项、一个指标网格（目标 / 测试桩 / 运行 / 崩溃 /
  语料库）、一个关注列表以及审查队列。卡片标题可深度链接到完整界面（测试桩、运行、发现、
  构件）。
- **报告** —— 撰写并保存 Markdown 报告。**生成**会根据最新测试活动数据构建草稿；
  **保存草稿**会存储它；**复制**会复制该 Markdown。
- **复现** —— 为每个崩溃构建一条精确的 \`hobot-fuzz regress\` 命令供复制。
- **审查** —— 等待人工处理的报告、测试桩和崩溃队列。
- **GitLab / GitHub** —— 将崩溃变成问题草稿，然后**复制**它，或通过提供方 API 直接
  **提交**它（需要在 设置 -> 问题跟踪器 中配置仓库 + 令牌）。
- **健康** —— 引擎就绪情况和 DefectDojo 状态。

**前置条件：** **起草报告**同时需要一个活动项目和一个目标。问题导出需要一个项目，以便解
析 Git 远程仓库。
`,he=`
# AI 助手（聊天）

**用途：** 一个对话式智能体，可以通过工具调用驱动整个模糊测试流程，并按项目保存历史
记录。

**你可以做什么：**

- **发送消息** —— 智能体在工作时会实时输出其工具活动（"正在调用工具：..."）。它可以为你
  发现、生成测试桩、运行模糊测试、分类定级并管理语料库。
- **Auto / Plan 模式** —— Plan 会要求智能体在行动前先制定计划。
- **附加一个项目文件夹**，使工具在正确的工作区中运行。
- **选择一个智能体**（默认为"orchestrator"）和一个**模型**。
- **撤销上一轮**、**清除历史**、**回退到某一轮**，以及创建对话的**分支**。
- 当智能体触及批准关卡时，就地**批准 / 拒绝**安全护栏提示。

**发送：** 如果"回车发送"已开启（设置），回车发送、Shift+Enter 换行；如果关闭，则用
**Cmd/Ctrl+Enter** 发送。

**前置条件与注意事项：** 对话是按项目保存的。如果没有配置提供方，助手会回复它无法生成
响应——请在**设置 -> 提供方**中添加一个。选择一个项目文件夹，智能体才能运行工具。
`,ge=`
# 模糊测试工作流

**用途：** 将整个流水线放在一个页面上。选择一个项目，然后在不离开界面的情况下操作
发现 -> 测试桩 -> 运行 -> 分类定级 的折叠面板。语料库作为持续性工具位于下方。

**你可以做什么：**

- **选择文件夹...** 来设置项目（或选择最近使用的一个）。在选择项目之前，项目入口下方的
  一切都处于禁用状态。
- 展开任意阶段以就地操作。随着流水线推进，当前阶段会自动展开；某个阶段有反馈时（例如运
  行请求重新生成测试桩），会为你展开相应的部分。

**它显示什么：** 每个阶段一个带编号的状态徽章（数字 / 对勾 / 表示跳过的横线）以及一个彩
色左边框（强调色 = 当前，绿色 = 完成）。
`,fe=`
# 发现（目标发现）

**用途：** 扫描一个 C/C++ 项目，找出最值得模糊测试的函数，并按契合度评分排名。

**你可以做什么：**

- 选择**语言**（C 或 C++）并点击**发现**（工作时会显示"正在扫描..."）。在设置项目之前处
  于禁用状态。
- 展开一个候选项以查看其**调用树**。展开会获取每个函数的覆盖率——只有在至少运行过一次之
  后才有意义。

**它显示什么：** "找到 N 个候选项"，按契合度评分排序。每个候选项列出其符号、类别、
\`file:line\`、一段通俗易懂的理由、契合度评分、复杂度，以及一个可达性徽章（"可达 N ..."）。
所选语言会流转到测试桩阶段。

**注意：** 目前的发现覆盖 C 和 C++（tree-sitter）以及一个基于词法的 Rust 扫描。测试桩
生成另外通过 cargo-fuzz 支持 Rust。
`,me=`
# 测试桩（测试桩生成）

**用途：** 为目标生成一个由 LLM 编写的测试桩，在沙箱中编译并冒烟测试，然后明确地
**批准**它用于测试活动。

**五个步骤：**

1. **生成** —— AI 编写测试桩源码（\`harness_draft\`）。
2. **编译** —— 在沙箱中构建它。只有编译成功才标记为完成。
3. **运行冒烟测试** —— 一次简短的模糊测试运行，用以确认测试桩确实触及了目标。
4. **批准** —— 冒烟测试干净后点击**批准用于测试活动**，或者如果冒烟测试本身崩溃，则点击
   **带已知发现批准**。这是人工关卡：批准会绑定那份确切的 源码 + 引擎 + 目标。
5. **生成种子** —— 创建一个初始语料库。

**构建并冒烟测试**（主按钮）会一次性运行步骤 1-3 并播种，但会刻意在批准之前停下，以确保
始终有人工审查。

**选择器：** 目标（按契合度排序）、引擎（libFuzzer / AFL++ / honggfuzz /
ClusterFuzzLite；Rust 仅限 libFuzzer / ClusterFuzzLite）以及语言（C / C++ / Rust）。

**注意事项：** 重新生成或重新编译测试桩会使先前的批准失效——你必须重新批准，因为引擎将要
运行的源码已经改变。如果某个测试桩此前已经构建过，本界面会将其加载进来并显示一个
"已有测试桩"横幅。
`,be=`
# 运行（模糊测试运行）

**用途：** 在沙箱中用一个模糊测试引擎（或一个 Syzkaller 内核测试活动）针对目标运行，并
观察实时进度。

**你可以做什么：**

- **运行模糊测试**（Syzkaller 则为**启动测试活动**）。设置**引擎**、**时长**（秒）和目标
  符号。
- **停止**正在进行的运行。
- 如果覆盖率停滞，界面可能会提供**重新生成测试桩**（跳转到测试桩界面）。

**前置条件（重要）：** 一次普通运行需要一个目标，其测试桩既**已构建**（一次真实的磁盘检
查）**又已批准**（已针对匹配的引擎批准）。目标标签会告诉你是哪种情况："（已批准）"、
"（需要批准）"或"（未构建）"。警告会直接链接到测试桩界面以便修复。而一次 Syzkaller 内核
测试活动则需要一个项目外加内核构件（bzImage、rootfs、SSH 密钥、manager.cfg）。

**Web 模式：** 基于测试桩的用户态运行通过带身份验证的 REST/SSE 传输，并支持按运行追踪进
度、状态和取消。Syzkaller 需要启动本地内核/虚拟机构件并可能使用 KVM，因此仅限桌面版。

**它显示什么：** 实时统计卡片（已覆盖边、崩溃、每秒执行数）、运行后摘要、覆盖率停滞 /
自动回退提示，以及一段流式日志。
`,ye=`
# 分类定级（崩溃分类定级）

**用途：** 摄取、分类并去重上一次运行产生的崩溃，并撰写报告。

**你可以做什么：**

- **扫描崩溃** —— 摄取崩溃，运行 CASR 严重程度/可利用性分析，并按堆栈签名去重。
- **撰写报告** —— 生成一份 Markdown 报告并保存为草稿。
- **推送到 DefectDojo** —— 当存在崩溃且已配置 DefectDojo 时出现。
- 将报告导出为 Markdown、HTML、PDF 或 DOCX（PDF/DOCX 需要 \`pandoc\`）。

**注意事项：** 分类定级需要曾经发生过一次运行。当一次运行结束*且存在*崩溃时，hobot_fuzz
会为你**自动分类定级并自动撰写一次报告**。此处不包含 Syzkaller 内核运行——它们的崩溃位于
Syzkaller 工作目录中——因此该按钮会被禁用并附带说明。

**它显示什么：** 一个崩溃列表（类别、严重程度徽章、文件名）以及一个详情面板，包含 CASR
分析、堆栈签名和起草的缺陷报告。

**如何理解一条发现：** *类别*是错误类别（例如"Asan" = 由 AddressSanitizer 捕获的内存缺
陷）。*严重程度*评估危险性——"可利用"意味着攻击者很可能滥用它。每条发现都是一个真实、已复
现的崩溃。
`,ve=`
# 语料库（语料库管理）

**用途：** 为所选目标播种、扩充、精简并检视模糊测试所变异的示例输入集合。

**你可以做什么**（在选择目标之前全部禁用）：

- **用 AI 生成** —— 请求 LLM 合成种子输入。
- **播种** —— 创建一个初始语料库。
- **扩充** —— 扩大语料库。
- **精简** —— 将其最小化（会先确认）。
- **列出** —— 显示当前条目。

**注意事项：** 语料库的作用范围限定在所选目标的工作区。没有目标时，会提示你在测试桩界面
中选择一个。一个好的初始语料库能帮助模糊测试更快地发现缺陷。

**它显示什么：** 一个包含 文件、SHA256（截断）、来源和大小 的表格。
`,ze=`
# 项目

**用途：** 管理你已经扫描或模糊测试过的项目文件夹。

**你可以做什么：**

- **添加项目** —— 选择一个文件夹，将其设为活动项目，并跳转到发现。
- 每个项目：**发现**、**运行**、从最近列表中移除（**X**——仅本地，保留你的数据），以及
  **删除所有数据**（垃圾桶图标——具有破坏性且不可逆；会移除数据库记录和磁盘上的工作区）。

**注意事项：** **X** 只会在最近列表中忘记该文件夹；**垃圾桶**图标则会永久删除该项目的所有
内容。
`,we=`
# 构件

**用途：** 浏览所有项目和运行中的崩溃复现样本和语料库输入。

**你可以做什么：** 筛选、**重新扫描**、**导出**（仅限桌面版）、**清除全部**，以及删除单个
崩溃或语料库条目。它会在打开时自动扫描。

**它显示什么：** 一个带计数的"崩溃"区块和一个"语料库"区块。加载失败会显示一个明确的错误
状态，而非空状态。
`,ke=`
# 报告（已撰写报告）

**用途：** 所有项目和目标中每一份已撰写报告的归处。

**你可以做什么：** 筛选报告、**打开**一份以预览并导出（Markdown / HTML / PDF / DOCX）、
将其**推送**到 DefectDojo，或删除它。

**它们从何而来：** 当一次运行发现崩溃时，分类定级会自动生成报告；你也可以从仪表盘手动撰
写它们。

**它显示什么：** 一个列表（标题、状态、目标、更新时间）以及一个预览弹窗，可渲染 Markdown
表格和 Mermaid 图表。
`,Se=`
# 运行历史

**用途：** 活动项目的每一次模糊测试运行，附带趋势和两次运行的对比。

**你可以做什么：**

- 选择最多两次运行进行**对比**。
- 每次运行：切换其**覆盖率曲线**，或删除它。**清除全部**会清空历史。
- **自动回退策略** —— 当一个新的测试桩修订版本使覆盖率下降超过某个阈值时，hobot_fuzz 可
  以自动回退（或仅标记）它。你可以将其配置为**全局**（写入主配置）或**按项目**（一个覆盖
  项），并可选择仅通知模式。测试桩修订版本的变更会标注在趋势图上，你可以在那里进行差异对
  比并回退到较早的修订版本。

**它显示什么：** 趋势图（覆盖率 / 吞吐量 / 崩溃）、对比卡片，以及每次运行的行（引擎、目
标、状态、测试桩修订版本、边、执行数、崩溃、时长）。

**注意事项：** 回归对比只会在条件可比的运行之间触发（相同的目标、引擎、时长、资源、
sanitizer、语料库和环境）。
`,Ee=`
# 策略审计

**用途：** 每一项自动回退策略决策的持久化时间线，以便任何一次自动回退在事后都能被解释清
楚。

**你可以做什么：** 将范围限定为**本项目**或**所有项目**，并查看这些事件。

**它显示什么：** 已回退与已标记的计数，以及每个事件的行（项目、目标、覆盖率下降百分比、
从/到修订版本、时间戳）。
`,xe=`
# 智能体

**用途：** 编写驱动模糊测试运行时的 AI 智能体——它们的角色、允许使用的工具、技能和系统提
示词。

**你可以做什么：** 创建一个**新建智能体**，或**编辑**、**复制**、删除一个自定义智能体。编
辑器可设置名称、id（一个安全的 slug）、描述、角色、自主性、系统提示词、允许工具的复选框、
技能、模型标签、温度和最大迭代次数。

**注意事项：** 内置智能体无法删除，只能**重置**为其出厂定义。
`,Ce=`
# 技能

**用途：** 注入到智能体上下文中的可复用操作手册（例如目标分类定级或测试桩编写）。

**你可以做什么：** 创建一个**新建技能**，或**编辑**、**复制**、删除一个自定义技能。一个技
能包含名称（slug）、版本、描述、领域标签和一个 Markdown 正文。

**注意事项：** 内置技能只能重置，无法删除。
`,Re=`
# 知识库

**用途：** hobot_fuzz 已学到的内容（目标、运行、崩溃），外加对你项目代码和文档的全文
（BM25）搜索。

**你可以做什么：**

- **索引项目**使其可搜索，然后**搜索**。
- **添加文档**以摄取 PDF、Office 文件或 HTML 页面（会转换为文本）。
- **清除**知识库。

**前置条件：** 搜索和摄取需要一个活动项目，且在项目建立索引之前搜索处于禁用状态。需要一
个已配置的数据库（\`HF_DB_PATH\`，由 \`hobot-fuzz init\` 创建）。
`,Ae=`
# 自动化

**用途：** 调度无头后台模糊测试活动，按间隔、cron 计划或单次，在项目的各个目标之间轮换。

**你可以做什么：** 选择一个项目文件夹，挑选一个范围（所有已批准的目标或单个目标）、一个触
发器（间隔 / cron / 单次）、每次运行的时长以及一个预算（最大运行次数或分钟数），然后
**调度**它。可暂停、恢复或删除测试活动，并设置并发运行的最大数量。

**前置条件（重要）：** 只有拥有**已批准（promoted）测试桩**的目标才可调度。如果某个项目一
个都没有，表单会对此进行说明，且**调度**按钮保持禁用。请为测试活动指定一个绝对项目文件夹
——它独立于你当前打开的项目而拥有自己的路径。间隔至少为 10 秒；cron 需要五个字段；"单次"
需要一个 RFC3339 时间戳。

**提示：** 当一个已调度的测试活动发现崩溃时，无论你在哪里，应用都会弹出一个消息提示。
`,De=`
# 汽车协议

**用途：** 分析不可变的汽车协议捕获文件、检查 sidecar 能力、准备确定性变异和类型化回放
计划，并查看保留的操作证据，同时保持现有沙箱和批准边界不变。

**默认状态：** 该子系统是编译时可选功能，并且在操作员通过**设置 -> 汽车协议**进行配置
之前由运行时策略禁用。协议名称只表示契约词汇；当前构建实际能够解码或执行的内容以固定
版本 sidecar 经验证的能力为准。

**可用工作流：**

- **离线捕获分析**以只读方式暂存经过摘要校验的捕获文件，并在禁用网络的 sidecar 沙箱中
  解码。它绝不会打开车辆接口。
- **变异和虚拟回放**生成确定性变异和类型化计划。执行仅限已配置的 \`vcanN\` 接口，并且
  仍需通过服务策略、安全护栏、沙箱检查和确认。
- **物理台架**默认禁用，也不能从此工作区直接启用。每次操作都需要精确允许列表，并且必须
  在计划和预算确定后获得新的、绑定到该计划的人工批准。
- **活动汇总与报告**将保留的操作、失败、协议状态、结果计数、安全策略和证据摘要整理为
  确定性报告。**使用 AI 生成**可选择追加与提供方无关的解读，其中的操作、状态和记录引用
  必须与保留证据一致。AI 文本仅供参考，不能更改或授权回放计划。

智能体可以提出分析或回放计划，但不能启用该功能、选择未列入允许列表的接口、伪造批准证据
或放宽限额。能力检查是证据，不是发送流量的许可。默认测试和发布检查绝不会连接物理接口。

**它显示什么：** 策略状态、离线分析控件、适配器能力证据、虚拟/物理就绪说明、受限变异
控件、保留的操作历史，以及操作数、失败数、唯一状态数和已提升状态证据等报告指标。每份
生成的报告也会保存为**报告**中的草稿，供审查和导出。
`,je=`
# DefectDojo

**用途：** DefectDojo 是一个开源的漏洞管理平台。hobot_fuzz 可以将分类定级后的崩溃作为发
现推送给它，并将其 Web 界面直接嵌入到应用内。

**你可以做什么：** 在应用内打开它（侧边栏中的 **DefectDojo**，配置后显示）、**重新加载**
它、**在浏览器中打开**，或者在 hobot_fuzz 管理本地实例时**启动**它。

**前置条件：** 仅限桌面版（Web 版本会在你的浏览器中打开 DefectDojo）。该实例启动大约需要
一分钟；在其就绪之前，视图会显示一个加载指示器。请在**设置 -> 集成**中配置它。
`,Te=`
# 设置

设置是一个全窗口编辑器。由配置支撑的部分使用经过验证的表单；**模糊测试**和**提供方**还提
供无损的 **FORM / RAW** TOML 切换。一个**保存更改**按钮用于持久化当前可编辑部分。

**各部分：**

- **常规** —— 配置/数据目录、语言、主题、字体大小、macOS 窗口边框样式、沙箱**架构**
  （arm64 / amd64；更改它会重建镜像），以及**运行设置向导**。
- **提供方** —— 添加和配置 LLM 提供方（OpenAI、OpenAI 兼容、Anthropic、DeepSeek、
  Gemini、Ollama、Azure）：模型、Base URL、API 密钥、标签、成本、并发数、上下文窗口，以
  及**测试连接**。
- **模糊测试** —— 启用生产引擎、选择默认引擎，并设置受限时长、CPU 和内存。强制沙箱、网络
  阻断和人工批准以不可关闭的保护项显示。
- **汽车协议** —— 在该功能可用时，配置单独沙箱化的 sidecar、协议、模式、限额和显式物理台
  架允许列表。
- **存储** —— 服务解析出的工作区路径和需要确认的**清除工作区**操作。
- **集成** —— DefectDojo 连接以及**测试连接**。
- **问题跟踪器** —— 用于提交问题的 GitHub/GitLab 仓库和令牌，以及**测试连接**。
- **关于** —— 版本、许可证和链接。
`,Ie=`
# 键盘快捷键

| 快捷键 | 操作 |
| --- | --- |
| **Cmd/Ctrl + K** | 打开命令面板（跳转到任意界面） |
| Arrow Up / Down、Enter、Esc | 在命令面板内导航和选择 |
| **Cmd/Ctrl + Enter** | 发送聊天消息（当"回车发送"关闭时） |
| Enter | 发送聊天消息（当"回车发送"开启时；Shift+Enter 换行） |
| Left / Right / Home / End | 在仪表盘标签页之间移动 |
| Enter | 从输入框运行发现 / 知识库搜索 |
| Enter / Esc | 确认 / 取消对话框 |
| Arrow keys / Home / End / Esc | 导航下拉菜单 |

命令面板（Cmd/Ctrl+K）是在应用中穿梭最快的方式。
`,_e=`
# 疑难解答

常见消息及其含义。

## 设置与沙箱

- **"Docker isn't running"（Docker 未运行）** —— 启动 Docker/OrbStack。状态栏会尝试自
  动启动它并构建沙箱镜像。
- **"Fuzzing sandbox image not built"（模糊测试沙箱镜像未构建）** —— 镜像仍在构建或构建
  失败；首次启动时请给它几分钟。
- **"Syzkaller is not available in web mode"（Web 模式下无法使用 Syzkaller）** —— 内核/
  虚拟机活动需要可信的本地桌面工作流；用户态模糊测试仍可在浏览器中运行。

## 提供方 / AI

- **"No provider"（无提供方）** 或 **"Make sure a provider is configured in Settings"
  （请确保在设置中配置了提供方）** —— 在**设置 -> 提供方**中添加一个 LLM 提供方和 API 密
  钥，然后**测试连接**。

## 流水线关卡

- **"Select a project folder..."（请选择一个项目文件夹...）** —— 先打开一个项目（侧边栏
  的"打开项目"）。
- **"The active harness binary is missing"（活动测试桩二进制文件缺失）** —— 在测试桩界面
  构建测试桩。
- **"...has not been explicitly approved for full campaigns"（...尚未被明确批准用于完整
  测试活动）** —— 批准该测试桩（测试桩 -> 批准用于测试活动）。运行需要一个既已构建**又**已
  批准的测试桩。
- **"...found no crashes -- nothing to triage"（...未发现崩溃——无需分类定级）** —— 本次
  运行是干净的；没有可分类定级的内容（此阶段被标记为跳过）。

## 自动化

- **"This project has no promoted harness yet"（此项目尚无已批准的测试桩）** —— 先批准一
  个测试桩；只有已批准的目标才可调度。
- **"Interval must be ... >= 10"、"Cron must have 5 fields"、"Once must be an RFC3339
  timestamp"** —— 修正触发器的值（间隔必须 >= 10、Cron 必须有 5 个字段、单次必须是
  RFC3339 时间戳）。

## 知识库

- **"No database configured (HF_DB_PATH). Run \`hobot-fuzz init\`"（未配置数据库
  (HF_DB_PATH)。请运行 \`hobot-fuzz init\`）** —— 从 CLI 一次性初始化配置/数据库。

## 恢复

- **"N interrupted runs recovered"（已恢复 N 次被中断的运行）** —— 某次运行被崩溃或退出所
  中断；你磁盘上的崩溃和语料库完好无损。关闭该横幅即可清除它。
`,Pe=`
# 命令行等价物

应用所做的一切也都能通过 \`hobot-fuzz\` CLI 完成，两者共用同一个服务核心。一个完整的测试
活动：

\`\`\`bash
hobot-fuzz init                                              # 一次性配置/数据库设置
hobot-fuzz discover /path/to/project --lang c               # 第 1 步
hobot-fuzz harness  /path/to/project --target parse_value --engine libfuzzer   # 第 2-3 步
hobot-fuzz run      /path/to/project --target parse_value --engine libfuzzer --duration 30m   # 第 4-5 步
hobot-fuzz triage   /path/to/project --target parse_value   # 第 6 步
hobot-fuzz corpus   /path/to/project --target parse_value --op seed|grow|prune|list

# 可选汽车协议功能：报告保留的离线/虚拟证据。
hobot-fuzz automotive report /path/to/project --output automotive-report.html --format html
hobot-fuzz automotive report /path/to/project --ai
\`\`\`

此外还有 \`hobot-fuzz serve\`（REST + SSE API）和 \`hobot-fuzz tui\`（终端 UI）。完整的命
令参考请参见项目 README。
`,Le=`
# 术语表

- **Fuzzing（模糊测试）** —— 自动向程序抛出海量畸形/随机输入，以找到使其崩溃的输入。
- **Target（目标）** —— 你想模糊测试的一个特定函数或入口点，通常是处理不受信任输入的那种
  （解析器、解码器等）。
- **Harness（测试桩）** —— 将模糊测试字节喂给目标的那一小段测试代码。hobot_fuzz 会为你编
  写它。
- **Fuzzing engine（模糊测试引擎）** —— 生成输入并将目标运行数百万次的工具：libFuzzer、
  AFL++、honggfuzz，外加 ClusterFuzzLite 和 Syzkaller。
- **Corpus（语料库）** —— 模糊测试保留并变异的示例输入集合。一个好的初始（"种子"）语料库
  能加快缺陷发现。
- **Coverage（覆盖率）** —— 模糊测试已触及了程序代码的多少。覆盖率越高，探索到的行为越多。
  "边（Edges）"是覆盖率的跳转转移。
- **Crash（崩溃）** —— 使程序失败的输入（段错误、abort、内存错误）。每个唯一的崩溃都是一
  个候选缺陷。
- **Triage（分类定级）** —— 对崩溃进行梳理：归并重复项、判断严重程度，并逐一写清楚。
- **Sanitizer / ASan（插桩检测器）** —— 编译进目标的一种调试工具，能在细微内存缺陷（如缓
  冲区溢出）发生的那一刻就检测到它们。
- **CASR** —— hobot_fuzz 用来评估崩溃严重程度和可利用性并对相似崩溃进行聚类的分析器。
- **Exploitable（可利用）** —— 一种严重程度评级，意味着攻击者很可能将该崩溃转化为真正的
  安全攻破。
- **Stack signature（堆栈签名）** —— 崩溃调用栈的指纹，用于去重实际上属于同一缺陷的崩溃。
- **Sandbox（沙箱）** —— 构建和运行不受信任代码的隔离 Docker 环境，使其无法危害你的机器。
- **Promote / Approve（批准）** —— 将经过冒烟测试的测试桩标记为可信、可用于完整测试活动的
  人工步骤。
- **Smoke test（冒烟测试）** —— 一次简短的模糊测试运行，用以在完整测试活动之前确认一个新
  测试桩确实触及了目标。
- **HITL（人工介入）** —— 由人来批准有风险的操作、而非让 AI 无人监督地执行的原则。
- **LLM provider（LLM 提供方）** —— 为助手提供动力的 AI 服务（例如 OpenAI）；你需要提供一
  个 API 密钥。
- **DefectDojo** —— 一个用于管理漏洞的开源平台；hobot_fuzz 可以向它推送发现。
`,Ne=[{id:"welcome",group:"start",title:"欢迎与安全模型",keywords:"简介 概述 什么是模糊测试 安全 沙箱 人工介入 hitl",body:ce},{id:"first-run",group:"start",title:"首次运行与设置",keywords:"向导 提供方 api 密钥 docker 安装 引导 快速开始",body:le},{id:"pipeline",group:"start",title:"流水线与顺利流程",keywords:"流程 阶段 顺序 发现 测试桩 运行 分类定级 语料库 工作流",body:ue},{id:"dashboard",group:"pipeline",title:"仪表盘",keywords:"工作台 概览 就绪度 报告 复现 审查 健康 指标",body:pe},{id:"chat",group:"pipeline",title:"AI 助手（聊天）",keywords:"智能体 对话 工具 计划 自动 分支 回退 模型",body:he},{id:"workflow",group:"pipeline",title:"模糊测试工作流",keywords:"折叠面板 连贯流程 单页 阶段",body:ge},{id:"discover",group:"pipeline",title:"发现目标",keywords:"扫描 候选项 排名 契合度评分 可达性 调用图 c cpp",body:fe},{id:"harness",group:"pipeline",title:"生成测试桩",keywords:"起草 编译 冒烟 批准 promote 种子 引擎 语言 rust",body:me},{id:"run",group:"pipeline",title:"运行模糊测试",keywords:"测试活动 引擎 时长 syzkaller 内核 边 执行数 停止 覆盖率",body:be},{id:"triage",group:"pipeline",title:"分类定级崩溃",keywords:"casr 严重程度 去重 堆栈签名 缺陷报告 defectdojo 导出",body:ye},{id:"corpus",group:"pipeline",title:"管理语料库",keywords:"种子 播种 扩充 精简 最小化 输入 ai 生成",body:ve},{id:"projects",group:"library",title:"项目",keywords:"最近 添加 删除 移除 文件夹 工作区",body:ze},{id:"artifacts",group:"library",title:"构件",keywords:"崩溃 语料库 输入 浏览 导出 清除",body:we},{id:"reports",group:"library",title:"报告",keywords:"撰写 markdown html pdf docx 导出 预览",body:ke},{id:"runs",group:"library",title:"运行历史",keywords:"趋势 对比 覆盖率曲线 自动回退 回归 测试桩修订版本",body:Se},{id:"audit",group:"library",title:"策略审计",keywords:"自动回退 事件 时间线 已回退 已标记",body:Ee},{id:"agents",group:"library",title:"智能体",keywords:"角色 工具 技能 系统提示词 自主性 自定义 内置",body:xe},{id:"skills",group:"library",title:"技能",keywords:"操作手册 领域 内置 自定义 root.md",body:Ce},{id:"knowledge",group:"library",title:"知识库",keywords:"bm25 搜索 索引 摄取 文档 pdf 已学习",body:Re},{id:"automation",group:"library",title:"自动化",keywords:"调度 测试活动 cron 间隔 无头 已批准 并发 预算",body:Ae},{id:"automotive",group:"library",title:"汽车协议",keywords:"can uds pcap 离线 vcan 回放 sidecar 物理台架 策略 证据 ai 活动 报告 导出 状态",body:De},{id:"defectdojo",group:"library",title:"DefectDojo",keywords:"漏洞管理 发现 嵌入 推送 集成",body:je},{id:"settings",group:"config",title:"设置",keywords:"提供方 模糊测试 汽车协议 沙箱 引擎 存储 集成 问题跟踪器 表单 原始 toml",body:Te},{id:"shortcuts",group:"reference",title:"键盘快捷键",keywords:"热键 命令面板 cmd k ctrl",body:Ie},{id:"troubleshooting",group:"reference",title:"疑难解答",keywords:"错误 问题 docker 提供方 关卡 消息 修复 帮助",body:_e},{id:"cli",group:"reference",title:"命令行等价物",keywords:"cli 终端 hobot-fuzz 命令 serve tui",body:Pe},{id:"glossary",group:"reference",title:"术语表",keywords:"定义 术语 词汇 含义",body:Le}];function Oe(s,r){if(!r)return!0;const o=`${s.title} ${s.keywords??""} ${s.body}`.toLowerCase();return r.toLowerCase().split(/\s+/).filter(Boolean).every(n=>o.includes(n))}function Me(){const{locale:s}=k(),r=s==="zh",o=(t,a)=>r?a:t,n=r?Ne:ie,m=r?de:_,[i,b]=u.useState(""),[y,v]=u.useState(n[0].id),c=u.useMemo(()=>n.filter(t=>Oe(t,i)),[n,i]),l=c.find(t=>t.id===y)??c[0]??null,h=m.map(t=>({...t,sections:c.filter(a=>a.group===t.id)})).filter(t=>t.sections.length>0);return e.jsxs("div",{className:"flex flex-col gap-4",style:{animation:"fadeIn 0.2s ease"},children:[e.jsxs("div",{className:"flex flex-wrap items-start justify-between gap-3",children:[e.jsx(S,{title:o("Help & Documentation","帮助与文档"),description:o("How to use the hobot_fuzz desktop app, screen by screen. Everything here works offline.","如何逐屏使用 hobot_fuzz 桌面应用。此处内容均可离线查看。")}),e.jsxs("div",{className:"flex items-center gap-2",children:[e.jsxs(g,{variant:"outline",size:"sm",onClick:()=>{p(A)},title:o("Open the getting-started guide","打开入门指南"),children:[e.jsx(E,{size:14})," ",o("Getting Started","入门")]}),e.jsxs(g,{variant:"outline",size:"sm",onClick:()=>{p(f)},title:o("Open the GitLab repository","打开 GitLab 仓库"),children:[e.jsx(x,{size:14})," GitLab"]})]})]}),e.jsxs("div",{className:"flex gap-4 min-w-0",style:{alignItems:"flex-start"},children:[e.jsxs("nav",{className:"surface-card flex flex-col gap-2 shrink-0",style:{width:260,padding:"var(--space-md)",position:"sticky",top:0,maxHeight:"calc(100vh - 160px)",overflow:"auto"},"aria-label":o("Documentation sections","文档章节"),children:[e.jsxs("div",{className:"flex items-center gap-2 rounded-md",style:{padding:"6px 8px",background:"var(--surface-secondary)",border:"1px solid var(--border)"},children:[e.jsx(C,{size:14,className:"text-text-muted shrink-0"}),e.jsx("input",{value:i,onChange:t=>b(t.target.value),placeholder:o("Search the docs...","搜索文档…"),className:"flex-1 bg-transparent outline-none text-sm text-text-primary min-w-0",style:{border:"none"},"aria-label":o("Search documentation","搜索文档")})]}),h.length===0?e.jsx("p",{className:"text-xs text-text-muted",style:{padding:"8px 4px"},children:o(`No topics match "${i}".`,`没有匹配“${i}”的主题。`)}):h.map(t=>e.jsxs("div",{className:"flex flex-col gap-0.5",children:[e.jsx("span",{className:"text-xs font-semibold uppercase",style:{color:"var(--text-muted)",letterSpacing:"0.08em",padding:"8px 6px 2px"},children:t.title}),t.sections.map(a=>{const d=l?.id===a.id;return e.jsx("button",{onClick:()=>v(a.id),className:`text-left rounded-md transition-colors ${d?"bg-surface-active text-text-primary":"bg-transparent text-text-secondary hover:bg-surface-hover hover:text-text-primary"}`,style:{padding:"6px 8px",fontSize:13,border:"none",cursor:"pointer"},"aria-current":d?"page":void 0,children:a.title},a.id)})]},t.id))]}),e.jsxs("section",{className:"surface-card markdown-body flex-1 min-w-0",style:{padding:"var(--space-lg)",minHeight:400},children:[l?e.jsx(D,{remarkPlugins:[j],components:{code({className:t,children:a,...d}){const{lang:z,text:w}=T(t,a);return z==="mermaid"?e.jsx(I,{code:w}):e.jsx("code",{className:typeof t=="string"?t:void 0,...d,children:a})}},children:l.body}):e.jsx("p",{className:"text-sm text-text-muted",children:o("Select a topic to read it here.","选择一个主题以在此阅读。")}),e.jsxs("div",{className:"flex items-center gap-3 mt-6 pt-4",style:{borderTop:"1px solid var(--border)"},children:[e.jsx(R,{size:14,className:"text-text-muted"}),e.jsxs("span",{className:"text-xs text-text-muted",children:[o("Looking for the deep-dive design docs? See the ","想查看深入的设计文档？请访问"),e.jsx("button",{onClick:()=>{p(f)},style:{background:"none",border:"none",padding:0,color:"var(--accent)",cursor:"pointer"},children:o("project repository","项目仓库")}),o(".","。")]})]})]})]})]})}export{Me as HelpView};
