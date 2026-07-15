// In-app user documentation for the hobot_fuzz desktop app.
//
// The content is authored here as Markdown strings and rendered by HelpView
// with the same react-markdown + remark-gfm pipeline the report preview uses,
// so it renders offline with no backend call and works in both the Tauri app
// and web (VITE_BACKEND=http) modes.
//
// Keep this factual: every screen description must match what the code does.
// When a screen's behavior changes, update the matching section here.

export interface HelpSection {
  id: string;
  group: string;
  title: string;
  /** Extra search terms beyond the title + body (synonyms a user might type). */
  keywords?: string;
  body: string;
}

export interface HelpGroup {
  id: string;
  title: string;
}

export const HELP_GROUPS: HelpGroup[] = [
  { id: "start", title: "Getting Started" },
  { id: "pipeline", title: "The Fuzzing Pipeline" },
  { id: "library", title: "Library & Resources" },
  { id: "config", title: "Configuration" },
  { id: "reference", title: "Reference" },
];

// --------------------------------------------------------------------------
// Getting Started
// --------------------------------------------------------------------------

const WELCOME = `
# Welcome to hobot_fuzz

**hobot_fuzz is an AI fuzzing agent.** You point it at a codebase and it finds
the functions most worth testing, writes the test code for them, runs a real
fuzzing engine inside a safe sandbox, and explains any bugs it finds -- asking
for your approval at the steps that matter.

## What is fuzzing?

Fuzzing throws millions of malformed and random inputs at a program as fast as
possible, watching for any that make it crash or misbehave. Each crash is a
potential bug, often a security vulnerability. It is one of the most effective
ways to find serious bugs -- and normally a lot of expert work. hobot_fuzz
automates that work.

## The safety model (why this is safe to run)

Fuzzing runs untrusted, possibly-malformed code. hobot_fuzz uses defense in
depth so nothing dangerous happens without you:

- **Sandboxed execution.** Every harness build and fuzz run happens inside a
  Docker sandbox, never directly on your machine.
- **Human-in-the-loop (HITL) gates.** Generated harness source is reviewed by an
  LLM triage step *and* by you before it is promoted for full campaigns.
- **Never run without approval.** hobot_fuzz never runs generated code on your
  host without your explicit approval.

## Who it is for

- **Developers** hardening their code who are not fuzzing experts.
- **Security teams** scaling up testing without hand-writing every harness.
- **Anyone curious** about what fuzzing finds in a codebase.

Continue to **First Run** to get set up, then **The Fuzzing Pipeline** to run
your first campaign. Every technical term is defined in the **Glossary**.
`;

const FIRST_RUN = `
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
3. **Sandbox** -- keep **Use Docker sandbox** on (recommended).
4. **Guardrails** -- the human-approval gates for compiling harnesses and
   starting runs.
5. **Storage** -- where run data, corpora, and crashes live (informational).
6. **Complete** -- click **Get Started**.

You can add more providers, tune every engine, and change guardrails later in
**Settings**. On first launch the app also builds the sandbox image, which can
take a few minutes.

## Then what?

The bottom **Status Bar** shows green dots once Docker, the sandbox image, and
the fuzzing engines are ready. When they are, head to **The Fuzzing Pipeline**.
`;

const PIPELINE_OVERVIEW = `
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
`;

// --------------------------------------------------------------------------
// Pipeline screens
// --------------------------------------------------------------------------

const SCREEN_DASHBOARD = `
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
`;

const SCREEN_CHAT = `
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
`;

const SCREEN_WORKFLOW = `
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
`;

const SCREEN_DISCOVER = `
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
`;

const SCREEN_HARNESS = `
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
`;

const SCREEN_RUN = `
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
`;

const SCREEN_TRIAGE = `
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
`;

const SCREEN_CORPUS = `
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
`;

// --------------------------------------------------------------------------
// Library & resources
// --------------------------------------------------------------------------

const SCREEN_PROJECTS = `
# Projects

**Purpose:** manage the project folders you have scanned or fuzzed.

**What you can do:**

- **Add project** -- pick a folder, make it active, and jump to Discover.
- Per project: **Discover**, **Run**, remove from recents (the **X** -- local
  only, keeps your data), and **delete all data** (the trash icon -- destructive
  and irreversible; removes the DB records and the on-disk workspace).

**Gotcha:** the **X** only forgets the folder in the recents list; the **trash**
icon permanently deletes everything for that project.
`;

const SCREEN_ARTIFACTS = `
# Artifacts

**Purpose:** browse crash reproducers and corpus inputs across all projects and
runs.

**What you can do:** filter, **Rescan**, **Export** (desktop only), **Clear all**,
and delete individual crashes or corpus entries. It auto-scans on open.

**What it shows:** a "Crashes" section and a "Corpus" section with counts. A
failed load shows a distinct error state, not an empty one.
`;

const SCREEN_REPORTS = `
# Reports (Composed Reports)

**Purpose:** the home for every composed report across projects and targets.

**What you can do:** filter reports, **Open** one to preview and export it
(Markdown / HTML / PDF / DOCX), **push** it to DefectDojo, or delete it.

**Where they come from:** Triage produces reports automatically when a run finds
crashes, and you can compose them by hand from the Dashboard.

**What it shows:** a list (title, status, target, updated time) and a preview
modal that renders Markdown tables and Mermaid diagrams.
`;

const SCREEN_RUNS = `
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
`;

const SCREEN_AUDIT = `
# Policy Audit

**Purpose:** a durable timeline of every auto-revert policy decision, so an
automated revert is always explainable after the fact.

**What you can do:** scope to **This project** or **All projects** and review the
events.

**What it shows:** counts of reverted vs flagged, and per-event rows (project,
target, coverage drop %, from/to revision, timestamp).
`;

const SCREEN_AGENTS = `
# Agents

**Purpose:** author the AI agents that drive the fuzzing runtime -- their role,
allowed tools, skills, and system prompt.

**What you can do:** create a **New agent**, or **Edit**, **Duplicate**, or
delete a custom one. The editor sets the name, id (a safe slug), description,
role, autonomy, system prompt, allowed-tools checkboxes, skills, model tags,
temperature, and max iterations.

**Gotcha:** built-in agents cannot be deleted, only **reset** to their shipped
definition.
`;

const SCREEN_SKILLS = `
# Skills

**Purpose:** reusable playbooks injected into an agent's context (for example,
target triage or harness authoring).

**What you can do:** create a **New skill**, or **Edit**, **Duplicate**, or
delete a custom one. A skill has a name (slug), version, description, domain
tags, and a Markdown body.

**Gotcha:** built-in skills reset rather than delete.
`;

const SCREEN_KNOWLEDGE = `
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
`;

const SCREEN_AUTOMATION = `
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
`;

const SCREEN_DEFECTDOJO = `
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
`;

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

const SCREEN_SETTINGS = `
# Settings

Settings is a full-window editor. Every config-backed section has a **FORM / RAW**
toggle -- the form and the raw TOML are two lossless views of the same file --
and one **Save Changes** button that persists whichever view is active.

**Sections:**

- **General** -- config/data directories, language, theme, font size, macOS
  window chrome, the sandbox **Architecture** (arm64 / amd64; changing it
  rebuilds the image), and **Run Setup Wizard**.
- **Providers** -- add and configure LLM providers (OpenAI, OpenAI-compatible,
  Anthropic, DeepSeek, Gemini, Ollama, Azure): model, base URL, API key, tags,
  cost, concurrency, context window, and **Test Connection**.
- **Session / Tools** -- generic key/value config forms.
- **Runtime** -- sandbox backend (Docker recommended; Native is dev-only),
  Docker image, resource limits, and network access during build vs fuzz.
- **Engines** -- enable/disable each engine and set its binary, default
  duration, memory, and supported languages. Disabled engines disappear from the
  Run screen.
- **Guardrails** -- permission mode (Strict / Auto / Manual), HITL approval gates
  (harness compilation, fuzzer execution, bug-report publication), the HITL risk
  threshold, and loop detection.
- **Storage** -- SQLite path, transcript directory, and **Clear Workspace**.
- **Integrations** -- DefectDojo connection and **Test connection**.
- **Issue Tracker** -- GitHub/GitLab repo and token for filing issues, with
  **Test connection**.
- **About** -- version, license, and links.
`;

// --------------------------------------------------------------------------
// Reference
// --------------------------------------------------------------------------

const REF_SHORTCUTS = `
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
`;

const REF_TROUBLESHOOTING = `
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
`;

const REF_CLI = `
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
\`\`\`

There is also \`hobot-fuzz serve\` (REST + SSE API) and \`hobot-fuzz tui\` (a
terminal UI). See the project README for the full command reference.
`;

const REF_GLOSSARY = `
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
`;

export const HELP_SECTIONS: HelpSection[] = [
  { id: "welcome", group: "start", title: "Welcome & Safety Model", keywords: "intro overview what is fuzzing safe sandbox hitl", body: WELCOME },
  { id: "first-run", group: "start", title: "First Run & Setup", keywords: "wizard provider api key docker install onboarding getting started", body: FIRST_RUN },
  { id: "pipeline", group: "start", title: "The Pipeline & Happy Path", keywords: "flow stages order discover harness run triage corpus workflow", body: PIPELINE_OVERVIEW },

  { id: "dashboard", group: "pipeline", title: "Dashboard", keywords: "workbench overview readiness reports repro review health metrics", body: SCREEN_DASHBOARD },
  { id: "chat", group: "pipeline", title: "AI Assistant (Chat)", keywords: "agent conversation tools plan auto branches rollback model", body: SCREEN_CHAT },
  { id: "workflow", group: "pipeline", title: "Fuzzing Workflow", keywords: "accordion connected flow one page stages", body: SCREEN_WORKFLOW },
  { id: "discover", group: "pipeline", title: "Discover Targets", keywords: "scan candidates ranking fit score reachability call graph c cpp", body: SCREEN_DISCOVER },
  { id: "harness", group: "pipeline", title: "Generate Harness", keywords: "draft compile smoke approve promote seeds engine language rust", body: SCREEN_HARNESS },
  { id: "run", group: "pipeline", title: "Run the Fuzzer", keywords: "campaign engine duration syzkaller kernel edges execs stop coverage", body: SCREEN_RUN },
  { id: "triage", group: "pipeline", title: "Triage Crashes", keywords: "casr severity dedup stack signature bug report defectdojo export", body: SCREEN_TRIAGE },
  { id: "corpus", group: "pipeline", title: "Manage the Corpus", keywords: "seed grow prune minimize inputs ai generate", body: SCREEN_CORPUS },

  { id: "projects", group: "library", title: "Projects", keywords: "recent add delete remove folder workspace", body: SCREEN_PROJECTS },
  { id: "artifacts", group: "library", title: "Artifacts", keywords: "crashes corpus inputs browse export clear", body: SCREEN_ARTIFACTS },
  { id: "reports", group: "library", title: "Reports", keywords: "composed markdown html pdf docx export preview", body: SCREEN_REPORTS },
  { id: "runs", group: "library", title: "Run History", keywords: "trends compare coverage curve auto-revert regression harness revision", body: SCREEN_RUNS },
  { id: "audit", group: "library", title: "Policy Audit", keywords: "auto-revert events timeline reverted flagged", body: SCREEN_AUDIT },
  { id: "agents", group: "library", title: "Agents", keywords: "roles tools skills system prompt autonomy custom built-in", body: SCREEN_AGENTS },
  { id: "skills", group: "library", title: "Skills", keywords: "playbooks domain built-in custom root.md", body: SCREEN_SKILLS },
  { id: "knowledge", group: "library", title: "Knowledge", keywords: "bm25 search index ingest documents pdf learned", body: SCREEN_KNOWLEDGE },
  { id: "automation", group: "library", title: "Automation", keywords: "schedule campaign cron interval headless promoted concurrency budget", body: SCREEN_AUTOMATION },
  { id: "defectdojo", group: "library", title: "DefectDojo", keywords: "vulnerability management findings embed push integration", body: SCREEN_DEFECTDOJO },

  { id: "settings", group: "config", title: "Settings", keywords: "providers runtime engines guardrails storage integrations issue tracker form raw toml", body: SCREEN_SETTINGS },

  { id: "shortcuts", group: "reference", title: "Keyboard Shortcuts", keywords: "hotkeys command palette cmd k ctrl", body: REF_SHORTCUTS },
  { id: "troubleshooting", group: "reference", title: "Troubleshooting", keywords: "errors problems docker provider gating messages fix help", body: REF_TROUBLESHOOTING },
  { id: "cli", group: "reference", title: "Command-Line Equivalent", keywords: "cli terminal hobot-fuzz commands serve tui", body: REF_CLI },
  { id: "glossary", group: "reference", title: "Glossary", keywords: "definitions terms vocabulary meaning", body: REF_GLOSSARY },
];
