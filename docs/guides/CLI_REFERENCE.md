# CLI Reference

[← Back to the README](../../README.md)

## Quick Start (CLI)

### 1. Initialize configuration

```bash
oxfuzz init
oxfuzz doctor
```

This materializes the supported `*.example.toml` templates and creates the
database. `init` prints the config directory it wrote to. Every command
resolves that directory in the same order:

1. `--config <dir>` (a global flag, accepted before or after the subcommand),
2. the `HF_CONFIG_DIR` environment variable,
3. the per-user config dir, when it already holds config files
   (`~/Library/Application Support/oxfuzz/config` on macOS,
   `$XDG_DATA_HOME/oxfuzz/config` or `~/.local/share/oxfuzz/config` on Linux,
   `%APPDATA%\oxfuzz\config` on Windows),
4. the enclosing source tree's `config/`, found by walking up from the current
   directory (kept for development). A walk-up binding prints a one-line
   stderr warning naming the directory and the `HF_CONFIG_DIR` override, so
   running the CLI inside an unrelated Rust project that has a `config/`
   directory never binds that project's files silently.

A `--config`/`HF_CONFIG_DIR` value naming an existing non-directory fails at
startup with the exact problem; a directory that does not exist yet is created
on demand (this is how `init` and the test fixtures use it). Environment
overrides remain explicit in `.env.example`; `init` does not create or modify
`.env`.

### 2. Configure at least one LLM provider

Copy `config/providers.example.toml` to `config/providers.toml` and fill it in,
then export the matching key in the environment that launches `oxfuzz`:

```toml
[[providers]]
id = "openai-main"
provider_type = "openai"
model = "gpt-4o"
tags = ["reasoning", "general"]
api_key_env = "OPENAI_API_KEY"
```

`.env.example` is a variable reference, not an automatically loaded file. If
you keep local values in `.env`, export them before launching the process (for
example, `set -a; source .env; set +a` in a POSIX shell).

Offline / no-key operation: without a provider, drafting falls back to the
heuristic template, but smoke qualification still requires the independent LLM
pre-execution review and fails closed. To qualify harnesses anyway, pass
`--no-llm-review` to `oxfuzz harness` per invocation (or set
`harness.allow_unreviewed_smoke = true` in `oxfuzz.toml` for the deployment).
Every bypass is persisted as a marked review record and a policy audit row;
promotion still requires human approval.

### 3. Authorize execution before the first run

Compiling or running a generated harness and launching a fuzzer are high-risk
actions. The default guardrail policy requires approval for them. On a terminal
(stdin and stderr both TTYs) the CLI asks per action:

```text
[approval] High-risk action 'run libfuzzer for 1800s' requires approval [y]es/[n]o/[a]lways:
```

- `y` approves that one request; the next one asks again.
- `n` denies it. An empty answer, end of input, or anything unrecognized also
  denies -- the prompt fails closed.
- `a` approves and allows that action kind (`run_fuzzer`, `run_harness`, ...)
  for the rest of the process. The memory is per kind and per invocation; it
  is never persisted.

Every outcome is echoed to the transcript (`[approval] approved: ...` /
`[approval] denied: ...`) and persisted in the policy audit trail (`oxfuzz
policy decisions`).

When stdin or stderr is not a terminal -- a pipe, CI, or any headless launch --
the CLI never prompts and never blocks on input. Approval then comes from the
environment, as before:

```bash
export HF_AUTO_APPROVE=1
```

`HF_AUTO_APPROVE=1` also approves without prompting on a terminal.
`HF_GUARDRAILS=permissive` instead auto-approves every action with an audit
trail; reserve it for trusted local loops. `oxfuzz serve` always uses the
environment policy: a server's approvals cannot come from its own terminal.
The desktop app asks for approval through an interactive dialog and does not
read these variables. See `.env.example` for the full variable reference and
the [Safety Model](SAFETY_MODEL.md) for the reasoning.

### 4. Qualify and review a retained harness

```bash
# Discover and rank targets in a project
oxfuzz discover /path/to/project --lang c --rank

# Export an immutable authoring packet. The packet carries its work-order SHA-256.
oxfuzz work-order export /path/to/project --target parse_value --lang c \
  --engine afl++ --out work-order.md

# Author harness.c from that packet, then retain the submission UUID in the JSON.
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human

# Compile, independently review, and smoke-test that immutable submission.
# Retain the attempt UUID returned in the JSON.
oxfuzz work-order qualify --submission <submission UUID>

# Stop and review the exact source, lint, review, binary digest, and smoke result.
# Promotion is a separate human action bound to that retained attempt.
oxfuzz work-order promote --attempt <attempt UUID>
```

`--rank` uses AI assessment when a provider is available. The JSON includes
the ordered inventory, per-target UUID assessments, `candidate_sources`
(`ai_assessed` or `scan_only` in inventory order), `ranking_source`, and a
reason when it falls back to scan ranking. `--ai auto` keeps scan results when
the provider is missing or fails; `--ai require` reports an error if AI cannot
assess every admitted target; `--ai off` uses scan ranking only. AI assessment
considers at most 64 targets in batches of 16, and leaves every original
`fit_score` unchanged. The desktop Discover screen runs this assessment
automatically after its initial scan and displays the three factors directly.

Discovery scans more languages than the harness pipeline can build. Every
candidate carries a derived `harnessable` flag from the single
`TargetLanguage::harnessable` predicate (C, C++, and Rust today). A scan of a
discovery-only language (`--lang go`, `--lang python`) still runs and persists
its inventory, but each candidate is marked `"harnessable": false` and stderr
notes that harness generation is not yet available for that language, naming
the supported set. Harness draft/compile/generate, `oxfuzz fuzz` target
auto-selection, and `oxfuzz campaign` enforce the same predicate, so a
discovery-only target fails with that message at the harness boundary rather
than at a late build step.

### 5. Run and inspect the campaign

```bash
# Work Order runs always use the complete selector returned by the retained order.
oxfuzz run /path/to/project --target src/parser.c::parse_value \
  --engine afl++ --duration 60m

# Read retained health without changing the run.
oxfuzz health --run <run UUID>

# Triage the crashes it found
oxfuzz triage /path/to/project --target src/parser.c::parse_value

# Explicitly run or resume the retained seven-step terminal closeout.
oxfuzz closeout --run <run UUID>
```

`work-order import` and `work-order qualify` never promote. Rerunning
`oxfuzz harness` generates a new draft, so it is not an approval operation for
the source you just reviewed. A full campaign requires the exact promoted
harness revision and still executes only through the mandatory sandbox.

### Optional Semgrep target enrichment

After ordinary C or C++ discovery, you can explicitly enrich the ranking:

```bash
oxfuzz discover /path/to/c-project --lang c --semgrep
```

Without `--semgrep`, discovery is unchanged and Semgrep does not run. The
enriched output is labelled **Semgrep static-analysis signals**. A signal is an
advisory prioritization hint, not a confirmed vulnerability or a fuzzing crash.
Each target retains its immutable base discovery score, shows the Semgrep
boost separately, and reports the effective score used for ordering. Distinct
matched rules contribute by severity, but the total boost is capped at `0.20`
and the effective score cannot exceed `1.0`.

The first release supports only C and C++, permits one active enrichment
operation per canonical project, and lets Ctrl-C or the desktop **Stop** action
cancel that exact operation. Source or base-score changes make a saved overlay
stale; oxfuzz then uses base-only ranking and asks you to rediscover or rerun
enrichment. Scan, validation, mapping, persistence, cancellation, or cleanup
failure is atomic: partial findings and partial score changes are never
published.

The sandbox uses Semgrep CE `1.169.0` and the reviewed
[`0xdea/semgrep-rules` commit `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`](https://github.com/0xdea/semgrep-rules/tree/4d66ecf30bfb1809a984085f2c86a8c3915bfc71)
offline. Runtime scans do not contact the Semgrep Registry and do not accept
user-provided rules, configuration, flags, tokens, or autofix requests. CVE
Binary Tool integration is outside this release's scope.

## Command Reference

| Command | What it does |
| --- | --- |
| `init` | Scaffold config from templates into the resolved config directory (see Quick Start) and create/migrate the database. |
| `doctor [--engine <e> [--duration <d>] [--require-provider]] [--build-image] [--json]` | Probe Docker and bundled engines. When the sandbox image is missing, the output names how to build it (`oxfuzz doctor --build-image`, `scripts/build-sandbox.sh`, or the canonical `docker build` command; JSON carries it as `sandbox_image_remedy`). `--build-image` runs that build from the source checkout's `docker/sandbox/Dockerfile` -- the same build the desktop app runs on first launch -- then re-probes; it fails loud when Docker is unavailable or no source checkout is found. With `--engine`, enforce selected-engine availability and run policy; optionally require provider configuration. Exit non-zero on failure. |
| `discover <project> --lang c [--rank] [--ai auto\|require\|off] [--semgrep]` | Scan a project; `--rank` requests service-owned AI assessment, and `--semgrep` explicitly adds separate C/C++ enrichment. Every candidate carries a derived `harnessable` flag; a discovery-only language (`go`, `python`) still scans and persists its inventory but marks each candidate `false` with a note naming the supported set. |
| `harness <project> --target <sym> --engine <e> [--draft-only] [--repair N] [--refine] [--promote] [--no-llm-review] [--sanitizer address\|undefined]` | Write, compile (optionally auto-repair or coverage-refine), and smoke-qualify a newly generated harness. Smoke requires the independent LLM pre-execution review; with no provider configured it fails closed unless you pass `--no-llm-review` (or set `harness.allow_unreviewed_smoke = true`), which persists a marked bypass record and an audit row -- without the model review, only the lexical lint and your own promotion decision check the harness. Without `--promote`, review the output; rerunning creates another draft. Use the retained Work Order flow below when approval must name a previously reviewed source. |
| `work-order export\|import\|list\|submissions\|qualify\|rank\|promote ...` | Manage immutable external harness packets, submissions, qualification attempts, deterministic ranking, and exact-attempt promotion. |
| `run <project> --target <sym> --engine <e> --duration 60m [--cpus N] [--timeout-ms N] [--resume] [--sanitizer address\|undefined]` | Run a sandboxed campaign with the active promoted harness (Ctrl-C cancels cooperatively). A file-qualified selector is `<relative-file>::<complete-symbol>`; a retained Work Order run always uses that complete selector. `--cpus N` requests a per-run CPU allocation within the configured `fuzzing.sandbox.max_cpus` ceiling; an allocation above one runs libFuzzer fork mode (`-fork=N`) and honggfuzz `--threads N` (AFL++ runs a single instance). `--timeout-ms N` overrides the per-input timeout for this run. `--resume` (AFL++ only) continues the most recent compatible AFL++ session instead of cold-starting; see "AFL++ session resume" below. `--sanitizer` asserts the promoted harness's build sanitizer (mismatch fails before any engine starts); see "Sanitizer selection" below. |
| `run . --replay <run UUID>` | Replay a retained run with its recorded engine, duration, per-input timeout, and deterministic seed under current policy. The positional `.` is ignored in replay mode; the retained run resolves its original project. `--timeout-ms` and `--sanitizer` do not combine with `--replay`: the recorded timeout and sanitizer replay exactly. |
| `runs list [--project <path>] [--active] [--limit N] [--json]` | List persisted runs, newest first: short id, target, engine, status, start, duration, crashes. |
| `runs status <run-id-or-prefix> [--json]` | Show one run's full record plus its latest persisted live telemetry, when any was retained. |
| `runs stop <run-id-or-prefix>` | Cooperatively cancel a run owned by this process; exits non-zero with the reason otherwise. |
| `campaign <project> --target <sym> --engine <e> [--timeout-ms N] [--resume] [--sanitizer address\|undefined]` | Run and triage a bounded campaign using an already smoke-qualified, human-promoted harness. Prints an iteration marker per iteration plus the same throttled live status line as `run`; raw engine output lines stay internal to the campaign. `--timeout-ms N` applies the per-input timeout to every iteration. `--resume` (AFL++ only) applies to every iteration: iteration N continues the output tree iteration N-1 produced. `--sanitizer` asserts the promoted harness's build sanitizer for every iteration. |
| `fuzz <project> [--target <sym>] [--engine <e>] [--lang <l>] [--duration-secs N] [--iterations N] [--timeout-ms N] [--resume] [--sanitizer address\|undefined] [--ai auto\|require\|off] [--no-llm-review] [--fresh] [--json]` | One-command onboarding: discover -> harness -> smoke -> promote -> campaign in a single invocation. The only pause is the human promotion gate; a denial stops the pipeline before any campaign. Reuses an already-promoted harness for the same target/engine unless `--fresh` is given. `--resume` (AFL++ only) forwards to the campaign stage. `--sanitizer` selects the build sanitizer for a fresh harness and re-qualifies rather than reusing a promoted harness built with the other sanitizer. |
| `health --run <run UUID>` | Assess retained campaign health. This read-only command never stops, restarts, or resizes the run. |
| `trust --run <run UUID>` | Audit which claims about a finished run its retained evidence supports. Read-only; starts no build, run, or coverage measurement. |
| `closeout --run <run UUID>` | Explicitly run or resume the seven retained terminal closeout steps. Successful/skipped steps remain retained; failed or dependency-blocked work can be retried. |
| `triage <project> --target <sym>` | Ingest, dedup, classify (CASR), and draft reports for crashes. |
| `corpus <project> --target <sym> --op seed\|llmseed\|grow\|prune\|cprune\|survival\|regen\|minimize\|absorb\|concolic\|import\|list [--from <dir>]` | Manage the corpus. `prune` removes byte duplicates; `cprune`, `survival`, `regen`, `minimize`, and optional `concolic` have the distinct execution/provider requirements below; `import` requires `--from`. |
| `build diagnose <project> [--json]` | Read current build prerequisites and the exact available plan without building. |
| `build profile show\|set\|clear ...` | Read or explicitly change the optional CMake/plain-Make project build profile. `show` remains available in builds without Build Doctor. |
| `build history <project> [--limit N] [--json]` | Read retained diagnosis and build output. |
| `build run <project> --expected-profile-sha256 <digest> [--json]` | Execute the exact reviewed profile in the sandbox and reject a stale profile digest. |
| `coverage <project> --target <sym>` | Summarize line/region/function coverage. |
| `unreached <project> [--lang c]` | Rank entry points that no retained coverage measurement has ever covered. Reads cached measurements; never triggers one. |
| `attribution <project> [--lang c]` | Attribute every discovered target against retained coverage and order the result for the next harness: untouched first, partial frontier next, saturated last. |
| `regress <project> --target <sym>` | Re-run the known crash reproducers to verify they still (or no longer) crash. |
| `ci <project> --target <sym> --engine <e> [--sarif out.sarif]` | CI gate: seed, run, triage, and export SARIF; exits non-zero when crashes are found. |
| `sarif <project> --target <sym> --out results.sarif` | Export triaged crashes as a SARIF report for code scanning. |
| `defectdojo <project> --target <sym>` | Push triaged crashes to DefectDojo as findings. |
| `repro <project> --target <sym> [--engine <e>] [--lang c] [--crash <id>] [--out <dir>]` | Bundle a crash reproducer (harness, input, and `REPRODUCE.md`) for handoff outside oxfuzz. Defaults to the first crash and `oxfuzz_repro`. |
| `ingest <project> --file <file>` | Ingest a document (PDF/Office/HTML) into the knowledge base. |
| `knowledge index\|search <project> [query]` | Index a project for search, or run a full-text (BM25) query over it. |
| `agent "<message>" [--project <dir>] [--agent <id>]` | Drive the conversational agent from the terminal. Requires an LLM provider. |
| `schedule list\|create\|history\|recovery list\|recovery acknowledge <occurrence-id>\|... ` | Manage scheduled headless fuzzing campaigns and acknowledge an ambiguous one-time occurrence as cancelled. |
| `session new\|history\|checkpoints\|branches\|rollback ...` | Manage chat sessions and their per-turn checkpoints. |
| `report <project> --target <sym> --out report.md [--report-lang en\|zh]` | Render a full Markdown campaign report. `--report-lang zh` writes it in Simplified Chinese; file paths, stack frames, symbol names, crash signatures, engine and sanitizer names and all figures stay verbatim. |
| `export [project] --output evidence.json` | Export a reproducibility bundle containing scoped targets, runs, harnesses, crashes, corpus, and filesystem evidence. |
| `serve --host 127.0.0.1 --port 8081` | Start the REST + SSE API (`hf-web`). Non-loopback hosts require `HF_WEB_TOKEN`. |
| `arm [--url <url>] [--off\|--status]` | Grant, withdraw, or report the execution authorization a restarted server needs before its scheduler resumes restored or missed work. |
| `providers thaw <id>` | Thaw a frozen provider after a verifying health check. |
| `policy decisions [--limit N]` | List recorded guardrail authorization decisions, newest first. |
| `tui <project>` | Browse the target inventory and copy accurate next-step commands. |

Userspace engines for `harness`, `run`, and `campaign`: `afl++`, `honggfuzz`,
`libfuzzer`. `syzkaller` fuzzes kernel images from the trusted-local desktop
workflow; the CLI harness and run commands do not accept it.

### One-command onboarding (`oxfuzz fuzz`)

```bash
oxfuzz fuzz /path/to/project
```

`fuzz` runs the whole pipeline in one invocation, printing a stage header as
each step starts:

```text
--- [1/5] discover: scanning /path/to/project (language: auto-detect) ---
--- [2/5] harness: drafting and compiling 'parse_value' for libfuzzer (auto-repair up to 2x) ---
--- [3/5] smoke: qualifying 'parse_value' ---
--- [4/5] promote: 'parse_value' needs your approval ---
--- [5/5] campaign: 3 iteration(s) x 60s on 'parse_value' (libfuzzer) ---
```

Each stage is the operation the standalone commands run: target discovery
(`--target` picks one explicitly, otherwise the highest-fit candidate with a
working harness path that the engine can drive wins -- discovery-only
languages, Go and Python today, are never auto-selected; `--lang` pins the
language, otherwise every supported language is scanned and the picked
candidate carries its own), harness
generation with the auto-repair loop, smoke qualification behind the
pre-execution review, and the same bounded campaign `oxfuzz campaign` runs,
with the same throttled live status line. `campaign` itself is unchanged and
still requires a pre-promoted harness.

Promotion is the pipeline's human gate and is never skipped for a fresh
harness: on a terminal it asks `[y]es/[n]o/[a]lways`, and a denial stops the
pipeline before any campaign -- nothing is promoted and no fuzzer runs. For
unattended runs, export `HF_AUTO_APPROVE=1`.

Re-running `fuzz` on a target that already has a promoted harness for the
chosen engine reuses that exact revision -- no re-draft, no re-smoke, no
re-approval -- so the command is idempotent once a project is onboarded.
`--fresh` forces a full re-qualification (new draft, new review, new approval).

A failure at any stage exits non-zero and names the stage plus a remediation
(for example, a harness that still does not compile after the repair loop
suggests `--ai require` or the manual work-order flow). `--ai` governs every
model call in the pipeline (harness drafting, campaign seed generation, the
run dictionary, triage reports); `--no-llm-review` is the same audited
smoke-review bypass as on `oxfuzz harness`; `--json` prints the pipeline
outcome as JSON on stdout and moves stage headers and live progress to
stderr.

### Live run status

`run` and `campaign` print a throttled afl-fuzz-style status line (at most one
per second) as the engine reports stats:

```text
execs=128934 exec/s=842 edges=1523 corpus=91 cycles=2 stability=100.0% crashes=0 hangs=0 last_find=14s
```

Only fields the engine reports are printed. `execs` and `corpus` come from
all three userspace engines (honggfuzz via its Iterations and Corpus Size
ticks); `edges` comes from libFuzzer and AFL++ (honggfuzz reports no edge
count); `cycles`, `stability`, `last_find`, and `uptime` come from AFL++'s
`fuzzer_stats` (polled from the bind-mounted output tree about every 2 seconds
and re-read once at run close); honggfuzz `hangs` comes from its Timeouts
tick. `crashes` counts crash signal events as they stream in. Engine log
lines print unthrottled in `run`; `campaign` prints only iteration markers,
the status line, and crash markers.

### Run lifecycle (list, status, stop)

```bash
oxfuzz runs list [--project /path/to/project] [--active] [--limit 20] [--json]
oxfuzz runs status <run-id-or-prefix> [--json]
oxfuzz runs stop <run-id-or-prefix>
```

`runs list` reads the same persisted history as the web Run History view and
prints it newest first: short id (the first eight characters, accepted as the
id argument by the other two commands whenever the prefix is unambiguous),
target, engine, status, start time, duration, and crash count. `--active`
keeps only runs still in flight (pending or running).

`runs status` prints the full persisted record for one run — both revisions,
evidence directory, requested budget, terminal edges/execs/crash count — plus
the latest retained live telemetry snapshot when the campaign-health monitor
persisted one (observation time, edges, current/mean/peak throughput, free
disk). A running run's terminal metrics stay absent until it closes; the
telemetry snapshot is what is durable mid-run.

`runs stop` requests cooperative cancellation through the same service
operation as the REST `POST /runs/{id}/cancel`. Cancellation is an in-process
signal to the run's cancellation token, so a one-shot CLI process can stop
only a run that process owns; for a run owned by a server or another CLI/TUI
the command exits non-zero and names the owning-process recourse instead of
pretending to signal anything. Unknown, ambiguous, and already-terminal ids
also exit non-zero with the reason.

There is deliberately no `runs attach`: the progress event stream (engine
stats snapshots, log lines, crash markers) is delivered only to in-process
subscribers of the owning process, and the run row's metrics persist only at
termination. The one cross-process mid-run record is the campaign-health
telemetry snapshot, refreshed on the health-assessment cadence (30 seconds by
default) for health assessment rather than progress rendering; `runs status`
already surfaces it. A faithful attach needs a persisted progress journal or
a cross-process broadcast channel, which is a separate design.

### Harness Work Order commands

The Work Order feature exposes exactly seven CLI operations:

```bash
oxfuzz work-order export <project> --target <symbol> --lang c \
  --engine libfuzzer [--out packet.md | --json]
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human [--parent <submission UUID>]
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin external-tool --tool <name> \
  [--model <label>] [--response-id <id>] [--parent <submission UUID>]
oxfuzz work-order list [--project <project>]
oxfuzz work-order submissions --work-order <work-order SHA-256>
oxfuzz work-order qualify --submission <submission UUID>
oxfuzz work-order rank --attempt <attempt UUID> [--attempt <attempt UUID> ...]
oxfuzz work-order promote --attempt <attempt UUID>
```

CLI tracing diagnostics go to stderr, keeping JSON stdout parseable even with
verbose logging or invalid provider configuration.

For scripts, `work-order export --json` returns the complete retained packet,
including its ID and file-qualified target. It cannot be combined with `--out`.
`harness <project> --target <symbol> --engine <engine> --draft-only --json`
returns a draft including its exact source. JSON draft output requires
`--draft-only` and rejects repair, refinement, and promotion. Add `--ai require`
when model authoring is required. Import that source and qualify the returned
submission ID; approve the retained attempt rather than rerunning authoring.

`doctor --engine <engine> --duration <duration> --require-provider --json`
returns `ready`, named `problems`, the selected engine, system probes, and
`provider_configured`. The provider field is null when not requested. Provider
configuration is checked without contacting a model; a configured provider does
not prove valid credentials or connectivity. A pool with no constructed providers
(for example, all API-key variables missing or empty) fails preflight. Duration and provider flags require
`--engine`. Ordinary `doctor` keeps its general any-engine readiness check, and
its JSON gains `sandbox_image_remedy` (a one-line build instruction) whenever
the sandbox image is missing.

For normal `run`, an omitted `--duration` uses `fuzzing.default_duration_secs`.
An omitted `--cpus` uses the configured `fuzzing.sandbox.max_cpus`
allocation; a request above that ceiling fails before seed preparation. The
CLI resolves engine, duration, and CPU policy before storage bootstrap or seed
preparation. The service rechecks policy when launching the campaign.

### Per-input timeout

Every campaign run carries an explicit per-input timeout: one input running
longer is a hang finding instead of a wedged run. An omitted `--timeout-ms`
uses `fuzzing.default_timeout_ms` (default 1000 ms); both are validated to
`1..=3600000` and a rejected value fails before any run starts. The unit is
milliseconds because AFL++ takes `-t` in ms; libFuzzer `-timeout=<s>` and
honggfuzz `--timeout=<s>` take whole seconds, so a sub-second budget rounds
up, never to zero. The resolved value is persisted with the run configuration,
so `run --replay` re-executes it exactly, and an explicit timeout is never
silently overridden by engine `extra_args` (it is emitted last, and all three
userspace engines apply the last occurrence of a repeated flag).

Hang findings surface in the live status line (`hangs=N`: AFL++ `saved_hangs`,
honggfuzz `Timeouts`) and in the run summary (`hangs (per-input timeouts): N`),
which additionally counts libFuzzer's `timeout-*` artifacts. Syzkaller has no
per-input timeout knob; a wedged kernel campaign is bounded by the sandbox
wall-clock cap only.

### Sanitizer selection

C/C++ harnesses build with AddressSanitizer by default; `--sanitizer
undefined` builds them with UndefinedBehaviorSanitizer instead (halt-on-error:
a finding aborts the process so the engine records a crash). UBSan catches a
bug class ASan misses -- signed overflow, invalid shifts, misalignment, null
dereference -- so practitioners run both. The sanitizer is baked into the
harness binary: the harness revision records it, and a run always records the
harness's own sanitizer in its persisted run configuration, so replays,
auto-revert baselines, change-impact comparisons, and AFL++ resume donors
never mix sanitizers.

- `oxfuzz harness --sanitizer undefined` builds (and `fuzz --sanitizer
  undefined` builds and qualifies) a UBSan harness; the configured
  `[fuzzing] default_sanitizer` (default `address`) applies when no flag is
  given.
- `oxfuzz run --sanitizer undefined` and `campaign --sanitizer undefined`
  ASSERT the promoted harness was built with that sanitizer: a mismatch fails
  before any engine starts and names the rebuild command. With no flag, the
  run uses whatever the promoted harness was built with. `--sanitizer` does
  not combine with `run --replay` (a replay re-executes the recorded
  configuration exactly) or with `harness --refine` (refinement keeps the
  active revision's build sanitizer).
- Rust targets build AddressSanitizer-only (cargo-fuzz/libfuzzer-sys has no
  UBSan path); a non-`address` selection fails before any drafting or build.
- `memory`, `thread`, and `none` are rejected with the reason; the sandbox
  toolchain cannot honor them (see `docs/standards/ENGINE_ADAPTER_STANDARD.md`
  3.5 for the per-engine flag mapping and evidence).

### AFL++ session resume

By default every AFL++ run cold-starts: staging builds a fresh output tree,
so an interrupted run's queue cycle position, favored bookkeeping, and cycle
counts are lost (its queue *inputs* survive -- closeout absorbs them into the
retained corpus -- but the AFL-internal state does not).

`--resume` (on `run`, `campaign`, and `fuzz`) opts into session continuation.
A resumed run copies the most recent compatible output tree into its own
fresh staging directory and launches `afl-fuzz` with `AFL_AUTORESUME=1`, so
every prior instance directory resumes in place and any instance added by a
larger `--cpus` allocation cold-starts from the staged corpus. Compatible
means: same target workspace, AFL++ campaign kind, terminal status, and the
exact same harness binary (the staged binary's SHA-256 must match -- a
recompiled harness cold-starts). With no compatible prior tree the run
cold-starts and journals that fact; a donor tree over the 32 MiB copy ceiling
is a loud error, not a silent cold start.

Resume is AFL++-only: requesting it for another engine fails at policy
resolution. `run --replay` never resumes -- a replay re-executes the retained
inputs exactly, so it conflicts with `--resume` at the flag level. The
deployment-wide default is `[fuzzing] default_resume` (off); the flag
overrides it per invocation, and scheduled campaigns and the web/desktop
launch follow the configured default. Hand-rolled resume flags are rejected:
the AFL adapter refuses `-i -`/`-i-` in engine extra args, and the runner
refuses a hand-set `AFL_AUTORESUME` in the run environment -- the typed
`resume` setting is the only source of resume truth.

A resumed tree is the new run's own evidence: closeout reads its
`fuzzer_stats`, absorbs its queue, and ingests crash artifacts (prior
sessions' crashes included) through the same deduplicated triage path.

Export returns a content-addressed work-order ID. Import returns an immutable
submission UUID and records provenance; source must be a nonempty regular,
non-symlink UTF-8 file of at most 65,536 bytes. Qualification returns a new
attempt UUID and is the only operation above that compiles, reviews, and smoke
tests. Rank reads retained attempts. Before promote, inspect the source and the
retained lint, independent review, source/binary digests, verdict, crashes, and
throughput for the selected attempt. Promote accepts only that exact attempt ID
and does not redraft or requalify it. A `Suspect` attempt can technically be
promoted explicitly, but refinement and a new smoke qualification are the
recommended response. A crash-bearing failed attempt is ineligible.

The work order retains the complete `relative-file::symbol` selector. Use it
for every run, coverage, and corpus command that follows the Work Order flow,
including when the display symbol is currently unique. A symbol label by itself
does not preserve the reviewed Work Order workspace identity.

### Campaign health and closeout

`oxfuzz health --run <UUID>` evaluates retained evidence for coverage plateau,
stale worker statistics, missing managed invocation, disk pressure, and terminal
failure. Missing evidence is reported as unavailable. Health is observational;
it does not control the campaign and does not prove a Docker process, worker, or
VM is alive.

`oxfuzz closeout --run <UUID>` operates only on a terminal, harness-backed
campaign and resumes at unfinished work. The retained steps are triage,
minimize, corpus absorb, coverage, blockers, disposition, and trust report.
Opening Run History in the desktop app is read-only; the CLI command itself is
the explicit execution request. Historical source coverage and blocker results
remain unavailable when current workspace files cannot establish them.

### Build profiles

Build profiles support `cmake`, `make`, `meson`, and `autotools`. Meson and
Autotools profiles carry no definitions (the `--define` allowlist is CMake's
`-D` model). A set operation is explicit:

```bash
oxfuzz build profile set /path/to/project \
  --component-root . --build-system cmake \
  --compile-database-path build/compile_commands.json \
  --define BUILD_TESTING=OFF --dependency command:cmake
oxfuzz build diagnose /path/to/project --json
oxfuzz build run /path/to/project \
  --expected-profile-sha256 <reviewed profile SHA-256> --json
oxfuzz build history /path/to/project --limit 20 --json
oxfuzz build profile clear /path/to/project --json
```

Review the normalized component, expected compile database, dependencies,
exact argv, immutable image, and profile digest returned by diagnose. `build
run` writes the oxfuzz-owned build area inside the selected project and runs
only through the sandbox. Clearing a profile keeps diagnosis/build history.

### Corpus operation meanings

`seed`, `grow`, `prune`, `absorb`, `import`, and `list` use deterministic corpus
operations. `llmseed` contacts the configured provider. `survival`, `cprune`,
and `regen` require an exact promoted, smoke-qualified AFL++ harness; `regen`
also asks the provider for bounded replacement seeds. `minimize` (also accepted
as `cmin`) requires an exact promoted, smoke-qualified libFuzzer harness.
`concolic` is available only with its feature and performs sandboxed symbolic
enrichment. Engine-backed actions repeat qualification and current policy checks
at execution time. `prune` claims byte deduplication only; `cprune` retains one
input per whole-map fingerprint and is not a global minimum covering set.

### Coverage experiments and replay

There is no coverage-experiment lifecycle subcommand in the current CLI. The
desktop Corpus view, REST resources under `/coverage/experiments`, and trusted
local native commands create, list, read, complete, or cancel retained
experiments. These operations retain evidence and perform no discovery,
provider call, coverage calculation, promotion, harness execution, or fuzzer
execution.

For a prepared experiment whose baseline has a retained seed, the existing CLI
handoff is:

```bash
# Run this with the same oxfuzz configuration/database used by the application.
oxfuzz run . --replay <baseline UUID>
```

Replay resolves the original project from the retained baseline, which must
still be available. It pins the recorded seed, engine, and duration, while using
the current promoted harness and current corpus under current policy. Keep every
other compared setting unchanged. Ordinary `oxfuzz run` derives a new seed and
will not produce an attachable match. A legacy baseline with a null seed cannot
be reproduced for comparison by replay; run a new seeded baseline and prepare a
new experiment. After the later run terminates, refresh the experiment and
explicitly attach its run UUID. Failed/cancelled/no-op outcomes remain visible;
an edge delta is descriptive and does not prove entry into the goal function.

The REST API exposes deterministic discovery and start/status/result/cancel/retry
for progressive AI discovery, plus harness, user-space run start/status/cancel,
corpus, triage, reporting, and management endpoints. Syzkaller remains a
trusted-local-desktop workflow because its kernel, rootfs, SSH, and VM inputs
require a stronger boundary.

#### Recover an ambiguous one-time campaign

```bash
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>
```

Acknowledgement records an expired, non-terminal occurrence with an unknown
prior outcome as cancelled and permanently consumes that one-time schedule. It
does not stop, resume, or adopt an orphaned sandbox process, and does not prove
its termination. To retry, create a new one-time schedule so it receives a new
schedule identifier and a new durable receipt. Recurring schedules remain
available when the one-time journal is blocked.

The equivalent REST operations are:

```text
GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```

### Optional automotive protocol workflows

The `automotive-scapy` feature adds sandboxed automotive capture analysis,
deterministic mutation and replay-plan generation, retained operation evidence,
state-signature corpus promotion, and evidence-backed campaign reporting. It is
enabled by default in the product crates (CLI, web, desktop) and turned on at
runtime out of the box, so the CAN/UDS workspace is always present; build with
`--no-default-features` to drop it. Physical-bench access stays disabled and
approval-gated regardless. The Rust application never imports Scapy or runs host
Python; Scapy 2.7.0 and optional `python-can` support live in a separately built
GPL-2.0 sidecar image.

```bash
# Build the separately distributed, pinned sidecar image.
./scripts/build-scapy-sidecar.sh

# The transport contract is compiled in by default (use --no-default-features
# to exclude it).
cargo build -p hf-cli

# The subsystem is enabled by default; inspect the active policy (and
# `automotive disable` if you need to turn it off).
target/debug/oxfuzz automotive settings

# Offline capture analysis never contacts a CAN interface.
target/debug/oxfuzz automotive analyze /path/to/project \
  --protocol uds --capture /path/to/capture.pcap

# Compose a deterministic report from retained operations and protocol states.
target/debug/oxfuzz automotive report /path/to/project \
  --output automotive-campaign.html --format html

# Compose it in Simplified Chinese. Evidence citations, pipeline stage
# identifiers, protocol/bus/ECU/adapter names, digests, paths and every figure
# stay verbatim; omitting the flag composes in English.
target/debug/oxfuzz automotive report /path/to/project --report-lang zh

# Optionally append provider-neutral AI interpretation. Unknown evidence
# citations are rejected and the deterministic report remains authoritative.
target/debug/oxfuzz automotive report /path/to/project --ai
```

The Automotive workspace follows a practical evidence pipeline: inspect the
pinned adapter, analyze an immutable capture, generate deterministic mutations,
build a typed replay plan, optionally perform a separately confirmed virtual
replay, and compose a campaign report. Reports retain failed and partial
operations, distinguish protocol-state novelty from source coverage, cite
operation/request/transcript/state evidence, show the effective safety posture,
and list concrete missing stages and next actions. When an LLM provider is
configured, AI may add a clearly labelled interpretation with hypotheses and
recommendations; it cannot modify a plan, enable policy, approve traffic, or
replace deterministic facts. Composed reports are saved to the shared Reports
workspace and can be exported as Markdown or HTML, plus DOCX/PDF when the host
has the required document tools.

Offline analysis uses a network-disabled sandbox. Virtual CAN additionally
requires an allowlisted `vcanN` interface and a high-risk guardrail approval.
Physical-bench mode is excluded from the default policy and requires explicit
enablement, an exact interface/arbitration/service allowlist, a fresh
plan-scoped human approval, and stricter limits. No generated plan is executed
on a host or vehicle as part of the normal test or build process.
