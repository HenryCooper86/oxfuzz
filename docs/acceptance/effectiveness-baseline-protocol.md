# Held-out effectiveness baseline protocol

Status: **runnable procedure; no qualified results yet**. The cohort validator,
the report reader, and the trial runner are in place and covered by script
tests; no live trials have been executed or reviewed.

The benchmark measures the one-command pipeline (`oxfuzz fuzz`: discover ->
harness -> smoke -> human-approved promote -> bounded campaign) on held-out
public targets the harness pipeline was not tuned against, one isolated
configuration, database, and workspace per trial.

## 1. The frozen cohort

Freeze a JSON cohort before collecting outcomes. Build it with the runner
(section 4) and validate it with
`python3 scripts/effectiveness_benchmark.py <cohort.json>`. The validator
rejects unknown fields, duplicate JSON keys or IDs, unresolved trial
references, unsupported project language/engine pairs, mutable source
revisions, missing source and sandbox digests, and invalid budgets. A passing
validation means the matrix is well formed; it does
not approve any target or harness for execution.

The top-level record has `schema_version: 1`, `cohort_id`, a 40-character
`candidate_commit`, and nonempty `projects`, `conditions`, and `trials` arrays.
Each project names an HTTPS `source_url`, full 40-character Git `revision`,
license, canonical `language` (`c`, `cpp`, or `rust`), 64-character staged-source
digest, and selected function symbols. C and C++ may use any declared userspace
engine; Rust may use libFuzzer only. Go and Python remain discovery-only until
their campaign paths are implemented and qualified.
Each condition fixes the engine, selection
strategy, provider family and model ID, sanitizer, top-k cutoff, campaign
duration, memory and CPU ceilings, model-call and dollar ceilings, and full
sandbox image SHA-256. Each trial names one project, condition, selected
function, deterministic seed, and unique trial ID.

`source_sha256` must be the service's `oxfuzz-run-source-v1` digest of the
staged build inputs. A repository archive hash is useful for source review but
is not interchangeable with that run-bound digest.

Condition-to-CLI mapping at execution time: `engine`, `duration_secs`,
`sanitizer`, `max_mem_mb`, and `max_cpus` are written into the trial's
condition-frozen `oxfuzz.toml` (and `--duration-secs`/`--sanitizer` onto the
`fuzz` invocation); `provider_family`/`model_id` select the model policy
(`--ai require`, or `--ai off --no-llm-review` for the offline leg whose
provider family is `none`); `selection_strategy` and `top_k` record how the
cohort's `selected_functions` were chosen (for `ranked`, from
`oxfuzz discover --rank`) and do not change a trial run, because every trial
passes its function explicitly with `--target`. `model_call_budget` and
`model_cost_budget_usd` are enforced post-hoc: the runner flags exceeded
budgets per trial and the report reader rejects an over-budget manifest. The
CLI has no runtime model-budget cutoff.

## 2. The held-out target manifest

`docs/acceptance/held-out-targets.json` is the reviewed, machine-readable
target list: three C JSON parsers (cJSON, yyjson, mjson) pinned by full
commit, license, and selected function, carried over from
[the 2026-09-27 candidate review](held-out-cohort-candidates-2026-09-27.md).
None ships in `examples/`. The runner validates the manifest (HTTPS sources,
40-character revisions, supported languages, unique ids) before any use.

Targets are vendored once, then verified offline:

```bash
python3 -m scripts.effectiveness_run fetch          # clone + pin-check
python3 -m scripts.effectiveness_run fetch --check  # offline re-verification
```

Fetch clones into `fuzz_workspace/effectiveness/targets/<id>` and checks out
the exact pinned revision (`git rev-parse HEAD` must equal it; a mismatch is a
hard error). The git checkout is what makes the pinned revision verifiable;
`fetch --check` and the run dry-run reject a tree without one. On an
air-gapped host, vendor the tree another way (for example `git clone` on a
connected host, then copy the directory with its `.git`), and record the
substitution in the acceptance record. The vendored tree must not be edited
afterwards.

## 3. Prerequisites

- A built CLI: `cargo build --release -p hf-cli` (or `--oxfuzz
  target/debug/oxfuzz`).
- Docker running, with the sandbox image built:
  `oxfuzz doctor --build-image` (or `scripts/build-sandbox.sh`).
- For provider-backed conditions: a config dir (`oxfuzz init`) whose
  `providers.toml` carries the condition's model, and the provider key
  variable exported in the environment that launches the runner (the runner
  passes its environment through to each trial).
- `HF_AUTO_APPROVE=1` is set by the runner for every trial child: the
  promotion gate is satisfied by environment policy, headlessly, exactly as
  documented in `docs/guides/CLI_REFERENCE.md`. Every approval lands in the
  trial's retained `oxfuzz policy decisions` trail.

## 4. Procedure

### 4.1 Calibrate the frozen digests

Two cohort values are only knowable after the service has staged a build:
`source_sha256` (the `oxfuzz-run-source-v1` digest of the staged inputs,
harness included) and `sandbox_image_sha256` (the resolved docker image id).
Run one calibration pass per project and read both from its database:

```bash
env HF_CONFIG_DIR=/tmp/calib/config HF_DB_PATH=/tmp/calib/oxfuzz.db \
    HF_WORKSPACE_DIR=/tmp/calib/workspace HF_AUTO_APPROVE=1 \
    oxfuzz fuzz fuzz_workspace/effectiveness/targets/cjson \
    --target cJSON_ParseWithLengthOpts --engine libfuzzer --lang c \
    --duration-secs 60 --iterations 1 --ai off --no-llm-review --json
sqlite3 /tmp/calib/oxfuzz.db \
    "SELECT source_rev, sandbox_rev FROM runs WHERE run_kind='campaign' \
     ORDER BY started_at DESC LIMIT 1"
```

`sandbox_rev` reads `docker-image-id-sha256:<64 hex>`; strip the prefix. The
image id must equal `docker image inspect oxfuzz/fuzz-sandbox:0.2.1 --format
'{{.Id}}'` with its `sha256:` prefix stripped. A calibration run that fails
before staging (no Docker, no image) produces no row; fix readiness first
(`oxfuzz doctor --json` names the blocker).

### 4.2 Freeze the cohort

Conditions live in a JSON array, one object per condition (the sandbox image
digest comes from the `--sandbox-image-sha256` flag):

```json
[
  {
    "id": "ranked-libfuzzer",
    "engine": "libfuzzer",
    "selection_strategy": "ranked",
    "provider_family": "openai",
    "model_id": "gpt-4o",
    "sanitizer": "address",
    "top_k": 5,
    "duration_secs": 600,
    "max_mem_mb": 2048,
    "max_cpus": 2,
    "model_call_budget": 40,
    "model_cost_budget_usd": 1.0
  }
]
```

```bash
python3 -m scripts.effectiveness_run freeze \
  --conditions conditions.json \
  --cohort-id held-out-c-parsers-2026-10-13 \
  --sandbox-image-sha256 <image id hex> \
  --source-sha256 cjson=<staged digest> \
  --source-sha256 yyjson=<staged digest> \
  --source-sha256 mjson=<staged digest> \
  --output cohort.json
python3 scripts/effectiveness_benchmark.py cohort.json
```

`freeze` derives each trial seed deterministically from the cohort and trial
ids, validates the assembled cohort with the same `validate_cohort` the
validator uses, and refuses to write an invalid matrix. `--candidate-commit`
defaults to this checkout's `HEAD`; `--replicates N` adds N seeds per
project/function/condition cell.

### 4.3 Dry-run the whole matrix

```bash
python3 -m scripts.effectiveness_run run --cohort cohort.json \
  --out results/dry-run --dry-run [--config <dir>]
```

The dry run executes nothing and needs no Docker, provider, or network. It
fails on: an invalid cohort or manifest, a cohort/manifest identity mismatch,
a missing CLI binary, an unvendored or wrongly pinned target, and a missing
config dir or `providers.toml` when a condition is provider-backed. It warns
on: a `doctor` probe that is not ready (per engine/duration/provider
combination, naming the problems), a model id absent from `providers.toml`,
and an unexported provider key variable (named, never valued). It prints the
full run matrix and an estimated duration: frozen fuzz time plus a 300 s
harness+smoke allowance per trial. With the checked-in manifest, one
600 s condition, and three projects, that is 30 min of fuzzing and roughly
45 min end to end.

### 4.4 Run the trials

```bash
python3 -m scripts.effectiveness_run run --cohort cohort.json \
  --out results/$(date +%Y%m%d-%H%M%S) [--config <dir>] \
  [--compute-usd-per-hour 0.10] [--only-trial <id>]...
```

Each trial gets a private `HF_CONFIG_DIR` (condition-frozen `oxfuzz.toml` plus
a copy of the operator's `providers.toml`), `HF_DB_PATH`, and
`HF_WORKSPACE_DIR`, so every run, crash, and model call attributes to exactly
one trial. The trial command is one pipeline invocation:

```bash
oxfuzz fuzz <target dir> --target <function> --engine <condition engine> \
  --lang <language> --duration-secs <condition duration> --iterations 1 \
  --sanitizer <condition sanitizer> --ai require --json
```

(`--ai off --no-llm-review` instead for the `none` provider leg.) One campaign
iteration of the frozen duration is one trial; replicates come from the
cohort, not from `--iterations`. A trial whose CLI exits non-zero, times out
(frozen duration plus a 900 s grace, `--trial-timeout-grace-secs`), or yields
no campaign run is recorded `failed` with the reason; failures stay in every
artifact. Per trial the runner checks conformance of each recorded campaign
run against the cohort (engine, duration, memory, CPUs, sanitizer, staged
source digest, sandbox image digest) and names every mismatch in
`results.json`.

After the campaign, the runner collects `oxfuzz coverage` output, reads the
trial database read-only for runs, deduplicated crashes, and model cost, and
-- unless `--no-evidence-export` -- starts a short-lived
`oxfuzz serve` on the loopback interface with a fresh token and the trial's
own state to export the service's schema-2 campaign evidence manifest
(`POST /campaign/evidence`, model cost from the trial's own diagnostics
ledger) and the exact function-coverage export
(`GET /runs/{id}/function-coverage`). Each exported manifest is pre-checked
against the cohort binding exactly as the report reader will check it.

### 4.5 Report

`results/<ts>/` contains:

- `results.json` -- the structured record: cohort identity, host and CLI
  identity, and per trial the outcome, wall-clock, campaign runs executed,
  unique crashes after `(run, stack signature)` dedup, time-to-first-crash
  (upper bound: earliest crash artifact file time minus the persisted run
  start), peak edges, line/function/region coverage, LLM calls/tokens/cost,
  budget flags, conformance mismatches, evidence references, and limitations.
  Unmeasured fields are `null` with a named limitation, never zero.
- `summary.md` -- the acceptance-record summary (claim/outcome, source
  identity, runtime identity, execution limits, evidence, review).
- `observations.json` -- the report-reader index, written only when every
  completed trial has cohort-bound evidence (a failed trial with no manifest
  is reader-valid and does not block it). Then:

  ```bash
  python3 -m scripts.effectiveness_report cohort.json results/<ts>/observations.json
  ```
- `trials/<id>/` -- CLI transcripts, the trial database and workspace;
  `evidence/<id>/` -- exported manifests with their SHA-256 references.

The trial matrix must be retained unchanged alongside failed, zero-progress,
and unavailable outcomes. A run's peak edge count is not evidence that its
selected function was entered. Missing function coverage, cost, crash origin,
or time-series samples must remain unavailable in the report rather than
becoming zero. Live work needs independent review and exact-source human
approval, and all builds and runs must use `hf-runtime` sandboxing. No customer
targets or finding publication are part of this baseline.

## 5. Known gaps

- **Trial seeds cannot be pinned through the CLI.** Every run derives its seed
  from its random run id (`hf_engine::seed::derive_run_seed`), so a frozen
  trial seed never equals the recorded `run_config.seed`, and the report
  reader's seed equality check rejects the manifest. The runner detects this
  at binding time, keeps the trial's metrics complete in `results.json`, and
  withholds the observation reference. Reproducibility meanwhile comes from
  the retained run: `oxfuzz run . --replay <run-id>` re-executes the recorded
  seed exactly. Restoring the strict binding needs a seed-pinning CLI flag
  (deliberate future work, not a workaround).
- **The evidence export requires the default feature set**
  (`proof-carrying`) on the `oxfuzz serve` binary and a loopback port for the
  short-lived server; `--no-evidence-export` skips it and says so per trial.
- **Time-to-first-crash is an upper bound** (crash artifact file timestamp
  minus persisted run start); engines do not persist discovery timestamps.
- **honggfuzz reports no edge count**; edge coverage stays unavailable for
  honggfuzz conditions.
- **Model budgets are post-hoc** (flagged by the runner, enforced by the
  report reader); the CLI cannot stop a trial mid-flight at a dollar ceiling.

## 6. The report reader

The report reader accepts a separate JSON observation index with
`schema_version: 1`, the same `cohort_id`, and exactly one entry per declared
trial. Each entry has `id`, `outcome` (`completed`, `failed`, `cancelled`, or
`unavailable`),
`reason` (null for a completed trial), and `campaign_manifest` and
`function_coverage` references. A reference has a path relative to the index
and the SHA-256 of that exact JSON file; use null for an absent measurement.
Artifact references reject symlinks in every path component and cannot escape
the observation directory. The reader caps each JSON input at 16 MiB while
reading, before parsing or checking its digest.
Generate the report with
`python3 -m scripts.effectiveness_report <cohort.json> <observations.json>`.
The reader checks file hashes and joins service exports by run, binary,
source snapshot, image, target, engine, and fixed run settings. It reports
observed function entry only from a positive exact-run counter. A zero counter
means `not_observed`, with a limitation, rather than proven non-entry.
Duration, memory, CPU, and seed in a campaign manifest must retain their JSON
integer types as well as their frozen values; equal decimal or boolean values
are not accepted as the same settings.

Current summaries cover terminal trial outcomes, peak edges, attributable
model-plus-compute cost, and selected-function entry when measured. The report
retains each trial's project ID and provides project-by-condition and overall
condition summaries. Every numeric summary includes the sorted measured
samples, an unavailable count, and a median; a project with no campaign
measurement therefore remains visible rather than contributing a false zero.
Discovery top-k usefulness, qualification rate, time to useful campaign, branch coverage
over time, and reproducible versus harness-caused crashes remain unavailable
until their retained inputs and classification are added. The report reader
checks the whole-file hash supplied by the observation index; review the
service-produced manifest and its own digest at export time before archiving
that file.
