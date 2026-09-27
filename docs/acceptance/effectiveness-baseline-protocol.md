# Held-out effectiveness baseline protocol

Status: **cohort validation and partial retained-evidence reporting**. No
held-out projects, live trials, or effectiveness results have been qualified.

Freeze a JSON cohort before collecting outcomes. Validate it with
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

The trial matrix must be retained unchanged alongside failed, zero-progress,
and unavailable outcomes. A run's peak edge count is not evidence that its
selected function was entered. Missing function coverage, cost, crash origin,
or time-series samples must remain unavailable in the eventual report rather
than becoming zero. Live work needs independent review and exact-source human
approval, and all builds and runs must use `hf-runtime` sandboxing. No customer
targets or finding publication are part of this baseline.

The report reader accepts a separate JSON observation index with
`schema_version: 1`, the same `cohort_id`, and exactly one entry per declared
trial. Each entry has `id`, `outcome` (`completed`, `failed`, `cancelled`, or
`unavailable`),
`reason` (null for a completed trial), and `campaign_manifest` and
`function_coverage` references. A reference has a path relative to the index
and the SHA-256 of that exact JSON file; use null for an absent measurement.
Artifact references reject symlinks in every path component and cannot escape
the observation directory.
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
