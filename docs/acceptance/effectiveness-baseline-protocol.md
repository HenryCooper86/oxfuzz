# Held-out effectiveness baseline protocol

Status: **cohort validation only**. No held-out projects, live trials, or
effectiveness results have been qualified by this file.

Freeze a JSON cohort before collecting outcomes. Validate it with
`python3 scripts/effectiveness_benchmark.py <cohort.json>`. The validator
rejects unknown fields, duplicate JSON keys or IDs, unresolved trial
references, mutable source revisions, missing source and sandbox digests, and
invalid budgets. A passing validation means the matrix is well formed; it does
not approve any target or harness for execution.

The top-level record has `schema_version: 1`, `cohort_id`, a 40-character
`candidate_commit`, and nonempty `projects`, `conditions`, and `trials` arrays.
Each project names an HTTPS `source_url`, full 40-character Git `revision`,
license, 64-character SHA-256 of the exact target-source snapshot to be staged,
and selected function symbols. Each condition fixes the engine, selection
strategy, provider family and model ID, sanitizer, top-k cutoff, campaign
duration, memory and CPU ceilings, model-call and dollar ceilings, and full
sandbox image SHA-256. Each trial names one project, condition, selected
function, deterministic seed, and unique trial ID.

The trial matrix must be retained unchanged alongside failed, zero-progress,
and unavailable outcomes. A run's peak edge count is not evidence that its
selected function was entered. Missing function coverage, cost, crash origin,
or time-series samples must remain unavailable in the eventual report rather
than becoming zero. Live work needs independent review and exact-source human
approval, and all builds and runs must use `hf-runtime` sandboxing. No customer
targets or finding publication are part of this baseline.
