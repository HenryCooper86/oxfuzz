# Clang harness context comparison

This protocol compares ordinary drafting with opt-in LLVM CFG and Static
Analyzer context. It uses three fixed, repository-owned C/C++ fixtures in
`tests/fixtures/clang_effectiveness`: a guarded record parser, an allocated
decoder, and a C++ parser with private implementation methods. Each fixture has
one baseline and one enriched trial, with separate project, configuration,
database, workspace and seed directories. This small cohort tests feasibility;
it cannot establish general bug-finding effectiveness.

## Freeze and author

Build the CLI with `clang-analysis,harness-work-order,proof-carrying`. Resolve the
fuzz sandbox and analyzer image tags to immutable SHA-256 image IDs. Prepare:

```sh
python3 -m scripts.clang_effectiveness prepare --out /absolute/comparison \
  --sandbox-image sha256:IMAGE_ID --analyzer-image sha256:ANALYZER_ID \
  --model glm-5.3 --duration-secs 30
```

The packet binds fixture source, target selector, initial seed, configuration,
model, standard BigModel endpoint, both images, sanitizer, RNG seed, resources
and duration. `verify_packet` rejects modified source/seed/config bytes. Do not
change a failed harness or silently regenerate it. One authoring response and
one independent exact-source review per trial fit the initial total twelve-call
budget. Transport failures and retries count toward that total too.

The authorized standard endpoint is `https://open.bigmodel.cn/api/paas/v4`.
Use an external private credential file; no secret belongs in this packet or
repository. A loopback counting gateway may forward the provider client's chat
requests to that endpoint. Before every upstream dispatch it must reserve a
slot through `CallBudget`, durably retaining the exact outgoing JSON. Retain
responses, status and usage by call ID. Apply the packet's common 8192 output
token limit, low reasoning effort and temperature 0.2 to both conditions, and
retain those wire choices before dispatch. Refuse further requests when twelve
slots have been reserved; retries and health probes cannot evade that cap.
GLM-5.3's thinking remains enabled as required by the provider.

For each trial, discover the target (add `--clang` only for the enriched trial),
export its work-order packet, and use `harness --draft-only --json --ai require`.
Import that exact source through `work-order import` with model provenance.
Compile and independently review it through existing qualification operations.
`qualification_command` sets `HF_AUTO_APPROVE=0`: it can compile and review but
must stop at the human execution gate. A denied smoke operation is an expected
pre-approval state, not a compile failure. Retain its attempt and source/binary
digests. No generated harness executes during this preparation.

## Approve and measure

Present the exact retained sources and review verdicts to the operator. Obtain
approval for those revisions before smoke, promotion, campaigns or coverage
replay. After approval, use the existing service smoke operation on the same
active compiled revision, which reuses its exact-digest review. Do not re-draft
or recompile through a second work-order qualification: a different revision
would require a new review and another budget slot. Promote only a qualified
revision whose target-entry evidence meets the existing promotion rules.

Seed both trial corpora with the same retained bytes, then run the promoted
harness for thirty seconds with RNG seed 1337, one CPU and 2048 MiB. Keep the
smoke and campaign counters separate. Use the existing service coverage
collector, including its sandboxed LLVM tools and retained per-function
profiles. Never invoke a generated executable on the host or infer target
entry from an LLM opinion or a successful compilation.

## Retain and report

Save actual CLI/service JSON, per-trial SQLite state, exact draft/imported
source, compiled revision IDs/digests, independent review, human approval,
run IDs/configs/image identities, function coverage and engine progress. Check
the model identity in actual responses. Report analysis duration, build
success, observed target entry, covered/total downstream functions, engine edge
coverage, throughput and wall time separately. Draft/review input/output token
counts come from actual provider responses, including failed trials where
available. Record failures rather than replacing them with another model.

`covered_functions`/`total_functions` count instrumented functions in the fixed
project source file downstream of the target, excluding the target and harness.
Target-file branch outcome counters are reported separately as
`target_branches_covered`/`target_branches_total`, directly from the retained LLVM
file summary. Engine edges include harness code and cannot establish a gain in
target-only coverage. Use the final reported campaign execution rate; a peak
sample is not the whole campaign's rate. Record competing host workloads when
interpreting these timing measurements.

An observation binds its packet/trial identity and retained execution evidence
with matching reviewed source/binary digests. Execution metrics, including zero,
require that evidence; absent metrics stay null. The report validator rejects
mixed source/model/budget identities, duplicate trials and unapproved execution
claims. Build the machine-readable report with:

```sh
python3 -m scripts.clang_effectiveness report \
  --packet /absolute/comparison/comparison.json \
  --observations /absolute/comparison/observations.json \
  --out /absolute/comparison/results.json
```

Transport-fixture qualifications in CI establish pipeline behavior only. They
are never effectiveness observations. Reports must name the three-fixture
cohort, all failed or unavailable trials and the twelve-call cap.
