# Clang harness context: initial GLM comparison

The integration works through real model drafting, sandbox compilation,
independent source review, human approval, smoke qualification and campaigns.
This three-fixture comparison does **not** show an aggregate coverage gain.
Enriched context added one C parser guard outcome and missed one C++ parser
outcome, with much greater input-token use. These results justify measuring
context quality rather than assuming more analysis always produces a better
harness.

## Frozen comparison

The [protocol](clang-effectiveness-protocol.md) used three repository-owned C/C++
fixtures and two conditions, in separate databases and workspaces. Both used
GLM-5.3 through the standard BigModel API, temperature 0.2, low reasoning effort,
an 8192 output-token cap, libFuzzer, address sanitizer, one CPU, 2048 MiB,
60-second smoke qualification and a 30-second campaign with RNG seed 1337.
Actual campaign starting-corpus digests matched within all three pairs.
No repair or replacement draft was used.

Exactly twelve upstream requests completed: six drafts and six independent
exact-source reviews. The gateway reserved each request durably before sending
it and refused any further upstream requests. All responses identified the
model as `glm-5.3`. The operator approved the six retained source/binary
revisions before any harness executed. All builds, executions, profiles and
coverage collection went through existing service operations and hf-runtime.

The CLI was built with defaults disabled and
`clang-analysis,harness-work-order,proof-carrying`. Only enriched trials retained
Clang evidence, with a 32768-byte model-context ceiling. Immutable sandbox and
analyzer IDs, CLI/source/seed/configuration digests, run IDs, source/binary
reviews, actual token usage and profile-export digests are in the
[machine-readable results](clang-effectiveness-2026-10-20.json). Packet ID:
`80299cda666da97b8676385b0ad2abaafe951ba6aac6abcf30452f403073c564`.

## Observed results

| Fixture | Condition | Compiled / entered | Downstream functions | Target branch outcomes | Final reported exec/s | Clang seconds |
| --- | --- | --- | --- | --- | ---: | ---: |
| C record parser | Baseline | yes / yes | 1/1 | 25/26 | 799605 | 0 |
| C record parser | Enriched | yes / yes | 1/1 | 26/26 | 636737 | 0.220 |
| C decoder handles | Baseline | yes / yes | 3/3 | 13/18 | 473326 | 0 |
| C decoder handles | Enriched | yes / yes | 3/3 | 13/18 | 267355 | 0.250 |
| C++ command parser | Baseline | yes / yes | 2/2 | 21/22 | 436226 | 0 |
| C++ command parser | Enriched | yes / yes | 2/2 | 20/22 | 791476 | 0.226 |

Both conditions compiled 3/3 harnesses, entered 3/3 targets, and covered all six
instrumented downstream project functions. Aggregate target-file branch outcome
coverage was 59/66 in each condition. No crash was recorded in these bounded
smoke/campaign runs.

The enriched C record harness explicitly tested null and truncated inputs. The
C++ baseline tested a null pointer for empty input; the enriched draft used a
minimal direct call. The retained target-file counters expose those tradeoffs.
Engine edge counts are also retained, but include harness code and must not be
read as target-only coverage gains.

| Condition | Draft + review input tokens | Draft + review output tokens |
| --- | ---: | ---: |
| Baseline | 1519 | 569 |
| Enriched | 37449 | 569 |

Clang seconds measure the retained operation from admission to completion on
these tiny fixtures with already available images. They exclude helper image
builds and model latency. Baseline zero means no Clang operation was requested.

## Limits and retained evidence

There is one run per fixture/condition. The fixtures are small and share simple
input signatures. Rust quality checks ran concurrently on the host, so the
execution rates describe these runs and do not isolate a causal performance
effect. A fixed RNG seed does not make feedback-driven fuzzing deterministic.
No general bug-finding or coverage improvement follows from this cohort.

The frozen analyzer image preceded the final library-callback metadata fix.
Re-running the final helper on all three exact source snapshots produced
identical graph/CFG/exploration evidence except for the helper executable hash.
The machine-readable report retains that equivalence check. Final helper
qualification separately covers library callbacks, templates and lambdas.

The local qualification bundle retains the packet, trial databases, exact
sources, independent reviews, human approval, request ledger, provider
responses, stdout/stderr, run evidence and LLVM exports. The public result
contains their immutable identities and counters; no credential is included.
Missing measurements remain null rather than being converted to zero.

## Follow-up: planning and context cost (2026-10-21)

Re-rendering the exact retained context of all three enriched trials through the
improved planner and compact renderer, with no new provider calls or harness
executions, reduced the retained provider-section bytes and corrected a
selection failure:

| Fixture | Section bytes before | Section bytes after | Modeled calls before | Modeled calls after | Branch observations before | Branch observations after | Omitted records |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| C record parser | 31,267 | 12,148 | 2 | 2 | 53 (23 distinct) | 23 | 0 |
| C decoder handles | 32,411 | 17,817 | 26 (5 distinct) | 5 | 1 | 32 (all distinct) | 73 |
| C++ command parser | 21,394 | 11,616 | 2 | 2 | 29 (22 distinct) | 22 | 0 |

Total section bytes fell from 85,072 to 41,581 (51.1%). The decoder trial
previously retained 26 repeated call witnesses and a single guard observation
while omitting 302 records; it now retains all 32 distinct guard observations
and only the 73 helper-side omissions, so guard guidance that the model did not
previously see is present in a smaller section. The compact renderer
states each unit-qualified declaration identity once behind prompt-local symbol
indices, and exact-duplicate call/branch observations are coalesced before
budgeting, with guards selected ahead of calls and raw CFGs. Plan references
were re-validated against the retained observations.

These final measurements include the complete target declaration in the symbol
table and the renderer's exact wrapper allowance during planning.

This is a byte measurement on retained contexts, not a re-run of the frozen
coverage comparison. It establishes no coverage improvement; a repeated
like-for-like coverage run would require fresh provider calls and human
approvals under the comparison protocol.
