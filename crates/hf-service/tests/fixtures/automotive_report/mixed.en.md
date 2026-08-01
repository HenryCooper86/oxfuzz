# Automotive Fuzzing Campaign Report: `mixed`

| | |
|---|---|
| Project | `mixed` |
| Generated | 2026-07-16T09:00:00Z |
| Tool | oxfuzz 0.1.0 |
| Evidence window | 4 retained operation(s) |

## Executive Summary

This report synthesizes **4 retained automotive operation(s)**: **0 completed**, **1 partial**, **1 failed**, **1 running**, and **1 cancelled**. The bounded snapshot contains **1 unique protocol-state digest(s)** and **0 promoted state-corpus artifact(s)** across **1 observed protocol(s)**.

Retained failures are reported as operational evidence and should be resolved before the corresponding workflow stage is repeated.

Protocol-state novelty is **not source coverage** and does not by itself prove a vulnerability.

## Scope and Safety Posture

| Control | Effective posture |
|---|---|
| Runtime automotive policy | enabled |
| Allowed protocols | `can` |
| Allowed modes | `offline_pcap` |
| Virtual interfaces | 4 allowlisted |
| Physical bench | invalid: enabled without required approval; 5 allowlisted interface(s) |
| Dangerous diagnostic services | exceptionally allowed by policy |
| Per-operation bounds | 8 events; 9 seconds; 10 transmitted events/second |

All captured, mutation, planning, and replay evidence remains subject to service validation, sandbox isolation, typed limits, guardrails, and the human-approval boundary.

## Campaign Workflow

| Stage | Status | Completed | Failed |
|---|---|---:|---:|
| Adapter capability inspection | Not recorded | 0 | 0 |
| Immutable capture analysis | Not recorded | 0 | 0 |
| Deterministic mutation generation | Attention | 0 | 1 |
| Typed replay-plan construction | Attention | 0 | 1 |
| Supervised virtual replay | Attention | 0 | 1 |

Physical-bench validation is intentionally excluded from campaign-completeness scoring. It remains a separately approved activity after the exact plan and budgets are known.

## Protocol-State Exploration

| Protocol | Unique states | Promoted artifacts |
|---|---:|---:|
| `uds` | 1 | 0 |

### State Evidence

- `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]` (`uds`), observed by [OP:00000000-0000-0000-0000-00000000000b].

## Findings

### Operational failure: `execute_replay`

- Evidence: [OP:00000000-0000-0000-0000-00000000000e]
- Mode: `virtual_can`
- Protocol: `not selected`
- Retained error: no error detail retained

### Partial result: `build_replay_plan`

- Evidence: [OP:00000000-0000-0000-0000-00000000000d]
- Result: typed operation did not complete
- Required action: review the retained transcript and limits before retrying.

### Interpretation Boundary

Observed states, successful decoding, and completed replay steps are campaign evidence. They do not by themselves prove exploitability, security impact, or unsafe vehicle behavior.

## Evidence Manifest

| Operation evidence | Stage | Mode / protocol | Status | Validated result | Request digest | Transcript evidence | Artifact directory |
|---|---|---|---|---|---|---|---|
| [OP:00000000-0000-0000-0000-00000000000b] | `analyze_capture` | `offline_pcap` / `n/a` | running | not retained | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | not retained | `.service/automotive/running` |
| [OP:00000000-0000-0000-0000-00000000000c] | `generate_mutations` | `offline_pcap` / `can` | cancelled | not retained | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/cancelled` |
| [OP:00000000-0000-0000-0000-00000000000d] | `build_replay_plan` | `offline_pcap` / `can` | done | not retained | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/partial` |
| [OP:00000000-0000-0000-0000-00000000000e] | `execute_replay` | `virtual_can` / `n/a` | failed | not retained | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | not retained | `.service/automotive/failed` |

## Limitations

- The report covers only the bounded retained evidence snapshot and cannot infer events that were not persisted.
- Protocol-state digests are not source-code line, function, region, or edge coverage.
- A completed operation confirms contract-valid execution, not absence of security defects.
- Offline and virtual evidence does not validate a physical ECU, vehicle network, timing behavior, or bench wiring.
- AI-assisted interpretation, when appended, is advisory and cannot authorize execution or establish a finding.

## Recommendations

1. Triage the 1 retained operational failure(s) by operation id before repeating those stages.
2. Next, inspect the pinned adapter capabilities.
3. Next, analyze an immutable representative capture.
4. Next, generate a deterministic, reviewable mutation set.
5. Review and promote suitable artifacts for the 1 observed state(s) without retained corpus evidence.
6. If policy and runtime readiness permit, conduct a separately confirmed supervised virtual-CAN replay.
---

_Deterministic evidence report generated by oxfuzz 0.1.0 on 2026-07-16T09:00:00Z._
